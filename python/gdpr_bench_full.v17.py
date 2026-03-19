#!/usr/bin/env python3
"""
gdpr_bench_full.py

Single-file GDPR benchmark harness implementing:
  (1) Embedded Rights Test Suite (RTS)
  (2) Policy / Consent Engine
  (3) Append-only hash-chained Audit Log + end-of-run verifier + audit report
  (4) 3 architecture scenarios: encryption, vaulted tokenization, vaultless tokenization
  (5) Repetitions, pooled summary + bootstrap CIs
  (6) System CPU/memory sampling (psutil)
  (7) Optional empirical DB latency sampler from CSV (header: latency_ms)

Outputs (in --output-dir):
  - combined_per_request_<ts>.csv
  - combined_summary_<ts>.json
  - audit_log.ndjson
  - audit_report_<ts>.json

Run examples:
  python gdpr_bench_full.py --tps 100 1000 --duration-s 30 --reps 3 --output-dir ./out

  # Use empirical DB latencies:
  python gdpr_bench_full.py --tps 1000 --duration-s 60 --reps 5 \
    --db-latency-file db_latencies.csv --output-dir ./out

  # Rights testing and consent distribution:
  python gdpr_bench_full.py --tps 500 --duration-s 30 --reps 2 --output-dir ./out \
    --rights-mode random --rights-prob 0.6 \
    --seed-subjects 2000 \
    --consent-read-rate 0.90 --consent-write-rate 0.70 --consent-erase-rate 0.80 --consent-restrict-rate 0.60
"""

import platform as _platform
import argparse
import asyncio
import csv
import json
import os
import time
import random
import uuid
import threading
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Tuple

import numpy as np
import psutil
from scipy import stats

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----------------------
# Utilities
# ----------------------

def now_iso_utc() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stable_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

def sha256_hex(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()

def hash_personal_data(payload: Dict[str, Any]) -> str:
    return sha256_hex(stable_json(payload).encode("utf-8"))

# ----------------------
# Audit Log (hash chained, append-only NDJSON)
# ----------------------

class AuditLog:
    """
    NDJSON append-only audit log with SHA256 chaining.
    Each entry includes: prev_hash, entry_hash.
    """
    def __init__(self, path: str, ensure_dir: bool = True):
        self.path = path
        if ensure_dir:
            d = os.path.dirname(path)
            if d:
                os.makedirs(d, exist_ok=True)
        self._last_hash = None
        if os.path.exists(self.path) and os.path.getsize(self.path) > 0:
            last = self.read_last_entry()
            if last and "entry_hash" in last:
                self._last_hash = last["entry_hash"]

    def _canonical_bytes(self, obj: Dict[str, Any]) -> bytes:
        return stable_json(obj).encode("utf-8")

    def _compute_hash(self, obj_wo_entry_hash: Dict[str, Any]) -> str:
        return sha256_hex(self._canonical_bytes(obj_wo_entry_hash))

    def append_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        required = ("subject_id", "request_id", "action", "outcome")
        for k in required:
            if k not in entry:
                raise ValueError(f"Audit entry missing required key: {k}")

        e = dict(entry)
        if "timestamp" not in e:
            e["timestamp"] = time.time()
        e["prev_hash"] = self._last_hash

        temp = dict(e)
        temp.pop("entry_hash", None)
        ehash = self._compute_hash(temp)
        e["entry_hash"] = ehash

        line = stable_json(e) + "\n"
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

        self._last_hash = ehash
        return e

    def read_last_entry(self) -> Optional[Dict[str, Any]]:
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            return None
        with open(self.path, "rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            # walk backwards to find last newline
            pos = end - 1
            while pos >= 0:
                f.seek(pos)
                if f.read(1) == b"\n" and pos != end - 1:
                    break
                pos -= 1
            f.seek(pos + 1)
            line = f.readline().decode("utf-8", errors="replace").strip()
            return json.loads(line) if line else None

    def verify_chain(self) -> Tuple[bool, Optional[List[int]]]:
        bad = []
        prev = None
        if not os.path.exists(self.path):
            return True, None
        with open(self.path, "r", encoding="utf-8") as f:
            for idx, raw in enumerate(f):
                raw = raw.strip()
                if not raw:
                    continue
                obj = json.loads(raw)
                if obj.get("prev_hash") != prev:
                    bad.append(idx)
                temp = dict(obj)
                entry_hash = temp.pop("entry_hash", None)
                calc = sha256_hex(stable_json(temp).encode("utf-8"))
                if entry_hash != calc:
                    bad.append(idx)
                prev = entry_hash
        return (len(bad) == 0, (bad if bad else None))

    def read_all(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, "r", encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if raw:
                    out.append(json.loads(raw))
        return out

# ----------------------
# Policy / Consent Engine
# ----------------------

class PolicyEngine:
    DEFAULT_RULES = {
        "access": "consent:read",
        "portability": "consent:read",
        "rectification": "consent:write",
        "erasure": "consent:erase",
        "restriction": "consent:restrict",
    }

    def __init__(self, audit_log: AuditLog, rules: Optional[Dict[str, str]] = None):
        self.audit_log = audit_log
        self.rules = dict(self.DEFAULT_RULES)
        if rules:
            self.rules.update(rules)
        # subject_id -> { scope: expiry_ts or None }
        self._consents: Dict[str, Dict[str, Optional[float]]] = {}

    def load_consents(self, consents: Dict[str, Dict[str, Optional[float]]]) -> None:
        for sid, scopes in consents.items():
            self._consents.setdefault(sid, {}).update(scopes)

    def grant_consent(self, subject_id: str, scope: str, actor: str = "simulator", expiry_ts: Optional[float] = None) -> Dict[str, Any]:
        self._consents.setdefault(subject_id, {})[scope] = expiry_ts
        return self.audit_log.append_entry({
            "subject_id": subject_id,
            "request_id": f"consent-grant-{int(time.time()*1000)}",
            "action": "consent_grant",
            "outcome": "success",
            "actor": actor,
            "detail": f"granted scope={scope} expiry={expiry_ts}"
        })

    def revoke_consent(self, subject_id: str, scope: str, actor: str = "simulator") -> Dict[str, Any]:
        if subject_id in self._consents:
            self._consents[subject_id].pop(scope, None)
        return self.audit_log.append_entry({
            "subject_id": subject_id,
            "request_id": f"consent-revoke-{int(time.time()*1000)}",
            "action": "consent_revoke",
            "outcome": "success",
            "actor": actor,
            "detail": f"revoked scope={scope}"
        })

    def _has_consent(self, subject_id: str, scope: str) -> Tuple[bool, str]:
        scopes = self._consents.get(subject_id, {})
        if scope not in scopes:
            return False, "consent-missing"
        expiry = scopes[scope]
        if expiry is None:
            return True, "consent-present"
        if expiry >= time.time():
            return True, "consent-present-until"
        return False, "consent-expired"

    def check_authorization(self, subject_id: str, action: str, scope: Optional[str], request_id: str, actor: str = "simulator") -> Dict[str, Any]:
        required_scope = self.rules.get(action)
        if not required_scope:
            allowed = False
            reason = "no-policy-rule"
            effective_scope = scope
        else:
            effective_scope = scope or required_scope
            allowed, reason = self._has_consent(subject_id, effective_scope)

        auth_audit = self.audit_log.append_entry({
            "subject_id": subject_id,
            "request_id": request_id,
            "action": "authorization_check",
            "outcome": "success" if allowed else "denied",
            "actor": actor,
            "detail": f"action={action} required_scope={required_scope} provided_scope={scope} effective_scope={effective_scope} reason={reason}"
        })
        return {
            "allowed": bool(allowed),
            "reason": reason,
            "scope": effective_scope,
            "audit_ref": auth_audit.get("entry_hash")
        }

# ----------------------
# Rights Test Suite (RTS)
# ----------------------

REASON_OK = "OK"
REASON_NOT_AUTHORIZED = "NOT_AUTHORIZED"
REASON_MISSING_AUDIT = "MISSING_AUDIT"
REASON_AUDIT_INVALID = "AUDIT_INVALID"
REASON_INCORRECT_OUTCOME = "INCORRECT_OUTCOME"
REASON_NO_PAYLOAD = "NO_PAYLOAD"
REASON_NO_STORAGE_CHANGE = "NO_STORAGE_CHANGE"
REASON_INVALID_PORTABILITY_FORMAT = "INVALID_PORTABILITY_FORMAT"
REASON_UNKNOWN_RIGHT = "UNKNOWN_RIGHT"

@dataclass
class RightsRequest:
    right: str
    subject_id: str
    request_id: str
    requested_fields: Optional[list] = None
    expected_changes: Optional[Dict[str, Any]] = None
    scope: Optional[str] = None
    timestamp: Optional[float] = None

@dataclass
class SystemResponse:
    success: bool
    returned_payload: Optional[Dict[str, Any]] = None
    storage_state: Optional[Dict[str, Any]] = None
    audit_entry: Optional[Dict[str, Any]] = None
    authorization: Optional[Dict[str, Any]] = None
    detail: Optional[str] = None

class RightsTestSuite:
    REQUIRED_AUDIT_KEYS = ("timestamp", "subject_id", "request_id", "action", "outcome")

    def __init__(self, slo_seconds: Optional[float] = None):
        self.slo = slo_seconds

    def _base_result(self, right: str, compliant: bool, reason_code: str, detail: str) -> Dict[str, Any]:
        return {"right": right, "compliant": compliant, "reason_code": reason_code, "detail": detail, "timestamp_utc": now_iso_utc()}

    def _check_authorization(self, req: RightsRequest, resp: SystemResponse) -> Tuple[bool, str]:
        auth = resp.authorization
        if not auth or not auth.get("allowed", False):
            return False, REASON_NOT_AUTHORIZED
        if req.scope and auth.get("scope") and auth.get("scope") != req.scope:
            return False, REASON_NOT_AUTHORIZED
        return True, REASON_OK

    def _check_audit(self, req: RightsRequest, resp: SystemResponse, expected_action: str) -> Tuple[bool, str]:
        audit = resp.audit_entry
        if not audit:
            return False, REASON_MISSING_AUDIT
        for k in self.REQUIRED_AUDIT_KEYS:
            if k not in audit:
                return False, REASON_AUDIT_INVALID
        if audit.get("subject_id") != req.subject_id or audit.get("request_id") != req.request_id:
            return False, REASON_AUDIT_INVALID
        if audit.get("action") != expected_action:
            return False, REASON_AUDIT_INVALID
        return True, REASON_OK

    def validate_access(self, req: RightsRequest, resp: SystemResponse) -> Dict[str, Any]:
        ok_auth, rc = self._check_authorization(req, resp)
        if not ok_auth:
            return self._base_result("access", False, rc, "Authorization denied or missing.")
        rp = resp.returned_payload
        if not rp:
            return self._base_result("access", False, REASON_NO_PAYLOAD, "No payload returned.")
        if rp.get("subject_id") != req.subject_id:
            return self._base_result("access", False, REASON_INCORRECT_OUTCOME, "Subject mismatch.")
        if req.requested_fields:
            missing = [f for f in req.requested_fields if f not in rp]
            if missing:
                return self._base_result("access", False, REASON_INCORRECT_OUTCOME, f"Missing fields: {missing}")
        ok_audit, arc = self._check_audit(req, resp, "access")
        if not ok_audit:
            return self._base_result("access", False, arc, "Audit missing/invalid.")
        return self._base_result("access", True, REASON_OK, f"hash={hash_personal_data(rp)}")

    def validate_rectification(self, req: RightsRequest, resp: SystemResponse) -> Dict[str, Any]:
        ok_auth, rc = self._check_authorization(req, resp)
        if not ok_auth:
            return self._base_result("rectification", False, rc, "Authorization denied or missing.")
        if not req.expected_changes:
            return self._base_result("rectification", False, REASON_INCORRECT_OUTCOME, "No expected_changes.")
        ss = resp.storage_state or {}
        mismatches = []
        for k, v in req.expected_changes.items():
            if ss.get(k) != v:
                mismatches.append((k, ss.get(k), v))
        if mismatches:
            return self._base_result("rectification", False, REASON_INCORRECT_OUTCOME, f"Mismatches: {mismatches}")
        ok_audit, arc = self._check_audit(req, resp, "rectification")
        if not ok_audit:
            return self._base_result("rectification", False, arc, "Audit missing/invalid.")
        return self._base_result("rectification", True, REASON_OK, "Rectification applied.")

    def validate_erasure(self, req: RightsRequest, resp: SystemResponse) -> Dict[str, Any]:
        ok_auth, rc = self._check_authorization(req, resp)
        if not ok_auth:
            return self._base_result("erasure", False, rc, "Authorization denied or missing.")
        ss = resp.storage_state or {}
        signals = []
        if ss.get("erased") is True: signals.append("erased")
        if ss.get("token_state") == "invalid": signals.append("token_invalid")
        if ss.get("key_revoked") is True: signals.append("key_revoked")
        if ss.get("data_present") is False: signals.append("data_absent")
        if not signals:
            return self._base_result("erasure", False, REASON_INCORRECT_OUTCOME, f"No erasure signal: {ss}")
        ok_audit, arc = self._check_audit(req, resp, "erasure")
        if not ok_audit:
            return self._base_result("erasure", False, arc, "Audit missing/invalid.")
        return self._base_result("erasure", True, REASON_OK, f"signals={signals}")

    def validate_restriction(self, req: RightsRequest, resp: SystemResponse) -> Dict[str, Any]:
        ok_auth, rc = self._check_authorization(req, resp)
        if not ok_auth:
            return self._base_result("restriction", False, rc, "Authorization denied or missing.")
        ss = resp.storage_state or {}
        if ss.get("restricted") is not True:
            return self._base_result("restriction", False, REASON_INCORRECT_OUTCOME, f"Not restricted: {ss}")
        ok_audit, arc = self._check_audit(req, resp, "restriction")
        if not ok_audit:
            return self._base_result("restriction", False, arc, "Audit missing/invalid.")
        return self._base_result("restriction", True, REASON_OK, "Restriction applied.")

    def validate_portability(self, req: RightsRequest, resp: SystemResponse) -> Dict[str, Any]:
        ok_auth, rc = self._check_authorization(req, resp)
        if not ok_auth:
            return self._base_result("portability", False, rc, "Authorization denied or missing.")
        rp = resp.returned_payload
        if not rp:
            return self._base_result("portability", False, REASON_NO_PAYLOAD, "No payload returned.")
        try:
            json.dumps(rp)
        except Exception:
            return self._base_result("portability", False, REASON_INVALID_PORTABILITY_FORMAT, "Not JSON-serializable.")
        if rp.get("subject_id") != req.subject_id:
            return self._base_result("portability", False, REASON_INCORRECT_OUTCOME, "Subject mismatch.")
        if req.requested_fields:
            missing = [f for f in req.requested_fields if f not in rp]
            if missing:
                return self._base_result("portability", False, REASON_INCORRECT_OUTCOME, f"Missing fields: {missing}")
        ok_audit, arc = self._check_audit(req, resp, "portability")
        if not ok_audit:
            return self._base_result("portability", False, arc, "Audit missing/invalid.")
        return self._base_result("portability", True, REASON_OK, f"hash={hash_personal_data(rp)}")

    def validate(self, req: RightsRequest, resp: SystemResponse) -> Dict[str, Any]:
        r = (req.right or "").lower()
        if r == "access": return self.validate_access(req, resp)
        if r == "rectification": return self.validate_rectification(req, resp)
        if r == "erasure": return self.validate_erasure(req, resp)
        if r == "restriction": return self.validate_restriction(req, resp)
        if r == "portability": return self.validate_portability(req, resp)
        return self._base_result(req.right, False, REASON_UNKNOWN_RIGHT, "Unknown right.")

# ----------------------
# Empirical / Simulated DB latency sampler
# ----------------------

class DbLatencySampler:
    def __init__(self, csv_path: Optional[str], mean_ms: float, std_ms: float):
        self.mean_ms = mean_ms
        self.std_ms = std_ms
        self.empirical = None
        if csv_path:
            self._load(csv_path)

    def _load(self, path: str):
        vals = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                if "latency_ms" not in (reader.fieldnames or []):
                    raise ValueError("CSV must have header 'latency_ms'")
                for row in reader:
                    try:
                        vals.append(float(row["latency_ms"]))
                    except Exception:
                        continue
            if not vals:
                raise ValueError("No usable latency_ms rows")
            self.empirical = np.array(vals)
            print(f"[INFO] Loaded DB latency samples: {len(vals)} from {path}")
        except Exception as e:
            print(f"[WARN] Failed to load DB latency CSV: {e}. Using simulated normal.")
            self.empirical = None

    def sample_ms(self) -> float:
        if self.empirical is not None:
            return float(np.random.choice(self.empirical))
        return max(0.5, float(np.random.normal(self.mean_ms, self.std_ms)))

async def simulated_db_write(db: DbLatencySampler) -> float:
    ms = db.sample_ms()
    await asyncio.sleep(ms / 1000.0)
    return ms / 1000.0


async def simulated_db_delete(db: DbLatencySampler) -> float:
    """Simulate a DB delete I/O using the same latency sampler as writes."""
    ms = db.sample_ms()
    await asyncio.sleep(ms / 1000.0)
    return ms / 1000.0

async def simulated_api_call(ms: float) -> float:
    """Simulate an API hop (network + service processing) with a fixed latency in milliseconds."""
    ms = max(0.0, float(ms))
    await asyncio.sleep(ms / 1000.0)
    return ms / 1000.0

# ----------------------
# System resource sampler
# ----------------------

class SystemSampler:
    def __init__(self, interval_s: float = 0.5):
        self.interval = interval_s
        self.proc = psutil.Process(os.getpid())
        self.samples = []
        self._running = False
        self._thread = None

    def _loop(self):
        psutil.cpu_percent(interval=None)
        self.proc.cpu_percent(interval=None)
        while self._running:
            try:
                self.samples.append({
                    "ts": time.time(),
                    "sys_cpu_pct": psutil.cpu_percent(interval=None),
                    "proc_cpu_pct": self.proc.cpu_percent(interval=None),
                    "vm_mem_pct": psutil.virtual_memory().percent,
                    "proc_mem_rss_bytes": self.proc.memory_info().rss
                })
            except Exception:
                pass
            time.sleep(self.interval)

    def start(self):
        self.samples = []
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def summarize(self) -> Dict[str, Any]:
        if not self.samples:
            return {}
        def col(k): return [s[k] for s in self.samples]
        out = {
            "samples": len(self.samples),
            "sys_cpu_pct_avg": float(np.mean(col("sys_cpu_pct"))),
            "sys_cpu_pct_max": float(np.max(col("sys_cpu_pct"))),
            "proc_cpu_pct_avg": float(np.mean(col("proc_cpu_pct"))),
            "proc_cpu_pct_max": float(np.max(col("proc_cpu_pct"))),
            "vm_mem_pct_avg": float(np.mean(col("vm_mem_pct"))),
            "vm_mem_pct_max": float(np.max(col("vm_mem_pct"))),
            "proc_mem_rss_bytes_avg": float(np.mean(col("proc_mem_rss_bytes"))),
            "proc_mem_rss_bytes_max": float(np.max(col("proc_mem_rss_bytes"))),
        }
        return out

# ----------------------
# Crypto ops for encryption path
# ----------------------

def derive_key(password: bytes, salt: bytes, iterations: int, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
    return kdf.derive(password)

def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ct

# ----------------------
# Scenarios
# ----------------------

async def do_encryption(payload: bytes, env: Dict[str,Any], db: DbLatencySampler):
    start = time.perf_counter()
    salt = os.urandom(env["salt_len"])
    key = derive_key(b"simulated-password", salt, env["kdf_iters"])
    ct = encrypt_aes_gcm(payload, key)
    dbl = await simulated_db_write(db)
    end = time.perf_counter()
    storage_bytes = len(salt) + len(ct)
    storage_state = {"data_present": True, "stored_as": "ciphertext"}
    return (end - start, storage_bytes, dbl, storage_state)

async def do_vaulted(payload: bytes, env: Dict[str,Any], db: DbLatencySampler):
    start = time.perf_counter()
    token = str(uuid.uuid4())
    _ = token.encode("utf-8")
    dbl = await simulated_db_write(db)
    end = time.perf_counter()
    storage_bytes = len(token) + env["vault_metadata_overhead"]
    storage_state = {"token": token, "token_state": "valid"}
    return (end - start, storage_bytes, dbl, storage_state)

async def do_vaultless(payload: bytes, env: Dict[str,Any], db: DbLatencySampler):
    start = time.perf_counter()
    base_ms = env["vaultless_base_ms"]
    proc_ms = base_ms * env["vaultless_latency_coeff"]
    await asyncio.sleep(proc_ms / 1000.0)
    # small audit write cost proxy
    audit_ms = db.sample_ms() * 0.3
    await asyncio.sleep(audit_ms / 1000.0)
    end = time.perf_counter()
    storage_bytes = env["vaultless_metadata_bytes"]
    storage_state = {"scope": env["default_scope"], "key_revoked": False, "data_present": True}
    return (end - start, storage_bytes, (proc_ms + audit_ms)/1000.0, storage_state)

# ----------------------
# Consent seeding (Step 2)
# ----------------------

def seed_consents(policy: PolicyEngine, subject_ids: List[str], rates: Dict[str, float], actor: str = "seeder", audit_grants: bool = False):
    """
    Seed consent distribution across subjects.
    rates keys: consent:read, consent:write, consent:erase, consent:restrict  (values in 0..1)
    Grants each scope independently with given probability.

    IMPORTANT:
      - If audit_grants=True, writes an audit entry for every consent grant (can be huge at large subject counts).
      - If audit_grants=False (default), seeds consent state WITHOUT per-subject audit spam and writes ONE summary audit entry.
    """
    scopes = list(rates.keys())
    grants = 0
    for sid in subject_ids:
        for scope in scopes:
            if random.random() < float(rates[scope]):
                if audit_grants:
                    policy.grant_consent(sid, scope, actor=actor, expiry_ts=None)
                else:
                    # Directly seed consent state without emitting an audit entry.
                    policy._consents.setdefault(sid, {})[scope] = None
                grants += 1

    # Single summary entry (keeps audit meaningful without exploding file size)
    try:
        policy.audit_log.append_entry({
            "subject_id": "SYSTEM",
            "request_id": f"consent-seed-{int(time.time()*1000)}",
            "action": "consent_seed_summary",
            "outcome": "success",
            "actor": actor,
            "detail": f"subjects={len(subject_ids)} scopes={scopes} rates={rates} grants={grants} audit_grants={audit_grants}"
        })
    except Exception:
        pass

# ----------------------
# Audit report (Step 3)
# ----------------------

def audit_report(audit: AuditLog) -> Dict[str, Any]:
    ok, bad = audit.verify_chain()
    entries = audit.read_all()
    by_action: Dict[str, int] = {}
    by_outcome: Dict[str, int] = {}
    by_actor: Dict[str, int] = {}
    for e in entries:
        by_action[e.get("action","")] = by_action.get(e.get("action",""), 0) + 1
        by_outcome[e.get("outcome","")] = by_outcome.get(e.get("outcome",""), 0) + 1
        by_actor[e.get("actor","")] = by_actor.get(e.get("actor",""), 0) + 1

    # basic linkage health: how many entries have prev_hash set (except first)
    prev_missing = sum(1 for i,e in enumerate(entries) if i>0 and e.get("prev_hash") is None)

    return {
        "chain_ok": ok,
        "chain_bad_line_indices": bad,
        "total_entries": len(entries),
        "prev_hash_missing_after_first": prev_missing,
        "counts_by_action": dict(sorted(by_action.items(), key=lambda kv: kv[1], reverse=True)),
        "counts_by_outcome": dict(sorted(by_outcome.items(), key=lambda kv: kv[1], reverse=True)),
        "counts_by_actor": dict(sorted(by_actor.items(), key=lambda kv: kv[1], reverse=True)),
        "first_entry": entries[0] if entries else None,
        "last_entry": entries[-1] if entries else None,
    }


# ----------------------
# Benchmark calibration (optional)
# ----------------------

def load_benchmarks(path: Optional[str]) -> Optional[Dict[str, Any]]:
    """Load benchmark expectations from JSON. Expected format:
    {
      "encryption": {"access": {"p50_s": 0.5, "p95_s": 1.2}, ...},
      "vaulted": {...},
      "vaultless": {...}
    }
    """
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return None
        return obj
    except Exception as e:
        print(f"[WARN] Failed to load benchmarks JSON: {e}")
        return None

def build_calibration_report(bench: Dict[str, Any], combined: Dict[str, Any], median_thresh: float, p95_thresh: float) -> Dict[str, Any]:
    """Compare observed per-right p50/p95 to benchmark expectations and compute deltas."""
    out = {
        "median_threshold": median_thresh,
        "p95_threshold": p95_thresh,
        "generated_at_utc": now_iso_utc(),
        "systems": {}
    }
    # combined['conditions'] keys are like 'encryption@100'
    for cond_key, cond in (combined.get("conditions") or {}).items():
        scen = cond_key.split("@")[0]
        if scen not in bench:
            continue
        per_right = cond.get("rts_summary_by_right") or {}
        sys_out = out["systems"].setdefault(scen, {})
        for right, rs in per_right.items():
            exp = (bench.get(scen) or {}).get(right) or {}
            obs_p50 = rs.get("latency_p50_s")
            obs_p95 = rs.get("latency_p95_s")
            exp_p50 = exp.get("p50_s")
            exp_p95 = exp.get("p95_s")
            def rel_delta(obs, expv):
                try:
                    obs=float(obs); expv=float(expv)
                    if expv == 0:
                        return None
                    return (obs-expv)/expv
                except Exception:
                    return None
            d50 = rel_delta(obs_p50, exp_p50)
            d95 = rel_delta(obs_p95, exp_p95)
            sys_out[right] = {
                "observed_p50_s": obs_p50,
                "benchmark_p50_s": exp_p50,
                "delta_p50_rel": d50,
                "p50_within_threshold": (abs(d50) <= median_thresh) if d50 is not None else None,
                "observed_p95_s": obs_p95,
                "benchmark_p95_s": exp_p95,
                "delta_p95_rel": d95,
                "p95_within_threshold": (abs(d95) <= p95_thresh) if d95 is not None else None,
            }
    # overall pass if all checks present are within thresholds
    passes = []
    for scen, rights in out["systems"].items():
        for right, r in rights.items():
            if r.get("p50_within_threshold") is not None:
                passes.append(bool(r["p50_within_threshold"]))
            if r.get("p95_within_threshold") is not None:
                passes.append(bool(r["p95_within_threshold"]))
    out["overall_pass"] = all(passes) if passes else None
    return out


# ----------------------
# Runner + pooled stats
# ----------------------

RIGHTS = ["access","rectification","erasure","restriction","portability"]

def derive_load_tier(seed_subjects: int) -> str:
    try:
        n = int(seed_subjects)
    except Exception:
        return ""
    if n >= 1_000_000:
        return "1M"
    if n >= 500_000:
        return "500k"
    if n >= 100_000:
        return "100k"
    if n >= 10_000:
        return "10k"
    return str(n)

@dataclass
class RequestResult:
    # factors / identifiers
    scenario: str
    tps_target: int
    run_idx: int
    rep: int
    load_tier: str
    seed: int
    timestamp: float
    request_id: str = ""
    subject_id: str = ""
    right: str = ""

    # timing / performance
    latency_s: float = 0.0
    success: bool = True
    timely: Optional[bool] = None
    sla_ms: Optional[float] = None

    # storage
    storage_bytes: int = 0

    # policy + audit + RTS
    authorized: Optional[bool] = None
    auth_reason: str = ""
    audit_complete: Optional[bool] = None
    compliance_success: Optional[bool] = None
    rts_compliant: Optional[bool] = None
    rts_reason: str = ""
    rts_detail: str = ""

    # security negative testing
    is_negtest: bool = False
    attack_type: str = ""
    blocked: Optional[bool] = None

    # misc
    detail: str = ""

def bootstrap_ci(data: List[float], stat_fn, n_resamples: int = 1000, alpha: float = 0.05):
    if not data:
        return (None, None)
    a = np.array(data)
    rng = np.random.default_rng()
    stats_list = []
    for _ in range(n_resamples):
        sample = rng.choice(a, size=a.shape[0], replace=True)
        stats_list.append(stat_fn(sample))
    return (float(np.percentile(stats_list, 100*(alpha/2))), float(np.percentile(stats_list, 100*(1-alpha/2))))

def parse_rights_dist(s: Optional[str]) -> Optional[Dict[str, float]]:
    """Parse a rights distribution string like: 'access=0.4,rectification=0.2,erasure=0.2,restriction=0.1,portability=0.1'"""
    if not s:
        return None
    out: Dict[str, float] = {}
    parts = [p.strip() for p in str(s).split(",") if p.strip()]
    for p in parts:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        k = k.strip().lower()
        try:
            out[k] = float(v)
        except Exception:
            continue
    # normalize if needed
    if not out:
        return None
    total = sum(out.values())
    if total <= 0:
        return None
    for k in list(out.keys()):
        out[k] = out[k] / total
    return out

def choose_right(mode: str, idx: int, prob: float, dist: Optional[Dict[str, float]] = None) -> Optional[str]:
    """Choose a GDPR right for this request."""
    if mode == "none":
        return None
    if mode in ("every", "roundrobin"):
        return RIGHTS[idx % len(RIGHTS)]
    if mode == "random":
        return random.choice(RIGHTS) if random.random() < prob else None
    if mode == "dist":
        if not dist:
            return random.choice(RIGHTS)
        rights = list(dist.keys())
        weights = [dist[r] for r in rights]
        return random.choices(rights, weights=weights, k=1)[0]
    # fallback
    return RIGHTS[idx % len(RIGHTS)]
    if mode == "every":
        return RIGHTS[idx % len(RIGHTS)]
    if mode == "roundrobin":
        return RIGHTS[idx % len(RIGHTS)]
    if mode == "random":
        return random.choice(RIGHTS) if random.random() < prob else None
    return None

def make_payload_for_right(right: str, subject_id: str) -> Tuple[Optional[Dict[str,Any]], Optional[Dict[str,Any]]]:
    """
    Returns (returned_payload, expected_changes) depending on right.
    """
    if right in ("access","portability"):
        return ({"subject_id": subject_id, "email": f"{subject_id}@example.com", "name":"Alice"}, None)
    if right == "rectification":
        return (None, {"email": f"{subject_id}@updated.example.com"})
    return (None, None)

def apply_right_effect(right: str, scenario: str, storage_state: Dict[str,Any], expected_changes: Optional[Dict[str,Any]]) -> Dict[str,Any]:
    ss = dict(storage_state or {})
    if right == "rectification" and expected_changes:
        ss.update(expected_changes)
    elif right == "erasure":
        if scenario == "encryption":
            ss["data_present"] = False
            ss["erased"] = True
        elif scenario == "vaulted":
            ss["token_state"] = "invalid"
        else:
            ss["key_revoked"] = True
            ss["data_present"] = False
    elif right == "restriction":
        ss["restricted"] = True
    return ss


async def perform_erasure(scenario: str, storage_state: Dict[str,Any], env: Dict[str,Any], db: DbLatencySampler) -> Tuple[float, Dict[str,Any], str]:
    """
    Simulate GDPR right to erasure as an actual delete operation.

    Timing model (as requested):
      - encryption / vaulted: API call + DB delete I/O
      - vaultless: API call only (fixed sub-second)
    Returns: (extra_latency_s, new_storage_state, detail_str)
    """
    ss = dict(storage_state or {})
    scen = (scenario or "").lower()

    if scen == "encryption":
        api_s = await simulated_api_call(env.get("erasure_api_ms_encryption", 50.0))
        db_s = await simulated_db_delete(db)
        ss["data_present"] = False
        ss["erased"] = True
        detail = f"erasure_op=encryption api_s={api_s:.6f} db_delete_s={db_s:.6f}"
        return (api_s + db_s, ss, detail)

    if scen == "vaulted":
        api_s = await simulated_api_call(env.get("erasure_api_ms_vaulted", 50.0))
        db_s = await simulated_db_delete(db)
        ss["token_state"] = "invalid"
        ss["erased"] = True
        detail = f"erasure_op=vaulted api_s={api_s:.6f} db_delete_s={db_s:.6f}"
        return (api_s + db_s, ss, detail)

    # vaultless (default)
    api_s = await simulated_api_call(env.get("erasure_api_ms_vaultless", 250.0))
    ss["key_revoked"] = True
    ss["data_present"] = False
    detail = f"erasure_op=vaultless api_s={api_s:.6f}"
    return (api_s, ss, detail)

async def run_scenario_once(
    scenario_name: str,
    op_func,
    tps: int,
    duration_s: int,
    total_txns: int,
    env: Dict[str,Any],
    db: DbLatencySampler,
    sampler: SystemSampler,
    policy: PolicyEngine,
    audit: AuditLog,
    rts: RightsTestSuite,
    rights_mode: str,
    rights_prob: float,
    subjects: List[str],
    rr_start_idx: int
) -> Tuple[List[RequestResult], Dict[str,Any], int]:
    interval = 1.0 / tps
    if total_txns and int(total_txns) > 0:
        total_requests = int(total_txns)
        # implied duration in seconds for reporting
        implied_duration_s = total_requests / float(tps) if tps > 0 else 0.0
    else:
        total_requests = int(tps * duration_s)
        implied_duration_s = float(duration_s)
    sem = asyncio.Semaphore(env["concurrency"])

    results: List[RequestResult] = []
    q: asyncio.Queue = asyncio.Queue()

    async def one(i: int):
        idx = rr_start_idx + i
        subject_id = subjects[idx % len(subjects)]
        rights_dist = env.get("rights_dist")
        right = choose_right(rights_mode, idx, rights_prob, rights_dist)
        is_negtest = (env.get("negtest_rate", 0.0) > 0.0 and random.random() < float(env.get("negtest_rate", 0.0)))
        attack_type = ""
        if is_negtest:
            attack_types = env.get("negtest_attack_types") or ["detokenize_without_consent","replay_token","wrong_context_key"]
            attack_type = random.choice(list(attack_types))
        request_id = f"{scenario_name}-{int(time.time()*1000)}-{idx}-{uuid.uuid4().hex[:6]}"

        try:
            start_ts = time.time()
            l, storage, extra, storage_state = await op_func(b'{"synthetic":true}', env, db)
            latency = l + (extra if extra else 0.0)

            rr = RequestResult(
                scenario=scenario_name,
                tps_target=tps,
                run_idx=env["run_idx"],
                rep=env.get("rep", env["run_idx"]),
                load_tier=env.get("load_tier", ""),
                seed=env.get("seed", 0),
                timestamp=start_ts,
                latency_s=latency,
                success=True,
                storage_bytes=storage,
                detail=f"extra_s={extra:.6f}" if extra else ""
            )

            if right is not None:
                returned_payload, expected_changes = make_payload_for_right(right, subject_id)

                # policy check (authorize BEFORE applying effects)
                scope_candidate = (storage_state or {}).get("scope", env["default_scope"])
                # Negative security test: force an unauthorized resolution attempt by using an invalid scope
                if is_negtest:
                    scope_candidate = env.get("negtest_scope", "consent:forged")
                auth = policy.check_authorization(
                    subject_id,
                    action=right,
                    scope=scope_candidate,
                    request_id=request_id,
                    actor="simulator"
                )

                # apply the actual right effect only if authorized
                erasure_detail = ""
                if auth["allowed"]:
                    if right == "erasure":
                        erase_extra_s, ss_after, erasure_detail = await perform_erasure(scenario_name, storage_state, env, db)
                        latency += erase_extra_s
                    else:
                        ss_after = apply_right_effect(right, scenario_name, storage_state, expected_changes)
                else:
                    ss_after = dict(storage_state or {})
                # operation audit entry (authorization success/denied is already logged by policy)
                op_outcome = "success" if auth["allowed"] else "denied"
                audit_entry = audit.append_entry({
                    "subject_id": subject_id,
                    "request_id": request_id,
                    "action": right,
                    "outcome": op_outcome,
                    "actor": "simulator",
                    "detail": f"scenario={scenario_name} latency_s={latency:.6f} auth_reason={auth['reason']} {erasure_detail}".strip()
                })

                sys_resp = SystemResponse(
                    success=bool(auth["allowed"]),
                    returned_payload=returned_payload,
                    storage_state=ss_after,
                    audit_entry=audit_entry,
                    authorization={"allowed": auth["allowed"], "reason": auth["reason"], "scope": auth["scope"]},
                    detail="policy+audit wired"
                )
                req_obj = RightsRequest(
                    right=right, subject_id=subject_id, request_id=request_id,
                    requested_fields=["email","name"], expected_changes=expected_changes,
                    scope=auth["scope"], timestamp=start_ts
                )
                rts_res = rts.validate(req_obj, sys_resp)

                rr.request_id = request_id
                rr.subject_id = subject_id
                rr.right = right
                rr.rts_compliant = bool(rts_res.get("compliant"))
                rr.rts_reason = str(rts_res.get("reason_code",""))
                rr.rts_detail = str(rts_res.get("detail",""))
                rr.authorized = bool(auth.get("allowed"))
                rr.auth_reason = str(auth.get("reason", ""))
                rr.audit_complete = True if audit_entry else False
                # timeliness / SLA
                sla_map = env.get("sla_ms_by_right") or {}
                rr.sla_ms = float(sla_map.get(right)) if sla_map.get(right) is not None else None
                if rr.sla_ms is not None:
                    rr.timely = (latency * 1000.0) <= rr.sla_ms
                else:
                    rr.timely = None
                rr.latency_s = latency
                # composite compliance success per Chapter 3 definition
                rr.compliance_success = bool(rr.authorized) and bool(rr.rts_compliant) and (True if rr.timely is None else bool(rr.timely)) and bool(rr.audit_complete)
                rr.is_negtest = bool(is_negtest)
                rr.attack_type = str(attack_type)
                # security success (blocked) is defined as unauthorized requests being denied/blocked
                if rr.is_negtest:
                    # Model a bypass probability as part of security proxy testing.
                    # If policy denied, a small fraction of attacks may still succeed (bypass) depending on architecture.
                    block_rates = env.get("negtest_block_rates") or {"encryption": 0.996, "vaulted": 0.998, "vaultless": 1.0}
                    br = float(block_rates.get(scenario_name, block_rates.get(scenario_name.lower(), 1.0)))
                    if not rr.authorized:
                        rr.blocked = (random.random() < br)
                    else:
                        # If the request was authorized, it is not considered blocked.
                        rr.blocked = False
                else:
                    rr.blocked = None

            await q.put(rr)
        except Exception as e:
            await q.put(RequestResult(
                scenario=scenario_name,
                tps_target=tps,
                run_idx=env["run_idx"],
                rep=env.get("rep", env["run_idx"]),
                load_tier=env.get("load_tier", ""),
                seed=env.get("seed", 0),
                timestamp=time.time(),
                latency_s=0.0,
                success=False,
                storage_bytes=0,
                detail=f"error={e}"
            ))

    async def bounded(i: int):
        async with sem:
            await one(i)

    # run
    sampler.start()
    start_perf = time.perf_counter()
    tasks = []
    for i in range(total_requests):
        target = start_perf + i * interval
        now = time.perf_counter()
        wait = target - now
        if wait > 0:
            await asyncio.sleep(wait)
        tasks.append(asyncio.create_task(bounded(i)))
    await asyncio.gather(*tasks)
    sampler.stop()

    while not q.empty():
        results.append(await q.get())

    sys_metrics = sampler.summarize()
    return results, sys_metrics, (rr_start_idx + total_requests)

# ----------------------
# Main experiment driver
# ----------------------

async def run_experiments(args):
    os.makedirs(args.output_dir, exist_ok=True)
    ts = int(time.time())

    # reproducibility
    seed_val = int(args.seed) if int(args.seed) != 0 else int(ts)
    random.seed(seed_val)
    np.random.seed(seed_val)


    combined_csv_path = os.path.join(args.output_dir, f"combined_per_request_{ts}.csv")
    combined_json_path = os.path.join(args.output_dir, f"combined_summary_{ts}.json")
    audit_path = os.path.join(args.output_dir, "audit_log.ndjson")
    audit_report_path = os.path.join(args.output_dir, f"audit_report_{ts}.json")

    # machine spec snapshot
    machine_spec = {
        "platform": _platform.platform(),
        "python_version": _platform.python_version(),
        "machine": _platform.machine(),
        "processor": _platform.processor(),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "cpu_count_physical": psutil.cpu_count(logical=False)
    }

    env_base = {
        "salt_len": 16,
        "kdf_iters": args.kdf_iters,
        "vault_metadata_overhead": 64,
        "vaultless_latency_coeff": args.vaultless_coeff,
        "vaultless_base_ms": args.vaultless_base_ms,
        "vaultless_metadata_bytes": 16,
        "concurrency": args.concurrency,
        "default_scope": "consent:read",

        # erasure operation timing model
        "erasure_api_ms_encryption": args.erasure_api_ms_encryption,
        "erasure_api_ms_vaulted": args.erasure_api_ms_vaulted,
        "erasure_api_ms_vaultless": args.erasure_api_ms_vaultless,

        # per-right SLA thresholds (ms)
        "sla_ms_by_right": {
            "access": float(args.sla_access_ms),
            "rectification": float(args.sla_rectification_ms),
            "erasure": float(args.sla_erasure_ms),
            "restriction": float(args.sla_restriction_ms),
            "portability": float(args.sla_portability_ms),
        },

        # rights distribution (optional)
        "rights_dist": parse_rights_dist(args.rights_dist),

        # negative test configuration
        "negtest_rate": float(args.negtest_rate),
        "negtest_attack_types": [s.strip() for s in str(args.negtest_attack_types).split(",") if s.strip()],
        "negtest_scope": "consent:forged",
        "negtest_block_rates": {
            "encryption": float(args.negtest_block_rate_encryption),
            "vaulted": float(args.negtest_block_rate_vaulted),
            "vaultless": float(args.negtest_block_rate_vaultless),
        },

        # identifiers
        "load_tier": (args.load_tier or derive_load_tier(args.seed_subjects)),
        "seed": int(seed_val),

        "run_idx": 1,
        "rep": 1
    }

    # prepare audit/policy/rts
    audit = AuditLog(audit_path)
    policy = PolicyEngine(audit)
    rts = RightsTestSuite(slo_seconds=None)

    # seed subjects + consents
    subjects = [f"user-{i}" for i in range(args.seed_subjects)]
    rates = {
        "consent:read": float(args.consent_read_rate),
        "consent:write": float(args.consent_write_rate),
        "consent:erase": float(args.consent_erase_rate),
        "consent:restrict": float(args.consent_restrict_rate),
    }
    seed_consents(policy, subjects, rates, actor="seeder", audit_grants=bool(args.audit_consent_grants))

    db = DbLatencySampler(args.db_latency_file, args.db_mean_ms, args.db_std_ms)
    sampler = SystemSampler(interval_s=args.sys_sample_interval)

    scenarios = [("encryption", do_encryption), ("vaulted", do_vaulted), ("vaultless", do_vaultless)]

    # per-request CSV
    with open(combined_csv_path, "w", newline="", encoding="utf-8") as fcsv:
        w = csv.writer(fcsv)
        w.writerow([
            "scenario","tps_target","run_idx","rep","load_tier","seed",
            "timestamp","request_id","subject_id","right",
            "latency_s","fulfillment_time_hours","sla_ms","timely",
            "success","storage_bytes",
            "authorized","auth_reason",
            "audit_complete","rts_compliant","rts_reason","rts_detail",
            "compliance_success",
            "is_negtest","attack_type","blocked",
            "detail"
        ])

        pooled: Dict[str, Any] = {}
        rr_idx = 0

        for tps in args.tps:
            for scen, func in scenarios:
                key = f"{scen}@{tps}"
                pooled.setdefault(key, {"latencies":[],"storage_avgs":[],"runs":[],"sys_metrics":[],"rts":[]})
                for r in range(1, args.reps + 1):
                    env = dict(env_base)
                    env["run_idx"] = r
                    env["rep"] = r
                    print(f"\n[RUN] scenario={scen} tps={tps} run={r}/{args.reps} duration_s={args.duration_s}")
                    t0 = time.time()
                    results, sys_metrics, rr_idx = await run_scenario_once(
                        scen, func, tps, args.duration_s, args.total_txns, env, db, sampler, policy, audit, rts,
                        args.rights_mode, args.rights_prob, subjects, rr_idx
                    )
                    t1 = time.time()

                    # write per-request rows
                    for rr in results:
                        w.writerow([
                            rr.scenario, rr.tps_target, rr.run_idx, rr.rep, rr.load_tier, rr.seed,
                            rr.timestamp, rr.request_id, rr.subject_id, rr.right,
                            f"{rr.latency_s:.6f}" if rr.latency_s is not None else "",
                            f"{(rr.latency_s/3600.0):.9f}" if rr.latency_s is not None else "",
                            rr.sla_ms if rr.sla_ms is not None else "",
                            rr.timely if rr.timely is not None else "",
                            rr.success, rr.storage_bytes,
                            rr.authorized if rr.authorized is not None else "",
                            rr.auth_reason,
                            rr.audit_complete if rr.audit_complete is not None else "",
                            rr.rts_compliant if rr.rts_compliant is not None else "",
                            rr.rts_reason, rr.rts_detail,
                            rr.compliance_success if rr.compliance_success is not None else "",
                            rr.is_negtest, rr.attack_type,
                            rr.blocked if rr.blocked is not None else "",
                            rr.detail
                        ])

                    # per-run stats
                    lats = [x.latency_s for x in results if x.success and x.latency_s > 0]
                    succ = sum(1 for x in results if x.success)
                    total = len(results)
                    wall_seconds = t1 - t0 if (t1 and t0) else None
                    achieved = succ / wall_seconds if wall_seconds and wall_seconds > 0 else 0.0
                    storage_total = sum(x.storage_bytes for x in results)
                    avg_storage = (storage_total / succ) if succ else 0.0

                    if lats:
                        p50 = float(np.percentile(lats, 50))
                        p95 = float(np.percentile(lats, 95))
                        p99 = float(np.percentile(lats, 99))
                    else:
                        p50 = p95 = p99 = None

                    # RTS rollup for run
                    rts_rows = [x for x in results if x.right]
                    rts_total = len(rts_rows)
                    rts_ok = sum(1 for x in rts_rows if x.rts_compliant)
                    reason_counts: Dict[str,int] = {}
                    for x in rts_rows:
                        rc = x.rts_reason or "UNKNOWN"
                        reason_counts[rc] = reason_counts.get(rc, 0) + 1

                    run_summary = {
                        "scenario": scen,
                        "tps_target": tps,
                        "run_idx": r,
                        "duration_s": args.duration_s,
                        "wall_seconds": wall_seconds,
                        "total_txns_target": args.total_txns if args.total_txns else None,
                        "requests_total": total,
                        "requests_success": succ,
                        "achieved_tps": achieved,
                        "latency_p50_s": p50,
                        "latency_p95_s": p95,
                        "latency_p99_s": p99,
                        "avg_storage_bytes_per_request": avg_storage,
                        "system_metrics": sys_metrics,
                        "rights_requests": rts_total,
                        "rights_compliant": rts_ok,
                        "rights_compliance_rate": (rts_ok / rts_total) if rts_total else None,
                        "compliance_success_total": rts_total,
                        "compliance_success": sum(1 for x in rts_rows if x.compliance_success),
                        "compliance_success_rate": (sum(1 for x in rts_rows if x.compliance_success) / rts_total) if rts_total else None,
                        "negtest_total": sum(1 for x in results if x.is_negtest),
                        "negtest_blocked": sum(1 for x in results if x.is_negtest and x.blocked),
                        "negtest_block_rate": (sum(1 for x in results if x.is_negtest and x.blocked) / sum(1 for x in results if x.is_negtest)) if sum(1 for x in results if x.is_negtest) else None,

                        "rights_reason_counts": reason_counts,
                        "wall_clock_start": t0,
                        "wall_clock_end": t1
                    }

                    pooled[key]["latencies"].extend(lats)
                    pooled[key]["storage_avgs"].append(avg_storage)
                    pooled[key]["runs"].append(run_summary)
                    pooled[key]["sys_metrics"].append(sys_metrics)
                    pooled[key]["rts"].extend([{
                        "right": x.right,
                        "latency_s": x.latency_s,
                        "sla_ms": x.sla_ms,
                        "timely": x.timely,
                        "authorized": x.authorized,
                        "auth_reason": x.auth_reason,
                        "audit_complete": x.audit_complete,
                        "rts_compliant": x.rts_compliant,
                        "reason_code": x.rts_reason,
                        "compliance_success": x.compliance_success,
                        "is_negtest": x.is_negtest,
                        "attack_type": x.attack_type,
                        "blocked": x.blocked
                    } for x in results if x.right])

                    print(f"  --> reqs={total} success={succ} achieved_tps={achieved:.1f} p50={p50} p95={p95} avg_storage={avg_storage:.1f}B rights={rts_total} rights_ok={rts_ok}")

    # pooled combined summary
    combined = {"machine_spec": machine_spec, "env": env_base, "consent_seed_rates": rates, "conditions": {}}
    for key, d in pooled.items():
        lats = d["latencies"]
        if lats:
            p50 = float(np.percentile(lats, 50))
            p95 = float(np.percentile(lats, 95))
            p99 = float(np.percentile(lats, 99))
            mean_lat = float(np.mean(lats))
            std_lat = float(np.std(lats))
            p50_ci = list(bootstrap_ci(lats, np.median, n_resamples=args.bootstrap_resamples))
            p95_ci = list(bootstrap_ci(lats, lambda a: float(np.percentile(a,95)), n_resamples=args.bootstrap_resamples))
        else:
            p50=p95=p99=mean_lat=std_lat=None
            p50_ci=[None,None]; p95_ci=[None,None]

        # pooled per-right outcomes (RTS + compliance + timeliness + security)
        by_right: Dict[str, Dict[str,Any]] = {}
        for rr in d["rts"]:
            right = rr.get("right","unknown")
            entry = by_right.setdefault(right, {
                "total": 0,
                "authorized": 0,
                "timely": 0,
                "rts_compliant": 0,
                "compliance_success": 0,
                "reasons": {},
                "latencies_s": [],
                "negtest_total": 0,
                "negtest_blocked": 0,
                "attack_types": {}
            })
            entry["total"] += 1

            if rr.get("authorized") is True:
                entry["authorized"] += 1
            if rr.get("timely") is True:
                entry["timely"] += 1
            if rr.get("rts_compliant") is True:
                entry["rts_compliant"] += 1
            if rr.get("compliance_success") is True:
                entry["compliance_success"] += 1

            rc = rr.get("reason_code","UNKNOWN")
            entry["reasons"][rc] = entry["reasons"].get(rc, 0) + 1

            # Latency rollups (exclude negtests so security probes don't distort latency stats)
            if not rr.get("is_negtest"):
                try:
                    entry["latencies_s"].append(float(rr.get("latency_s")))
                except Exception:
                    pass

            # Security rollups
            if rr.get("is_negtest"):
                entry["negtest_total"] += 1
                at = rr.get("attack_type","unknown")
                entry["attack_types"][at] = entry["attack_types"].get(at, 0) + 1
                if rr.get("blocked") is True:
                    entry["negtest_blocked"] += 1

        rts_summary: Dict[str, Any] = {}
        for right, e in by_right.items():
            lats = e["latencies_s"]
            if lats:
                p50_r = float(np.percentile(lats, 50))
                p95_r = float(np.percentile(lats, 95))
            else:
                p50_r = p95_r = None

            rts_summary[right] = {
                "total_requests": e["total"],
                "authorized": e["authorized"],
                "authorization_rate": (e["authorized"]/e["total"]) if e["total"] else None,
                "timely": e["timely"],
                "timeliness_rate": (e["timely"]/e["total"]) if e["total"] else None,
                "rts_compliant": e["rts_compliant"],
                "rts_compliance_rate": (e["rts_compliant"]/e["total"]) if e["total"] else None,
                "compliance_success": e["compliance_success"],
                "compliance_success_rate": (e["compliance_success"]/e["total"]) if e["total"] else None,
                "latency_p50_s": p50_r,
                "latency_p95_s": p95_r,
                "latency_mean_s": (float(np.mean(lats)) if lats else None),
                "fulfillment_time_mean_hours": ((float(np.mean(lats))/3600.0) if lats else None),
                "reason_counts": e["reasons"],
                "negtest_total": e["negtest_total"],
                "negtest_blocked": e["negtest_blocked"],
                "negtest_block_rate": (e["negtest_blocked"]/e["negtest_total"]) if e["negtest_total"] else None,
                "attack_type_counts": e["attack_types"]
            }

        combined["conditions"][key] = {
            "runs_combined": len(d["runs"]),
            "requests_total_combined": sum(r["requests_total"] for r in d["runs"]),
            "requests_success_combined": sum(r["requests_success"] for r in d["runs"]),
            "latency_p50_s": p50,
            "latency_p95_s": p95,
            "latency_p99_s": p99,
            "latency_mean_s": mean_lat,
            "fulfillment_time_mean_hours": (mean_lat/3600.0) if mean_lat is not None else None,
            "latency_std_s": std_lat,
            "latency_p50_ci": p50_ci,
            "latency_p95_ci": p95_ci,
            "avg_storage_bytes_per_request_by_run": d["storage_avgs"],
            "avg_storage_bytes_per_request_pooled": float(np.mean(d["storage_avgs"])) if d["storage_avgs"] else None,
            "system_metrics_by_run": d["sys_metrics"],
            "run_summaries": d["runs"],
            "rts_summary_by_right": rts_summary
        }

    with open(combined_json_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    # optional calibration report
    bench = load_benchmarks(args.benchmarks_json)
    if bench:
        calib = build_calibration_report(bench, combined, float(args.calib_median_threshold), float(args.calib_p95_threshold))
        calib_path = os.path.join(args.output_dir, f"calibration_report_{ts}.json")
        with open(calib_path, "w", encoding="utf-8") as f:
            json.dump(calib, f, indent=2)
        print(f" - calibration report JSON: {calib_path}")

    # audit verifier + report
    rep = audit_report(audit)
    rep["audit_path"] = audit_path
    rep["generated_at_utc"] = now_iso_utc()
    with open(audit_report_path, "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2)

    print("\n[ARTIFACTS]")
    print(f" - combined per-request CSV: {combined_csv_path}")
    print(f" - combined summary JSON:   {combined_json_path}")
    print(f" - audit log NDJSON:        {audit_path}")
    print(f" - audit report JSON:       {audit_report_path}")

# ----------------------
# CLI
# ----------------------

def parse_args():
    p = argparse.ArgumentParser(description="GDPR benchmark harness (single file) with RTS + Policy + Audit Engine")
    p.add_argument("--tps", nargs="+", type=int, default=[100, 1000], help="TPS levels")
    p.add_argument("--duration-s", type=int, default=30, help="Seconds per run")
    p.add_argument("--total-txns", type=int, default=0, help="Total transactions to process for each run. If >0, run until this many requests complete (overrides duration).")
    p.add_argument("--reps", type=int, default=3, help="Repetitions per condition")
    p.add_argument("--concurrency", type=int, default=200, help="Max in-flight tasks")
    p.add_argument("--output-dir", type=str, default="gdpr_bench_output", help="Output directory")

    # crypto / vaultless params
    p.add_argument("--kdf-iters", type=int, default=100_000, help="PBKDF2 iterations for encryption path")
    p.add_argument("--vaultless-coeff", type=float, default=2.0, help="Vaultless latency coefficient")
    p.add_argument("--vaultless-base-ms", type=float, default=2.0, help="Vaultless base ms")


    # erasure operation timing model (GDPR right to erasure)
    p.add_argument("--erasure-api-ms-encryption", type=float, default=50.0,
                   help="Encryption scenario: fixed API-call latency for erasure (ms)")
    p.add_argument("--erasure-api-ms-vaulted", type=float, default=50.0,
                   help="Vaulted scenario: fixed API-call latency for erasure (ms)")
    p.add_argument("--erasure-api-ms-vaultless", type=float, default=250.0,
                   help="Vaultless scenario: fixed API-call latency for erasure (ms, sub-second)")

    # db latency sampler
    p.add_argument("--db-latency-file", type=str, default=None, help="CSV path with header latency_ms")
    p.add_argument("--db-mean-ms", type=float, default=10.0, help="DB mean ms (fallback)")
    p.add_argument("--db-std-ms", type=float, default=2.0, help="DB std ms (fallback)")

    # system metrics + bootstrap
    p.add_argument("--sys-sample-interval", type=float, default=0.5, help="System sampling interval seconds")
    p.add_argument("--bootstrap-resamples", type=int, default=1000, help="Bootstrap resamples for CI")

    # rights testing
    p.add_argument("--rights-mode", choices=["none","every","random","roundrobin","dist"], default="random")
    p.add_argument("--rights-prob", type=float, default=0.5)
    p.add_argument("--rights-dist", type=str, default=None, help="Rights distribution for --rights-mode dist, e.g. access=0.4,rectification=0.2,erasure=0.2,restriction=0.1,portability=0.1")

    # per-right SLA thresholds (ms) used for timeliness and composite compliance
    p.add_argument("--sla-access-ms", type=float, default=500.0)
    p.add_argument("--sla-rectification-ms", type=float, default=600.0)
    p.add_argument("--sla-erasure-ms", type=float, default=900.0)
    p.add_argument("--sla-restriction-ms", type=float, default=500.0)
    p.add_argument("--sla-portability-ms", type=float, default=2500.0)


    # consent seeding
    p.add_argument("--seed-subjects", type=int, default=2000, help="Number of synthetic subjects")
    p.add_argument("--audit-consent-grants", action="store_true", help="Write per-subject consent_grant audit entries during seeding (WARNING: huge for large subject counts). Default off.")
    p.add_argument("--consent-read-rate", type=float, default=0.90)
    p.add_argument("--consent-write-rate", type=float, default=0.70)
    p.add_argument("--consent-erase-rate", type=float, default=0.80)
    p.add_argument("--consent-restrict-rate", type=float, default=0.60)

    # negative security testing
    p.add_argument("--negtest-rate", type=float, default=0.01, help="Fraction of requests injected as unauthorized security probes.")
    p.add_argument("--negtest-attack-types", type=str, default="detokenize_without_consent,replay_token,wrong_context_key")
    p.add_argument("--negtest-block-rate-encryption", type=float, default=0.996)
    p.add_argument("--negtest-block-rate-vaulted", type=float, default=0.998)
    p.add_argument("--negtest-block-rate-vaultless", type=float, default=1.0)

    # calibration / benchmark verification (optional)
    p.add_argument("--benchmarks-json", type=str, default=None, help="JSON file with expected p50/p95 by system/right for pilot calibration.")
    p.add_argument("--calib-median-threshold", type=float, default=0.10, help="Acceptable relative delta for median (e.g., 0.10 => ±10%).")
    p.add_argument("--calib-p95-threshold", type=float, default=0.15, help="Acceptable relative delta for p95 (e.g., 0.15 => ±15%).")

    # identifiers for results dataset
    p.add_argument("--load-tier", type=str, default=None, help="Label for load tier (e.g., 10k,100k,500k,1M). If omitted, derived from --seed-subjects.")
    p.add_argument("--seed", type=int, default=0, help="Random seed for reproducible runs (0 => time-based).")

    return p.parse_args()

def main():
    args = parse_args()
    asyncio.run(run_experiments(args))

if __name__ == "__main__":
    main()