# GDPR Benchmark Harness – Vaultless Tokenization Experiments

This repository contains the experimental harness used to evaluate three data-protection architectures under GDPR data subject rights workloads:

1. **Encryption-only**
2. **Vault-based tokenization**
3. **Vaultless, consent-scoped tokenization**

The benchmark is designed to support the methodology described in *Chapter 3* of the dissertation *“A Novel Vaultless Tokenization Approach to Implementing Data Subject Rights Under the GDPR”*.  
All experiments are executed using **synthetic data only** and require **no human subjects**.

---

## 1. What this script does

The script `gdpr_bench_full.py` performs controlled, repeatable load tests that simulate GDPR rights requests at varying transactions-per-second (TPS) levels.

For each architecture and load level, it measures:

- End-to-end latency (p50 / p95 / p99)
- Achieved throughput (TPS)
- Storage overhead per request
- System resource utilization (CPU, memory)
- GDPR rights compliance (Articles 15–20 proxies)
- Authorization decisions based on consent
- Immutable audit logging with hash-chain verification

The harness integrates **three core subsystems**:

| Subsystem | Purpose |
|---------|--------|
| **Policy Engine** | Enforces consent-scoped authorization rules |
| **Rights Test Suite (RTS)** | Validates correctness, authorization, auditability per GDPR right |
| **Audit Engine** | Writes append-only, hash-chained audit logs and verifies integrity |

---

## 2. Architecture scenarios tested

### 2.1 Encryption-only
- Uses PBKDF2 + AES-GCM
- Simulates storage of salt + ciphertext
- Erasure modeled as data deletion / absence

### 2.2 Vault-based tokenization
- Generates UUID tokens
- Simulates persistent token vault storage
- Erasure modeled as token invalidation

### 2.3 Vaultless tokenization
- Stateless, consent-scoped processing
- Latency modeled via configurable coefficient
- Erasure modeled as key / scope revocation
- No persistent identifier storage

---

## 3. Requirements

### OS
- Ubuntu 24.04+ (tested on AWS EC2)

### Python
- Python 3.9+

### Python packages
```bash
pip install cryptography numpy psutil scipy
```

```bash
python gdpr_bench_full.py -h
```

Generate Synthetic PII (Appendix Scripts)

Synthetic PII must be generated prior to benchmarking to establish dataset realism.

Example:

```bash
python generate_random_pii.py --rows 100000 --out pii.csv
```

Notes:
	No real personal data is used.
	The benchmark harness does not persist PII.
	Generated datasets may optionally be sampled per request in extended experiments.
	Dataset size should be documented in Chapter 3 and referenced in Chapter 4.
	

3. Recommended Execution Order

Experiments should be run in three phases:
Smoke Test (sanity check)
Pilot Run (calibration)
Final Experimental Runs (results)

Do not skip phases.


4. Phase 1 — Smoke Test
Purpose

Validate environment

Confirm outputs are written

Verify audit log integrity

Command
python gdpr_bench_full.py \
  --tps 50 \
  --duration-s 15 \
  --reps 1 \
  --output-dir out_smoke

Expected Output Files
out_smoke/
├── combined_per_request_<timestamp>.csv
├── combined_summary_<timestamp>.json
├── audit_log.ndjson
└── audit_report_<timestamp>.json

Example Audit Report Output
{
  "chain_ok": true,
  "total_entries": 842,
  "counts_by_action": {
    "authorization_check": 421,
    "access": 211,
    "erasure": 210
  }
}


Requirement:
"chain_ok": true must be present before proceeding.

5. Phase 2 — Pilot Experiment
Purpose

Calibrate latency behavior

Observe saturation thresholds

Validate GDPR rights enforcement

Command
python gdpr_bench_full.py \
  --tps 100 500 1000 \
  --duration-s 30 \
  --reps 2 \
  --concurrency 500 \
  --rights-mode random \
  --rights-prob 0.6 \
  --seed-subjects 5000 \
  --output-dir out_pilot

6. Phase 3 — Final Experimental Runs
Purpose

Generate dissertation-grade results

Populate Chapter 4 tables

Example Command
python gdpr_bench_full.py \
  --tps 100 500 1000 2500 \
  --duration-s 120 \
  --reps 5 \
  --concurrency 1000 \
  --rights-mode random \
  --rights-prob 0.6 \
  --seed-subjects 20000 \
  --consent-read-rate 0.95 \
  --consent-write-rate 0.75 \
  --consent-erase-rate 0.85 \
  --consent-restrict-rate 0.65 \
  --bootstrap-resamples 3000 \
  --output-dir out_final

7. Consent Seeding Model

Before each run, the Policy Engine seeds synthetic subjects with consent scopes.

Example distribution:

95% → consent:read

75% → consent:write

85% → consent:erase

65% → consent:restrict

This ensures:

Realistic authorization failures

Non-trivial GDPR compliance rates

Meaningful RTS evaluation

8. Output Artifacts and Interpretation
8.1 combined_per_request_*.csv

One row per request.

Key columns:

scenario — encryption / vaulted / vaultless

latency_s — end-to-end latency

storage_bytes

right — GDPR right (if applicable)

rts_compliant

rts_reason

Used for:

Distribution plots

Post-hoc analysis

Statistical validation

8.2 combined_summary_*.json (PRIMARY RESULT FILE)

This file feeds Chapter 4 (Results).

Example:

"vaultless@1000": {
  "latency_p50_s": 0.0042,
  "latency_p95_s": 0.0098,
  "avg_storage_bytes_per_request_pooled": 16.0,
  "rts_summary_by_right": {
    "access": {
      "total_requests": 910,
      "compliant": 886,
      "compliance_rate": 0.973
    }
  }
}


Interpretation:

Vaultless architecture shows low latency at scale

Storage overhead is minimal

Compliance rates reflect consent enforcement

8.3 audit_log.ndjson

Append-only audit trail.

Each entry includes:

prev_hash

entry_hash

subject

action

outcome

Supports:

GDPR Article 5(2) accountability

Non-repudiation

Traceability

8.4 audit_report_*.json

Example:

{
  "chain_ok": true,
  "total_entries": 45231,
  "counts_by_action": {
    "authorization_check": 22615,
    "access": 11320,
    "erasure": 11296
  }
}


Interpretation:

Audit integrity verified

All authorization and rights operations are traceable

9. Expected Behavioral Patterns (Sanity Checks)
Observation	Expected	Meaning
Vaultless lowest latency	Yes	Stateless design
Encryption highest CPU	Yes	KDF cost
Compliance < 100%	Yes	Consent enforcement
TPS plateaus	Yes	Instance saturation
Audit entries > requests	Yes	Auth + operation logging

If these patterns do not appear, review configuration.

10. When to Stop Increasing Load

Stop increasing TPS when:

Achieved TPS < 70% of target

p95 latency grows non-linearly

CPU remains >95% sustained

Document this as saturation point, not failure.

11. Mapping Artifacts to Dissertation Chapters
Artifact	Dissertation Use
combined_summary_*.json	Chapter 4 tables
combined_per_request_*.csv	Statistical analysis
audit_report_*.json	Compliance validation
Consent parameters	Methodology justification
12. Execution Completion Checklist

 Smoke test passes

 Audit chain verified

 Pilot run reviewed

 Final runs completed

 Outputs archived

 Chapter 4 tables populated