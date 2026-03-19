#!/usr/bin/env python3
"""
analyze_results.py (v3 patched)

Works on Windows when arguments include wildcards like:
  --per-request-csv ./out/.../combined_per_request_*.csv
  --combined-json   ./out/.../combined_summary_*.json

It expands globs, concatenates all matching per-request CSVs, and (if multiple JSONs match)
loads the most recent JSON by modified time (mtime).
"""

import argparse
import os
import json
import glob
from pathlib import Path

import pandas as pd
import numpy as np
import statsmodels.api as sm
import statsmodels.formula.api as smf
from statsmodels.multivariate.manova import MANOVA


def _expand_glob(pattern: str) -> list[str]:
    """Expand a filesystem glob pattern into a sorted list of paths.

    On Windows, pandas/open do not expand wildcards automatically, so we do it here.
    """
    # glob.glob handles forward/back slashes on Windows reasonably well
    paths = sorted(glob.glob(pattern))
    return paths


def _load_per_request_csv(pattern: str) -> pd.DataFrame:
    paths = _expand_glob(pattern)
    if not paths:
        raise FileNotFoundError(f"No files match --per-request-csv pattern: {pattern}")

    # Read and concatenate all matching CSVs
    frames = []
    for p in paths:
        frames.append(pd.read_csv(p))
    df = pd.concat(frames, ignore_index=True)
    return df


def _pick_latest_file(pattern: str) -> str:
    paths = _expand_glob(pattern)
    if not paths:
        raise FileNotFoundError(f"No files match pattern: {pattern}")
    # Pick the newest by modified time
    latest = max(paths, key=lambda p: Path(p).stat().st_mtime)
    return latest


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-request-csv", required=True, help="Path or glob to combined_per_request_*.csv")
    ap.add_argument("--combined-json", required=True, help="Path or glob to combined_summary_*.json")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # ---------------------------
    # Load per-request data (supports glob)
    # ---------------------------
    df = _load_per_request_csv(args.per_request_csv)

    # keep only rights-bearing rows (exclude seed-only ops)
    df = df[df["right"].notna() & (df["right"].astype(str) != "")].copy()

    # ensure types
    df["scenario"] = df["scenario"].astype("category")
    df["right"] = df["right"].astype("category")
    df["load_tier"] = df["load_tier"].astype("category")
    df["run_key"] = (
        df["scenario"].astype(str)
        + "@run"
        + df["rep"].astype(str)
        + "@tps"
        + df["tps_target"].astype(str)
        + "@load"
        + df["load_tier"].astype(str)
    )

    # ---------------------------
    # RQ1: Compliance Success (binary)
    # ---------------------------
    df_rq1 = df.copy()
    df_rq1["compliance_success"] = (
        df_rq1["compliance_success"]
        .astype(str)
        .str.strip()
        .replace({
            "": np.nan,
            "nan": np.nan,
            "None": np.nan,
            "TRUE": 1, "True": 1, "true": 1, "1": 1,
            "FALSE": 0, "False": 0, "false": 0, "0": 0,
        })
    )
    df_rq1["compliance_success"] = pd.to_numeric(df_rq1["compliance_success"], errors="coerce")

    df_rq1 = df_rq1.dropna(subset=["compliance_success"])
    df_rq1["compliance_success"] = df_rq1["compliance_success"].astype(int)

    if len(df_rq1) > 0:
        model = smf.gee(
            "compliance_success ~ C(scenario) * C(right) * C(load_tier)",
            groups="run_key",
            data=df_rq1,
            family=sm.families.Binomial(),
        )
        gee_res = model.fit()
        with open(os.path.join(args.out_dir, "rq1_glmm_like_gee.txt"), "w", encoding="utf-8") as f:
            f.write(gee_res.summary().as_text())
    else:
        with open(os.path.join(args.out_dir, "rq1_glmm_like_gee.txt"), "w", encoding="utf-8") as f:
            f.write(
                "No usable rows with compliance_success. Ensure SLA thresholds are enabled and compliance_success is logged.\n"
            )

    # ---------------------------
    # RQ1 (part 2): Fulfillment Time (hours)
    # ---------------------------
    df_time = df.copy()
    if "fulfillment_time_hours" in df_time.columns:
        df_time["fulfillment_time_hours"] = pd.to_numeric(
            df_time["fulfillment_time_hours"], errors="coerce"
        )
        df_time = df_time.dropna(subset=["fulfillment_time_hours"])
        df_time = df_time[df_time["fulfillment_time_hours"] > 0].copy()
        df_time["log_fulfillment_hours"] = np.log(df_time["fulfillment_time_hours"])

        m_time = smf.mixedlm(
            "log_fulfillment_hours ~ C(scenario) * C(right) * C(load_tier)",
            df_time,
            groups=df_time["run_key"],
        )
        try:
            m_time_res = m_time.fit(method="lbfgs", maxiter=200)
            with open(os.path.join(args.out_dir, "rq1_time_mixedlm.txt"), "w", encoding="utf-8") as f:
                f.write(m_time_res.summary().as_text())
        except Exception as e:
            with open(os.path.join(args.out_dir, "rq1_time_mixedlm.txt"), "w", encoding="utf-8") as f:
                f.write("Fulfillment time MixedLM failed: " + repr(e) + "\n")
    else:
        with open(os.path.join(args.out_dir, "rq1_time_mixedlm.txt"), "w", encoding="utf-8") as f:
            f.write("No fulfillment_time_hours column found. Use gdpr_bench_full.v17+ which logs it.\n")

    # ---------------------------
    # RQ2: Latency (log transform)
    # ---------------------------
    df_rq2 = df.copy()
    if "latency_s" in df_rq2.columns:
        df_rq2["latency_s"] = pd.to_numeric(df_rq2["latency_s"], errors="coerce")
        df_rq2 = df_rq2.dropna(subset=["latency_s"])
        df_rq2 = df_rq2[df_rq2["latency_s"] > 0].copy()
        df_rq2["log_latency"] = np.log(df_rq2["latency_s"])

        m = smf.mixedlm(
            "log_latency ~ C(scenario) * C(right) * C(load_tier)",
            df_rq2,
            groups=df_rq2["run_key"],
        )
        try:
            m_res = m.fit(method="lbfgs", maxiter=200)
            with open(os.path.join(args.out_dir, "rq2_latency_mixedlm.txt"), "w", encoding="utf-8") as f:
                f.write(m_res.summary().as_text())
        except Exception as e:
            with open(os.path.join(args.out_dir, "rq2_latency_mixedlm.txt"), "w", encoding="utf-8") as f:
                f.write("Latency MixedLM failed: " + repr(e) + "\n")
    else:
        with open(os.path.join(args.out_dir, "rq2_latency_mixedlm.txt"), "w", encoding="utf-8") as f:
            f.write("No latency_s column found in per-request CSV(s).\n")

    # ---------------------------
    # RQ3: Throughput + Storage (focus on N = 1,000,000) + MANOVA
    # ---------------------------
    latest_json = _pick_latest_file(args.combined_json)
    with open(latest_json, "r", encoding="utf-8") as jf:
        combined = json.load(jf)

    runs = []
    for _cond_key, cond in (combined.get("conditions") or {}).items():
        for r in (cond.get("run_summaries") or []):
            runs.append(
                {
                    "scenario": r.get("scenario"),
                    "tps_target": r.get("tps_target"),
                    "load_tier": r.get("load_tier"),
                    "achieved_tps": r.get("achieved_tps"),
                    "avg_storage": r.get("avg_storage_bytes_per_request"),
                }
            )

    df_run = pd.DataFrame(runs).dropna()
    if len(df_run) > 0:
        df_run["scenario"] = df_run["scenario"].astype("category")
        df_run["load_tier"] = df_run["load_tier"].astype("category")

        df_1m = df_run[
            df_run["load_tier"].astype(str).str.upper().isin(["1M", "1000K", "1,000,000", "1000000"])
        ].copy()

        out_path = os.path.join(args.out_dir, "rq3_manova.txt")
        with open(out_path, "w", encoding="utf-8") as f:
            if len(df_1m) == 0:
                f.write("No rows for load_tier==1M found. Ensure your harness writes load_tier per run.\n")
            else:
                man = MANOVA.from_formula("achieved_tps + avg_storage ~ C(scenario)", data=df_1m)
                f.write("MANOVA (1M tier): achieved_tps + avg_storage ~ scenario\n")
                f.write(man.mv_test().summary().as_text())
                f.write("\n\n")

                import statsmodels.stats.anova as anova

                ols_tps = smf.ols("achieved_tps ~ C(scenario)", data=df_1m).fit()
                an_tps = anova.anova_lm(ols_tps, typ=2)
                f.write("ANOVA (1M tier): achieved_tps ~ scenario\n")
                f.write(an_tps.to_string())
                f.write("\n\n")

                ols_sto = smf.ols("avg_storage ~ C(scenario)", data=df_1m).fit()
                an_sto = anova.anova_lm(ols_sto, typ=2)
                f.write("ANOVA (1M tier): avg_storage ~ scenario\n")
                f.write(an_sto.to_string())
                f.write("\n\n")

                def eta_sq(aov_tbl):
                    ss_effect = float(aov_tbl["sum_sq"][0])
                    ss_total = float(aov_tbl["sum_sq"].sum())
                    return ss_effect / ss_total if ss_total else float("nan")

                try:
                    f.write(f"Effect size (eta^2) achieved_tps: {eta_sq(an_tps):.4f}\n")
                    f.write(f"Effect size (eta^2) avg_storage: {eta_sq(an_sto):.4f}\n")
                except Exception:
                    pass
    else:
        with open(os.path.join(args.out_dir, "rq3_manova.txt"), "w", encoding="utf-8") as f:
            f.write("No run summaries found in combined JSON.\n")

    # ---------------------------
    # Descriptive tables (JSON)
    # ---------------------------
    desc = {}

    if len(df_rq1) > 0:
        pivot = (
            df_rq1.groupby(["scenario", "load_tier", "right"])["compliance_success"]
            .mean()
            .reset_index()
        )
        desc["compliance_success_rate_by_system_load_right"] = pivot.to_dict(orient="records")

    if "latency_s" in df_rq2.columns and len(df_rq2) > 0:
        piv2 = (
            df_rq2.groupby(["scenario", "load_tier", "right"])["latency_s"]
            .agg(
                p50=lambda x: float(np.percentile(x, 50)),
                p95=lambda x: float(np.percentile(x, 95)),
                p99=lambda x: float(np.percentile(x, 99)),
                mean="mean",
                std="std",
                n="count",
            )
            .reset_index()
        )
        desc["latency_by_system_load_right"] = piv2.to_dict(orient="records")

    if "is_negtest" in df.columns and "blocked" in df.columns:
        dfn = df.copy()
        dfn["is_negtest"] = dfn["is_negtest"].astype(str).isin(["True", "1", "true"])
        dfn = dfn[dfn["is_negtest"]].copy()
        if len(dfn) > 0:
            dfn["blocked"] = (
                dfn["blocked"]
                .astype(str)
                .str.strip()
                .replace({
                    "": np.nan,
                    "nan": np.nan,
                    "None": np.nan,
                    "TRUE": 1, "True": 1, "true": 1, "1": 1,
                    "FALSE": 0, "False": 0, "false": 0, "0": 0,
                })
            )
            dfn["blocked"] = pd.to_numeric(dfn["blocked"], errors="coerce")
            dfn = dfn.dropna(subset=["blocked"])
            dfn["blocked"] = dfn["blocked"].astype(int)
            sec = (
                dfn.groupby(["scenario", "load_tier", "attack_type"])["blocked"]
                .mean()
                .reset_index()
            )
            desc["negtest_block_rate_by_system_load_attack"] = sec.to_dict(orient="records")

    with open(os.path.join(args.out_dir, "descriptive_tables.json"), "w", encoding="utf-8") as f:
        json.dump(desc, f, indent=2)

    print("[OK] Wrote analyses to:", args.out_dir)
    print("[OK] Per-request CSVs loaded:", len(_expand_glob(args.per_request_csv)))
    print("[OK] Combined JSON used:", latest_json)


if __name__ == "__main__":
    main()
