#!/usr/bin/env python3
"""
scripts/run_pipeline.py
------------------------
Master script that runs the full Secure Sight data pipeline end-to-end:

  1. preprocess.py          → data/cleaned.csv
  2. feature_engineering.py → data/features.parquet
  3. preprocess_emails.py   → data/email_features.parquet
  4. generate_blacklist.py  → data/blacklist.csv
  5. train_ensemble.py      → models/ensemble.pkl + metadata.json
  6. train_email_model.py   → models/email_staging/email_model_research.pkl + research report

Usage:
    python scripts/run_pipeline.py [--skip-preprocess] [--skip-features]
                                   [--skip-emails]     [--skip-blacklist]
                                   [--skip-train]      [--skip-email-train]
"""

import argparse
import subprocess
import sys
import logging
import time
import os

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        logging.getLogger(__name__).info("console_encoding_unavailable")

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

STEPS = [
    ("preprocess",      "scripts/preprocess.py",          "URL preprocessing"),
    ("features",        "scripts/feature_engineering.py", "URL feature engineering"),
    ("emails",          "scripts/preprocess_emails.py",   "Email preprocessing"),
    ("blacklist",       "scripts/generate_blacklist.py",  "Blacklist generation"),
    ("train",           "scripts/train_ensemble.py",      "URL ensemble training"),
    ("email-train",     "scripts/train_email_model.py",   "Email research-candidate training (not used by serving)"),
]


def run_step(script: str, label: str) -> bool:
    path = os.path.join(ROOT, script)
    print(f"\n{'-'*60}")
    print(f"  [>]  {label}")
    print(f"{'-'*60}")
    t0 = time.time()
    result = subprocess.run([sys.executable, path], cwd=ROOT)
    elapsed = time.time() - t0
    if result.returncode != 0:
        print(f"\n  [X] FAILED ({label}) after {elapsed:.1f}s")
        return False
    print(f"\n  [OK] Done in {elapsed:.1f}s")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure Sight full pipeline runner")
    for key, _, _ in STEPS:
        parser.add_argument(f"--skip-{key}", action="store_true",
                            help=f"Skip the {key} step")
    args = parser.parse_args()

    skip_flags = {key: getattr(args, f"skip_{key.replace('-', '_')}")
                  for key, _, _ in STEPS}

    print("=" * 60)
    print("  Secure Sight -- Full Pipeline")
    print("=" * 60)

    total_start = time.time()
    failed = []

    for key, script, label in STEPS:
        if skip_flags[key]:
            print(f"\n  [SKIP] Skipping: {label}")
            continue
        ok = run_step(script, label)
        if not ok:
            failed.append(label)
            print(f"\n  Pipeline aborted at: {label}")
            sys.exit(1)

    total = time.time() - total_start
    print(f"\n{'='*60}")
    if failed:
        print(f"  Pipeline completed with {len(failed)} failure(s):")
        for f in failed:
            print(f"    [X] {f}")
    else:
        print(f"  [OK] All steps completed successfully in {total:.1f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()
