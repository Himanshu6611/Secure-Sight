#!/usr/bin/env python3
"""Write aggregate-only URL and email dataset audits; never serialize samples."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit, unquote

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")


def _url_audit() -> dict:
    rows_path = ROOT / "data/v5_1_1/rows.csv"
    split_path = ROOT / "data/v5_1_1/splits.json"
    manifest_path = ROOT / "data/v5_1_1/manifest.json"
    if not all(path.exists() for path in (rows_path, split_path, manifest_path)):
        return {"status": "UNAVAILABLE", "reason": "frozen URL rows/splits/manifest are incomplete"}

    rows = pd.read_csv(rows_path)
    required = {"row_id", "url", "label", "registrable_domain"}
    if not required <= set(rows.columns):
        return {"status": "INVALID", "reason": "required frozen URL columns are missing"}
    split = json.loads(split_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    from quality.evaluate import partition_audit

    leakage = partition_audit(rows, split)
    labels = pd.to_numeric(rows.label, errors="coerce")
    malformed = 0
    near_keys = []
    for value in rows.url.fillna("").astype(str):
        try:
            parsed = urlsplit(value)
            port = parsed.port
            valid = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
        except ValueError:
            valid = False
            parsed = urlsplit("")
            port = None
        malformed += not valid
        near_keys.append(hashlib.sha256(repr((parsed.hostname, port, unquote(parsed.path).rstrip("/") or "/",
                                              tuple(sorted(parsed.query.split("&"))))).encode()).hexdigest())
    duplicate_summary = pd.DataFrame({"key": near_keys, "label": labels}).groupby("key").agg(
        rows=("label", "size"), labels=("label", "nunique"))
    source = ROOT / "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
    conflict_groups = int(((duplicate_summary.rows > 1) & (duplicate_summary.labels > 1)).sum())
    status = "PASS" if leakage["status"] == "PASS" and labels.isna().sum() == 0 and conflict_groups == 0 else "REVIEW_REQUIRED"
    return {
        "status": status,
        "initial_rows_before_cleaning": int(manifest.get("initial_rows", len(rows))),
        "cleaned_rows": int(manifest.get("cleaned_rows", len(rows))),
        "rows_removed_during_cleaning": int(manifest.get("initial_rows", len(rows)) - manifest.get("cleaned_rows", len(rows))),
        "rows": len(rows), "class_counts": {str(k): int(v) for k, v in labels.value_counts(dropna=False).sort_index().items()},
        "unknown_labels": int(labels.isna().sum()), "malformed_urls": int(malformed),
        "exact_duplicate_urls": int(rows.url.duplicated().sum()),
        "canonicalized_duplicate_groups": int((duplicate_summary.rows > 1).sum()),
        "conflicting_canonicalized_label_groups": conflict_groups,
        "registrable_domains": int(rows.registrable_domain.nunique()),
        "split_leakage_audit": leakage,
        "dataset_version": manifest.get("dataset_version"),
        "source_license": "CC BY 4.0 per prior source review; confirm the local source copy and attribution before redistribution",
        "license_review_status": "REVIEW_REQUIRED",
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "publisher_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest() if source.exists() else None,
        "limitations": ["Collection timestamps and campaign identities are unavailable.",
                        "Canonicalized duplicate groups with conflicting labels require review.",
                        "Source attribution and license compliance require owner confirmation.",
                        "Historical benchmark results do not establish current deployment performance."],
    }


def _email_audit() -> dict:
    path = ROOT / "data/email_features.parquet"
    manifest_path = ROOT / "data/email_manifest.json"
    if not path.exists():
        return {"status": "UNAVAILABLE", "reason": "processed email features are missing"}
    frame = pd.read_parquet(path)
    if not {"label", "source_id", "group_id"} <= set(frame.columns) or not manifest_path.exists():
        return {"status": "REBUILD_REQUIRED", "reason": "email features lack grouped provenance; run scripts/preprocess_emails.py"}
    from ml.email_dataset import email_dataset_audit

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    features = [column for column in frame if column not in {"label", "source_id", "group_id"}]
    result = email_dataset_audit(frame, features)
    result["status"] = "PASS" if not result["invalid_labels"] and not result["conflicting_group_labels"] else "REVIEW_REQUIRED"
    result["manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    result["dataset_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    result["dataset_version"] = manifest.get("dataset_version")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "reports/dataset_audit.json")
    args = parser.parse_args()
    report = {"url": _url_audit(), "email": _email_audit(),
              "privacy": "Aggregate counts and hashes only; no URLs, messages, addresses, or samples are written."}
    _write(args.output, report)
    print(json.dumps({"report": str(args.output), "url_status": report["url"]["status"],
                      "email_status": report["email"]["status"]}, indent=2))


if __name__ == "__main__":
    main()
