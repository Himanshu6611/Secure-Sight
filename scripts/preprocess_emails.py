#!/usr/bin/env python3
"""
scripts/preprocess_emails.py
-----------------------------
Load all email datasets, combine subject + body, extract features,
and write data/email_features.parquet.

Dataset column map
------------------
phishing_email.csv  : text_combined, label
CEAS_08.csv         : subject, body, label
Enron.csv           : subject, body, label
Ling.csv            : subject, body, label
Nazario.csv         : subject, body, label
Nigerian_Fraud.csv  : subject, body, label
SpamAssasin.csv     : subject, body, label
"""

import os
import sys
import logging
import warnings
import json
import math
from pathlib import Path
import pandas as pd
from concurrent.futures import ProcessPoolExecutor, as_completed

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        logging.getLogger(__name__).info("console_encoding_unavailable")

warnings.filterwarnings("ignore")

ROOT     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RAW_DIR  = os.path.join(ROOT, "data", "raw")
OUT_PATH = os.path.join(ROOT, "data", "email_features.parquet")

sys.path.insert(0, ROOT)
from utils.email_extraction import extract_email_features
from ml.email_dataset import grouped_email_ids
from ml.dataset import compute_file_hash

DATASETS = [
    ("phishing_email.csv",  "text_combined", "label"),
    ("CEAS_08.csv",         None,            "label"),
    ("Enron.csv",           None,            "label"),
    ("Ling.csv",            None,            "label"),
    ("Nazario.csv",         None,            "label"),
    ("Nigerian_Fraud.csv",  None,            "label"),
    ("SpamAssasin.csv",     None,            "label"),
]

def _to_binary_label(val) -> int:
    try:
        value = float(val)
        return int(value) if math.isfinite(value) and value in {0.0, 1.0} else -1
    except (ValueError, TypeError):
        return -1

def _combine_text(row, text_col) -> str:
    if text_col:
        return str(row.get(text_col, "") or "")
    subject = str(row.get("subject", "") or "")
    body    = str(row.get("body",    "") or "")
    return (subject + " " + body).strip()

def _extract_row(args):
    row_index, text, label, source_id, group_id = args
    feats = extract_email_features(text)
    feats["row_index"] = row_index
    feats["label"] = label
    feats["source_id"] = source_id
    feats["group_id"] = group_id
    return feats

def load_dataset(filename: str, text_col, label_col: str) -> pd.DataFrame:
    path = os.path.join(RAW_DIR, filename)
    if not os.path.exists(path):
        print(f"  [!] Missing: {filename}")
        return pd.DataFrame()

    print(f"  Loading {filename} ... ", end="", flush=True)
    try:
        df = pd.read_csv(path, low_memory=False)
    except Exception as exc:
        print(f"ERROR ({exc})")
        return pd.DataFrame()

    lc = next((c for c in [label_col, "Label", "Class", "Result"] if c in df.columns), None)
    if lc is None:
        print(f"no label column found (cols: {df.columns.tolist()}) - skipped")
        return pd.DataFrame()

    if text_col and text_col not in df.columns:
        text_col = None

    if text_col:
        texts = df[text_col].fillna("").astype(str)
    else:
        sub  = df.get("subject", pd.Series([""] * len(df))).fillna("").astype(str)
        body = df.get("body",    pd.Series([""] * len(df))).fillna("").astype(str)
        texts = sub + " " + body

    labels = df[lc].apply(_to_binary_label)

    mask = (labels >= 0) & (texts.str.strip() != "")
    texts  = texts[mask].reset_index(drop=True)
    labels = labels[mask].reset_index(drop=True)

    print(f"{len(texts):,} rows (phish={int((labels==1).sum()):,}, legit={int((labels==0).sum()):,})")
    if "sender" in df:
        senders = df.loc[mask, "sender"].fillna("").astype(str).reset_index(drop=True)
    else:
        senders = pd.Series([""] * len(texts))
    return pd.DataFrame({"text": texts, "label": labels, "sender": senders,
                         "source_id": filename})

def main() -> None:
    print("=" * 60)
    print("Secure Sight -- Email Preprocessing")
    print("=" * 60)

    frames: list[pd.DataFrame] = []
    for filename, text_col, label_col in DATASETS:
        df = load_dataset(filename, text_col, label_col)
        if not df.empty:
            frames.append(df)

    if not frames:
        print("[ERROR] No email data loaded - aborting.")
        sys.exit(1)

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n  Total emails: {len(combined):,}")

    print("  Extracting features ... ", end="", flush=True)
    group_ids = grouped_email_ids(combined["text"].tolist(), combined["sender"].tolist())
    pairs = [(i, text, label, source, group) for i, (text, label, source, group) in
             enumerate(zip(combined["text"], combined["label"], combined["source_id"], group_ids))]

    results = []
    extraction_failures = 0
    try:
        with ProcessPoolExecutor() as pool:
            futures = {pool.submit(_extract_row, p): i for i, p in enumerate(pairs)}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception:
                    extraction_failures += 1
                    logging.getLogger(__name__).warning("email_source_unavailable")
    except Exception:
        results = [_extract_row(p) for p in pairs]

    feat_df = pd.DataFrame(results)
    if feat_df.empty:
        sys.exit("[ERROR] No email features could be extracted; output was not replaced.")
    feat_df = feat_df.sort_values("row_index", kind="stable").drop(columns="row_index").reset_index(drop=True)
    feat_df["label"] = feat_df["label"].astype(int)
    feature_columns = [column for column in feat_df.columns if column not in {"label", "source_id", "group_id"}]
    missing_feature_rows = int(feat_df[feature_columns].isna().any(axis=1).sum())
    feat_df = feat_df.dropna(subset=feature_columns + ["label", "source_id", "group_id"]).reset_index(drop=True)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    feat_df.to_parquet(OUT_PATH, index=False)

    phish = int((feat_df["label"] == 1).sum())
    legit = int((feat_df["label"] == 0).sum())
    print(f"done")
    print(f"\n  [OK] Saved {len(feat_df):,} rows -> {OUT_PATH}")
    print(f"    Phishing : {phish:,}  ({phish/len(feat_df)*100:.1f}%)")
    print(f"    Legit    : {legit:,}  ({legit/len(feat_df)*100:.1f}%)")
    print(f"    Features : {len(feature_columns)}")
    print(f"    Groups   : {feat_df.group_id.nunique():,}; extraction failures: {extraction_failures:,}; missing-feature rows removed: {missing_feature_rows:,}")
    manifest = {
        "dataset_version": "email-v2-grouped",
        "source_files": {path.name: compute_file_hash(path) for path in sorted(Path(RAW_DIR).glob("*.csv"))
                         if path.name in {name for name, _, _ in DATASETS}},
        "rows": len(feat_df), "groups": int(feat_df.group_id.nunique()),
        "class_counts": {str(k): int(v) for k, v in feat_df.label.value_counts().sort_index().items()},
        "source_counts": {str(k): int(v) for k, v in feat_df.source_id.value_counts().sort_index().items()},
        "features": feature_columns, "group_policy": "connected components of exact normalized message fingerprints and normalized sender addresses",
        "privacy": "Raw messages and sender values are not included in the feature parquet or manifest.",
        "dropped_missing_feature_rows": missing_feature_rows,
        "extraction_failures": extraction_failures,
        "label_policy": "Only numeric labels 0 and 1 are accepted; all other labels are excluded.",
        "license_review_status": "REQUIRED",
        "label_provenance_review_status": "REQUIRED",
        "collection_timestamps": "UNAVAILABLE",
    }
    with open(os.path.join(ROOT, "data", "email_manifest.json"), "w", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, allow_nan=False)
    print("=" * 60)

if __name__ == "__main__":
    main()
