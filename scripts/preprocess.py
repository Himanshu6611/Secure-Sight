"""Correct PhiUSIIL source labels and preserve complete URL identity."""
import pathlib
import sys
import json
import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ml.dataset import normalize_training_url, clean_source_dataset

normalise_url = normalize_training_url


def _to_binary_label(value, source="phiusiil"):
    try:
        value = int(value)
    except (ValueError, TypeError):
        return -1
    if value not in {0, 1}:
        return -1
    if source == "phiusiil":
        return 1-value
    if source == "securesight":
        return value
    raise ValueError("Unknown source label mapping")


def load_phiusiil(path):
    rows = pd.read_csv(path, usecols=["URL","label"]).rename(columns={"URL":"url"})
    rows["label"] = rows.label.map(_to_binary_label)
    return rows[rows.label >= 0]


def main():
    source = ROOT / "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
    frame, manifest = clean_source_dataset(pd.read_csv(source,usecols=["URL","label"]),source="phiusiil")
    frame.to_csv(ROOT/"data/cleaned.csv",index=False)
    (ROOT/"data/metadata").mkdir(exist_ok=True)
    (ROOT/"data/metadata/preprocessing_report.json").write_text(json.dumps(manifest,indent=2),encoding="utf8")
    print(f"Corrected dataset: {len(frame)} rows; target 1=phishing, 0=legitimate")


if __name__=="__main__":
    main()
