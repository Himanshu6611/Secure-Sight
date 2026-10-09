"""Source-specific labels, normalized deduplication and reproducible domain splits."""
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from utils.domain_extraction import extract_domain_components

ROOT_DIR = Path(__file__).resolve().parents[1]
CLEANED_CSV_PATH = ROOT_DIR / "data/v5_1_1/rows.csv"
MANIFEST_PATH = ROOT_DIR / "data/metadata/dataset_manifest.json"


def compute_file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024*1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_training_url(value):
    if not isinstance(value,str) or not value.strip():
        return ""
    value = value.strip()
    if any(ord(c)<32 or c in '\\<>"' for c in value):
        return ""
    try:
        parsed = urlsplit(value if "://" in value else "http://"+value)
        if parsed.scheme.lower() not in {"http","https"} or not parsed.hostname:
            return ""
        host = parsed.hostname.rstrip(".").lower().encode("idna").decode("ascii")
        host = "["+host+"]" if ":" in host else host
        if parsed.port and not ((parsed.scheme == "http" and parsed.port == 80) or (parsed.scheme == "https" and parsed.port == 443)):
            host += ":"+str(parsed.port)
        if parsed.username is not None or parsed.password is not None:
            return ""
        return urlunsplit((parsed.scheme.lower(),host,parsed.path or "/",parsed.query,parsed.fragment))
    except (ValueError,UnicodeError):
        return ""


def clean_source_dataset(frame, source="phiusiil"):
    if source not in {"phiusiil","securesight"}:
        raise ValueError("An explicit supported source label mapping is required")
    df = frame.rename(columns={"URL":"url"}).dropna(subset=["url","label"]).copy()
    initial=len(df)
    labels = pd.to_numeric(df["label"],errors="coerce")
    df=df[labels.isin([0,1])].copy()
    df["label"] = (1-labels.loc[df.index] if source=="phiusiil" else labels.loc[df.index]).astype(int)
    df["url"] = df["url"].map(normalize_training_url)
    df=df[df["url"]!=""].copy()
    conflicts=int((df.groupby("url")["label"].nunique()>1).sum())
    # Majority label, positive only in a documented tie; preserve the full query/fragment.
    labels=df.groupby("url",sort=False)["label"].mean().ge(.5).astype(int)
    df=pd.DataFrame({"url":labels.index,"label":labels.values})
    df["registrable_domain"]=[extract_domain_components(u)["normalized_registrable_domain"] for u in df["url"]]
    df["row_id"]=[hashlib.sha256((u+"\0"+str(y)).encode()).hexdigest() for u,y in zip(df.url,df.label)]
    report=dict(initial_rows=initial,cleaned_rows=len(df),conflicting_urls=conflicts,source=source,
        label_mapping={"0":"legitimate","1":"phishing"},source_label_mapping={"0":"phishing","1":"legitimate"} if source=="phiusiil" else {"0":"legitimate","1":"phishing"},
        label_distribution=df.label.value_counts().to_dict(),normalization="IDNA host; default port; full path/query/fragment preserved",
        duplicate_policy="normalized URL majority; tie phishing",dataset_version="5.1.1")
    return df,report


def prepare_and_clean_dataset(csv_path=CLEANED_CSV_PATH):
    # This helper accepts already corrected SecureSight data, not publisher labels.
    df, manifest=clean_source_dataset(pd.read_csv(csv_path),source="securesight")
    manifest["source_sha256"]=compute_file_hash(csv_path)
    Path(MANIFEST_PATH).parent.mkdir(parents=True,exist_ok=True)
    Path(MANIFEST_PATH).write_text(json.dumps(manifest,indent=2),encoding="utf8")
    return df,manifest


def split_dataset_by_domain_group(df,test_size=.15,val_size=.15,random_state=42):
    majority=df.groupby("registrable_domain")["label"].mean().ge(.5).astype(int)
    domains=majority.index.to_numpy()
    development,test = train_test_split(domains,test_size=test_size,stratify=majority.values,random_state=random_state)
    train,validation = train_test_split(development,test_size=val_size/(1-test_size),
        stratify=majority.loc[development].values,random_state=random_state+1)
    sets=[set(train),set(validation),set(test)]
    if any(sets[i]&sets[j] for i,j in [(0,1),(0,2),(1,2)]):
        raise ValueError("Domain split overlap")
    return tuple(df[df.registrable_domain.isin(group)].copy().reset_index(drop=True) for group in sets)
