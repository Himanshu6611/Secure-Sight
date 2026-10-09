# SecureSight — Dataset

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## 1. Dataset Composition

**Primary Source:** PhiUSIIL Phishing URL Dataset (UCI ML Repository) + Phase 2–4 Feature Extraction

| Attribute | Value |
|---|---|
| Dataset Name | SecureSight Phishing Benchmark Dataset |
| Version | 5.0.0 (Phase 5) |
| Raw Samples | 235,795 (PhiUSIIL original) |
| Cleaned Samples | ~232,472 after duplicate removal and validation |
| Feature Dimensions | 57 canonical features (Phase 2 + 3 + 4) |
| Feature Schema Version | 4.0 |
| Label Domain | Binary classification |
| Class 0 (Legitimate) | 97,623 samples |
| Class 1 (Phishing) | 134,849 samples |
| Class Ratio (min/max) | 0.724 (moderate imbalance, F1-driven threshold recommended) |
| Unique Registrable Domains | 175,509 |

## 2. Provenance & Source Attribution

### Primary Dataset

| Field | Value |
|---|---|
| Dataset Name | PhiUSIIL Phishing URL Dataset |
| Host | UCI Machine Learning Repository / PhiUSIIL Research Lab |
| Source URL | https://archive.ics.uci.edu/ |
| Collection Date | 2024 |
| License | UCI ML Repository Public Use (citation required) |
| Original Size | 235,795 URLs |
| Original Labels | Approx. balanced: ~118k legitimate / ~117k phishing |

### Secondary Derived Dataset

The canonical `data/features.parquet` matrix is produced by running SecureSight's Phase 2, 3, 4 feature extractors over the cleaned URLs. The extractors are:

- Phase 2 URL Features — `utils.url_features.extract_advanced_url_features`
- Phase 3 Domain/DNS/TLS/Reputation — `utils.domain_intelligence.analyze_domain_intelligence`
- Phase 4 HTML/DOM/Content/NLP — `utils.web_intelligence.analyze_web_intelligence`

These are composed into a single aligned DataFrame via `ml.features.extract_unified_feature_dict` and `ml.features.align_features_df`.

## 3. Label Definition & Mapping

Per `data/metadata/label_definition.json`:

```json
{
  "0": "legitimate",
  "1": "phishing"
}
```

Source labels mapped deterministically:

| Source Label | Target Code | Semantics |
|---|---|---|
| "legitimate", "benign" | 0 | URL is not a phishing page |
| "phishing", "malicious" | 1 | URL is a phishing page / credential theft |
| "unknown", ambiguous | DROPPED | Not used for training or evaluation |

Conflicting-label rule (per manifest): for the same normalized URL appearing with contradictory labels, the majority wins; ties are conservatively encoded as phishing (1).

## 4. Cleaning & Deduplication Pipeline

Steps executed by `ml.dataset.prepare_and_clean_dataset`:

1. **Load raw CSV** — requires `url` and `label` columns; rows missing either are dropped.
2. **Label coercion** — labels cast to `{0,1}`; rows with labels outside {0,1,legitimate,phishing,benign,malicious} are dropped.
3. **Exact URL dedup** — `pandas.drop_duplicates(subset=["url"])` retains first occurrence.
4. **Registrable-domain extraction** — `tldextract` is applied for every URL to produce the domain grouping key used later for the leakage-aware split.
5. **Missing-value auditing** — NaN/Inf feature rows are reported; downstream `SimpleImputer(strategy="median")` in the preprocessing pipeline fills residual gaps deterministically.
6. **Feature matrix** — Phase 2–4 extractors produce a 57-column numeric matrix, persisted as Parquet at `data/features.parquet`.

### Cleaning Statistics (measured)

| Metric | Value |
|---|---|
| Original PhiUSIIL rows | 235,795 |
| Final cleaned rows | 232,472 |
| Removed (invalid labels, malformed, duplicates) | ~3,323 |
| Domains identified | 175,509 |

## 5. Train / Validation / Test Split

**Strategy:** Domain-grouped stratified split 70% / 15% / 15%

Implemented by `ml.dataset.split_dataset_by_domain_group`:

- **Grouping key:** registrable domain (via `tldextract`). All URLs sharing the same registrable domain always land in the SAME split (train OR val OR test — never cross). This is the primary leakage control.
- **Stratification:** per-domain label majority class stratifies the domain groups so class balance is preserved across splits.
- **Random state:** 42 (reproducible).

### Split Sizes (measured)

| Split | Samples | Unique Domains |
|---|---|---|
| Training | 167,965 | 122,857 |
| Validation | 33,153 | 26,326 |
| Test (holdout, untouched) | 31,354 | 26,326 |
| **Total** | **232,472** | **175,509** |

### Domain-Leakage Assertion

At training time `write_dataset_hashes` + training.py verifies:

- Train ⋂ Val domains = ∅
- Train ⋂ Test domains = ∅
- Val ⋂ Test domains = ∅

**Verified status:** PASSED (logged during training run).

## 6. Missing-Value & Feature Type Guarantees

Per `ml.inference.SecureSightPredictor._validate_feature_vector`:

- Every feature in `FEATURE_ORDER` that is missing from the input vector is reported in `imputed_features` list of the predict response.
- Values are median-imputed (consistent with the trained `SimpleImputer(strategy="median")` pipeline step).
- Non-numeric feature values cause a `E002` `INVALID_FEATURE_VECTOR` rejection (never silently coerced).
- NaN or ±Inf input values cause `E002` rejection (never silently SAFE).

## 7. Deterministic Integrity Artifacts

### `data/metadata/dataset_hash.json`

Produced by `ml.training.write_dataset_hashes`:

```json
{
  "algorithm": "SHA-256",
  "generated_at": "<ISO-8601 timestamp of training run>",
  "artifacts": {
    "raw_csv":      { "path": "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv", "sha256": "...", "bytes": ... },
    "cleaned_csv":  { "path": "data/cleaned.csv", "sha256": "...", "bytes": ... },
    "features_parquet": { "path": "data/features.parquet", "sha256": "...", "bytes": ... }
  }
}
```

### `data/metadata/dataset_manifest.json`

Complete provenance, label_mapping, duplicate_handling, split_strategy, and preprocessing_steps (see file). These two metadata files are consumed by the model-training orchestrator so every training run can reproduce or detect drift in its upstream data.

## 8. Limitations

- No per-sample collection timestamps are available; **temporal validation is not possible** for this dataset. The closest proxy is domain-age features, but these do not substitute for a temporal train/val/test split.
- ~23% of samples are missing active DNS/TLS responses at extraction time; those features are 0-imputed and this is reflected in lower per-feature importance.
- Domains with >10 URLs are a minority; domain-group splitting can occasionally produce small deviations from exact 70/15/15 ratio but always preserves no-crossing invariant.
- No explicit multi-language NLP detector for `urgency_score` / `credential_score` is deployed; English training data dominates.

See `docs/ML_SECURITY.md` for dataset-poisoning and adversarial controls, and `docs/PHASE_05_REPORT.md` for final measured test-set impact of these limitations.
