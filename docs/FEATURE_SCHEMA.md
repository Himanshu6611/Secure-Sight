# Feature schema 5.1.1

Canonical schema: models/v5/feature_schema.json and ml/features.py.

| Stage | Fields | Model use |
| --- | --- | --- |
| URL | 59 | Required, actually learned |
| Domain | 9 | Optional observed evidence |
| HTML | 22 | Optional observed evidence |
| Content | 7 | Optional observed evidence |
| Total | 97 | Stable ordered input contract |

Missing observations remain null/NaN, not zero. Training uses fold-local imputation of observed URL fields only. Unknown names, missing required URL fields and nonfinite/invalid numeric values fail closed. Conventional www prefixes are normalized only for lexical features; original network destinations are preserved.

The publisher provides no representative labeled raw HTML/TLS/registration snapshots. Optional fields are not claimed as trained classifier contributions.

## Phase 9 current behavior

Phase 9 exposes a separate 9.0.0 brand evidence feature manifest in config/brand_features.json. It is not appended to the 97-field 5.1.1 model input. Optional evidence is used only by the central Phase 6/7 adapters; historical observations remain unscored.
