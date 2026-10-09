# Dependency audit — 8 October 2026

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

The first pip-audit run (after Flask/Werkzeug were upgraded for modern request controls) reported 52 advisory entries across 11 installed packages. Duplicate advisory entries were returned by the feed; this is not a count of 52 unique vulnerabilities. The subsequent installed-environment audit returned no known vulnerabilities. This is a point-in-time advisory check, not proof of security.

| Package | First audited version | Installed remediation |
| --- | --- | --- |
| cryptography | 46.0.3 | 50.0.2 |
| filelock | 3.20.2 | 4.0.12 |
| idna | 3.11 | 3.20 |
| pip | 25.0.1 | 26.2.1 |
| pyarrow | 22.0.0 | 25.0.1 |
| pygments | 2.19.2 | 2.21.0 |
| pytest | 8.2.2 | 9.1.1 |
| python-dotenv | 1.0.1 | 1.2.4 |
| requests | 2.32.3 | 2.34.2 |
| scikit-learn | 1.4.2 | 1.5.1 |
| urllib3 | 2.6.2 | 2.8.0 |

## Compatibility and scope

- Flask 2.2.5 / Werkzeug 2.2.3 were moved to 3.1.3 / 3.1.9 for trusted-host and request-body controls; original route tests were rerun.
- scikit-learn 1.4.2 had advisory PYSEC-2024-110; 1.5.1 addresses that advisory and matches the local email artifact. URL artifact warnings remain. Four URL and two email predictions captured before the upgrade still match within 1e-8.
- imbalanced-learn 0.12.2 broke training imports under scikit-learn 1.5.1; 0.12.4 restores them. No model was retrained or overwritten.
- cryptography, filelock, pip and Pygments were environment/tooling or transitive packages. Updating these in the existing virtual environment does not make them new application services.
- Core runtime and development requirements are separated and direct runtime versions pinned. Redis counters use Flask-Limiter; dnspython and urllib3 support bounded, pinned outbound connections.
- PyTorch and Transformers were declared originally but not installed. Their optional CLIP path is preserved in requirements-image-ml.txt; it requires its own installation, advisory audit and inference validation.
- requests is retained as a tldextract dependency; its unsafe direct use for scan-target fetching was removed. The former unused VirusTotal/DATABASE_URL settings and unused route imports were removed.
- pip list --outdated was reviewed. Unrelated major upgrades (NumPy, pandas, latest scikit-learn, Gunicorn) were intentionally deferred; latest version is not automatically the most compatible one.
- pip check passed. No duplicate top-level declarations remain. Broad requirements are not a fully transitive hash-locked environment; regenerate a platform-specific lock for release.
- Bandit on app/ and utils/ reported no findings after review. Static analysis does not validate runtime defenses.

## Reproduce

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\venv\Scripts\python.exe -m pip_audit
.\venv\Scripts\python.exe -m pip check
.\venv\Scripts\python.exe -m pytest -q
```

Container OS packages, optional image ML, live Redis/TLS and deployment infrastructure are outside this local installed-environment result.
