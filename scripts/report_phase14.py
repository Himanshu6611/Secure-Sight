"""Build Phase 14 documents from local verification artifacts, without rerunning scans."""
import collections
import json
from pathlib import Path
from defusedxml import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / "reports/phase14_20261009"
D = ROOT / "docs"


def read(name):
    return json.loads((R / name).read_text(encoding="utf8"))


def write(name, body):
    (D / name).write_text(body.strip() + "\n", encoding="utf8")


def main():
    junit = ET.parse(R / "final.xml").getroot()
    cases = list(junit.iter("testcase"))
    counts = collections.Counter(c.attrib.get("classname", "unknown") for c in cases)
    failures = len(list(junit.iter("failure"))) + len(list(junit.iter("error")))
    skipped = len(list(junit.iter("skipped")))
    e, release = read("gates_engineering.json"), read("gates_release.json")
    models, audit, env, perf = [read(n) for n in ("model_comparison.json", "leakage_audit.json", "evaluation_environment.json", "performance.json")]
    calibration = read("calibration_comparison.json")
    model = models["current_calibrated_stack"]
    intro = f"Executed 2026-10-09 on Windows; {len(cases)} tests, {failures} failures/errors, {skipped} skips. Historical pre-remediation baseline: 731 passed. Evidence: `reports/phase14_20261009/`; commands/logs and JUnit are retained.\n"
    inventory = "# Phase 14 executed test inventory\n\n" + intro
    inventory += "\nCounts are parametrized JUnit cases by module, not inflated claims of separate testing layers. Modules overlap layers; there is no honest single numerical pyramid.\n\n| Module | Executed cases |\n|---|---:|\n"
    inventory += "\n".join(f"| {name} | {count} |" for name, count in sorted(counts.items()))
    inventory += "\n\nUnit/metamorphic: URL features, normalization, risk, gate integrity, leakage adversaries, historical observations. Integration: pinned fetch/DNS, provider circuits, encrypted SQLite, worker isolation, OCR/QR, signed C2PA and email authentication. API/security: error/schema/status contracts, auth/CSRF/tenant isolation, exports, poisoned JSON, upload bounds, SSRF and rate limits. Workflow integration: URL/domain/web/brand/risk/explanation fixtures; email URL/image correlation; media evidence; dashboard evidence/graph/timeline/export. These mocked or in-process workflows are not a live provider or production browser E2E certification.\n\nFrontend: seven local Playwright/axe browser E2E tests passed with no failures, flakes or skips. Coverage includes public routes, all three scanner modes, keyboard and focus, form labels/errors/loading/result announcements, upload validation, WCAG 2.1 A/AA automated checks and mobile layout. JSON and HTML reports are retained under `reports/phase14_20261009/` and `web/playwright-report/`. This does not replace manual assistive-technology testing or live provider/production certification. Optional neural deepfake model and labeled real-world genuine/manipulated image benchmarks are UNAVAILABLE; media tests verify explicit unavailable/unknown states, synthetic forensic and real OCR/QR/C2PA fixtures. No accuracy claim for deepfake detection.\n\nConditional skips exist for missing v5 artifacts and non-Windows Job integration. This execution has zero skips. Required gates reject any unapproved skip. No blanket retry, xfail or flaky-test waiver was added. No observed flaky failure in these runs; this does not establish absence of flakes.\n"
    write("TEST_INVENTORY.md", inventory)
    write("PHASE_14_TEST_INVENTORY.md", inventory)
    write("TEST_STRATEGY.md", """# Testing strategy

Run from the repository with Python 3.12 and pinned `requirements-dev.txt`; Node and Windows Tesseract with English/Hindi data are external prerequisites. Preserve private instance data. Providers are mocked for deterministic tests; real-network testing is opt-in and isolated. No training, model promotion or threshold change is part of Phase 14.

Commands executed: baseline `venv/Scripts/python.exe -m pytest tests -q --junitxml=reports/phase14_20261009/baseline.xml`; targeted Phase 14/history tests (51 passed); final `venv/Scripts/python.exe -m quality.run --stage all`; release evidence `venv/Scripts/python.exe -m quality.run --stage report --profile release` (expected nonzero while evidence is unavailable).

The runner executes fatal lint plus whitespace checks, strict mypy on the typed gate module only, two frontend Node syntax checks, model replay/regressions, full pytest with branch coverage, Bandit, heuristic working-tree secret/license inventory, pinned dependency audit and controlled serial performance. There is no repository-wide strict typing or frontend bundler: the frontend is vanilla JS. Coverage is diagnostic; aggregate security/auth/parser/intake/risk statement >=80% and branch >=60% are guarded. Aggregate passing can hide a weak individual file; inspect coverage.json before changes.

Engineering guards: historical FPR <=1%, FNR <=10%, ECE <=0.05, exact prediction replay and grouped split checks; serial dashboard p95 <=250ms and zero errors. These are explicit provisional regression tolerances, not approved public safety targets. Missing/nonfinite evidence never passes. Test failures or unapproved skips fail gates; no retry masks errors.

CI `.github/workflows/quality.yml` is configured for a protected self-hosted Windows/X64 `securesight-quality` runner, trusted main/master pushes and manual dispatch only. No untrusted PR execution on that runner. Remote CI was NOT RUN. The checkout must contain curated model/data/split and historical prediction assets plus raw source/metadata; these locally untracked assets are not automatically distributed. Preflight fails clearly when missing. Provision a dedicated ephemeral runner with Python/Node/Tesseract, never a production machine; no private instance, .env, credentials or service keys. Artifact hashes verify integrity against approved metadata, not authenticity if an attacker replaces both. Trusted manifests/assets must be controlled independently.

Seed 20261009 fixes baseline/interval sampling. Serving artifacts and split untouched. Timings and dependency advisory snapshots vary; source_snapshot.json and evaluation_environment.json record actual dirty source/environment identity. No prospective generalization, concurrent load, worker OS sandbox, full accessibility or campaign/temporal dataset claim is inferred from engineering PASS.
""")
    dataset = "# Dataset card: frozen URL corpus 5.1.1\n\nSource: [UCI PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), donated 3 March 2024, CC BY 4.0, Arvind Prasad and Shalini Chandra. Preserve attribution for redistribution. Original labels 1=legitimate/0=phishing are converted to project 0=legitimate/1=phishing. Local retrieval date was not recorded; it cannot be reconstructed from training time.\n\n235,795 publisher rows; 234,885 cleaned rows (134,849 legitimate, 100,036 phishing). 910 duplicate removals/merges; one conflicting normalized URL resolved by majority, tie to phishing. This label resolution can introduce bias; labels are publisher labels, not independent contemporary adjudication. URL normalization/IDNA and SHA256 URL+label identity are checked. Publisher filename/similarity/target-derived fields are excluded: 59 lexical URL features observed; remaining 38 schema slots are explicitly NaN. URL query/path text can contain PII or tokens; corpus remains local, no raw URLs/emails in public report, no production captures in fixtures. External corpus redistribution requires review of sensitive URLs beyond license compliance.\n\n| Partition | Rows | Registrable domains | Legitimate | Phishing |\n|---|---:|---:|---:|---:|\n"
    dataset += "\n".join(f"| {n} | {v['rows']} | {v['domains']} | {v['labels']['0']} | {v['labels']['1']} |" for n, v in audit["partitions"].items())
    dataset += "\n\nFrozen grouped partitions have zero domain, row and normalized near-URL cross-partition overlap. Near-URL check decodes path/sorts query/removes scheme/fragment; it is not semantic page/image duplicate detection. All actual domains and row identifiers recomputed, source/features/rows/split/model checksums verified; train medians and grouped OOF separation verified. Sigmoid calibration uses calibration rows; operating threshold uses threshold-selection rows. Campaign IDs, capture dates and raw page/image clones are absent: campaign/temporal leakage and future external performance remain UNAVAILABLE. Offline static PSL avoids network-dependent grouping. Geography, language, capture-era and publisher selection biases limit representativeness. Previously inspected holdout is historical replay, not a new unseen test set.\n\nSource SHA256: `" + env["dataset_sha256"] + "`; split SHA256: `" + env["split_sha256"] + "`.\n"
    write("DATASET_CARD.md", dataset)
    ml = "# ML evaluation\n\n" + intro + f"\nAll {model['samples']} frozen test predictions reproduce to absolute tolerance 1e-12 with identical row order/labels. Serving version {env['model_version']}; threshold {model['threshold']}; schema {env['schema_version']}. No serving fit, promotion or threshold change. Confusion: TN 20080, FP 91, FN 432, TP 14951.\n\n"
    ml += "\n".join(f"- {k}: {model[k]:.6f}" for k in ("accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "false_positive_rate", "false_negative_rate"))
    ml += "\n\nDomain bootstrap 95% intervals (200 deterministic replicates): FPR 0.3334–0.5826%; FNR 2.3630–3.3446%. Row Wilson intervals also retained; independence is questionable within domains, so clustered intervals are preferable. These intervals do not quantify source/campaign drift or deployed-system error. Per-class metrics, reliability bins and confusion matrices are in model_comparison.json. ML probability is distinct from risk score, severity, confidence and final verdict.\n\n"
    ml += f"Raw stack Brier={calibration['raw_stack']['brier_score']:.6f}, ECE={calibration['raw_stack']['ece_10_equal_width']:.6f}; existing sigmoid stack Brier={calibration['sigmoid_stack']['brier_score']:.6f}, ECE={calibration['sigmoid_stack']['ece_10_equal_width']:.6f}. Calibration is measured; sigmoid does not improve every metric, and has not been refitted.\n\nRobustness encoded/IDN/http/query/long-URL slices include small or single-class support; unavailable ROC/PR-AUC and class rates are null. sklearn per-class zero values for unsupported precision/recall are display conventions, not observed performance. Language, page age, compression, provider type and live redirects lack representative labeled paired ML ground truth; integration fixtures do not substitute for those metrics.\n"
    write("ML_EVALUATION.md", ml)
    comparison = "# Model comparison\n\nSame frozen train/calibration/threshold-selection/test partitions. Current stack kept at frozen 0.93; existing train-fitted logistic baseline reused. Dummy prior fitted only to train labels. Baseline thresholds selected on validation under FPR <=1%, never on test. No winner selected or model promoted.\n\n| Model | Threshold | Accuracy | Precision | Recall | F1 | FPR | FNR | ROC AUC | PR AUC |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n"
    comparison += "\n".join("| " + name + " | " + " | ".join(f"{v[k]:.6f}" for k in ("threshold", "accuracy", "precision", "recall", "f1", "false_positive_rate", "false_negative_rate", "roc_auc", "pr_auc")) + " |" for name, v in models.items())
    comparison += "\n\nDummy becomes reject-all at the validation FPR constraint; zero FPR with 100% FNR is not useful detection. Current stack has modest historical gains over logistic, not a promise of generalization. Preserve existing serving and original baseline artifacts; full metrics, CIs and calibration remain machine-readable.\n"
    write("MODEL_COMPARISON.md", comparison)
    write("REGRESSION_CORPUS.md", """# Regression corpus

`tests/fixtures/quality/regression_cases.json` is a small versioned synthetic/property index; executable properties live in tests/test_phase14_quality.py and existing phase suites. .example/.invalid URLs, generated email/QR/OCR/media/C2PA content and mocked DNS/provider responses avoid live secrets and external request dependencies. Public brand names identify historical observations, not a licensed captured-page corpus. Existing tests cover IDN/encoding, redirect/private IP, new-site age, repurposing, email alignment/BEC/attachments, QR/OCR, logo uncertainty, C2PA/forensic states, tenant isolation and frontend/backend verdict immutability.

New adversarial split tests reject overlapping rows/domains/URLs, altered labels, missing/extra rows and incomplete partitions. Numeric gates reject NaN/absence; no empty or optional-only gate set passes. Fixed threshold is not changed by holdout metrics. Future-history regression now excludes a future record and leaves it unchanged for legitimate later queries. Failure/model absence cannot create SAFE/LEGITIMATE.

LOCAL-ML-001: original Phase 9 PayPal redirected-page suspicious result remains OPEN, owner model-maintainer, review 2026-11-09. The direct root lexical replay currently passes (probability ~0.012494); redacted historical redirected path prevents exact pipeline replay. This does not resolve or erase the original failure. No whitelist or test expectation weakening was added. `known_regressions.json` preserves the distinction. No observed flakes, no waivers; any future flake needs owner/issue/expiry before a bounded quarantine.
""")
    performance = "# Controlled performance baseline\n\n" + perf["scope"] + ".\n\n"
    performance += "\n".join(f"- {k}: {perf[k]}" for k in ("samples", "status_200", "failure_rate", "p50_ms", "p95_ms", "p99_ms", "throughput_serial_requests_per_second", "python_tracemalloc_peak_bytes", "outbound_calls"))
    performance += "\n\n200 observations support a local percentile estimate, with limited tail precision. No sustained concurrency, HTTP transport, production SQLite/Redis, scan/provider/decoder latency, queue delay, native RSS, saturation or real workload evidence. Scan completion/partial/failure rates and provider unavailability are unmeasured (null), not zero. Rate limiting is explicitly disabled only in the isolated measurement app, not serving configuration. Re-run `python -m quality.benchmark` on a controlled machine; compare scope/environment before timings. Public production load remains BLOCKED.\n"
    write("PERFORMANCE_BASELINE.md", performance)
    blockers = [g for g in release["gates"] if g["status"] != "PASS"]
    known = "# Known failures and unavailable evidence\n\nEngineering status: " + ("PASS" if e["pass"] else "FAIL") + "; public release: BLOCKED.\n\n"
    known += "\n".join(f"- {g['name']}: {g['status']}; {g['detail']}" for g in blockers)
    known += "\n\nLOCAL-ML-001 has model-maintainer ownership/review 2026-11-09 as above. Phase 14 fixes future-history inclusion and preserves all known shortcomings. OS worker isolation still lacks a proven filesystem/network sandbox; Windows job limits alone are insufficient. Campaign/time/page-image clone leakage unavailable. Remote CI runner/assets not provisioned or executed. Manual assistive-technology review, genuine manipulated-media accuracy and production concurrent load remain unverified despite passing automated browser E2E. No unavailable result is counted as PASS; no exceptions or blanket retries. Proposed follow-up owners: data-maintainer (prospective/campaign evidence), security-maintainer (sandbox), frontend-maintainer (UI/a11y), operations-maintainer (load/CI). These are role assignments for follow-up, not evidence of completed external work.\n"
    write("KNOWN_FAILURES.md", known)
    report = "# SecureSight Phase 14 report\n\n" + intro + f"\nEngineering quality gates: {'PASS' if e['pass'] else 'FAIL'}. Public-release gate: {'PASS' if release['pass'] else 'BLOCKED'}; nonzero release command is intentional evidence of unmet requirements. Phase 14 is PARTIAL against the entire document's definition of done.\n\n"
    report += "Implemented reproducible staged gates, frozen evaluation/comparisons/calibration/CIs, source identity, controlled benchmark, CI configuration, safe regression fixtures and cross-phase contract/metamorphic tests. Fixed backward-clock future-history leakage without rewriting historical evidence. Existing serving model, probability threshold and datasets remain unchanged.\n\n| Gate | Result | Evidence/detail |\n|---|---|---|\n"
    report += "\n".join(f"| {g['name']} | {g['status']} | {g['detail']} |" for g in e["gates"])
    report += f"\n\nHistorical frozen model FPR {100*model['false_positive_rate']:.4f}%, FNR {100*model['false_negative_rate']:.4f}%; no public accuracy guarantee. Source/env/model hashes, calibration, per-class metrics, leakage limitations and raw test artifacts retained. Python {env['python']}, sklearn {env['sklearn']}, NumPy {env['numpy']}, seed {env['seed']}; commit `{env['git_commit']}` plus dirty-working-tree source_snapshot.json (commit alone does not identify this implementation).\n\nSee TEST_INVENTORY, TEST_STRATEGY, DATASET_CARD, ML_EVALUATION, MODEL_COMPARISON, REGRESSION_CORPUS, PERFORMANCE_BASELINE and KNOWN_FAILURES. Local stages including browser E2E executed; remote CI was not executed. Full release blockers remain mandatory and cannot be bypassed by completing phase numbering. No deployment, commit or external publishing performed.\n"
    write("PHASE_14_REPORT.md", report)


if __name__ == "__main__":
    main()
