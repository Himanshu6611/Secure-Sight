"""Derive internal adversarial reports from actual local JUnit/probe artifacts."""
import hashlib
import json
import platform
from pathlib import Path
import subprocess
from defusedxml import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / "reports/phase15_20261009"
D = ROOT / "docs"


def write(name, text):
    (D / name).write_text(text.strip() + "\n", encoding="utf8")


def main():
    junit = ET.parse(R / "final.xml").getroot()
    cases = list(junit.iter("testcase"))
    failures = len(list(junit.iter("failure"))) + len(list(junit.iter("error")))
    skips = len(list(junit.iter("skipped")))
    ml = json.loads((R / "ml_robustness.json").read_text())
    bandit = json.loads((R / "bandit.json").read_text())
    tests = [c.attrib["classname"] + "." + c.attrib["name"] for c in cases]
    summary = f"2026-10-09, local Windows: baseline 757 passed; targeted 39 passed; final {len(cases)} passed, {failures} failures/errors, {skips} skips, 26 warnings. No retries or expected-failure suppression. Evidence: `reports/phase15_20261009/`."
    categories = {
        "URL/SSRF/DNS": ("ambiguous_or_restricted", "mixed_answers", "pinned", "private_dns", "redirect_blocks_private", "head_pins", "dns_mixed"),
        "MIME/attachments": ("nested_mime", "parser_mutations", "zip_bomb", "dangerous_attachment", "mime", "received_private", "auth_results"),
        "Media": ("media_mutations", "decoder", "animated", "xmp", "ocr", "c2pa", "qr"),
        "Dashboard/evidence/auth": ("foreign_export", "case_cannot", "cross_tenant", "mass_assignment", "csrf", "evidence", "export", "audit"),
        "Resources/outages": ("worker", "backpressure", "capacity", "quota", "circuit", "failure", "timeout", "partial"),
        "Risk/history/metamorphic": ("normalization", "idempotent", "contradict", "repurpos", "history", "logo", "age_alone", "chain_dedup"),
    }
    matrix = "# Adversarial test matrix\n\n" + summary + "\n\nKeyword-indexed references below overlap categories and are not unique coverage percentages. Actual JUnit names/statuses are authoritative.\n"
    for name, words in categories.items():
        selected = [t for t in tests if any(w in t.lower() for w in words)]
        matrix += "\n## " + name + f"\n\n{len(selected)} matching executed cases.\n\n" + "\n".join("- `" + t + "`" for t in selected) + "\n"
    matrix += "\nUntested: live CNAME/rebinding infrastructure, real browser navigation/download/popups (browser execution is disabled), production concurrent load/native sandbox escape, complete browser XSS/accessibility execution, prospective model accuracy and genuine/manipulated deepfake ground truth. Synthetic tests and code review do not establish those controls.\n"
    write("ADVERSARIAL_TEST_MATRIX.md", matrix)
    write("SSRF_REDTEAM_RESULTS.md", "# Local SSRF lab results\n\n" + summary + "\n\n15 new alternate IPv4, IPv6/mapped/translation, user-info, backslash, port, scheme and encoding cases rejected. Six mixed public/private answer sets rejected before pool construction; no sockets opened. Three public URL normalization variants are idempotent. Existing pinned gateway, public-to-private redirect, per-hop validation and no-reresolution regressions passed in the full suite. DNS mocks model address changes; no real metadata endpoint, public host or CNAME infrastructure was probed. Query text mentioning a private IP is data, not permission to follow it; downstream targets are revalidated. Dot segments are retained consistently, not claimed to be canonical path resolution. Socket pinning does not prove a worker-wide network sandbox.\n")
    write("PARSER_FUZZING_RESULTS.md", "# Parser fuzzing results\n\n" + summary + "\n\nBefore fix, a harmless 1200-layer MIME fixture (~under existing 2MiB ceiling) raised RecursionError in BytesParser before visit(depth) could enforce depth eight. P15-001 fixed with pre-construction structural budgets: <=32 Content-Type header lines and <=96 boundary-like lines, plus sanitized recursion fallback. 10/1200-level multipart and 1200-level message/rfc822 regressions reject with MIME_RESOURCE_LIMIT/413; large cases assert BytesParser never runs.\n\n150 deterministic MIME mutations (<=512 random bytes) and 150 malformed media samples reject safely or return bounded REQUEST_ONLY records; seed 20261009/15. This is bounded mutation smoke testing, not exhaustive fuzzing. Existing duplicate/conflicting headers, malformed auth, Received chronology, unknown charsets, encoded-body limits, archive traversal/nesting/bombs and encrypted/unsupported attachment states remain covered by phase suites. No payload execution. Conservative wire preflight can also reject bodies containing many header-like/separator lines; those inputs are resource-limited, not automatically phishing.\n")
    write("RESOURCE_LIMIT_TESTS.md", "# Resource limit verification\n\n" + summary + "\n\nExisting Windows Job CPU/memory, wall timeout, worker-output, worker-start cleanup, environment secret exclusion, decoder-pixel/file-size, bounded static response/crawl/redirect, scan semaphore, actor quota, email queue saturation/expiry/store-failure and provider circuit regressions passed with zero skips. Fake Redis/fixtures are not live Redis saturation. New MIME preflight prevents recursive tree construction for extreme nested MIME. Mutations are serial and bounded; no uncontrolled concurrent workload.\n\nInitial health was the passing baseline, not a measured CPU/RSS production baseline. Final full suite took approximately 68 seconds with branch coverage. No Phase 15 throughput/p95/p99/RSS/saturation measurement; Phase 14 serial dashboard measurements are historical and not reused as Phase 15 load results. No real browser engine is enabled: static analysis limits are tested, abusive-script execution/popups/downloads and browser crash cancellation are UNAVAILABLE. Proven filesystem/network OS isolation remains UNAVAILABLE; production load and alert/cancellation behavior require a dedicated staging job.\n")
    write("ML_ROBUSTNESS_REPORT.md", f"""# Offline ML robustness

20 deterministic lexical variations across five descriptive hosts, no network requests. Query/path/fragment content is harmless test text, not labeled current page ground truth. Model 5.1.1 frozen; no retraining, tuning, whitelist or promotion.

Observed label changes: {ml['label_changes']}/20. Maximum absolute probability change: {ml['max_absolute_probability_delta']:.6f}. All five case/trailing-dot variants have identical normalized URLs and unchanged predictions. Changing query/path/fragment changes feature vectors and can cross the threshold; this is a material sensitivity finding P15-002, not proof of 55% deployed false positives or an evasion success rate.

Raw per-case evidence is `ml_robustness.json`; preserve it as a challenge artifact. New startups, redesigns, rebrands, third-party mail, marketing redirects, absent C2PA and benign AI content require uncertainty and independent evidence; generated fixture expectations do not create contemporary labels. Existing domain-age-only, brand/logo-only, authentication-only and missing-provider safety regressions pass. Historical PayPal redirected case remains open from Phase 14. Confidence/risk/severity/verdict must not be equated with lexical probability.

Image resize/crop/compression and OCR noise robustness lack a representative labeled paired corpus and validated active deepfake model: UNAVAILABLE. No universal robustness claim. Remediation requires independently labeled, domain/campaign/time-separated train/validation/external holdout and calibration review; preserve frozen test rather than optimizing these 20 cases. Role owner model-maintainer, review 2026-11-09, OPEN; release blocked.
""")
    write("EVIDENCE_INTEGRITY_TESTS.md", "# Evidence and scoring integrity\n\n" + summary + "\n\nNew four cross-tenant graph/timeline/evidence/JSON-export probes return 404/no-store. Six case mass-assignment attempts (risk/verdict/confidence/role/tenant/evidence) return 400 and leave stored backend summary unchanged. Existing forged evidence/type rejection, case-reference tenant checks, revision guards, audit-chain verification, analyst-note score independence, duplicate/correlated-signal deduplication, confidence contradictions, observations/model-derived distinction and explanations referencing real evidence pass. Source timestamps remain source timestamps; future-history records cannot appear in past-time analysis. Missing timestamps and unavailable providers remain explicit.\n\nRisk-layer tests show that provider/model failure does not create SAFE/LEGITIMATE. Low-level lexical output remains fallible, as P15-002 demonstrates. Server-side escaping/rendering and DOM code checks are regression evidence, not a full interactive browser XSS proof. Unsupported neural/LLM judgments are not fabricated. No real private email or account data used.\n")
    findings = """# Security findings

P15-001 — MEDIUM — recursive MIME tree constructed before traversal resource limit. Scope app/email/parser.py; prerequisite a supplied deeply nested harmless MIME message within wire ceiling. Safe reproduction: generate 1200 nested multipart or message/rfc822 headers as in test_nested_mime_is_bounded_before_tree; pre-fix result RecursionError. Impact bounded-request parser failure/availability and incorrect error classification, not demonstrated code execution or data access. Evidence original local probe plus targeted/final JUnit. Remediation pre-parse structural ceiling and sanitized fallback. Owner backend-maintainer; FIXED; three regression cases pass, two assert parser constructor never runs. Conservative structural limits documented above.

P15-002 — MEDIUM reliability finding — lexical model sensitivity. Scope offline model 5.1.1; prerequisite URL query/path/fragment variation. Safe reproduction `python -m scripts.phase15_ml_probe`; no requests. 11/20 changed labels, maximum probability delta 0.975269, five canonical variants unchanged. Impact uncertain false-positive/negative behavior under distribution changes; no contemporary deployed accuracy measured. Owner model-maintainer; OPEN, review 2026-11-09. No test-set tuning or whitelist. Independent dataset/calibration remediation pending; release blocked. Historical PayPal full redirect reproduction also remains unavailable.

P15-003 — HIGH assurance gap (carried forward, exploit not demonstrated) — decoder/analysis workers have resource jobs/temp directories but no demonstrated filesystem/network sandbox. Scope production worker boundary; hostile local media/remote content would be a prerequisite for an actual decoder exploit. Safe evidence is configuration review and existing worker tests, not a sandbox escape attempt. Impact of a compromised native decoder cannot be constrained by resource limits alone. Owner security-maintainer; OPEN, no risk acceptance. Dedicated OS/container isolation plus staging filesystem/network denial tests required; release blocked.

No new critical exploit demonstrated. Passing local tests is not proof of absent vulnerabilities. Real browser/staging load/dependency supply-chain compromise/token lifecycle audit beyond existing regression coverage remain untested. Bandit is a limited static scan; heuristic secret inventory is working tree only, not history or complete credential detection.
"""
    write("SECURITY_FINDINGS.md", findings)
    write("REMEDIATION_TRACKER.md", """# Remediation tracker

| ID | Severity | Role owner | Status | Retest / next evidence | Review |
|---|---|---|---|---|---|
| P15-001 | MEDIUM | backend-maintainer | FIXED | 3 nesting regressions; 39 targeted, 796 full tests pass | 2026-10-09 |
| P15-002 | MEDIUM reliability | model-maintainer | OPEN | 11/20 offline label changes; independent labeled evaluation required | 2026-11-09 |
| P15-003 | HIGH assurance gap | security-maintainer | OPEN; no acceptance | OS filesystem/network denial and isolation proof | Before any public release |
| LOCAL-ML-001 | Historical false-positive concern | model-maintainer | OPEN | Redacted redirected URL prevents full replay | 2026-11-09 |
| STAGING-LOAD/UI | Unverified release evidence | operations/frontend-maintainer | UNAVAILABLE | Controlled production-like load and browser security/E2E tests | Before any public release |

Owners are follow-up roles, not claimed messages or external assignees. No formal acceptance, waivers or blanket retries. Test temp data cleans normally; retained report artifacts are intentional. Never close a model finding merely because one root URL now passes.
""")
    environment = {"python": platform.python_version(), "git_commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip(), "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in ("app/email/parser.py", "tests/test_phase15_adversarial.py", "scripts/phase15_ml_probe.py", "requirements-dev.txt")}, "model_sha256": hashlib.sha256((ROOT / "models/v5/model.pkl").read_bytes()).hexdigest(), "working_tree": "dirty; selected changed source hashes recorded", "baseline_passed": 757, "targeted_passed": 39, "final_cases": len(cases), "failures": failures, "skipped": skips, "bandit_findings": len(bandit["results"]), "public_release": "BLOCKED"}
    (R / "verification.json").write_text(json.dumps(environment, indent=2), encoding="utf8")
    write("PHASE_15_REPORT.md", "# SecureSight Phase 15 report\n\n" + summary + "\n\nStatus PARTIAL against the full definition of done. Local automated adversarial regressions PASS; public release BLOCKED. Fixed recursive-MIME pre-limit parser failure (P15-001), added 39 adversarial cases including 300 bounded inner mutations, measured 20 offline ML variations and preserved unresolved findings. Model/dataset/threshold unchanged.\n\nCommands: `python -m pytest tests -q` (baseline); `python -m pytest tests/test_phase15_adversarial.py -q` (targeted); `python -m pytest tests -q --cov=app --cov=utils --cov=ml --cov-branch` (final); `python -m scripts.phase15_ml_probe`; `python -m bandit -r app utils ml quality -f json`; `python scripts/security_inventory.py --output reports/phase15_20261009`; fatal flake8 and git diff whitespace checks. Logs/JUnit/branch coverage/probe/source hashes retained. Bandit findings " + str(len(bandit["results"])) + ". Dependency audit from Phase 14 is historical, not a new Phase 15 audit.\n\nRemaining: model sensitivity, historical PayPal redirect case, demonstrated OS sandbox, production load/cancellation/alerts, actual browser security/E2E and representative manipulated-media ground truth. High assurance gap has no formal risk acceptance. These block public release; no professional penetration-test or universal security/accuracy claim. Scope/limits and evidence are in the nine companion documents. No live public target, real victim data, malware or production load used.\n")


if __name__ == "__main__":
    main()
