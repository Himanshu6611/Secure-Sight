"""Fixed-command staged gates. Failing/unavailable required steps exit nonzero."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess  # nosec B404
import sys
import time
from defusedxml import ElementTree as ET
from quality.gates import Gate, numeric_gate, all_required_pass

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports/phase14_20261009"
PYTHON = sys.executable
NPM = "npm.cmd" if os.name == "nt" else "npm"
COMMANDS = {
    "lint": [[PYTHON, "-m", "flake8", "app", "utils", "ml", "quality", "tests/test_phase14_quality.py", "--select", "E9,F63,F7,F82"], ["git", "diff", "--check"]],
    "type": [[PYTHON, "-m", "mypy", "--strict", "quality/gates.py"]],
    "frontend": [[NPM, "ci", "--prefix", "web"], [NPM, "run", "build", "--prefix", "web"],
                  [NPM, "run", "lint", "--prefix", "web"], [NPM, "audit", "--prefix", "web", "--audit-level=high"],
                  [NPM, "exec", "--prefix", "web", "--", "playwright", "install", "chromium"],
                  [NPM, "run", "test:e2e", "--prefix", "web"], ["node", "--check", "app/static/dashboard.js"]],
    "model": [[PYTHON, "-m", "quality.evaluate"], [PYTHON, "-m", "quality.regression"]],
    "tests": [[PYTHON, "-m", "pytest", "tests", "-q", "--junitxml=reports/phase14_20261009/final.xml", "--cov=app", "--cov=utils", "--cov=ml", "--cov=quality", "--cov-branch", "--cov-report=json:reports/phase14_20261009/coverage.json"]],
    "security": [[PYTHON, "-m", "bandit", "-r", "app", "utils", "ml", "quality", "-f", "json", "-o", "reports/phase14_20261009/bandit.json"],
                 [PYTHON, "scripts/security_inventory.py", "--output", "reports/phase14_20261009"]],
    "dependencies": [[PYTHON, "-m", "pip", "check"], [PYTHON, "-m", "pip_audit", "-r", "requirements-dev.txt", "--format", "cyclonedx-json", "--output", "reports/phase14_20261009/dependency_sbom.json"]],
    "performance": [[PYTHON, "-m", "quality.benchmark"]],
}


def measured_gates(profile):
    gates = []
    coverage = json.loads((REPORT / "coverage.json").read_text())
    critical = [value["summary"] for name, value in coverage["files"].items() if any(part in name.replace("\\", "/") for part in ("app/security/", "app/dashboard/auth.py", "app/email/parser.py", "app/media/intake.py", "app/risk/"))]
    statements = sum(v["num_statements"] for v in critical); covered = sum(v["covered_lines"] for v in critical)
    branches = sum(v["num_branches"] for v in critical); covered_branches = sum(v["covered_branches"] for v in critical)
    gates.append(numeric_gate("critical_statement_coverage", 100 * covered / statements if statements else None, 80))
    gates.append(numeric_gate("critical_branch_coverage", 100 * covered_branches / branches if branches else None, 60))
    junit = ET.parse(REPORT / "final.xml").getroot()
    gates.append(numeric_gate("test_failures", float(len(list(junit.iter("failure"))) + len(list(junit.iter("error")))), 0, minimum=False))
    gates.append(numeric_gate("unapproved_skips", float(len(list(junit.iter("skipped")))), 0, minimum=False))
    comparison = json.loads((REPORT / "model_comparison.json").read_text())["current_calibrated_stack"]
    gates.append(numeric_gate("historical_fpr", comparison.get("false_positive_rate"), .01, minimum=False))
    gates.append(numeric_gate("historical_fnr", comparison.get("false_negative_rate"), .10, minimum=False))
    gates.append(numeric_gate("historical_ece", comparison.get("calibration", {}).get("ece_10_equal_width"), .05, minimum=False))
    audit = json.loads((REPORT / "leakage_audit.json").read_text())
    gates.append(Gate("leakage_replay", "PASS" if audit.get("status") == "PASS" and audit.get("prediction_replay") == "PASS" else "FAIL", True, "Frozen grouped partition checks and prediction replay"))
    perf = json.loads((REPORT / "performance.json").read_text())
    gates.append(numeric_gate("serial_dashboard_p95_ms", perf.get("p95_ms"), 250, minimum=False))
    gates.append(numeric_gate("serial_dashboard_failure_rate", perf.get("failure_rate"), 0, minimum=False))
    try:
        browser = json.loads((REPORT / "browser_e2e.json").read_text())
        stats = browser["stats"]
        completed = int(stats["expected"])
        unavailable = int(stats["skipped"])
        failures = int(stats["unexpected"]) + int(stats["flaky"])
        browser_status = "PASS" if completed > 0 and unavailable == 0 and failures == 0 else "FAIL"
        browser_detail = f"{completed} Playwright tests; {failures} failed/flaky, {unavailable} skipped; includes route, scanner, keyboard, contrast and responsive checks"
    except (OSError, ValueError, KeyError, TypeError):
        browser_status, browser_detail = "UNAVAILABLE", "Fresh Playwright JSON evidence missing or invalid"
    gates.append(Gate("full_ui_accessibility_e2e", browser_status, True, browser_detail))
    if profile == "release":
        try:
            sarif = json.loads((REPORT / "docker_scout.sarif").read_text())
            findings = sarif["runs"][0]["results"]
            critical_high = [
                item for item in findings
                if re.search(r"Severity\s*:\s*(?:CRITICAL|HIGH)\b", item["message"]["text"], re.I)
            ]
            gates.append(numeric_gate("container_critical_high_findings", float(len(critical_high)), 0, minimum=False))
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            gates.append(Gate("container_critical_high_findings", "UNAVAILABLE", True, "Fresh Docker Scout SARIF evidence missing or invalid"))
        for name in (
            "prospective_external_holdout",
            "campaign_temporal_leakage_evidence",
            "production_worker_isolation",
            "production_load",
            "historical_paypal_redirect_regression",
            "operator_retention_policy_and_restore",
            "production_redis_tls_egress_secrets",
        ):
            gates.append(Gate(name, "UNAVAILABLE", True, "Missing independent evidence; release remains blocked"))
    return gates


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=["all", "report", *COMMANDS], default="all")
    parser.add_argument("--profile", choices=["engineering", "release"], default="engineering")
    args = parser.parse_args(); REPORT.mkdir(parents=True, exist_ok=True)
    steps = []
    if args.stage != "report":
        for stage in COMMANDS if args.stage == "all" else [args.stage]:
            for i, command in enumerate(COMMANDS[stage]):
                tick = time.monotonic()
                path = REPORT / f"gate_{stage}_{i}.log"
                try:
                    with path.open("w", encoding="utf8") as output:
                        completed = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, timeout=900, check=False)  # nosec B603
                    status = "PASS" if completed.returncode == 0 else "FAIL"
                except (OSError, subprocess.TimeoutExpired):
                    status = "UNAVAILABLE"
                steps.append(Gate(stage + f"_{i}", status, True, f"{path.name}; {time.monotonic()-tick:.3f}s"))
                print(json.dumps(steps[-1].record()), flush=True)
        (REPORT / ("gate_steps.json" if args.stage == "all" else f"steps_{args.stage}.json")).write_text(json.dumps([g.record() for g in steps], indent=2), encoding="utf8")
    if args.stage in {"all", "report"}:
        try:
            gates = measured_gates(args.profile)
        except (OSError, ValueError, KeyError, ET.ParseError):
            gates = [Gate("measurement_contract", "UNAVAILABLE", True, "Required report missing/invalid")]
        if args.stage == "report":
            try:
                steps = [Gate(**value) for value in json.loads((REPORT / "gate_steps.json").read_text())]
            except (OSError, ValueError, TypeError):
                steps = [Gate("staged_execution", "UNAVAILABLE", True, "Full staged execution evidence missing")]
        all_gates = steps + gates
        output = {"profile": args.profile, "pass": all_required_pass(all_gates), "gates": [g.record() for g in all_gates],
                  "scope": "Engineering regression and historical benchmark; passing is not public-release certification"}
        (REPORT / f"gates_{args.profile}.json").write_text(json.dumps(output, indent=2), encoding="utf8")
        print(json.dumps({"profile": args.profile, "pass": output["pass"]}), flush=True)
        if not output["pass"]: raise SystemExit(1)
    elif not all_required_pass(steps): raise SystemExit(1)


if __name__ == "__main__": main()
