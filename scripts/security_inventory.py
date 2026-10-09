"""Content-free working-tree secret check and installed dependency/license inventory.

Not a Git-history or enterprise secret scanner. Findings never contain secret values.
"""
import ast
import argparse
import importlib.metadata as metadata
import json
from pathlib import Path
import re
import subprocess  # nosec B404

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "phase13_20261009"
PATTERNS = {
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS_ACCESS_KEY": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "GITHUB_TOKEN": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    "URL_CREDENTIALS": re.compile(r"https?://[^\s/:'\"]+:[^\s/@'\"]+@"),
}


def scan_source(path, text):
    findings = []
    for category, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append({"file": path, "line": text.count("\n", 0, match.start()) + 1, "category": category})
    if path.endswith(".py"):
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return findings + [{"file": path, "category": "PARSE_UNAVAILABLE"}]
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and re.fullmatch(r"(?:.*_)?(?:password|secret_key|api_key|access_token)", target.id, re.I):
                        value = node.value.value
                        if len(value) >= 12 and not any(marker in value.lower() for marker in ("example", "placeholder", "change-me", "unavailable")):
                            findings.append({"file": path, "line": node.lineno, "category": "LITERAL_CREDENTIAL_REVIEW"})
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=REPORT)
    report = parser.parse_args().output
    # Fixed argument vector and Git ignores keep private runtime files out of this scan.
    listed = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],  # nosec B603 B607
        cwd=ROOT, check=True, capture_output=True).stdout.decode().split("\0")
    findings, scanned = [], 0
    for name in sorted(set(listed)):
        if not name or name.startswith(("tests/", "reports/", "data/", "models/", "pyc_backup/")):
            continue
        path = ROOT / name
        if not path.is_file() or (path.suffix not in {".py", ".js", ".json", ".md", ".yml", ".yaml", ".toml", ".txt", ".html"} and name not in {".env.example", "Dockerfile", ".dockerignore"}):
            continue
        try:
            text = path.read_text(encoding="utf8")
        except UnicodeError:
            findings.append({"file": name, "category": "ENCODING_UNAVAILABLE"})
            continue
        scanned += 1
        findings.extend(scan_source(name, text))
    packages = []
    for dist in metadata.distributions():
        info = dist.metadata
        license_value = info.get("License-Expression") or info.get("License") or "UNREVIEWED"
        packages.append({"name": info.get("Name"), "version": dist.version,
                         "license_metadata": license_value[:512],
                         "license_classifiers": [c for c in info.get_all("Classifier", []) if c.startswith("License ::")]})
    report.mkdir(parents=True, exist_ok=True)
    output = {"scope": "current Git working tree including untracked source; no history; tests/data/models/private runtime excluded",
              "tool": "security_inventory.py/1.0", "scanned_files": scanned, "findings": findings,
              "limitations": "Format/literal heuristics miss unsupported tokens and dynamic secrets; inventory is not legal license approval.",
              "installed_packages": sorted(packages, key=lambda p: p["name"].lower())}
    (report / "supply_chain.json").write_text(json.dumps(output, indent=2), encoding="utf8")
    print(json.dumps({"scanned_files": scanned, "finding_count": len(findings), "findings": findings, "installed_packages": len(packages)}))
    if findings:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
