"""Local-only Phase 12 acceptance smoke; uses generated synthetic fixtures."""
import json
import re
import time
from pathlib import Path
from email.message import EmailMessage
import requests

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://localhost:5000"
REPORTS = ROOT / "reports" / "remediation_20261008"


def main():
    credentials = (ROOT / "instance" / "dashboard-login.txt").read_text(encoding="utf-8")
    client = requests.Session()
    login = client.get(BASE + "/dashboard/login", timeout=5)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)
    response = client.post(BASE + "/dashboard/login", data={"username": "himan-local", "password": re.search(r'^Password: (.+)$', credentials, re.M).group(1), "csrf_token": csrf}, timeout=10)
    response.raise_for_status()
    headers = {"X-CSRF-Token": client.get(BASE + "/api/v1/dashboard/session", timeout=5).json()["csrf_token"]}
    message = EmailMessage()
    message["From"] = "Finance <finance@example.com>"
    message["Reply-To"] = "payments@example.net"
    message["Subject"] = "Synthetic test: urgent payment with QR"
    message["Message-ID"] = "<phase12-demo@example.com>"
    message["Authentication-Results"] = "untrusted.invalid; spf=pass; dkim=pass; dmarc=pass"
    message.set_content("Urgent: pay the invoice today to our new bank account. Keep this confidential. https://example.com/")
    message.add_attachment((REPORTS / "phase10_demo.png").read_bytes(), maintype="image", subtype="png", filename="synthetic-qr.png")
    raw = message.as_bytes()
    (REPORTS / "phase12_demo.eml").write_bytes(raw)
    started = time.monotonic()
    submitted = client.post(BASE + "/api/v1/email/analyze", files={"file": ("synthetic-qr.eml", raw, "message/rfc822")}, headers=headers, timeout=10)
    assert submitted.status_code == 202
    job = submitted.json()
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        poll = client.get(BASE + job["poll_url"], headers={"Authorization": "Bearer " + job["token"]}, timeout=5).json()
        if poll.get("result"):
            break
        time.sleep(.35)
    result = poll["result"]
    identity = result["investigation_id"]
    record = client.get(BASE + "/api/v1/investigations/" + identity, timeout=10).json()
    assert result["risk"]["severity"] == "HIGH"
    assert {"Email", "Website", "QR", "OCR", "Media", "Domain", "Authentication"} <= set(record["panels"])
    assert {n["type"] for n in record["graph"]["nodes"]} >= {"EMAIL", "QR", "DOMAIN", "IMAGE"}
    assert sum(e["original_evidence_id"] == "html.external_credentials" for e in record["evidence"]) == 1
    exported = client.get(BASE + "/api/v1/investigations/" + identity + "/export?format=html", timeout=10)
    assert exported.status_code == 200
    summary = client.get(BASE + "/api/v1/dashboard/summary", timeout=5).json()
    proof = {"post_status": submitted.status_code, "terminal_state": poll["state"], "verdict": result["risk"]["verdict"], "severity": result["risk"]["severity"],
             "spf": result["authentication"]["spf"]["result"], "investigation_id": identity, "panels": list(record["panels"]),
             "graph_nodes": len(record["graph"]["nodes"]), "website_scans": len(result["urls"]), "body_qr_sources": result["urls"][0]["sources"],
             "export_status": exported.status_code, "telemetry_coverage_records": summary["telemetry_coverage_records"], "elapsed_seconds": round(time.monotonic() - started, 3),
             "synthetic_fixture": True, "credentials_recorded": False}
    (REPORTS / "phase12_acceptance_smoke.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
    print(json.dumps(proof))


if __name__ == "__main__":
    main()
