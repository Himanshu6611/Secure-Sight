"""Controlled HTTP security probes against fixed loopback only; no external DAST.

No raw credentials, bodies, URLs or query tokens are recorded in output.
"""
import json
from pathlib import Path
import re
import requests

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://localhost:5000"


def main():
    anonymous = requests.Session(); anonymous.trust_env = False
    checks = []
    def check(name, method, path, expected, client=anonymous, **kwargs):
        response = client.request(method, BASE + path, timeout=10, **kwargs)
        checks.append({"name": name, "status": response.status_code, "expected": expected,
                       "pass": response.status_code == expected,
                       "nosniff": response.headers.get("X-Content-Type-Options") == "nosniff",
                       "request_id": bool(response.headers.get("X-Request-ID"))})
        return response
    check("health", "GET", "/api/v1/health", 200)
    for path, name in [("/api/v1/investigations", "investigations"), ("/api/v1/cases", "cases"), ("/api/v1/dashboard/audit", "audit")]:
        check("unauthenticated_" + name, "GET", path, 401)
    for target, name in [("http://169.254.169.254", "metadata"), ("http://[::1]", "ipv6_loopback"), ("http://2130706433", "numeric_ip")]:
        check("ssrf_" + name, "POST", "/api/v1/scan", 400, json={"url": target})
    check("duplicate_json", "POST", "/api/v1/scan", 400,
          data='{"url":"https://example.com","url":"http://127.0.0.1"}', headers={"Content-Type": "application/json"})
    check("nonfinite_json", "POST", "/api/v1/ml/predict", 400,
          data='{"features":{"x":NaN}}', headers={"Content-Type": "application/json"})
    check("oversized_body", "POST", "/api/v1/scan", 413, data=b"x" * 9000, headers={"Content-Type": "application/json"})
    check("hostile_origin", "POST", "/api/v1/scan", 403, json={}, headers={"Origin": "https://hostile.invalid"})
    check("unsupported_svg", "POST", "/api/v1/media/analyze", 415, files={"file": ("fixture.svg", b'<svg onload="alert(1)"/>', "image/svg+xml")})
    private = requests.Session(); private.trust_env = False
    credentials = (ROOT / "instance" / "dashboard-login.txt").read_text(encoding="utf8")
    login = private.get(BASE + "/dashboard/login", timeout=10)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)
    private.post(BASE + "/dashboard/login", data={"username": "himan-local",
        "password": re.search(r'^Password: (.+)$', credentials, re.M).group(1), "csrf_token": csrf}, timeout=10).raise_for_status()
    check("authenticated_workspace", "GET", "/api/v1/investigations", 200, client=private)
    check("missing_csrf", "POST", "/api/v1/cases", 403, client=private, json={"title": "No record should be created"})
    check("invalid_bearer_no_cookie_fallback", "GET", "/api/v1/investigations", 401, client=private, headers={"Authorization": "Bearer invalid-local-token"})
    check("analyst_cannot_read_admin_audit", "GET", "/api/v1/dashboard/audit", 403, client=private)
    output = {"scope": "fixed localhost:5000 HTTP probes only; existing local analyst account; no public targets; no records created",
              "tool": "security_probe.py/1.0", "checks": checks, "passed": sum(c["pass"] for c in checks),
              "total": len(checks), "credentials_recorded": False, "penetration_test": False}
    report = ROOT / "reports" / "phase13_20261009" / "local_dast.json"
    report.write_text(json.dumps(output, indent=2), encoding="utf8")
    print(json.dumps({"passed": output["passed"], "total": output["total"]}))
    if output["passed"] != output["total"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
