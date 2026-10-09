"""Live smoke against an already-running local development server.

Only benign public brand homepages are scanned; save bounded evidence output.
"""
import json
import time
import urllib.request
from pathlib import Path


def main():
    output = dict(scope="Live benign-target smoke; not representative accuracy or production readiness.", scans=[])
    for target in ("https://www.paypal.com/", "https://www.microsoft.com/", "http://github.com/"):
        started = time.perf_counter()
        request = urllib.request.Request("http://localhost:5000/api/v1/scan",
            data=json.dumps({"url":target}).encode(), headers={"Content-Type":"application/json"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                body = json.load(response)
            item = dict(target=target, http_status=200, elapsed_ms=round((time.perf_counter()-started)*1000, 3),
                verdict=body["verdict"], assessment_version=body["assessment_version"],
                explanation_version=body["explanation"]["explanation_version"], explanation_status=body["explanation"]["status"],
                registration=body["domain_intelligence"]["registration"], web_status=body["web_intelligence"]["status"],
                brand=body["brand_intelligence"], timings=body["timings"], model_probability=body["ml_probability"],
                model_schema=body["feature_schema_version"], model_feature_count=len(body["feature_vector"]),
                analyzed_target=body["analysis_target"], redirect_count=body["behavior_intelligence"]["redirect_count"])
            output["scans"].append(item)
            print(json.dumps(dict(target=target, verdict=item["verdict"], web=item["web_status"],
                registration_source=item["registration"].get("source"), brand_match=item["brand"]["domain_match"],
                crawl=item["brand"]["crawl"]["status"], redirects=item["redirect_count"], elapsed_ms=item["elapsed_ms"])))
        except Exception as error:
            output["scans"].append(dict(target=target, error_type=type(error).__name__))
            print(type(error).__name__)
    path = Path("reports/remediation_20261008/phase9_live_smoke.json")
    path.write_text(json.dumps(output, indent=2)+"\n")
    if any(scan.get("http_status") != 200 for scan in output["scans"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
