# Security analytics

Phase 12 contract version: **12.0**.

Overview counts and charts use authorized stored events: verdicts, backend severities, risk/confidence histograms, UTC investigation volume, partial/failed analyses, unique high-risk domain indicators, high-risk emails, available brands/TLDs, BEC observations, authentication errors, redirects and QR-bearing phishing investigations. Telemetry coverage/missing records is explicit, especially for older snapshots. Repeated hashed domain/artifact/brand observations surface descriptive alerts.

Bins are descriptive indexes and do not classify verdicts. TLD/brand frequency is not causation; shared indicators do not establish campaigns. Rates are not measured accuracy. Deepfake detections, drift, calibration and validated ground truth remain unavailable. Active email-job counts cover this process only; not distributed Redis global analytics. Detailed telemetry is encrypted. At most 2000 investigations per tenant bound queries; aggregates use a bounded 32-entry, five-second process cache keyed by tenant and validated filters. Local capture/purge invalidates the cache; other workers may display up to five seconds of lag. Tenant-wide repeat alerts are explicitly distinguished from date-filtered charts.

Verification: `tests/test_phase12_dashboard.py`; [Phase 12 report](PHASE_12_REPORT.md).
