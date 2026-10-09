# SecureSight architecture

The scan service in app/services/scans.py is shared by the HTML URL form, /api/v1/scan and /api/analyze.

    Request policy, shared rate/capacity limits
       -> 59 lexical URL features -> calibrated grouped OOF model
       -> Domain/DNS/TLS/WHOIS/reputation observations
       -> Pinned HTML retrieval -> bounded DOM/content observations
       -> Separate evidence decision policy
       -> Escaped HTML / structured JSON

The 97-field schema records 59 URL, 9 domain, 22 HTML and 7 content fields. Only URL fields enter trained LR, RF and ExtraTrees pipelines: the source corpus has no representative raw HTML/domain snapshots. Optional unavailable values remain null/NaN. Sensitivity explanations perturb features to training medians and are not causal attributions.

Training uses fold-local imputation/scaling, grouped OOF stacking, independent domain partitions for calibration and threshold selection, and frozen final test IDs. Inference verifies version/schema and artifact SHA256 before loading trusted local joblib. Hashes detect accidental corruption; they do not replace artifact signing or trusted provisioning.

Outbound HTTP connects to validated literal IPs, preserving Host, SNI and certificate hostname checks. Each redirect revalidates its destination, without implicit proxy or hostname delegation. DNS and socket operations are bounded. Static parsing checks byte/node/depth/resource limits. Dynamic analysis reports NOT_EXECUTED.

The registry caches model objects per process but gives each application its own dictionary. Domain cache keys include scheme, host and port, with bounded LRU size and copied entries.

Missing models and unavailable essential stages cannot become safe verdicts. Historical benchmark blacklist matches remain unconfirmed suspicious observations. Model-only classifications become Suspicious; corroborated harvesting/confirmed malicious reputation becomes Phishing.

Email/image analysis are optional independent paths. There is no database/authentication/scan persistence. Production needs shared Redis, TLS termination, trusted proxy configuration, egress restrictions and verified resources.
