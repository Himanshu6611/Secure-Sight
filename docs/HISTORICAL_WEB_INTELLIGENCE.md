# Historical web intelligence

History is explicitly PARTIAL or UNAVAILABLE. `app/brand/history.py` keeps a thread-safe process-local observation store: 512 page keys, eight snapshots per key, 24-hour retention by default. A restart or retention expiry loses coverage. History is not persisted to disk and cannot establish a global earliest observation.

Store only SHA-256 page/site keys, text/DOM/script fingerprints, registry brand IDs, credential counts, capped external domains and hashes of current DNS/TLS/registration metadata. Query/fragment URLs are not indexed. Raw text, email addresses, credential input values, cookies, authorization, path tokens and provider vCards are not stored.

Compare actual prior observations for text/DOM/script/brand/form/resource changes and current DNS/TLS/registration metadata differences. These changes are observed differences, not malware or ownership-transfer proof. An older registration plus changes in brand and credential counts produces unscored repurposing context; repurposing_confirmed remains false.

Provider availability is returned explicitly: archive, passive DNS, historical certificates and ownership history are UNAVAILABLE. Current DNS or TLS changes are not represented as external historical coverage. Only current snapshots have data_age_seconds=0; provider registration retrieval timestamps are preserved by cache hits.

The retained first observation is process-local and retention-limited. Future integrations need vetted provider terms, explicit provenance, bounded JSON and validated observation timestamps. No external archival record is fabricated in the current implementation.
