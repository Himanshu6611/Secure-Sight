# Reputation semantics

Local entries are corrected historical training-source exact host matches with mixed-label hosts excluded. Metadata includes partition, source hash and CSV checksum. Missing/mismatched metadata prevents loading the list.

A match reports SUSPICIOUS with current maliciousness unconfirmed. A non-hit reports UNKNOWN. Historical labels are never a current verified threat feed or assurance of safety.

External API skeletons report UNAVAILABLE even if a key is configured; no fake SAFE result is fabricated. Aggregation reports SAFE only when every provider actually reports SAFE. Failures never disappear behind a single safe provider.

No live external reputation integration is implemented in the current scan pipeline. Its absence is visible in warnings.
