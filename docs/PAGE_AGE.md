# Page age

A page key hashes final hostname plus path. Query and fragment URLs are not indexed, preventing authentication/tracking values from entering history. Paths are hashed and not stored or displayed in public crawl output. Public URLs redact every nonroot path/query value.

The page field is independent of website_first_seen and domain creation. A newly observed /login can have a later local first_seen than an existing /about page. `created_at` remains null and `observed_age_days` is a retention-limited local observation age.

Unavailable pages have null first_seen; absence is not safety or evidence of recent creation. Snapshot caches retain the first observation until retention/eviction/restart rather than replacing it with every retrieval. Tests verify page/site separation, expiration, bounded storage and sensitive-URL exclusion.
