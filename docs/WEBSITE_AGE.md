# Website age

Domain registration age and website age are separate fields. Website first_seen is the earliest retained observation for the final hostname by this running SecureSight process. Subdomains are not silently merged into one website. HTTP/HTTPS share a hostname observation identity; this is explicitly a local lower bound.

`website_age.created_at` is always null without a verified creation source. `observed_age_days` measures elapsed days since first_seen, not actual creation age. Status is PARTIAL for retained observations and UNAVAILABLE when the page is inaccessible or the URL is not eligible for indexing. Confidence is a provisional provenance index, not a calibrated probability.

New first_seen on an old domain does not prove recent deployment or compromise. New startups, acquired domains and rebrands must not be classified malicious from age alone. Process restarts, the 24-hour retention horizon and 512-key eviction can reset the retained lower bound. No archive coverage is implied.
