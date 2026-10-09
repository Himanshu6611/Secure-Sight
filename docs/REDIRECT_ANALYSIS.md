# Redirect analysis

Phase 8 extends the existing `utils.safe_fetch.fetch_webpage_safely` gateway instead of adding a second fetcher. HTTP 301/302/303/307/308 responses are handled manually with automatic redirects/retries disabled. Every contacted destination passes the existing strict URL policy and a fresh public-address DNS check; the connection is pinned to a validated literal address.

config/behavior.json sets five followed redirects, a four-second request budget, a six-second total retrieval budget and a 1 MiB final-body budget. The controller can observe one additional boundary redirect header before stopping, so the maximum request/header count is six. Redirect bodies are not downloaded; final compressed/non-HTML responses are rejected. Configured limits may be reduced per call but cannot be expanded by request input.

Each HTTP hop records redacted source/destination URL, registrable domains, status/type, same-domain/subdomain/TLD/scheme/port changes, observed timing and whether the next destination actually returned a response. A header target is not proof of successful navigation. `redirect_count` counts observed headers, including a final un-followed header. `final_url` is available only after successful final-document retrieval; failures retain a redacted last-attempted URL.

Loop identity normalizes scheme/host/default port/empty path and ignores HTTP fragments while preserving query semantics. Returning to a visited destination stops immediately. Cross-domain redirects and HTTP-to-HTTPS upgrades are contextual and add no risk points by themselves. Existing Phase 2 shortener configuration is reused; shorteners are not automatically suspicious.

Phase 4 analyzes the already fetched final HTML. The scan service reuses cached Phase 3 intelligence for the final origin and extracts the final URL's existing lexical features for the unchanged serving model. It does not fetch the final HTML again or query reputation for every intermediate hop. Analysis remains synchronous under existing shared scan quotas/concurrency limits.
