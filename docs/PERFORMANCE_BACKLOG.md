# Outstanding performance backlog

P0: prior worker OS filesystem/network isolation and public-release ML/security gaps; no performance shortcut can accept them. Production stuck-job/crash/client-disconnect cancellation and mixed-workload saturation require a controlled staging environment. No risk acceptance implied.

P1: measure production-like HTTP/API/auth/serialization, disk-backed WAL concurrent readers/writers, actual hosting cold start and loaded model memory; measure URL-provider/crawl, email queue wait and OCR/media execution separately. Verify provider quotas and fair workload admission before worker tuning. Multi-worker aggregate freshness remains bounded by existing TTL but is not immediate invalidation.

P2: deep-offset/keyset pagination if demonstrated by real usage; possible covering/filter indexes only after selectivity/write-cost evidence; analytics telemetry filtering/decryption only if cold cost becomes material. Dedicated frontend Lighthouse/field CWV/accessibility measurements and private dashboard DOM profiling; no frontend speedup assumed from SQL. Measure added index file/write/startup cost before public rollout.

P3: compression, quantization, infrastructure migration, browser-enabled crawling and provider parallelization deferred: absent benefit/quality/isolation evidence. Current benchmark isolates listing; it does not establish whole-application capacity or external-source performance.
