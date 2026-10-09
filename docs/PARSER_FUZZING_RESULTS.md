# Parser fuzzing results

2026-10-09, local Windows: baseline 757 passed; targeted 39 passed; final 796 passed, 0 failures/errors, 0 skips, 26 warnings. No retries or expected-failure suppression. Evidence: `reports/phase15_20261009/`.

Before fix, a harmless 1200-layer MIME fixture (~under existing 2MiB ceiling) raised RecursionError in BytesParser before visit(depth) could enforce depth eight. P15-001 fixed with pre-construction structural budgets: <=32 Content-Type header lines and <=96 boundary-like lines, plus sanitized recursion fallback. 10/1200-level multipart and 1200-level message/rfc822 regressions reject with MIME_RESOURCE_LIMIT/413; large cases assert BytesParser never runs.

150 deterministic MIME mutations (<=512 random bytes) and 150 malformed media samples reject safely or return bounded REQUEST_ONLY records; seed 20261009/15. This is bounded mutation smoke testing, not exhaustive fuzzing. Existing duplicate/conflicting headers, malformed auth, Received chronology, unknown charsets, encoded-body limits, archive traversal/nesting/bombs and encrypted/unsupported attachment states remain covered by phase suites. No payload execution. Conservative wire preflight can also reject bodies containing many header-like/separator lines; those inputs are resource-limited, not automatically phishing.
