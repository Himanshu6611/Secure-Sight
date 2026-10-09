# Local SSRF lab results

2026-10-09, local Windows: baseline 757 passed; targeted 39 passed; final 796 passed, 0 failures/errors, 0 skips, 26 warnings. No retries or expected-failure suppression. Evidence: `reports/phase15_20261009/`.

15 new alternate IPv4, IPv6/mapped/translation, user-info, backslash, port, scheme and encoding cases rejected. Six mixed public/private answer sets rejected before pool construction; no sockets opened. Three public URL normalization variants are idempotent. Existing pinned gateway, public-to-private redirect, per-hop validation and no-reresolution regressions passed in the full suite. DNS mocks model address changes; no real metadata endpoint, public host or CNAME infrastructure was probed. Query text mentioning a private IP is data, not permission to follow it; downstream targets are revalidated. Dot segments are retained consistently, not claimed to be canonical path resolution. Socket pinning does not prove a worker-wide network sandbox.
