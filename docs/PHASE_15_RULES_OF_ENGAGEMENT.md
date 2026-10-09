# Phase 15 rules of engagement

Authorized by the user's Phase 15 implementation/testing request on 2026-10-09. Targets: this repository, isolated Flask test clients, in-memory encrypted SQLite, mocked DNS/provider/socket responses and disposable generated MIME/media. No public targets, metadata endpoint probes, production load, live malware, real victim content, credential changes or external publication.

Window: this local session, 2026-10-09. Roles: synthetic analyst/viewer/admin in team-a and admin in team-b from disposable test fixtures. Local dashboard/private instance is preserved; testing uses no real credentials. Seed 20261009 for parser/ML checks; media seed 15.

Ceilings: 150 parser mutations <=512 random bytes each; 150 malformed-media samples <=200 bytes each; nesting <=1200 levels, under the existing 2MiB/20,000-line wire ceiling; 39 initial adversarial parametrized cases. Existing resource regressions simulate quota saturation rather than unbounded load. Full suite single pytest process, timeout 180 seconds per shell-run expectation (worker tests retain their own strict deadlines). No automatic retries. Stop on unexpected network, persistent writes outside reports/test temp paths, repeated timeout, runaway child process or uncontrolled memory growth; stop the known test session and retain content-free logs. Never kill arbitrary processes.

Providers/DNS/HTTP pools are monkeypatched before malformed destination tests: tests assert no socket/pool construction for rejected targets. Real OCR/QR/C2PA and Windows worker resource tests operate on generated local content. No destructive stage or production workload is authorized by this scope.

Request IDs/statuses are checked by API regression tests; artifacts contain case IDs and summaries, no authentication tokens, raw private emails or victim content. Temporary fixtures are pytest-owned and cleaned normally. Retain reports as evidence, not runtime source content. Any unavailable browser/OS/network/production evidence remains explicitly unavailable. No formal risk acceptance is inferred. This is internal automated adversarial verification, not a claimed professional penetration test.
