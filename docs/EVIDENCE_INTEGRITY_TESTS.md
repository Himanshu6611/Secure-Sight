# Evidence and scoring integrity

2026-10-09, local Windows: baseline 757 passed; targeted 39 passed; final 796 passed, 0 failures/errors, 0 skips, 26 warnings. No retries or expected-failure suppression. Evidence: `reports/phase15_20261009/`.

New four cross-tenant graph/timeline/evidence/JSON-export probes return 404/no-store. Six case mass-assignment attempts (risk/verdict/confidence/role/tenant/evidence) return 400 and leave stored backend summary unchanged. Existing forged evidence/type rejection, case-reference tenant checks, revision guards, audit-chain verification, analyst-note score independence, duplicate/correlated-signal deduplication, confidence contradictions, observations/model-derived distinction and explanations referencing real evidence pass. Source timestamps remain source timestamps; future-history records cannot appear in past-time analysis. Missing timestamps and unavailable providers remain explicit.

Risk-layer tests show that provider/model failure does not create SAFE/LEGITIMATE. Low-level lexical output remains fallible, as P15-002 demonstrates. Server-side escaping/rendering and DOM code checks are regression evidence, not a full interactive browser XSS proof. Unsupported neural/LLM judgments are not fabricated. No real private email or account data used.
