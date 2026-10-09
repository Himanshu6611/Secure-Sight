# Evidence model and provenance

Canonical explanations consume the current Phase 6 assessment version and configuration hash. Each signal must match its known ID, category, correlation group and phase source. Raw numeric/status evidence is checked against the existing normalization definition; confidence and contribution must be finite and bounded, selected/state must be valid, and unavailable signals cannot carry values or contributions. Unknown or malformed evidence is omitted with a warning.

Supported evidence types are OBSERVED, INFERRED, MODEL_DERIVED, EXTERNAL, MISSING and CONTRADICTORY. Structural observations use OBSERVED; brand/content heuristics use INFERRED; URL model data uses MODEL_DERIVED; reputation uses EXTERNAL; absent observations use MISSING; existing Phase 6 conflict records use CONTRADICTORY. Sources preserve Phase 2, specific Phase 3 stages, Phase 4 static, Phase 5 or Phase 6 provenance.

User-facing reasons contain limited wording and scalar evidence. The technical view preserves supported signal IDs, sources, state, value, normalized value, selection, confidence and contribution, plus version/hash. It does not copy page titles, brand names, form destinations, URLs, headers, arbitrary free text, cookies or API keys. The password observation retains only a bounded count from an ANALYZED static result.

Contradictions translate only the three existing Phase 6 conflict codes: ML/reputation, low-model/observed-risk, and reputation/web. They explain confidence reduction without resolving conflicts by inventing findings. Missing observations disclose insufficient information; TIMEOUT and failed fetch states are preserved as missing information. ANALYSIS_FAILED has an explicit failure warning; UNKNOWN has an insufficient-evidence summary.

The deterministic summary consists of a verdict-specific registered sentence plus actual top-reason titles. No generative model is involved. Source reliability is an existing signal-quality proxy, not a newly estimated probability. Assessment confidence remains provisional and no explanation implies production accuracy or guaranteed safety.
