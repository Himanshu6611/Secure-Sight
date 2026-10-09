# Explainability architecture

Phase 7 translates existing observations; it does not detect threats again. The shared scan service passes the Phase 6 canonical assessment, trusted Phase 5 local explanation and Phase 4 static counts to `ExplanationEngine.explain`. The engine performs no fetching, DNS queries, HTML parsing, model loading, training or LLM calls.

The response preserves `assessment` and adds canonical fields to the existing `explanation`: version/hash, deterministic summary, top reasons, positive risk signals, negative/risk-reducing observations, local model explanation, contradictions, missing information, warnings, score adjustments and a bounded technical view. Existing `ml_detail` and `risk_breakdown` remain compatibility fields in the scan service. The server-rendered page shows explanations using Jinja autoescaping and native details controls.

Registry configuration lives in config/explanations.json. It maps all 19 Phase 6 signals and all 59 learned URL feature names. Trusted configuration is validated at application startup and has a semantic SHA256 for replay. The registry does not accept page-defined reasons or arbitrary formatting.

Top reasons default to five, with a configurable range of one to seven. Fewer reasons are returned when fewer observations qualify; the engine never pads a result with invented evidence. Confidence stays a provisional evidence-quality index. Local model feature impacts are different quantities from risk-score contributions. A critical/phishing assessment without matching strong reasons produces an inconsistency warning, never fabricated supporting evidence.

See DETECTION_REASONS.md, EVIDENCE_MODEL.md, ML_EXPLAINABILITY.md, EXPLANATION_SECURITY.md and PHASE_07_REPORT.md. Reproduce tests with `venv\Scripts\python.exe -m pytest tests -q` and controlled timing/replay with `venv\Scripts\python.exe scripts/validate_explanations.py`.

## Phase 9 current behavior

Current registry is 7.2.0 with Phase 6 policy 6.2.0. The existing brand signal can have validated phase_9 provenance. Contextual brand_reasons include HISTORICAL observations and zero additional score contribution, drawn from fixed known descriptions. Evidence fields remain bounded; raw page text, metadata instructions and historical provider payloads are not explanation prompts.
