"""Versioned projection contracts; upstream panel data remains source-owned."""
from typing import Any, TypedDict


class Summary(TypedDict):
    verdict: str
    risk_score: float | None
    severity: str | None
    confidence: float | None
    confidence_kind: str
    confidence_calibrated: bool
    analysis_completeness: float | None
    evidence_coverage: float | None
    ml_probability: float | None
    status: str


class Evidence(TypedDict):
    evidence_id: str
    indicator: str
    category: str
    evidence_type: str
    confidence: float | None
    source: str
    source_version: str | None
    timestamp: str | None
    artifact_hash: str | None
    value: Any


class Investigation(TypedDict):
    contract_version: str
    investigation_id: str
    created_at: str
    updated_at: str
    entity_type: str
    subject: str
    summary: Summary
    evidence: list[Evidence]
    explanations: list[dict]
    timeline: list[dict]
    graph: dict
    panels: dict
    analyst_assessment: dict
