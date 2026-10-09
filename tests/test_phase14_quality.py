"""Gate integrity, leakage adversaries, metamorphic and cross-phase contracts."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import numpy as np
import pandas as pd
import pytest
from jsonschema import Draft202012Validator
from quality.gates import Gate, all_required_pass, numeric_gate, wilson
from quality.evaluate import partition_audit, metrics, select_validation_threshold
from app.brand.history import ObservationStore
from app.security.urls import validate_url
from tests.risk.test_engine import context
from tests.test_phase12_dashboard import accounts, authenticate, url_result, saved


@pytest.mark.parametrize("value", [None, float("nan"), float("inf")])
def test_missing_metrics_cannot_pass(value):
    result = numeric_gate("missing", value, .01, minimum=False)
    assert result.status == "UNAVAILABLE" and not all_required_pass([result])


def test_gate_failures_and_optional_evidence_are_distinct():
    assert not all_required_pass([])
    assert not all_required_pass([Gate("optional", "PASS", False, "")])
    assert not all_required_pass([numeric_gate("fpr", .5, .01, minimum=False)])
    assert all_required_pass([numeric_gate("tests", 0, 0, minimum=False), Gate("optional", "UNAVAILABLE", False, "")])


@pytest.mark.parametrize("counts", [(-1, 1), (2, 1), (0, -1)])
def test_invalid_interval_counts(counts):
    with pytest.raises(ValueError): wilson(*counts)


def test_intervals_and_single_class_metrics_do_not_fabricate_auc():
    assert wilson(0, 0) is None
    assert wilson(0, 100)[1] > 0 and wilson(100, 100)[0] < 1
    result = metrics(np.zeros(4, dtype=int), np.array([0., .1, .2, .8]), .5)
    assert result["roc_auc"] is None and result["pr_auc"] is None
    assert result["false_negative_rate"] is None and result["false_positive_rate"] == .25


@pytest.fixture
def tiny_split():
    names = ["train", "calibration", "threshold_selection", "test"]
    rows = pd.DataFrame({"row_id": ["a", "b", "c", "d"], "url": [f"https://{k}.example/" for k in names],
                         "registrable_domain": [f"{k}.example" for k in names], "label": [0, 1, 0, 1]})
    split = {k: {"row_ids": [rows.iloc[i].row_id], "domains": [rows.iloc[i].registrable_domain],
                 "rows": 1, "labels": {str(rows.iloc[i].label): 1}} for i, k in enumerate(names)}
    return rows, split


@pytest.mark.parametrize("kind", ["row", "domain", "missing", "distribution", "url", "coverage"])
def test_frozen_partition_adversaries_fail(tiny_split, kind):
    rows, split = tiny_split
    assert partition_audit(rows, split)["status"] == "PASS"
    if kind == "row": split["test"]["row_ids"] = split["train"]["row_ids"]
    elif kind == "domain": rows.loc[3, "registrable_domain"] = rows.loc[0, "registrable_domain"]
    elif kind == "missing": split["test"]["row_ids"] = ["no-such-row"]
    elif kind == "distribution": split["test"]["labels"] = {"0": 1}
    elif kind == "url": rows.loc[3, "url"] = rows.loc[0, "url"]
    else: rows.loc[4] = ["e", "https://extra.example/", "extra.example", 0]
    with pytest.raises(ValueError): partition_audit(rows, split)


def test_validation_threshold_is_exact_and_holdout_independent():
    labels = np.array([0] * 100 + [1] * 10)
    probabilities = np.array([.01] * 99 + [.7] + [.8] * 10)
    threshold = select_validation_threshold(labels, probabilities)
    assert threshold["partition"] == "threshold_selection" and threshold["fpr"] <= .01
    before = threshold.copy()
    metrics(np.array([0, 1]), np.array([.99, .01]), threshold["threshold"])
    assert threshold == before


@pytest.mark.parametrize("age", [0, 1, 30, 365, 9000])
def test_domain_age_alone_is_not_phishing(app, age):
    observation = context()
    observation["domain_intelligence"]["registration"]["domain_age_days"] = age
    assert app.extensions["risk_engine"].calculate(observation)["verdict"] != "PHISHING"


@pytest.mark.parametrize("url", ["https://EXAMPLE.com/", "https://例え.jp/a%20b", "https://example.com/?x=%27"])
def test_url_normalization_idempotence(url):
    normalized = validate_url(url)
    assert validate_url(normalized) == normalized


def test_future_history_is_excluded_without_rewriting_future():
    store = ObservationStore()
    snapshot = {"text_sha256": "text", "dom_sha256": "dom", "script_sha256": "script", "brand_ids": ["paypal"], "password_count": 1, "external_domains": []}
    future = datetime(2026, 10, 9, tzinfo=timezone.utc)
    store.observe("https://example.com/", snapshot, future)
    before = copy.deepcopy(store.records)
    result = store.observe("https://example.com/", {**snapshot, "brand_ids": ["microsoft"]}, future - timedelta(hours=1))
    assert result["reason"] == "FUTURE_OBSERVATION_EXCLUDED" and result["snapshots"] == []
    assert result["website_first_seen"] is None and store.records == before
    assert store.observe("https://example.com/", snapshot, future + timedelta(seconds=1))["snapshots"]


def test_cross_phase_contract_and_export_immutability(client, accounts, saved):
    authenticate(client, accounts["analyst"])
    record = client.get("/api/v1/investigations/" + saved).json
    schema = json.loads((Path(__file__).resolve().parents[1] / "docs/schemas/investigation_v12.json").read_text())
    Draft202012Validator(schema).validate(record)
    summary = copy.deepcopy(record["summary"])
    for suffix in ("/evidence", "/graph", "/timeline", "/export?format=json"):
        response = client.get("/api/v1/investigations/" + saved + suffix)
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
    assert client.get("/api/v1/investigations/" + saved).json["summary"] == summary


def test_model_missing_does_not_create_safety_or_change_source(app):
    observation = context(); before = copy.deepcopy(observation)
    observation["ml_result"] = {"status": "MODEL_NOT_FOUND"}
    result = app.extensions["risk_engine"].calculate(observation)
    assert result["verdict"] not in {"SAFE", "LEGITIMATE"}
    assert observation["domain_intelligence"] == before["domain_intelligence"]
