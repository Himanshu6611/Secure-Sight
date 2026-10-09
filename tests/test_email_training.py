import numpy as np
import pandas as pd
import pytest

from ml.email_dataset import email_dataset_audit, grouped_email_ids, grouped_email_partitions
from ml.email_training import candidate_models, choose_threshold
from scripts.preprocess_emails import _to_binary_label


@pytest.mark.parametrize("value, expected", [
    (0, 0), (1, 1), (0.0, 0), (1.0, 1), ("0", 0), ("1", 1),
    (2, -1), (-1, -1), (1.5, -1), ("unknown", -1), (None, -1),
])
def test_email_label_mapping_rejects_unknown_and_non_binary_values(value, expected):
    assert _to_binary_label(value) == expected


def test_email_grouping_merges_duplicate_content_and_sender_without_exposing_identity():
    messages = ["  Verify   your account ", "verify your account", "Different message"]
    senders = ["Help <ALERT@EXAMPLE.COM>", "other@example.com", "alert@example.com"]
    groups = grouped_email_ids(messages, senders)
    assert groups[0] == groups[1]  # normalized duplicate message
    assert groups[0] == groups[2]  # sender connects otherwise different messages
    assert all(len(group) == 64 for group in groups)
    assert not any("example.com" in group or "Verify" in group for group in groups)


def test_email_partitions_keep_groups_disjoint_and_cover_all_rows():
    labels = np.repeat(np.arange(120) % 2, 2)
    groups = np.repeat([f"identity-{i}" for i in range(120)], 2)
    partitions = grouped_email_partitions(labels, groups, random_state=31)
    seen = set()
    for rows in partitions.values():
        current = set(groups[rows])
        assert not seen.intersection(current)
        assert set(np.unique(labels[rows])) == {0, 1}
        seen.update(current)
    assert seen == set(groups)


def test_smote_is_inside_cv_pipeline_and_has_class_weight_baseline():
    candidates = candidate_models()
    smote = candidates["logistic_smote"][0]
    assert "sampler" in smote.named_steps
    assert candidates["logistic_class_weight"][0].named_steps["classifier"].class_weight == "balanced"
    assert "sampler" not in candidates["logistic_class_weight"][0].named_steps


def test_threshold_selection_respects_false_positive_cap():
    labels = np.r_[np.zeros(500, dtype=int), np.ones(100, dtype=int)]
    probabilities = np.r_[np.linspace(0.0, 0.5, 500), np.linspace(0.2, 1.0, 100)]
    selected = choose_threshold(labels, probabilities, max_fpr=0.01)
    predictions = probabilities >= selected["threshold"]
    false_positive_rate = predictions[:500].mean()
    assert false_positive_rate <= 0.01
    assert selected["fpr"] == pytest.approx(false_positive_rate)


def test_email_audit_reports_aggregates_without_raw_content_or_senders():
    frame = pd.DataFrame({
        "label": [0, 1], "source_id": ["source-a", "source-b"],
        "group_id": ["a" * 64, "b" * 64], "feature": [0.1, 0.9],
        "message": ["private body text", "another private body"],
        "sender": ["private@example.com", "secret@example.com"],
    })
    report = email_dataset_audit(frame, ["feature"])
    serialized = str(report)
    assert report["rows"] == 2
    assert report["groups"] == 2
    assert "private body" not in serialized
    assert "example.com" not in serialized
