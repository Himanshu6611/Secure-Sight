"""Privacy-preserving identity and leakage-safe partitions for email research data."""
from __future__ import annotations

import hashlib
import re
from email.utils import parseaddr

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold


def normalize_message(value: str) -> str:
    return " ".join(str(value).split()).casefold()


def message_fingerprint(value: str) -> str:
    normalized = normalize_message(value)
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()


def normalize_sender(value: str | None) -> str | None:
    if not value:
        return None
    address = parseaddr(str(value))[1].strip().casefold()
    if not address or address.count("@") != 1:
        return None
    local, domain = address.rsplit("@", 1)
    if not local or not domain or any(char.isspace() for char in address):
        return None
    try:
        domain = domain.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+", local) or not re.fullmatch(r"[a-z0-9.-]+", domain):
        return None
    return local + "@" + domain


def grouped_email_ids(messages, senders):
    """Union exact normalized messages and normalized sender identities.

    Only opaque hashes are returned. Raw content and sender addresses are never
    written to the processed feature file.
    """
    if len(messages) != len(senders):
        raise ValueError("Email identity columns must have equal lengths")
    size = len(messages)
    parent = list(range(size))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left, right):
        a, b = find(left), find(right)
        if a != b:
            parent[max(a, b)] = min(a, b)

    owners = {}
    identity_tokens = []
    for index, (message, sender) in enumerate(zip(messages, senders)):
        content = message_fingerprint(message)
        normalized_sender = normalize_sender(sender)
        tokens = ["message:" + content]
        if normalized_sender:
            tokens.append("sender:" + hashlib.sha256(normalized_sender.encode()).hexdigest())
        identity_tokens.append(tokens)
        for token in tokens:
            previous = owners.setdefault(token, index)
            union(index, previous)

    components = {}
    for index, tokens in enumerate(identity_tokens):
        components.setdefault(find(index), set()).update(tokens)
    component_ids = {root: hashlib.sha256("\n".join(sorted(tokens)).encode()).hexdigest()
                     for root, tokens in components.items()}
    return [component_ids[find(index)] for index in range(size)]


def _holdout(indices, labels, groups, *, folds, seed, name):
    if len(set(groups)) < folds:
        raise ValueError(f"Need at least {folds} independent email groups for {name} partition")
    splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed)
    candidates = list(splitter.split(np.zeros((len(indices), 1)), labels, groups))
    target_fraction = 1 / folds

    def rank(pair):
        _, held = pair
        observed = labels[held]
        class_penalty = 0 if len(np.unique(observed)) == 2 else 1
        fraction_penalty = abs(len(held) / len(indices) - target_fraction)
        prevalence_penalty = abs(float(observed.mean()) - float(labels.mean())) if len(observed) else 1
        return class_penalty, fraction_penalty + prevalence_penalty, len(held)

    selected = min(candidates, key=rank)
    fit_local, held_local = selected
    fit, held = indices[fit_local], indices[held_local]
    if len(np.unique(labels[held_local])) != 2:
        raise ValueError(f"Email {name} partition lacks both classes; no honest metric can be reported")
    return fit, held


def grouped_email_partitions(labels, groups, random_state=20261009):
    """Create disjoint fit/calibration/threshold/test group partitions."""
    y = np.asarray(labels, dtype=int)
    group_values = np.asarray(groups, dtype=str)
    if y.ndim != 1 or group_values.ndim != 1 or len(y) != len(group_values) or len(y) == 0:
        raise ValueError("Email labels and group IDs must be non-empty aligned vectors")
    if set(np.unique(y)) != {0, 1} or any(not group for group in group_values):
        raise ValueError("Email partitioning requires binary labels and non-empty group IDs")
    all_rows = np.arange(len(y))
    trainval, test = _holdout(all_rows, y, group_values, folds=5, seed=random_state, name="test")
    fit_cal, threshold = _holdout(trainval, y[trainval], group_values[trainval], folds=5,
                                  seed=random_state + 1, name="threshold")
    fit, calibration = _holdout(fit_cal, y[fit_cal], group_values[fit_cal], folds=5,
                                 seed=random_state + 2, name="calibration")
    partitions = {"fit": fit, "calibration": calibration, "threshold_selection": threshold, "test": test}
    seen = set()
    for name, indices in partitions.items():
        current = set(group_values[indices])
        if seen & current:
            raise ValueError("Email group leaked across evaluation partitions")
        seen.update(current)
        if len(np.unique(y[indices])) != 2:
            raise ValueError(f"Email {name} partition lacks both classes")
    if seen != set(group_values):
        raise ValueError("Email partition coverage mismatch")
    return partitions


def email_dataset_audit(frame, feature_columns):
    """Return aggregate-only diagnostics; never return message or sender values."""
    if not {"label", "source_id", "group_id"} <= set(frame.columns):
        raise ValueError("Processed email data lacks source/group provenance; rebuild it first")
    labels = frame["label"]
    invalid = int((~labels.isin([0, 1])).sum())
    missing = int(frame[list(feature_columns)].isna().any(axis=1).sum())
    group_label_conflicts = int((frame.groupby("group_id")["label"].nunique() > 1).sum())
    source = {}
    for name, subset in frame.groupby("source_id", sort=True):
        source[str(name)] = {"rows": len(subset), "groups": int(subset.group_id.nunique()),
                             "class_counts": {str(k): int(v) for k, v in subset.label.value_counts().sort_index().items()}}
    feature_duplicates = int(frame.duplicated(subset=list(feature_columns)).sum())
    return {
        "rows": len(frame), "features": list(feature_columns),
        "class_counts": {str(k): int(v) for k, v in labels.value_counts().sort_index().items()},
        "invalid_labels": invalid, "rows_with_missing_features": missing,
        "exact_feature_duplicates": feature_duplicates,
        "groups": int(frame.group_id.nunique()), "conflicting_group_labels": group_label_conflicts,
        "sources": source,
        "limitations": ["Original collection timestamps/campaign IDs unavailable in the preprocessor inputs",
                        "Email source licensing and label provenance require owner review",
                        "Aggregate handcrafted features do not represent raw text model performance"],
    }
