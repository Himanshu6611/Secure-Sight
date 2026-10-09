"""Correlate only an explicitly submitted batch, never unrelated users."""
import hashlib
import re


def correlate(messages):
    groups = {}
    for index, email in enumerate(messages):
        headers = email["message"]["headers"]
        subject = re.sub(r"\s+", " ", headers["subject"].casefold()).strip()
        subject_hash = hashlib.sha256(subject.encode()).hexdigest() if subject else None
        identifiers = [("sender_domain", headers["from_domain"]), ("normalized_subject_sha256", subject_hash)]
        identifiers += [("attachment_sha256", a["sha256"]) for a in email["attachments"]]
        identifiers += [("image_phash", item["artifact"].get("phash")) for item in email["media"]]
        identifiers += [("qr_payload_sha256", qr["payload_sha256"]) for item in email["media"] for qr in item["qr"]["items"]]
        for kind, value in identifiers:
            if value:
                groups.setdefault((kind, value), set()).add(index)
    return {"version": "11.0", "status": "ANALYZED", "scope": "ONLY_THIS_EXPLICIT_BATCH", "cross_user_store": False,
        "groups": [{"identifier_type": kind, "identifier_sha256": hashlib.sha256(value.encode()).hexdigest(),
                    "message_indices": sorted(indices), "score_contribution": 0}
                   for (kind, value), indices in groups.items() if len(indices) > 1][:64],
        "interpretation": "Shared identifiers do not establish a malicious campaign."}
