"""Fail-closed configuration and bounded curated registry."""
import json
from pathlib import Path
from app.security.urls import validate_url
from utils.domain_extraction import extract_domain_components

ROOT = Path(__file__).resolve().parents[2] / "config"


def read_json(name):
    raw = (ROOT / name).read_bytes()
    if len(raw) > 32768:
        raise ValueError("Phase 9 configuration limit")
    return json.loads(raw)


def load_config():
    data = read_json("brand_intelligence.json")
    bounds = {"max_pages": (1, 20), "max_depth": (0, 2), "max_requests": (1, 100),
        "max_total_bytes": (1024, 5242880), "total_timeout_seconds": (1, 30),
        "history_max_entries": (1, 2048), "history_retention_seconds": (60, 604800)}
    if set(data) != set(bounds) | {"version", "history_scope"} or data["version"] != "9.0.0" or data["history_scope"] != "process_local_observations":
        raise ValueError("Invalid Phase 9 configuration")
    if any(type(data[k]) is not int or not lo <= data[k] <= hi for k, (lo, hi) in bounds.items()):
        raise ValueError("Invalid Phase 9 budget")
    return data


def load_registry():
    data = read_json("brand_registry.json")
    if data.get("version") != "9.0.0" or not isinstance(data.get("brands"), list) or not 0 < len(data["brands"]) <= 100:
        raise ValueError("Invalid brand registry")
    seen = set()
    for brand in data["brands"]:
        if set(brand) != {"id", "canonical_name", "aliases", "primary_domain", "official_domains", "sources"}:
            raise ValueError("Invalid brand entry")
        if brand["id"] in seen or not isinstance(brand["id"], str) or not brand["id"].isascii() or not brand["id"].isalpha():
            raise ValueError("Invalid brand identity")
        seen.add(brand["id"])
        for field, maximum in (("aliases", 16), ("official_domains", 32), ("sources", 16)):
            if not isinstance(brand[field], list) or not 0 < len(brand[field]) <= maximum:
                raise ValueError("Invalid brand list")
            if any(not isinstance(v, str) or not 0 < len(v) <= 2048 for v in brand[field]):
                raise ValueError("Invalid brand string")
        if not isinstance(brand["canonical_name"], str) or not brand["canonical_name"].isalnum() or len(brand["canonical_name"]) > 64:
            raise ValueError("Invalid brand name")
        if brand["primary_domain"] not in brand["official_domains"]:
            raise ValueError("Invalid canonical domain")
        for domain in brand["official_domains"]:
            url = validate_url("https://" + domain)
            if extract_domain_components(url)["normalized_hostname"] != domain or "/" in domain:
                raise ValueError("Invalid official domain")
        for source in brand["sources"]:
            if not validate_url(source).startswith("https://"):
                raise ValueError("Invalid brand source")
    return data
