"""Extract small fingerprints and registry-backed claims from the existing DOM.

Raw links are private routing data removed before API/UI output. No page text,
contacts, credential values or arbitrary JSON-LD are retained in observations.
"""
import hashlib
import json
import re
from urllib.parse import urljoin
from app.brand.config import load_registry
from app.security.urls import validate_url, InvalidURL
from utils.domain_extraction import extract_domain_components


def inspect_inventory(soup, base):
    sources = {"title": soup.title.get_text(" ", strip=True) if soup.title else "",
        "headings": " ".join(t.get_text(" ", strip=True)[:1024] for t in soup.find_all(["h1", "h2", "h3"])[:32]),
        "metadata": " ".join(str(t.get("content", ""))[:1024] for t in soup.find_all("meta")[:64]
            if str(t.get("name") or t.get("property") or "").lower() in {"description", "og:title", "og:description", "og:site_name", "twitter:title"}),
        "logo_alt": " ".join(str(t.get("alt", ""))[:256] for t in soup.find_all("img")[:64]),
        "form_labels": " ".join(t.get_text(" ", strip=True)[:256] for t in soup.find_all(["label", "button"])[:64])}
    json_errors, organizations, declared_urls = 0, [], []
    for meta in soup.find_all("meta")[:64]:
        if str(meta.get("property", "")).lower() == "og:url":
            declared_urls.append(str(meta.get("content", ""))[:2048])
    for script in soup.find_all("script", type="application/ld+json")[:8]:
        raw = script.get_text()
        if len(raw.encode("utf8")) > 16384:
            json_errors += 1
            continue
        try:
            data = json.loads(raw)
            nodes = data if isinstance(data, list) else data.get("@graph", [data]) if isinstance(data, dict) else []
            if not isinstance(nodes, list):
                raise ValueError("JSON-LD nodes")
            for node in nodes[:32]:
                if isinstance(node, dict) and node.get("@type") in {"Organization", "Corporation", "Brand"} and isinstance(node.get("name"), str):
                    organizations.append(node["name"][:256])
                    if isinstance(node.get("url"), str):
                        declared_urls.append(node["url"][:2048])
        except (ValueError, TypeError, RecursionError):
            json_errors += 1
    sources["structured_data"] = " ".join(organizations)
    texts = [t for t in soup.find_all(string=True) if not any(p.name in {"head", "title", "script", "style", "noscript", "template"} or p.has_attr("hidden") for p in t.parents)]
    visible = " ".join(str(t).strip() for t in texts)[:262144]
    sources["visible_text"] = visible
    claims = []
    for brand in load_registry()["brands"]:
        matches = [source for source, text in sources.items() if any(re.search(r"(?<!\w)" + re.escape(alias) + r"(?!\w)", text, re.I) for alias in brand["aliases"])]
        if matches:
            claims.append(dict(brand_id=brand["id"], sources=matches, source_count=len(matches),
                independence_group="STATIC_PAGE", confidence=min(.85, .35 + .1 * (len(matches)-1))))
    tags = " ".join(t.name for t in soup.find_all(True))
    scripts = " ".join(str(t.get("src", "inline"))[:2048] for t in soup.find_all("script")[:128])
    declared_domains = set()
    for value in declared_urls[:32]:
        try:
            declared_domains.add(extract_domain_components(validate_url(urljoin(base, value)))["normalized_registrable_domain"])
        except (ValueError, InvalidURL):
            continue
    return dict(brand_claims=claims, text_sha256=hashlib.sha256(visible.encode()).hexdigest(),
        dom_sha256=hashlib.sha256(tags.encode()).hexdigest(), script_sha256=hashlib.sha256(scripts.encode()).hexdigest(),
        text_char_count=len(visible), heading_count=len(soup.find_all(["h1", "h2", "h3"])),
        jsonld_error_count=json_errors,
        declared_domains=sorted(declared_domains),
        legal_link_count=sum(any(term in str(a.get("href", "")).casefold() for term in ("privacy", "terms", "legal")) for a in soup.find_all("a")[:128]),
        contact_link_count=sum("contact" in str(a.get("href", "")).casefold() for a in soup.find_all("a")[:128]),
        _links=[urljoin(base, str(a.get("href", ""))) for a in soup.find_all("a", href=True)[:128]])
