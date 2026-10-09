"""Priority, same-registrable-site crawl with one cumulative budget.

Root fetch is reused. robots.txt is consulted before child pages. No forms,
scripts, images, sitemap expansion, cookies, authenticated or query URLs.
"""
import time
from urllib.parse import urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser
from app.brand.config import load_config
from app.behavior.privacy import redact_url, normalize_destination
from app.security.urls import validate_url, InvalidURL
from utils.domain_extraction import extract_domain_components
from utils.safe_fetch import fetch_webpage_safely, DEFAULT_TIMEOUT, MAX_RESPONSE_BYTES
from utils.html_features import extract_html_features

PRIORITIES = ("login", "signin", "account", "verify", "security", "payment", "billing", "support", "contact", "about", "privacy", "terms")
FORBIDDEN = ("logout", "delete", "remove", "unsubscribe", "checkout", "purchase", "download", "reset", "oauth", "token")


def crawl_site(root, inventory, root_fetch, config=None):
    config = config or load_config()
    started = time.monotonic()
    deadline = started + config["total_timeout_seconds"]
    scope = extract_domain_components(root)["normalized_registrable_domain"]
    requests = root_fetch.get("request_count", 0)
    used_bytes = root_fetch.get("response_bytes", root_fetch.get("html_size", 0))
    root_elapsed = root_fetch.get("elapsed_ms", 0) / 1000
    deadline -= root_elapsed
    pages = [dict(url=redact_url(root), depth=0, status="ANALYZED", reused_root=True)]
    children, queue, seen = [], [], {normalize_destination(root)}
    stop, robots_state = None, "NOT_REQUESTED"

    def candidates(links, depth):
        for link in links:
            try:
                url = validate_url(link)
                parsed = urlsplit(url)
                if parsed.hostname != urlsplit(root).hostname:
                    continue  # robots policy is scoped to this origin's hostname.
                if parsed.query or parsed.fragment or any(term in parsed.path.casefold() for term in FORBIDDEN):
                    continue
                if extract_domain_components(url)["normalized_registrable_domain"] != scope:
                    continue
                normalized = normalize_destination(url)
                if normalized in seen:
                    continue
                seen.add(normalized)
                priority = next((i for i, term in enumerate(PRIORITIES) if term in parsed.path.casefold()), len(PRIORITIES))
                queue.append((priority, url, depth))
            except (ValueError, TypeError, InvalidURL):
                continue
        queue.sort(key=lambda p: (p[0], p[1]))

    def retrieve(url, robot=False):
        nonlocal requests, used_bytes, stop
        remaining = deadline-time.monotonic()
        if remaining <= 0 or requests >= config["max_requests"] or used_bytes >= config["max_total_bytes"]:
            stop = "RESOURCE_LIMIT_EXCEEDED"
            return None
        fetched = fetch_webpage_safely(url, max_bytes=min(MAX_RESPONSE_BYTES, config["max_total_bytes"]-used_bytes, 65536 if robot else MAX_RESPONSE_BYTES),
            max_redirects=min(5, config["max_requests"]-requests-1), timeout=min(DEFAULT_TIMEOUT, remaining),
            allowed_domain=scope, allowed_hostname=urlsplit(root).hostname, allowed_content_types={"text/plain"} if robot else None)
        requests += fetched.get("request_count", 0)
        used_bytes += fetched.get("response_bytes", 0)
        return fetched

    candidates(inventory.get("_links", []), 1)
    parser = None
    if queue and config["max_depth"] and config["max_pages"] > 1:
        parts = urlsplit(root)
        robot_url = urlunsplit((parts.scheme, parts.netloc, "/robots.txt", "", ""))
        fetched = retrieve(robot_url, True)
        if fetched and fetched["status"] == "SUCCESS":
            parser = RobotFileParser()
            parser.parse((fetched.get("html_content") or "").splitlines())
            robots_state = "AVAILABLE"
        elif fetched and fetched.get("status_code") in {404, 410}:
            robots_state = "NOT_PRESENT"
        else:
            robots_state = "UNAVAILABLE"
            stop = stop or "ROBOTS_UNAVAILABLE"
    while queue and not stop and len(pages) < config["max_pages"]:
        _, url, depth = queue.pop(0)
        if depth > config["max_depth"]:
            continue
        if parser and (not parser.can_fetch("SecureSight-Scanner", url) or parser.crawl_delay("SecureSight-Scanner") or parser.request_rate("SecureSight-Scanner")):
            pages.append(dict(url=redact_url(url), depth=depth, status="ROBOTS_DISALLOWED", reused_root=False))
            continue
        fetched = retrieve(url)
        if fetched is None:
            break
        page = dict(url=redact_url(url), depth=depth, status=fetched["status"], reused_root=False)
        pages.append(page)
        if fetched["status"] != "SUCCESS":
            continue
        try:
            html = extract_html_features(fetched.get("html_content") or "", fetched["final_url"])
            child = html["brand_inventory"]
            page.update(status="ANALYZED", brand_claims=child["brand_claims"], password_input_count=html["html_features"]["password_input_count"])
            children.append(dict(inventory=child, url=fetched["final_url"], html_features=html["html_features"], forms=html["forms"],
                resources=html["resources"], _page_index=len(pages)-1))
            seen.add(normalize_destination(fetched["final_url"]))
            if depth < config["max_depth"]:
                candidates(child["_links"], depth+1)
        except (ValueError, TypeError):
            page["status"] = "PARSE_FAILED"
    if queue and not stop:
        stop = "PAGE_OR_DEPTH_LIMIT"
    return dict(status="PARTIAL" if stop or any(p["status"] != "ANALYZED" for p in pages) else "ANALYZED",
        pages=pages, robots_status=robots_state, stop_reason=stop, request_count=requests, response_bytes=used_bytes,
        elapsed_ms=round((time.monotonic()-started)*1000 + root_elapsed*1000, 3), limits=config,
        sitemap_status="NOT_EXPANDED", same_site_only=True, _children=children)
