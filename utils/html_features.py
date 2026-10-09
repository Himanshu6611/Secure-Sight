"""Bounded, static DOM analysis; URLs are resolved without executing resources."""
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
from bs4 import BeautifulSoup
from utils.domain_extraction import extract_domain_components
from app.behavior.config import load_config
from app.behavior.static_redirects import inspect_static_behavior
from app.brand.inventory import inspect_inventory

MAX_HTML_BYTES = 1024 * 1024
MAX_DOM_NODES = 10000
MAX_DOM_DEPTH = 256
MAX_RESOURCES = 1000
HTML_FEATURE_NAMES = ["html_size", "tag_count", "form_count", "input_count", "password_input_count",
    "hidden_input_count", "iframe_count", "external_iframe_count", "script_count", "inline_script_count",
    "external_script_count", "external_domain_count", "external_form_count", "link_count", "external_link_count",
    "hidden_element_count", "obfuscated_script_count", "canonical_domain_mismatch", "favicon_domain_mismatch",
    "image_count", "stylesheet_count", "resource_count"]
JS_OBFUSCATION_PATTERNS = [re.compile(p) for p in [r"\beval\s*\(", r"\bFunction\s*\(",
    r"\batob\s*\(", r"\bdecodeURIComponent\s*\(", r"\bunescape\s*\(", r"\\x[0-9a-fA-F]{2}", r"\\u[0-9a-fA-F]{4}",
    r"[A-Za-z0-9+/]{256,}={0,2}"]]

class HTMLResourceLimit(ValueError):
    pass

class _BudgetParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.nodes = self.depth = 0
    def handle_starttag(self, tag, attrs):
        self.nodes += 1
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.depth += 1
        if self.nodes > MAX_DOM_NODES or self.depth > MAX_DOM_DEPTH:
            raise HTMLResourceLimit("HTML structure exceeds analysis limits")
    def handle_startendtag(self, tag, attrs):
        self.nodes += 1
        if self.nodes > MAX_DOM_NODES:
            raise HTMLResourceLimit("HTML structure exceeds analysis limits")
    def handle_endtag(self, tag):
        self.depth = max(0, self.depth - 1)


def extract_html_features(html_content, page_url):
    if not isinstance(html_content, str):
        html_content = ""
    if len(html_content.encode("utf8")) > MAX_HTML_BYTES:
        raise HTMLResourceLimit("HTML exceeds byte limit")
    budget = _BudgetParser(); budget.feed(html_content)
    soup = BeautifulSoup(html_content, "html.parser")
    page_domain = extract_domain_components(page_url)["normalized_registrable_domain"]
    base = page_url
    base_tag = soup.find("base", href=True)
    if base_tag:
        candidate = urljoin(page_url, str(base_tag["href"]))
        if urlsplit(candidate).scheme in {"http", "https"}:
            base = candidate
    def destination(value):
        absolute = urljoin(base, str(value or ""))
        if urlsplit(absolute).scheme not in {"http", "https"}:
            return "", "", False
        domain = extract_domain_components(absolute)["normalized_registrable_domain"]
        return absolute, domain, bool(domain and domain != page_domain)
    features = dict.fromkeys(HTML_FEATURE_NAMES, 0)
    features.update(html_size=len(html_content.encode("utf8")), tag_count=len(soup.find_all(True)))
    inputs = soup.find_all("input")
    features.update(input_count=len(inputs),
        password_input_count=sum(str(i.get("type", "")).lower() == "password" for i in inputs),
        hidden_input_count=sum(str(i.get("type", "")).lower() == "hidden" for i in inputs))
    forms = []
    external_domains = set()
    for form in soup.find_all("form"):
        action = str(form.get("action", ""))
        absolute, domain, external = destination(action)
        fields = form.find_all("input")
        pwd = sum(str(i.get("type", "")).lower() == "password" for i in fields)
        hidden = sum(str(i.get("type", "")).lower() == "hidden" for i in fields)
        forms.append(dict(action=action, resolved_action=absolute, action_domain=domain,
            method=str(form.get("method", "get")).lower(), field_count=len(fields), password_field_count=pwd,
            hidden_field_count=hidden, is_external=external, is_credential_form=bool(pwd),
            unsafe_action=bool(action and not absolute)))
        features["external_form_count"] += int(external)
        if external: external_domains.add(domain)
    features["form_count"] = len(forms)
    resources = []
    for tag in soup.find_all(["script", "iframe", "img", "link", "a"]):
        attr = "href" if tag.name in {"link", "a"} else "src"
        if not tag.get(attr): continue
        absolute, domain, external = destination(tag[attr])
        resources.append(dict(type=tag.name, url=absolute, domain=domain, is_external=external))
        if len(resources) > MAX_RESOURCES: raise HTMLResourceLimit("Resource count exceeds analysis limit")
        if external: external_domains.add(domain)
        if tag.name == "script": features["external_script_count"] += int(external)
        if tag.name == "iframe": features["external_iframe_count"] += int(external)
        if tag.name == "a": features["external_link_count"] += int(external)
    scripts = soup.find_all("script")
    features.update(script_count=len(scripts), inline_script_count=sum(not bool(t.get("src")) for t in scripts),
        obfuscated_script_count=sum(any(p.search(t.get_text()) for p in JS_OBFUSCATION_PATTERNS)
                                    for t in scripts if not t.get("src")),
        iframe_count=len(soup.find_all("iframe")), image_count=len(soup.find_all("img")),
        link_count=len(soup.find_all("a")), resource_count=len(resources), external_domain_count=len(external_domains))
    canonical_url = favicon_url = ""
    for link in soup.find_all("link", href=True):
        rels = {str(v).lower() for v in link.get("rel", [])}
        absolute, domain, external = destination(link["href"])
        if "canonical" in rels:
            canonical_url = absolute; features["canonical_domain_mismatch"] = int(external)
        if "icon" in rels:
            favicon_url = absolute; features["favicon_domain_mismatch"] = int(external)
        if "stylesheet" in rels: features["stylesheet_count"] += 1
    for tag in soup.find_all(True):
        style = re.sub(r"\s+", "", str(tag.get("style", "")).lower())
        features["hidden_element_count"] += int(tag.has_attr("hidden") or "display:none" in style or "visibility:hidden" in style)
    meta = {str(t.get("name") or t.get("property") or t.get("http-equiv")): str(t.get("content"))
            for t in soup.find_all("meta") if t.get("content")}
    title = soup.find("title")
    return dict(html_features=features, forms=forms, title=title.get_text().strip() if title else "",
        brand_inventory=inspect_inventory(soup, base),
        static_behavior=inspect_static_behavior(soup, base, load_config()),
        meta_tags=meta, canonical_url=canonical_url, favicon_url=favicon_url, resources=resources,
        scripts_summary=dict(total=features["script_count"], inline=features["inline_script_count"],
            external=features["external_script_count"], obfuscated=features["obfuscated_script_count"]),
        iframes_summary=dict(total=features["iframe_count"], external=features["external_iframe_count"]))
