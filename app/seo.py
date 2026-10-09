"""Public route registry and conservative indexing, independent of submitted data."""
from dataclasses import dataclass
import os
from urllib.parse import urlsplit
from html import escape
from flask import Blueprint, Response, current_app, redirect, render_template, request, has_request_context


@dataclass(frozen=True)
class Page:
    title: str
    description: str
    heading: str
    sections: tuple[tuple[str, str], ...] = ()


PAGES: dict[str, Page] = {
    "/": Page("SecureSight — URL, Email & Media Threat Analysis", "Inspect URL, email and media threat evidence with explanations, source context and explicit analysis limits.", "SecureSight"),
    "/guides/url-analysis": Page("Understanding URL Threat Evidence — SecureSight", "Learn how URL structure, domain history, redirects and website evidence contribute to a threat assessment, and where uncertainty remains.", "Understanding URL threat evidence", (
        ("What a URL assessment can tell you", "A suspicious link can combine an unusual address with a misleading brand claim or a request for credentials. SecureSight examines URL structure alongside available domain, website and redirect observations. A model probability describes a learned URL pattern; it is not a guarantee about the destination. Do not open a suspicious link merely because one signal looks reassuring."),
        ("Registration age is not website history", "Domain registration dates, observed page changes and first-seen timestamps answer different questions. A newly registered startup is not automatically phishing. An older domain can change ownership or purpose. Missing historical observations mean that history is unknown, not that a website has never changed."),
        ("Read the evidence and its limits", "Compare observed facts with inferred or model-derived signals. Redirects can change the destination; missing providers or failed page retrieval leave analysis incomplete. Confidence, risk score, severity and verdict have different meanings. For example, a brand name in a URL does not establish ownership. Verify a service through a trusted channel before entering credentials."))),
    "/guides/email-analysis": Page("Email Authentication & Threat Evidence — SecureSight", "Understand email identity, SPF, DKIM, DMARC, suspicious links, attachments and why authenticated mail can still be harmful.", "Understanding email threat evidence", (
        ("Start with identity and context", "A display name is a claim, not proof of who sent a message. SecureSight examines sender and reply addresses, available authentication evidence, links and attachment indicators. A changed Reply-To address can deserve attention, but legitimate third-party mail also exists. Urgent payment language alone does not establish fraud."),
        ("Authentication has a limited meaning", "SPF concerns permitted sending infrastructure; DKIM checks a signature; DMARC evaluates alignment with the visible sender domain. Results copied into an uploaded message are untrusted unless their provenance supports them. Passing authentication does not prove that a message is honest or that an account has not been compromised."),
        ("Handle messages carefully", "Only submit material you are authorized to inspect, preferably with unnecessary personal information removed. Links and extracted QR destinations are checked through the same bounded URL workflow. Attachment inspection is not permission to execute a file. Unsupported or failed checks remain unknown. Verify unusual payment or account requests through a separate trusted channel."))),
    "/guides/media-analysis": Page("OCR, QR & Content Credentials Limits — SecureSight", "Learn what text extraction, QR destinations, image forensics and C2PA Content Credentials can reveal without proving image authenticity.", "Understanding media and provenance evidence", (
        ("Extract evidence without assuming authenticity", "SecureSight inspects supported images for text, QR destinations, metadata and measured forensic properties. Extracted text is content to analyze, not an instruction to trust. QR links can be ordinary navigation or a threat destination; the image alone does not settle that question."),
        ("Content Credentials are provenance context", "C2PA validation can supply information about a signed manifest and its trust status. Presence does not prove that a depicted event is true; absence does not prove fabrication. Metadata can be missing after an ordinary export, and compression can change measured image properties."),
        ("Synthetic-media judgments remain limited", "A validated deepfake model is currently unavailable in this implementation. Genuine compressed images and benign AI-generated media must not be labeled harmful just for their origin or missing metadata. Unsupported formats, invalid provenance and failed OCR are explicit states. A manipulated-media benchmark and reviewed labels are needed before making detection-accuracy claims."))),
    "/privacy": Page("Privacy & Data Handling — SecureSight", "Read how submitted material, authorized investigations, temporary jobs and external intelligence providers are handled in SecureSight.", "Privacy and data handling", (
        ("Submit only authorized material", "URL, email and image inputs can contain sensitive data. Remove unnecessary personal information and do not submit passwords or access tokens. Public guide content and search metadata never contain scan inputs. No external engagement analytics tracker is installed by this SEO implementation."),
        ("Processing and saved investigations", "Email parsing handles original input for the request; this is not a promise that every processing buffer disappears instantly. Temporary job results can persist until their configured expiry. Authorized signed-in analysis can save derived investigation records, evidence and notes in an encrypted private store. Public anonymous scans are not saved by that investigation capture path. Retention of saved records is operator-managed; there is no automatic universal deletion deadline."),
        ("Providers, logs and deletion", "URL and domain intelligence may contact the submitted destination and configured external services; their policies also apply. Ordinary request logs use route/status diagnostics rather than raw private email content. Browser infrastructure, proxies, backups and operator systems require their own review. Request deletion through your deployment operator: an operator purge mechanism exists, while backups need separate handling. A public operator contact and deployment-specific retention policy must be supplied before public release."))),
    "/security": Page("Security Limits & Responsible Use — SecureSight", "Understand SecureSight's analysis limits, responsible-use boundaries and how to report incorrect results or security concerns.", "Security limits and responsible use", (
        ("Use evidence, not guarantees", "SecureSight is an academic threat-analysis project. Assessments reflect available evidence and can be wrong. Incomplete intelligence must not become a safe verdict. No independent certification, professional penetration-test claim or universal detection guarantee is made. Public deployment readiness requires further verification."),
        ("Keep analysis authorized", "Inspect only material you own or have permission to analyze. Do not use the service to test arbitrary targets destructively, execute suspicious attachments or submit victim credentials. Treat model signals and explanations as decision support; corroborate consequential decisions through trusted sources."),
        ("Report errors and concerns", "Send concerns privately to the operator using the contact channel provided with your deployment. Include an approximate time and request identifier if available; do not post raw emails, credentials or private investigation exports. A public contact address is not configured here and must be added by the operator before release. Related guides explain URL evidence, email authentication and media provenance."))),
}
bp = Blueprint("seo", __name__)


def enabled():
    return current_app.config["SEO_INDEXING_ENABLED"] and current_app.config["APP_ENV"] == "production"


def metadata():
    if not has_request_context():
        return {"page": None, "canonical": None, "indexable": False, "social_image": None, "schema": None}
    page = PAGES.get(request.path)
    public = page is not None and request.method == "GET"
    origin = current_app.config["SITE_URL"].rstrip("/")
    canonical = origin + request.path if public and enabled() else None
    indexable = bool(canonical and request.routing_exception is None and request.host_url.rstrip("/") == origin)
    return {"page": page, "canonical": canonical, "indexable": indexable,
            "social_image": origin + "/static/seo-social.png" if canonical else None,
            "schema": {"@context": "https://schema.org", "@type": "WebSite", "name": "SecureSight", "url": origin + "/", "inLanguage": "en"} if canonical and request.path == "/" else None}


def install(app):
    flag = app.config.get("SEO_INDEXING_ENABLED", os.getenv("SEO_INDEXING_ENABLED", "false").lower() == "true")
    if type(flag) is not bool:
        raise ValueError("SEO_INDEXING_ENABLED must be boolean")
    app.config["SEO_INDEXING_ENABLED"] = flag
    if flag:
        from .security.urls import validate_url, InvalidURL
        origin = urlsplit(app.config["SITE_URL"])
        if origin.scheme != "https" or origin.hostname in {"localhost", "127.0.0.1", "::1"} or origin.port not in {None, 443}:
            raise ValueError("Indexing requires an explicit HTTPS production origin")
        try:
            normalized = urlsplit(validate_url(app.config["SITE_URL"]))
        except InvalidURL as error:
            raise ValueError("Indexing requires a public origin") from error
        host = normalized.hostname
        if host not in app.config["TRUSTED_HOSTS"]:
            raise ValueError("Canonical hostname must be explicitly trusted")
        app.config["SITE_URL"] = "https://" + (f"[{host}]" if ":" in host else host)
    app.register_blueprint(bp)
    app.context_processor(lambda: {"seo": metadata()})

    @app.before_request
    def canonical_redirect():
        # Never redirect submissions, private routes or unknown hosts to another origin.
        if enabled() and request.method == "GET":
            path = request.path.rstrip("/") or "/"
            if path in PAGES and (request.path != path or request.host_url.rstrip("/") != app.config["SITE_URL"]):
                return redirect(app.config["SITE_URL"] + path, code=308)

    @app.after_request
    def indexation(response):
        if not (metadata()["indexable"] and response.status_code == 200):
            response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response


@bp.get("/guides/<slug>")
@bp.get("/privacy")
@bp.get("/security")
def public_page(slug=None):
    from flask import abort
    if request.path not in PAGES:
        abort(404)
    return render_template("public_info.html", page=PAGES[request.path], pages=PAGES)


def robots():
    body = "User-agent: *\nAllow: /\n" if enabled() else "User-agent: *\nDisallow: /\n"
    if enabled():
        body += "\nSitemap: " + current_app.config["SITE_URL"] + "/sitemap.xml\n"
    return Response(body, mimetype="text/plain")


def sitemap():
    origin = current_app.config["SITE_URL"]
    entries = "".join("<url><loc>" + escape(origin + path) + "</loc></url>" for path in PAGES) if enabled() else ""
    return Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + entries + "</urlset>", mimetype="application/xml")
