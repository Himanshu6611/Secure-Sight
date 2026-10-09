"""Indexing opt-in, private-route isolation and canonical public metadata contracts."""
import json
from bs4 import BeautifulSoup
from defusedxml import ElementTree as ET
from PIL import Image
from pathlib import Path
import pytest
from app.seo import PAGES, install


def production(app):
    # Isolated request-policy tests, not a simulated complete production deployment.
    app.config.update(APP_ENV="production", SEO_INDEXING_ENABLED=True, SITE_URL="https://example.com", TRUSTED_HOSTS=["example.com", "www.example.com"])


@pytest.mark.parametrize("path", list(PAGES))
def test_development_never_advertises_indexing(client, path):
    response = client.get(path)
    soup = BeautifulSoup(response.data, "html.parser")
    assert response.status_code == 200
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow"
    assert soup.find("meta", attrs={"name": "robots"})["content"] == "noindex, nofollow"
    assert soup.find("link", rel="canonical") is None


def test_canonical_sitemap_matches_unique_public_pages(client, app):
    production(app)
    response = client.get("/sitemap.xml", base_url="https://example.com")
    urls = [e.text for e in ET.fromstring(response.data).iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]
    assert urls == ["https://example.com" + path for path in PAGES]
    assert b"lastmod" not in response.data and b"priority" not in response.data
    titles, descriptions = set(), set()
    for url in urls:
        page = client.get(url)
        assert page.status_code == 200 and "X-Robots-Tag" not in page.headers
        soup = BeautifulSoup(page.data, "html.parser")
        assert len(soup.find_all("title")) == 1 and len(soup.find_all("link", rel="canonical")) == 1
        assert soup.find("link", rel="canonical")["href"] == url
        description = soup.find_all("meta", attrs={"name": "description"})
        assert len(description) == 1
        assert soup.title.text not in titles and description[0]["content"] not in descriptions
        titles.add(soup.title.text); descriptions.add(description[0]["content"])
        assert soup.find("meta", property="og:url")["content"] == url
        assert soup.find("meta", property="og:image")["content"] == "https://example.com/static/seo-social.png"
        assert len(soup.find_all("h1")) == 1
        for tag in soup.find_all("script", type="application/ld+json"):
            schema = json.loads(tag.text)
            assert schema["@type"] == "WebSite" and schema["name"] == "SecureSight"
            assert tag.get("nonce") and schema["url"] == "https://example.com/"
    robots = client.get("/robots.txt", base_url="https://example.com").text
    assert "Allow: /" in robots and "Disallow: /api/" not in robots
    assert "Sitemap: https://example.com/sitemap.xml" in robots


@pytest.mark.parametrize("path", ["/dashboard", "/dashboard/login", "/api/v1/investigations", "/missing", "/guides/missing"])
def test_private_and_error_routes_not_indexable(client, app, path):
    production(app)
    response = client.get(path, base_url="https://example.com")
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow"


@pytest.mark.parametrize("path", ["/", "/guides/url-analysis/", "/privacy/"])
def test_one_hop_canonical_origin_and_slash(client, app, path):
    production(app)
    response = client.get(path, base_url="http://www.example.com")
    assert response.status_code == 308
    assert response.headers["Location"] == "https://example.com" + (path.rstrip("/") or "/")
    assert client.get(response.headers["Location"]).status_code == 200


def test_query_canonical_and_post_privacy(client, app):
    production(app)
    response = client.get("/?utm_source=harmless", base_url="https://example.com")
    soup = BeautifulSoup(response.data, "html.parser")
    assert soup.find("link", rel="canonical")["href"] == "https://example.com/"
    response = client.post("/", data={"check_type": "invalid"}, base_url="https://example.com")
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow"
    assert response.status_code == 405


def test_brand_social_asset_and_no_tracker(client):
    response = client.get("/static/seo-social.png")
    assert response.status_code == 200
    with Image.open(Path("app/static/seo-social.png")) as image:
        assert image.size == (1200, 630)
    soup = BeautifulSoup(client.get("/privacy").data, "html.parser")
    assert not soup.find_all("script")
    assert "operator-managed" in soup.text


def test_untrusted_host_and_forwarded_headers_do_not_override_origin(client, app):
    production(app)
    bad = client.get("/", base_url="https://attacker.invalid")
    assert bad.status_code == 400 and bad.headers["X-Robots-Tag"] == "noindex, nofollow"
    response = client.get("/", base_url="https://example.com", headers={"X-Forwarded-Host": "attacker.invalid", "X-Forwarded-Proto": "http"})
    assert response.status_code == 200
    assert BeautifulSoup(response.data, "html.parser").find("link", rel="canonical")["href"] == "https://example.com/"


def test_unsafe_indexing_configuration_rejected(app):
    app.config.update(SEO_INDEXING_ENABLED=True, SITE_URL="http://localhost:5000")
    with pytest.raises(ValueError, match="HTTPS"):
        install(app)
