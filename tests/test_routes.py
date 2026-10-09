def test_home_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"SecureSight" in response.data or b"Secure Sight" in response.data
    assert b'id="root"' in response.data
    assert b"api-docs" not in response.data
    assert b"cdn.jsdelivr.net" not in response.data
    assert b"ui/app.js" in response.data and b"ui/style.css" in response.data
    assert b"Check a link, email or image before you trust" in response.data
    assert b".app-shell" in client.get("/static/ui/style.css").data
    assert client.get("/static/ui/app.js").status_code == 200


def test_legacy_html_scan_post_removed(client):
    assert client.post("/", data={"check_type": "url", "url": "https://example.com"}).status_code == 405

def test_url_analysis_post(client):
    response = client.post("/api/v1/scan", json={"url": "http://malicious-site.com"})
    assert response.status_code == 200
    assert "assessment" in response.json

def test_email_analysis_post(client):
    response = client.post("/api/v1/email/analyze", json={"raw_email": "Subject: hello\\n\\nHey, this is a normal email."})
    assert response.status_code == 202
    assert response.json["job_id"]

def test_robots_txt(client):
    response = client.get("/robots.txt")
    assert response.status_code == 200
    assert b"User-agent: *" in response.data
    assert b"Disallow: /" in response.data
    assert b"Sitemap:" not in response.data

def test_sitemap_xml(client):
    response = client.get("/sitemap.xml")
    assert response.status_code == 200
    assert response.mimetype == "application/xml"
    assert b"<loc>" not in response.data

def test_favicon(client):
    response = client.get("/favicon.ico")
    assert response.status_code == 200

def test_api_analyze_noindex(client):
    response = client.post("/api/analyze", json={"url": "http://example.com"})
    assert response.status_code == 200
    assert response.headers.get("X-Robots-Tag") == "noindex, nofollow"

def test_api_analyze_missing_url(client):
    response = client.post("/api/analyze", json={})
    assert response.status_code == 400
    assert b"No URL provided" in response.data

def test_image_analysis_post_no_file(client):
    response = client.post("/api/v1/media/analyze", data={})
    assert response.status_code == 415

