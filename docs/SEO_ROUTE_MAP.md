# Route indexation map

Approved registry: app/seo.py PAGES. Indexing requires explicit SEO_INDEXING_ENABLED=true, APP_ENV=production, validated public HTTPS SITE_URL and canonical hostname in TRUSTED_HOSTS. Default false keeps local/staging safe.

| Route | Production policy | Purpose |
|---|---|---|
| / | GET 200 indexable at canonical origin only | SecureSight |
| /guides/url-analysis | GET 200 indexable at canonical origin only | Understanding URL threat evidence |
| /guides/email-analysis | GET 200 indexable at canonical origin only | Understanding email threat evidence |
| /guides/media-analysis | GET 200 indexable at canonical origin only | Understanding media and provenance evidence |
| /privacy | GET 200 indexable at canonical origin only | Privacy and data handling |
| /security | GET 200 indexable at canonical origin only | Security limits and responsible use |
| POST / | noindex + no-store | Submitted scan state, no canonical/schema |
| /dashboard and login | Existing auth + noindex/no-store | Private UI |
| /api/* and exports/cases/jobs | Existing auth/authorization where required + noindex/no-store | Scan APIs and private records |
| Errors/unknown routes/redirects | noindex; real status codes | No soft 404 or invented equivalent |
| /static/* | Crawlable in production; not sitemap pages | Render assets |
| robots/sitemap | Discovery only, not access control | Empty sitemap when indexing disabled |

No private/user-specific URLs included. Public registry metadata does not read scan inputs. Production robots allows crawl rather than preventing observation of noindex; confidentiality relies on existing server-side authorization. Staging robots disallows all plus site-wide noindex; staging must also have deployment-level access protection if confidential. An opt-in flag is a conservative control, not automatic knowledge of all future preview domains.
