# React scanning workbench

The home page is a React 19 and TypeScript single-page workbench built with Vite. Flask serves its generated bundle from `app/static/ui`; the production Docker build compiles the same bundle in a pinned Node build stage and copies only the output into the Python runtime image.

The workbench offers three scans: website URL, email message, and image. Each uses the shared backend contract: `POST /api/v1/scan`, `POST /api/v1/email/analyze` plus its bearer-protected job poll, and `POST /api/v1/media/analyze`. The former HTML form scanner duplicated those workflows and used a separate legacy media utility; the root route is now a read-only React shell. Backend API routes remain available for the UI and authorized integrations. The old API promotion/documentation section has been removed from the homepage.

Magic UI's Blur Fade component adds a restrained entrance transition. A Watermelon registry Collapsible is used for optional evidence details; both components are local source files so the production browser does not depend on a component CDN. The scanner uses a single neutral workspace, three accessible tabs, one primary action, and a compact result with expandable evidence and uncertainty notes.

Build, lint, and audit the frontend with:

```powershell
cd web
npm ci
npm run build
npm run lint
npm audit --audit-level=high
```

The build writes the production bundle to `app/static/ui`. Run Flask afterwards to test the real integration. The quality runner executes these frontend checks, and `scripts/docker_smoke.ps1` verifies the built assets are served by an isolated container.

This UI migration does not claim improved detector accuracy. Risk weights, verdict thresholds, and confidence remain subject to the calibration limits in [RISK_CALIBRATION.md](RISK_CALIBRATION.md); changing them without representative full-pipeline labeled data would make the displayed metrics less trustworthy.
