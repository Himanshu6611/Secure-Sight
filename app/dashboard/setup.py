"""Configure opt-in production persistence and operator-provisioned accounts."""
import os
import secrets
from pathlib import Path
import click
from flask import g
from .store import Store
from .auth import load_principal, csrf


def install(app):
    path = app.config.get("DASHBOARD_DB_PATH") or os.getenv("DASHBOARD_DB_PATH")
    key = app.config.get("DASHBOARD_ENCRYPTION_KEY") or os.getenv("DASHBOARD_ENCRYPTION_KEY")
    if app.config["APP_ENV"] == "testing":
        path, key = path or ":memory:", key or secrets.token_urlsafe(48)
    elif app.config["APP_ENV"] == "production":
        # Existing production scans remain available; private dashboard fails closed until provisioned.
        if not path or not key or len(key) < 32:
            app.extensions["dashboard_store"] = None
            app.logger.warning("dashboard_disabled_configuration_missing")
            return
    else:
        path = path or str(Path(app.instance_path) / "dashboard.sqlite3")
        if not key:
            key_path = Path(app.instance_path) / "dashboard.key"
            key_path.parent.mkdir(parents=True, exist_ok=True)
            if not key_path.exists():
                with key_path.open("x", encoding="utf-8") as f:
                    f.write(secrets.token_urlsafe(48))
                os.chmod(key_path, 0o600)
            key = key_path.read_text(encoding="utf-8").strip()
    app.extensions["dashboard_store"] = Store(path, key)
    app.before_request(load_principal)

    @app.context_processor
    def dashboard_context():
        return {"dashboard_principal": getattr(g, "dashboard_principal", None), "dashboard_csrf": csrf}

    @app.cli.command("dashboard-user")
    @click.option("--username", required=True)
    @click.option("--tenant", required=True)
    @click.option("--role", type=click.Choice(["ADMIN", "ANALYST", "VIEWER", "API_CLIENT"]), default="ANALYST")
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def provision(username, tenant, role, password):
        """Create an account; privileges never come from submitted scan data."""
        token = app.extensions["dashboard_store"].provision(username, password, role, tenant)
        click.echo("Account created.")
        if token:
            click.echo("API bearer token (store securely; shown once): " + token)

    @app.cli.command("dashboard-audit-check")
    def audit_check():
        if not app.extensions["dashboard_store"].verify_audit():
            raise click.ClickException("TAMPERED: audit chain verification failed.")
        click.echo("VALID")

    @app.cli.command("dashboard-disable-user")
    @click.option("--username", required=True)
    def disable_user(username):
        """Revoke both live sessions and API credentials immediately."""
        store = app.extensions["dashboard_store"]
        with store.transaction():
            row = store.db.execute("SELECT id,tenant FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                raise click.ClickException("Account not found.")
            store.db.execute("UPDATE users SET active=0 WHERE id=?", (row["id"],))
            store.audit({"id": "OPERATOR_CLI", "tenant": row["tenant"]}, "ACCOUNT_DISABLED", row["id"])
        click.echo("Account disabled.")

    @app.cli.command("dashboard-purge")
    @click.option("--tenant", required=True)
    def purge(tenant):
        """Delete a tenant's private investigations/cases; retain content-free audit events."""
        store = app.extensions["dashboard_store"]
        with store.transaction():
            store.db.execute("DELETE FROM cases WHERE tenant=?", (tenant,))
            store.db.execute("DELETE FROM investigations WHERE tenant=?", (tenant,))
            store.audit({"id": "OPERATOR_CLI", "tenant": tenant}, "TENANT_CONTENT_PURGED")
            store.analytics_cache.clear()
        click.echo("Private tenant content purged. Securely manage encrypted backups separately.")

    from .routes import bp
    app.register_blueprint(bp)
    # Read-heavy private endpoints also receive bounded query rates.
    limiter = app.extensions["scan_limiter"]
    for endpoint in list(app.view_functions):
        if endpoint.startswith("dashboard."):
            rule = "10 per minute" if endpoint == "dashboard.login" else "120 per minute"
            app.view_functions[endpoint] = limiter.limit(rule)(app.view_functions[endpoint])

    @app.after_request
    def dashboard_headers(response):
        if app_request_private():
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response


def app_request_private():
    from flask import request
    return request.path.startswith("/dashboard")
