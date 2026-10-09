"""Flask application factory."""
from flask import Flask
from dotenv import load_dotenv
from .core.config import configure
from .core.observability import configure_logging


def create_app(config=None):
    # Scanner children must not read service secrets or initialize private data.
    analysis_worker = bool(config and config.get("ANALYSIS_WORKER"))
    if not analysis_worker:
        load_dotenv()
    app = Flask(__name__, static_folder="static", template_folder="templates")
    from .security.json_policy import StrictJSONProvider
    app.json = StrictJSONProvider(app)
    configure(app, config)
    app.json.compact = True
    configure_logging(app)
    from .behavior.config import load_config as load_behavior_config
    from .behavior.evidence import load_reasons
    app.extensions["behavior_config"] = load_behavior_config()
    load_reasons()
    from .brand.config import load_config as load_brand_config, load_registry as load_brand_registry
    app.extensions["brand_config"] = load_brand_config()
    app.extensions["brand_registry"] = load_brand_registry()
    from .risk.engine import RiskScoringEngine
    app.extensions["risk_engine"] = RiskScoringEngine()
    from .explanations.engine import ExplanationEngine
    app.extensions["explanation_engine"] = ExplanationEngine()
    from .email.jobs import EmailJobs
    app.extensions["email_jobs"] = EmailJobs(app)
    from .middleware import install
    install(app)
    from .dashboard.setup import install as install_dashboard
    if not analysis_worker:
        install_dashboard(app)
    from .services.scans import load_models
    load_models(app)
    from .routes import bp
    from .api.v1 import bp as api
    app.register_blueprint(bp)
    app.register_blueprint(api)
    from .middleware import install_scan_capacity
    install_scan_capacity(app)

    @app.context_processor
    def template_config():
        return {"site_url": app.config["SITE_URL"]}

    from .seo import install as install_seo
    install_seo(app)

    app.logger.info("application_started")
    return app
