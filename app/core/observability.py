"""Structured events exclude request content and exception messages."""
import json
import logging
import traceback
from datetime import datetime, timezone
from flask import g, has_request_context


class JSONFormatter(logging.Formatter):
    def format(self, record):
        data = {"timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname, "event": record.getMessage()}
        if has_request_context():
            data["request_id"] = getattr(g, "request_id", None)
            principal = getattr(g, "dashboard_principal", None)
            if principal:
                data["actor_id"] = principal["id"]
                data["actor_role"] = principal["role"]
        for key in ("status", "duration_ms", "endpoint", "error_type", "assessment_version",
                    "scoring_config_version", "scoring_config_sha256", "risk_score", "confidence",
                    "verdict", "evidence_coverage", "signal_ids", "phase", "redirect_count", "unique_domains", "error_code"):
            if hasattr(record, key):
                data[key] = getattr(record, key)
        if record.exc_info:
            data["error_type"] = record.exc_info[0].__name__
            data["frames"] = [{"function": f.name, "line": f.lineno}
                              for f in traceback.extract_tb(record.exc_info[2])]
        return json.dumps(data)


def configure_logging(app):
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    app.logger.handlers = [handler]
    app.logger.propagate = False
    app.logger.setLevel(app.config["LOG_LEVEL"])
    service_logger = logging.getLogger("utils")
    service_logger.handlers = [handler]
    service_logger.propagate = False
    service_logger.setLevel(app.config["LOG_LEVEL"])
    # Werkzeug's INFO access records include raw paths/query strings.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
