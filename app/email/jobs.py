"""Ephemeral bearer-protected jobs. No raw email or cross-user campaign store."""
import copy
import base64
import json
import hashlib
import hmac
import secrets
import threading
import time
from flask import current_app, g, has_request_context
from .parser import EmailError


class EmailJobs:
    def __init__(self, app=None):
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(2)
        self.records = {}
        self.dashboard_active = {}
        self.redis = self.crypto = None
        if app and app.config["APP_ENV"] == "production":
            import redis
            from cryptography.fernet import Fernet
            self.redis = redis.Redis.from_url(app.config["RATELIMIT_STORAGE_URI"], socket_connect_timeout=2, socket_timeout=2)
            self.crypto = Fernet(base64.urlsafe_b64encode(hashlib.sha256((app.config["SECRET_KEY"] + ":email-jobs-v11").encode()).digest()))

    def _get(self, job_id):
        if not self.redis:
            return self.records.get(job_id)
        blob = self.redis.get("{emailjobs}:result:" + job_id)
        if not blob or len(blob) > 3 * 1024 * 1024:
            return None
        try:
            return json.loads(self.crypto.decrypt(blob, ttl=600))
        except Exception:
            return None

    def _put(self, job_id, record, ttl):
        if not self.redis:
            self.records[job_id] = record
        else:
            raw = json.dumps(record, allow_nan=False).encode()
            if len(raw) > 2 * 1024 * 1024:
                raise EmailError("EMAIL_RESULT_RESOURCE_LIMIT", 503)
            self.redis.set("{emailjobs}:result:" + job_id, self.crypto.encrypt(raw), ex=ttl)
            self.redis.zadd("{emailjobs}:index", {job_id: time.time() + ttl})

    def _reserve(self, job_id):
        if not self.redis:
            return 0
        script = """
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
        if redis.call('ZCARD', KEYS[1]) >= 16 then return -1 end
        for i = 2, 3 do
            if redis.call('SET', KEYS[i], ARGV[2], 'NX', 'EX', 120) then
                redis.call('ZADD', KEYS[1], ARGV[3], ARGV[2])
                return i - 1
            end
        end
        return -1
        """
        return self.redis.eval(script, 3, "{emailjobs}:index", "{emailjobs}:slot:1", "{emailjobs}:slot:2", time.time(), job_id, time.time() + 600)

    def _release(self, job_id, lease):
        if self.redis and lease > 0:
            self.redis.eval("if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0", 1, "{emailjobs}:slot:" + str(lease), job_id)

    def _expire(self):
        if self.redis:
            return
        now = time.monotonic()
        for key in list(self.records):
            if self.records[key]["expires"] < now:
                del self.records[key]

    def submit(self, app, raw):
        principal = getattr(g, "dashboard_principal", None) if has_request_context() else None
        if not self.slots.acquire(blocking=False):
            raise EmailError("EMAIL_QUEUE_FULL", 503)
        job_id, token = secrets.token_hex(16), secrets.token_urlsafe(32)
        lease = 0
        try:
            with self.lock:
                self._expire()
                lease = self._reserve(job_id)
                if lease < 0 or not self.redis and len(self.records) >= 16:
                    raise EmailError("EMAIL_QUEUE_FULL", 503)
                self._put(job_id, {"token_hash": hashlib.sha256(token.encode()).hexdigest(), "state": "RECEIVED",
                    "expires": time.monotonic() + 600, "result": None}, 600)
        except Exception as exc:
            self.slots.release()
            try:
                self._release(job_id, lease)
            except Exception:
                app.logger.warning("email_job_lease_release_failed", extra={"phase": "11"})
            if isinstance(exc, EmailError):
                raise
            raise EmailError("EMAIL_JOB_STORE_UNAVAILABLE", 503) from None
        def progress(state):
            with self.lock:
                record = self._get(job_id)
                if record:
                    record["state"] = state
                    self._put(job_id, record, 600)
        def execute():
            from .service import analyze, analyze_batch
            try:
                with app.app_context():
                    result = analyze_batch(raw, progress=progress) if isinstance(raw, list) else analyze(raw, progress=progress)
                    if principal:
                        from app.dashboard.service import capture
                        identity = capture(result, "EMAIL", principal)
                        if identity:
                            result["investigation_id"] = identity
                state = result["analysis_status"]
            except Exception as exc:
                result = {"analysis_status": "FAILED", "risk": {"verdict": "UNKNOWN", "risk_score": None},
                          "error": {"code": exc.code if isinstance(exc, EmailError) else "EMAIL_ANALYSIS_FAILED"}}
                state = "FAILED"
                if principal:
                    with app.app_context():
                        from app.dashboard.service import capture
                        identity = capture(result, "EMAIL", principal)
                        if identity:
                            result["investigation_id"] = identity
            finally:
                with self.lock:
                    self.dashboard_active.pop(job_id, None)
                self.slots.release()
                try:
                    self._release(job_id, lease)
                except Exception:
                    app.logger.warning("email_job_lease_release_failed", extra={"phase": "11", "error_code": "EMAIL_JOB_STORE_UNAVAILABLE"})
            try:
                with self.lock:
                    record = self._get(job_id)
                    if record:
                        record.update(state=state, result=result, expires=time.monotonic() + 300)
                        if len(json.dumps(record, allow_nan=False).encode()) > 2 * 1024 * 1024:
                            record.update(state="FAILED", result={"analysis_status": "FAILED", "risk": {"verdict": "UNKNOWN", "risk_score": None}, "error": {"code": "EMAIL_RESULT_RESOURCE_LIMIT"}})
                        self._put(job_id, record, 300)
            except Exception:
                app.logger.warning("email_job_result_store_failed", extra={"phase": "11", "error_code": "EMAIL_JOB_STORE_UNAVAILABLE"})
        if principal:
            with self.lock:
                self.dashboard_active[job_id] = principal
        try:
            threading.Thread(target=execute, name="email-analysis", daemon=True).start()
        except Exception:
            with self.lock:
                self.dashboard_active.pop(job_id, None)
            self.slots.release()
            try:
                self._release(job_id, lease)
            except Exception:
                app.logger.warning("email_job_lease_release_failed", extra={"phase": "11"})
            raise EmailError("EMAIL_WORKER_UNAVAILABLE", 503) from None
        return {"job_id": job_id, "token": token, "state": "RECEIVED", "poll_url": "/api/v1/email/jobs/" + job_id,
                "expires_after_completion_seconds": 300}

    def read(self, job_id, token):
        if len(job_id) != 32 or any(c not in "0123456789abcdef" for c in job_id):
            return None
        with self.lock:
            self._expire()
            record = self._get(job_id)
            if not record or not hmac.compare_digest(record["token_hash"], hashlib.sha256(token.encode()).hexdigest()):
                return None
            return {"job_id": job_id, "state": record["state"], "result": copy.deepcopy(record["result"])}


def get_jobs():
    # Startup installs the store; each process is independent and bounded.
    return current_app.extensions["email_jobs"]
