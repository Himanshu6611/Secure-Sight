"""Tenant-indexed encrypted SQLite records and a keyed audit chain."""
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

ROLES = {"ADMIN", "ANALYST", "VIEWER", "API_CLIENT"}
STATUSES = {"NEW", "IN_REVIEW", "ESCALATED", "CONFIRMED", "CLOSED", "FALSE_POSITIVE"}
LABELS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "TRUE_NEGATIVE", "FALSE_NEGATIVE", "UNKNOWN"}


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path, key):
        self.lock = threading.RLock()
        self.analytics_cache = {}
        self.crypto = Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))
        self.audit_key = hashlib.sha256((key + ":audit-v12").encode()).digest()
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,token_hash TEXT UNIQUE);
        CREATE TABLE IF NOT EXISTS investigations(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,entity_type TEXT NOT NULL,verdict TEXT NOT NULL,severity TEXT,status TEXT NOT NULL,risk REAL,confidence REAL,subject BLOB NOT NULL,data BLOB NOT NULL);
        CREATE INDEX IF NOT EXISTS inv_scope_time ON investigations(tenant,created_at DESC);
        CREATE INDEX IF NOT EXISTS inv_scope_page ON investigations(tenant,created_at DESC,id);
        CREATE INDEX IF NOT EXISTS inv_scope_verdict ON investigations(tenant,verdict,status,entity_type);
        CREATE TABLE IF NOT EXISTS entities(tenant TEXT NOT NULL,investigation TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,kind TEXT NOT NULL,term TEXT NOT NULL,value BLOB NOT NULL);
        CREATE INDEX IF NOT EXISTS entity_search ON entities(tenant,term,kind);
        CREATE TABLE IF NOT EXISTS telemetry(investigation TEXT PRIMARY KEY REFERENCES investigations(id) ON DELETE CASCADE,tenant TEXT NOT NULL,data BLOB NOT NULL);
        CREATE INDEX IF NOT EXISTS telemetry_scope ON telemetry(tenant);
        CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,data BLOB NOT NULL);
        CREATE INDEX IF NOT EXISTS case_scope ON cases(tenant,created_at DESC);
        CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,event TEXT NOT NULL,previous TEXT NOT NULL,signature TEXT NOT NULL);
        """)
        # Backfill presentation search metadata for existing encrypted snapshots.
        with self.transaction():
            rows = self.db.execute("SELECT i.id,i.tenant,i.data FROM investigations i WHERE NOT EXISTS (SELECT 1 FROM entities e WHERE e.investigation=i.id AND e.kind='SOURCE')").fetchall()
            for row in rows:
                record = self.decrypt(row["data"])
                values = {(kind, e[key]) for e in record.get("evidence", []) for kind, key in (("SOURCE", "source"), ("EVIDENCE_TYPE", "evidence_type")) if isinstance(e.get(key), str)}
                for kind, value in values:
                    self.db.execute("INSERT INTO entities VALUES(?,?,?,?,?)", (row["tenant"], row["id"], kind, self.term(value), self.encrypt(value)))

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def encrypt(self, value):
        return self.crypto.encrypt(json.dumps(value, ensure_ascii=True, allow_nan=False).encode())

    def decrypt(self, value):
        return json.loads(self.crypto.decrypt(value))

    def term(self, value):
        return hmac.new(self.audit_key, str(value).casefold().encode(), hashlib.sha256).hexdigest()

    def audit(self, principal, action, target=None):
        previous = self.db.execute("SELECT signature FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous = previous[0] if previous else "0" * 64
        event = json.dumps({"at": now(), "actor": principal["id"], "tenant": principal["tenant"], "action": action, "target": target}, sort_keys=True)
        signature = hmac.new(self.audit_key, (previous + event).encode(), hashlib.sha256).hexdigest()
        self.db.execute("INSERT INTO audit(tenant,event,previous,signature) VALUES(?,?,?,?)", (principal["tenant"], event, previous, signature))

    def verify_audit(self):
        with self.lock:
            previous = "0" * 64
            for row in self.db.execute("SELECT * FROM audit ORDER BY seq"):
                expected = hmac.new(self.audit_key, (previous + row["event"]).encode(), hashlib.sha256).hexdigest()
                if row["previous"] != previous or not hmac.compare_digest(row["signature"], expected):
                    return False
                previous = row["signature"]
            return True

    def provision(self, username, password, role, tenant):
        if role not in ROLES or not 3 <= len(username) <= 80 or not 12 <= len(password) <= 256 or not 1 <= len(tenant) <= 80:
            raise ValueError("Invalid account: use a valid role and a password of at least 12 characters.")
        identity = secrets.token_hex(16)
        token = secrets.token_urlsafe(32) if role == "API_CLIENT" else None
        with self.transaction():
            self.db.execute("INSERT INTO users(id,tenant,username,password,role,token_hash) VALUES(?,?,?,?,?,?)", (identity, tenant, username, generate_password_hash(password), role, self.term(token) if token else None))
            self.audit({"id": "OPERATOR_CLI", "tenant": tenant}, "ACCOUNT_PROVISIONED", identity)
        return token

    def user(self, identity):
        with self.lock:
            row = self.db.execute("SELECT id,tenant,username,role FROM users WHERE id=? AND active=1", (identity,)).fetchone()
            return dict(row) if row else None

    def login(self, username, password):
        with self.lock:
            row = self.db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
            # A fixed valid dummy hash prevents an obvious missing-account timing shortcut.
            valid = check_password_hash(row["password"] if row else self.dummy_hash, password)
            if not row or not valid or row["role"] == "API_CLIENT":
                return None
            return {k: row[k] for k in ("id", "tenant", "username", "role")}

    @property
    def dummy_hash(self):
        if not hasattr(self, "_dummy_hash"):
            self._dummy_hash = generate_password_hash(secrets.token_urlsafe(32))
        return self._dummy_hash

    def bearer(self, token):
        if not 32 <= len(token) <= 128:
            return None
        with self.lock:
            row = self.db.execute("SELECT id,tenant,username,role FROM users WHERE token_hash=? AND active=1 AND role='API_CLIENT'", (self.term(token),)).fetchone()
            return dict(row) if row else None

    def save(self, principal, record, entities):
        identity = record["investigation_id"]
        with self.transaction():
            if self.db.execute("SELECT count(*) FROM investigations WHERE tenant=?", (principal["tenant"],)).fetchone()[0] >= 2000:
                raise ValueError("INVESTIGATION_CAPACITY_LIMIT")
            s = record["summary"]
            self.db.execute("INSERT INTO investigations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (identity, principal["tenant"], principal["id"], record["created_at"], record["updated_at"], record["entity_type"], s["verdict"], s["severity"], s["status"], s["risk_score"], s["confidence"], self.encrypt(record["subject"]), self.encrypt(record)))
            for item in entities[:512]:
                self.db.execute("INSERT INTO entities VALUES(?,?,?,?,?)", (principal["tenant"], identity, item["type"], self.term(item["search"]), self.encrypt(item["value"])))
            self.db.execute("INSERT INTO telemetry VALUES(?,?,?)", (identity, principal["tenant"], self.encrypt(record.get("telemetry", {}))))
            self.audit(principal, "INVESTIGATION_RECORDED", identity)
            self.analytics_cache.clear()
        return identity

    def get(self, principal, identity, audit=True):
        with self.transaction() if audit else self.lock:
            row = self.db.execute("SELECT data FROM investigations WHERE tenant=? AND id=?", (principal["tenant"], identity)).fetchone()
            if not row:
                return None
            value = self.decrypt(row[0])
            if audit:
                self.audit(principal, "INVESTIGATION_OPENED", identity)
            return value

    def listing(self, principal, filters, limit=25, offset=0):
        # Static SQL; every request value is bound, including pagination/search.
        where = """ FROM investigations WHERE tenant=:tenant
          AND (:verdict IS NULL OR verdict=:verdict) AND (:severity IS NULL OR severity=:severity)
          AND (:entity_type IS NULL OR entity_type=:entity_type) AND (:status IS NULL OR status=:status)
          AND (:since IS NULL OR created_at>=:since) AND (:until IS NULL OR created_at<=:until)
          AND (:confidence_min IS NULL OR confidence>=:confidence_min)
          AND (:q IS NULL OR id IN (SELECT investigation FROM entities WHERE tenant=:tenant AND term=:q))
          AND (:source IS NULL OR id IN (SELECT investigation FROM entities WHERE tenant=:tenant AND kind='SOURCE' AND term=:source))
          AND (:evidence_type IS NULL OR id IN (SELECT investigation FROM entities WHERE tenant=:tenant AND kind='EVIDENCE_TYPE' AND term=:evidence_type))
          AND (:brand IS NULL OR id IN (SELECT investigation FROM entities WHERE tenant=:tenant AND kind='BRAND' AND term=:brand))
          AND (:domain IS NULL OR id IN (SELECT investigation FROM entities WHERE tenant=:tenant AND kind='DOMAIN' AND term=:domain))"""
        query = "SELECT id,created_at,entity_type,verdict,severity,status,risk,confidence,subject" + where + " ORDER BY created_at DESC,id LIMIT :limit OFFSET :offset"
        args = {key: filters.get(key) for key in ("verdict", "severity", "entity_type", "status", "since", "until", "confidence_min")}
        args.update(tenant=principal["tenant"], q=self.term(filters["q"]) if filters.get("q") else None, limit=limit, offset=offset)
        args.update({key: self.term(filters[key]) if filters.get(key) else None for key in ("source", "evidence_type", "brand", "domain")})
        with self.lock:
            # A deferred read snapshot keeps count/page consistent across WAL writers.
            # SAVEPOINT also composes safely with an existing caller transaction.
            self.db.execute("SAVEPOINT listing_snapshot")
            try:
                count = self.db.execute("SELECT count(*)" + where, args).fetchone()[0]
                rows = self.db.execute(query, args).fetchall()
            finally:
                self.db.execute("RELEASE listing_snapshot")
            return {"total": count, "limit": limit, "offset": offset, "items": [{**{k: row[k] for k in row.keys() if k not in {"subject", "total"}}, "subject": self.decrypt(row["subject"])} for row in rows]}

    def entities(self, principal, query, limit, offset):
        with self.lock:
            rows = self.db.execute("SELECT investigation,kind,value FROM entities WHERE tenant=? AND term=? ORDER BY investigation LIMIT ? OFFSET ?", (principal["tenant"], self.term(query), limit, offset)).fetchall()
            return [{"investigation_id": row[0], "entity_type": row[1], "value": self.decrypt(row[2])} for row in rows]

    def case_get(self, principal, identity):
        row = self.db.execute("SELECT data FROM cases WHERE id=? AND tenant=?", (identity, principal["tenant"])).fetchone()
        return self.decrypt(row[0]) if row else None

    def case_save(self, principal, data):
        self.db.execute("INSERT INTO cases VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at,data=excluded.data WHERE cases.tenant=excluded.tenant", (data["id"], principal["tenant"], data["created_at"], now(), self.encrypt(data)))

    def case_list(self, principal, limit, offset):
        with self.lock:
            rows = self.db.execute("SELECT data FROM cases WHERE tenant=? ORDER BY created_at DESC LIMIT ? OFFSET ?", (principal["tenant"], limit, offset)).fetchall()
            return [self.decrypt(row[0]) for row in rows]
