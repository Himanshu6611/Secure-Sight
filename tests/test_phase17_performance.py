"""Deterministic query work/transaction/cache invariants, no timing assertions."""
import sqlite3
import pytest
from app.dashboard.store import Store
from app.dashboard.service import capture, analytics
from tests.test_phase12_dashboard import accounts, saved, url_result, authenticate


def test_pagination_plan_avoids_full_result_sort(app, accounts, saved):
    store = app.extensions["dashboard_store"]
    trace = []
    store.db.set_trace_callback(trace.append)
    try:
        page = store.listing(accounts["analyst"], {}, limit=1)
    finally:
        store.db.set_trace_callback(None)
    queries = [q for q in trace if q.startswith("SELECT")]
    assert len(queries) == 2 and "count(*)" in queries[0] and "OVER()" not in " ".join(queries)
    plan = [r[3] for r in store.db.execute("EXPLAIN QUERY PLAN " + queries[1])]
    assert any("inv_scope_page" in line for line in plan)
    assert not any("TEMP B-TREE" in line for line in plan)
    assert page["total"] == 1 and page["items"][0]["id"] == saved
    assert not store.db.in_transaction
    assert store.listing(accounts["analyst"], {}, offset=100)["total"] == 1
    assert store.listing(accounts["other"], {})["total"] == 0


def test_read_savepoint_never_commits_outer_writes(app, accounts, saved):
    store = app.extensions["dashboard_store"]
    account = accounts["analyst"]
    with pytest.raises(ValueError, match="rollback marker"):
        with store.transaction():
            store.case_save(account, {"id": "temporary-case", "created_at": "2026-10-09T00:00:00Z"})
            assert store.listing(account, {})["total"] == 1
            assert store.db.in_transaction
            raise ValueError("rollback marker")
    assert store.case_get(account, "temporary-case") is None
    assert not store.db.in_transaction


def test_count_and_page_share_snapshot_with_external_wal_writer(tmp_path):
    store = Store(str(tmp_path / "generated.sqlite3"), "synthetic-performance-key")
    account = {"id": "actor", "tenant": "fixture", "role": "ANALYST"}
    record = {"investigation_id": "a" * 32, "created_at": "2026-10-09T00:00:00Z", "updated_at": "2026-10-09T00:00:00Z", "entity_type": "URL", "subject": "synthetic", "summary": {"verdict": "UNKNOWN", "severity": "LOW", "status": "PARTIAL", "risk_score": 0, "confidence": 0}}
    store.save(account, record, [])
    original = list(store.db.execute("SELECT * FROM investigations").fetchone())
    writer = sqlite3.connect(tmp_path / "generated.sqlite3")
    inserted = []
    def interleave(sql):
        if sql.startswith("SELECT id,created_at") and not inserted:
            inserted.append(True)
            row = original.copy(); row[0] = "b" * 32
            writer.execute("INSERT INTO investigations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
            writer.commit()
    store.db.set_trace_callback(interleave)
    try:
        page = store.listing(account, {})
    finally:
        store.db.set_trace_callback(None)
        writer.close()
    assert inserted and page["total"] == len(page["items"]) == 1
    assert store.listing(account, {})["total"] == 2
    store.db.close()


def test_existing_analytics_cache_is_scoped_copied_and_invalidated(app, accounts, saved, url_result):
    store = app.extensions["dashboard_store"]
    with app.app_context():
        initial = analytics(store, accounts["analyst"])
        initial["total_scans"] = -1
        assert analytics(store, accounts["analyst"])["total_scans"] == 1
        assert analytics(store, accounts["other"])["total_scans"] == 0
        capture(url_result, "URL", accounts["analyst"])
        assert analytics(store, accounts["analyst"])["total_scans"] == 2


def test_optimized_pagination_preserves_filters_and_private_headers(client, accounts, saved):
    authenticate(client, accounts["analyst"])
    for suffix, expected in [("?offset=100", 1), ("?verdict=UNKNOWN", 0), ("?q=missing.example", 0)]:
        response = client.get("/api/v1/investigations" + suffix)
        assert response.status_code == 200 and response.json["total"] == expected
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Robots-Tag"] == "noindex, nofollow"
