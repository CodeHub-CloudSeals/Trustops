"""Write-through persistence of Store state: SQLite (dev), PostgreSQL via SQLAlchemy (Aurora / Cloud SQL), or one object in
Google Cloud Storage (`TAAD_STATE_GCS_URI=gs://bucket/state.json`, optimistic locking with `if_generation_match`).

This is a single-writer snapshot design (one `state` row, optimistic version check). It is durable and restart-safe,
but NOT horizontally scalable: run one API task until the normalised repository (db/migrations/002) replaces it.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Optional

from sqlalchemy import Column, Integer, MetaData, Table, Text, create_engine, select, update
from sqlalchemy.engine import URL, Engine

from .store import Store

TUPLE_KEYED = {"answers", "idempotency"}
FIELDS = ["users", "pending_users", "tenants", "assessments", "answers", "revisions", "evidence", "findings", "reports", "blueprints", "cases", "inventory",
          "idempotency", "registrations", "events", "audit", "invitations", "assignments", "engagements", "rate", "outbox",
          "not_assessed", "admin_bootstrap", "workflow_runs", "action_tokens", "runtime_evidence", "mock_sap",
          "integrations", "decisions", "policy_rules", "agents"]
META = MetaData()
STATE = Table("state", META, Column("id", Integer, primary_key=True), Column("version", Integer, nullable=False),
              Column("body", Text, nullable=False))


class PersistConflict(RuntimeError):
    """Another writer changed the state row; local state was reloaded and the request should be retried."""


STATUS: dict[str, Any] = {"last_save_at": None, "last_save_error": None, "saves": 0}   # surfaced by the service-health page
_engines: dict[str, Engine] = {}
_versions: dict[str, int] = {}


def url_from_env(sqlite_path: Optional[str] = None) -> Optional[str | URL]:
    if os.environ.get("TAAD_STATE_GCS_URI"):
        return os.environ["TAAD_STATE_GCS_URI"]
    if os.environ.get("TAAD_DB_HOST"):
        return URL.create("postgresql+psycopg", username=os.environ["TAAD_DB_USER"], password=os.environ["TAAD_DB_PASSWORD"],
                          host=os.environ["TAAD_DB_HOST"], database=os.environ.get("TAAD_DB_NAME", "taad"),
                          query={"sslmode": "require"})
    if os.environ.get("TAAD_DATABASE_URL"):
        return os.environ["TAAD_DATABASE_URL"]
    if sqlite_path:
        return f"sqlite:///{sqlite_path}"
    return None


def enabled() -> bool:
    return url_from_env(os.environ.get("TAAD_DB")) is not None


def _engine(target: str | URL) -> Engine:
    key = str(target)
    if key not in _engines:
        _engines[key] = create_engine(target, pool_pre_ping=True)
        META.create_all(_engines[key])
    return _engines[key]


def _enc(name: str, v: Any) -> Any:
    return [[list(k), val] for k, val in v.items()] if name in TUPLE_KEYED else v


def _dec(name: str, v: Any) -> Any:
    return {tuple(k): val for k, val in v} if name in TUPLE_KEYED else v


def _dump(store: Store) -> str:
    """Snapshot body. Fields written by another TrustOps version are carried through unchanged, never dropped."""
    with store.lock:
        body = dict(getattr(store, "_unknown_state", {}))
        body.update({f: _enc(f, getattr(store, f)) for f in FIELDS})
        return json.dumps(body, default=str)


def _apply(store: Store, body: str) -> None:
    data = json.loads(body)
    with store.lock:
        store._unknown_state = {f: v for f, v in data.items() if f not in FIELDS}
        for f, v in data.items():
            if f not in FIELDS:
                continue
            cur = getattr(store, f)
            cur.clear()
            dec = _dec(f, v)
            cur.update(dec) if isinstance(cur, dict) else cur.extend(dec)


# ---- Google Cloud Storage backend: the snapshot is a single object; its generation number is the version ----
_gcs_client: Any = None


def set_gcs_client(client: Any) -> None:  # tests
    global _gcs_client
    _gcs_client = client


def _is_gcs(target: Any) -> bool:
    return isinstance(target, str) and target.startswith("gs://")


def _gcs_parts(target: str) -> tuple[Any, str]:
    global _gcs_client
    if _gcs_client is None:
        from google.cloud import storage  # lazy: optional dependency
        _gcs_client = storage.Client()
    bucket, _, name = target[5:].partition("/")
    return _gcs_client.bucket(bucket), name or "state.json"


def _gcs_load(store: Store, target: str) -> bool:
    bucket, name = _gcs_parts(target)
    blob = bucket.get_blob(name)
    if blob is None:
        _versions[target] = 0
        return False
    body = blob.download_as_text()
    _versions[target] = blob.generation
    _apply(store, body)
    return True


def _gcs_save(store: Store, target: str) -> None:
    from google.api_core.exceptions import PreconditionFailed
    bucket, name = _gcs_parts(target)
    with store.lock:
        blob_text = _dump(store)
    blob = bucket.blob(name)
    try:
        blob.upload_from_string(blob_text, content_type="application/json", if_generation_match=_versions.get(target, 0))
    except PreconditionFailed:
        _gcs_load(store, target)
        raise PersistConflict("concurrent writer detected; state reloaded, retry the request") from None
    _versions[target] = blob.generation


def load(store: Store, target: Optional[str | URL] = None) -> bool:
    target = target or url_from_env(os.environ.get("TAAD_DB"))
    if target is None:
        return False
    if _is_gcs(target):
        return _gcs_load(store, str(target))
    eng = _engine(target)
    with eng.connect() as c:
        row = c.execute(select(STATE.c.version, STATE.c.body).where(STATE.c.id == 1)).first()
    if not row:
        _versions[str(target)] = 0
        return False
    _versions[str(target)] = row.version
    _apply(store, row.body)
    return True


def save(store: Store, target: Optional[str | URL] = None) -> None:
    try:
        _save(store, target)
    except PersistConflict:
        raise
    except Exception as exc:
        STATUS["last_save_error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
        raise
    else:
        STATUS.update(last_save_at=time.time(), last_save_error=None, saves=STATUS["saves"] + 1)


def _save(store: Store, target: Optional[str | URL] = None) -> None:
    target = target or url_from_env(os.environ.get("TAAD_DB"))
    if target is None:
        return
    if _is_gcs(target):
        return _gcs_save(store, str(target))
    eng, key = _engine(target), str(target)
    with store.lock:
        blob = _dump(store)
    expected = _versions.get(key, 0)
    with eng.begin() as c:
        if expected == 0:
            if c.execute(select(STATE.c.id).where(STATE.c.id == 1)).first():
                row = c.execute(select(STATE.c.version, STATE.c.body).where(STATE.c.id == 1)).first()
                _versions[key] = row.version
                _apply(store, row.body)
                raise PersistConflict("state row appeared concurrently; reloaded")
            c.execute(STATE.insert().values(id=1, version=1, body=blob))
            _versions[key] = 1
            return
        res = c.execute(update(STATE).where(STATE.c.id == 1, STATE.c.version == expected)
                        .values(version=expected + 1, body=blob))
        if res.rowcount != 1:
            row = c.execute(select(STATE.c.version, STATE.c.body).where(STATE.c.id == 1)).first()
            _versions[key] = row.version
            _apply(store, row.body)
            raise PersistConflict("concurrent writer detected; state reloaded, retry the request")
        _versions[key] = expected + 1
