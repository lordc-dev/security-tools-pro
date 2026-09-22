import sqlite3
import json
import time
import os
import threading
from pathlib import Path
from threading import Lock

CACHE_DIR = Path.home() / ".cache" / "security-tools-pro"
CACHE_DB = CACHE_DIR / "cache.db"

_defaults = {
    "cwe_csv_ttl": 86400,
    "nvd_ttl": 3600,
    "epss_ttl": 21600,
    "kev_ttl": 43200,
    "ghsa_ttl": 3600,
    "osv_ttl": 3600,
    "exploit_ttl": 7200,
}

_lock = Lock()

_rate_lock = threading.Lock()
_rate_tracker: dict[str, list[float]] = {}
_rate_limits: dict[str, tuple[int, float]] = {
    "nvd": (5, 30.0),
    "epss": (10, 1.0),
    "ghsa": (8, 1.0),
    "osv": (10, 1.0),
    "exploit": (6, 1.0),
    "default": (10, 1.0),
}


def _apply_rate_limit(bucket: str) -> bool:
    """Check rate limit. Returns True if allowed, False if over limit (non-blocking)."""
    with _rate_lock:
        now = time.monotonic()
        if bucket not in _rate_tracker:
            _rate_tracker[bucket] = []
        max_calls, window = _rate_limits.get(bucket, _rate_limits["default"])
        _rate_tracker[bucket] = [t for t in _rate_tracker[bucket] if now - t < window]
        if len(_rate_tracker[bucket]) >= max_calls:
            return False
        _rate_tracker[bucket].append(now)
        return True


def rate_limit(bucket: str = "default") -> bool:
    """Check rate limit before an API call. Returns True if allowed, False if over limit."""
    return _apply_rate_limit(bucket)


def set_rate_limit(bucket: str, max_calls: int, window: float) -> None:
    """Update rate limit for a bucket at runtime."""
    with _rate_lock:
        _rate_limits[bucket] = (max_calls, window)


_conn: sqlite3.Connection | None = None
_write_count = 0
_CLEANUP_EVERY = 100  # run expired-row cleanup every N writes

_stats_lock = threading.Lock()
_stats = {"hits": 0, "misses": 0, "expired": 0, "writes": 0}


def get_stats() -> dict:
    """Cache hit/miss counters for observability."""
    with _stats_lock:
        s = dict(_stats)
    total = s["hits"] + s["misses"]
    s["hit_rate"] = round(s["hits"] / total, 3) if total else 0.0
    return s


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(CACHE_DB), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        conn.commit()
        try:
            os.chmod(str(CACHE_DB), 0o600)
        except OSError:
            pass
        _conn = conn
    return _conn


def _maybe_cleanup(conn: sqlite3.Connection) -> None:
    global _write_count
    _write_count += 1
    if _write_count >= _CLEANUP_EVERY:
        _write_count = 0
        conn.execute("DELETE FROM kv WHERE expires_at < ?", (time.time(),))
        conn.commit()


def get(key: str) -> str | None:
    with _lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT value, expires_at FROM kv WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            with _stats_lock:
                _stats["misses"] += 1
            return None
        if time.time() > row[1]:
            conn.execute("DELETE FROM kv WHERE key = ?", (key,))
            conn.commit()
            with _stats_lock:
                _stats["expired"] += 1
            return None
        with _stats_lock:
            _stats["hits"] += 1
        return row[0]


def set(key: str, value: str, ttl: float | None = None) -> None:
    if ttl is None:
        ttl = _defaults.get(key.split(":")[0] + "_ttl", 3600)
    with _lock:
        conn = _get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO kv (key, value, expires_at) VALUES (?, ?, ?)",
            (key, value, time.time() + ttl),
        )
        conn.commit()
        with _stats_lock:
            _stats["writes"] += 1
        _maybe_cleanup(conn)


def get_json(key: str) -> dict | list | None:
    raw = get(key)
    if raw is None:
        return None
    return json.loads(raw)


def set_json(key: str, value: dict | list, ttl: float | None = None) -> None:
    set(key, json.dumps(value, ensure_ascii=False), ttl)


def get_config(key: str, default: str | None = None) -> str | None:
    with _lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT value FROM config WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else default


def set_config(key: str, value: str) -> None:
    with _lock:
        conn = _get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            (key, value),
        )
        conn.commit()


def cleanup() -> int:
    with _lock:
        conn = _get_conn()
        cur = conn.execute(
            "DELETE FROM kv WHERE expires_at < ?", (time.time(),)
        )
        conn.commit()
        return cur.rowcount