"""Local SQLite persistence behind a small repository boundary."""

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")

DATABASE_URL = os.getenv("DATABASE_URL", "")
if DATABASE_URL.startswith("sqlite:///"):
    DATABASE_PATH = Path(DATABASE_URL.removeprefix("sqlite:///"))
    if not DATABASE_PATH.is_absolute():
        DATABASE_PATH = ROOT_DIR / DATABASE_PATH
else:
    DATABASE_PATH = Path(os.getenv("SQLITE_PATH", ROOT_DIR / "security_scans.db"))


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_db() -> None:
    """Create portable tables; persistence can be replaced without changing API routes."""
    with _connection() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS status_checks (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                client_name TEXT NOT NULL
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at)")


def save_scan(payload: dict) -> None:
    with _connection() as connection:
        connection.execute(
            "INSERT INTO scans (id, created_at, payload) VALUES (?, ?, ?)",
            (payload["id"], payload["created_at"], json.dumps(payload)),
        )


def list_scans(limit: int = 100) -> list[dict]:
    with _connection() as connection:
        rows = connection.execute(
            "SELECT payload FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


def get_scan(scan_id: str) -> dict | None:
    with _connection() as connection:
        row = connection.execute("SELECT payload FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


def save_status_check(payload: dict) -> None:
    with _connection() as connection:
        connection.execute(
            "INSERT INTO status_checks (id, timestamp, client_name) VALUES (?, ?, ?)",
            (payload["id"], payload["timestamp"], payload["client_name"]),
        )


def list_status_checks(limit: int = 1000) -> list[dict]:
    with _connection() as connection:
        rows = connection.execute(
            "SELECT id, timestamp, client_name FROM status_checks ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
