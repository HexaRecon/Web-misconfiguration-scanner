"""SQLite persistence helpers; each operation uses its own short-lived connection."""

import sqlite3
from datetime import datetime, timezone

from config import DATABASE_PATH


def _connect():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_db():
    with _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER NOT NULL DEFAULT 0,
                current_step TEXT NOT NULL DEFAULT 'Queued',
                started_at TEXT NOT NULL,
                finished_at TEXT,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                target_url TEXT NOT NULL,
                detection_method TEXT NOT NULL,
                http_status INTEGER,
                evidence TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                remediation TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
            """
        )


def create_scan(target_url):
    with _connect() as connection:
        cursor = connection.execute(
            "INSERT INTO scans (target_url, status, started_at) VALUES (?, 'queued', ?)",
            (target_url, _now()),
        )
        return cursor.lastrowid


def update_scan(scan_id, *, status=None, progress=None, current_step=None, finished=False, error=None):
    updates = []
    values = []
    for column, value in (
        ("status", status),
        ("progress", progress),
        ("current_step", current_step),
        ("error", error),
    ):
        if value is not None:
            updates.append(f"{column} = ?")
            values.append(value)
    if finished:
        updates.append("finished_at = ?")
        values.append(_now())
    if not updates:
        return
    values.append(scan_id)
    with _connect() as connection:
        connection.execute(f"UPDATE scans SET {', '.join(updates)} WHERE id = ?", values)


def add_findings(scan_id, findings):
    if not findings:
        return
    rows = [
        (
            scan_id,
            item["title"],
            item["target_url"],
            item["detection_method"],
            item.get("http_status"),
            item["evidence"],
            item["severity"],
            item["description"],
            item["remediation"],
        )
        for item in findings
    ]
    with _connect() as connection:
        connection.executemany(
            """
            INSERT INTO findings
                (scan_id, title, target_url, detection_method, http_status,
                 evidence, severity, description, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def get_scan(scan_id):
    with _connect() as connection:
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        scan = dict(row)
        scan["findings"] = [
            dict(item)
            for item in connection.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
            )
        ]
        return scan


def list_scans(limit=100):
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT s.*, COUNT(f.id) AS finding_count
            FROM scans s LEFT JOIN findings f ON f.scan_id = s.id
            GROUP BY s.id ORDER BY s.id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
