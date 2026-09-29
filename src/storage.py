"""SQLite persistence and CSV exports.

Tables
------
scans      one row per scan run (settings and aggregate stats as JSON)
documents  one row per document: risk score, level, reason, masked subject/snippet
findings   one row per detected entity: type, confidence, MASKED value, position
skipped    files that could not be read, with the error
redactions redacted sample files produced for the scan

Only masked values are ever written. CSV exports go to output/exports/ for
Power BI / Excel.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from . import get_logger

log = get_logger("storage")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    source        TEXT NOT NULL,
    docs_scanned  INTEGER DEFAULT 0,
    docs_skipped  INTEGER DEFAULT 0,
    settings_json TEXT,
    stats_json    TEXT
);
CREATE TABLE IF NOT EXISTS documents (
    doc_id         TEXT NOT NULL,
    scan_id        INTEGER NOT NULL REFERENCES scans(scan_id),
    path           TEXT,
    file_type      TEXT,
    sender         TEXT,
    date           TEXT,
    subject        TEXT,
    risk_score     REAL,
    risk_level     TEXT,
    reason         TEXT,
    finding_count  INTEGER,
    char_count     INTEGER,
    truncated      INTEGER,
    toxic          INTEGER,
    entity_types   TEXT,
    masked_snippet TEXT,
    PRIMARY KEY (scan_id, doc_id)
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id      INTEGER NOT NULL,
    doc_id       TEXT NOT NULL,
    entity_type  TEXT NOT NULL,
    confidence   REAL,
    masked_value TEXT,
    "start"      INTEGER,
    "end"        INTEGER
);
CREATE TABLE IF NOT EXISTS skipped (
    scan_id INTEGER NOT NULL,
    path    TEXT,
    error   TEXT
);
CREATE TABLE IF NOT EXISTS redactions (
    scan_id       INTEGER NOT NULL,
    doc_id        TEXT,
    source        TEXT,
    redacted_path TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_doc ON findings(scan_id, doc_id);
CREATE INDEX IF NOT EXISTS idx_docs_level ON documents(scan_id, risk_level);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA)
    return conn


def create_scan(conn: sqlite3.Connection, started_at: str, source: str, settings: Dict[str, Any]) -> int:
    cur = conn.execute("INSERT INTO scans (started_at, source, settings_json) VALUES (?, ?, ?)",
                       (started_at, source, json.dumps(settings)))
    conn.commit()
    return int(cur.lastrowid)


def save_results(conn: sqlite3.Connection, scan_id: int, documents: List[Dict[str, Any]],
                 findings_by_doc: Dict[str, List[Dict[str, Any]]], skipped: List[Dict[str, str]]) -> None:
    """Bulk-insert documents, findings and skipped files for one scan."""
    conn.executemany(
        "INSERT INTO documents (doc_id, scan_id, path, file_type, sender, date, subject, risk_score, risk_level, "
        "reason, finding_count, char_count, truncated, toxic, entity_types, masked_snippet) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(d["doc_id"], scan_id, d["path"], d["file_type"], d["sender"], d["date"], d["subject"],
          d["risk_score"], d["risk_level"], d["reason"], d["finding_count"], d["char_count"],
          int(d["truncated"]), int(d["toxic"]), d["entity_types"], d["masked_snippet"]) for d in documents])
    conn.executemany(
        'INSERT INTO findings (scan_id, doc_id, entity_type, confidence, masked_value, "start", "end") '
        "VALUES (?,?,?,?,?,?,?)",
        [(scan_id, doc_id, f["entity_type"], f["confidence"], f["masked_value"], f["start"], f["end"])
         for doc_id, fs in findings_by_doc.items() for f in fs])
    conn.executemany("INSERT INTO skipped (scan_id, path, error) VALUES (?,?,?)",
                     [(scan_id, s["path"], s["error"]) for s in skipped])
    conn.commit()


def save_redactions(conn: sqlite3.Connection, scan_id: int, redactions: List[Dict[str, str]]) -> None:
    conn.executemany("INSERT INTO redactions (scan_id, doc_id, source, redacted_path) VALUES (?,?,?,?)",
                     [(scan_id, r["doc_id"], r["source"], r["redacted_path"]) for r in redactions])
    conn.commit()


def finish_scan(conn: sqlite3.Connection, scan_id: int, finished_at: str, docs_scanned: int,
                docs_skipped: int, stats: Dict[str, Any]) -> None:
    conn.execute("UPDATE scans SET finished_at=?, docs_scanned=?, docs_skipped=?, stats_json=? WHERE scan_id=?",
                 (finished_at, docs_scanned, docs_skipped, json.dumps(stats), scan_id))
    conn.commit()


def export_csvs(conn: sqlite3.Connection, scan_id: int, export_dir: Path,
                unique_by_type: Optional[Dict[str, int]] = None) -> Dict[str, Path]:
    """Write documents.csv, findings_summary.csv and entity_counts.csv for one scan."""
    export_dir.mkdir(parents=True, exist_ok=True)
    docs = pd.read_sql_query(
        "SELECT doc_id, scan_id, path, file_type, sender, date, subject, risk_score, risk_level, reason, "
        "finding_count, char_count, truncated, toxic, entity_types FROM documents WHERE scan_id=? "
        "ORDER BY risk_score DESC", conn, params=(scan_id,))
    summary = pd.read_sql_query(
        "SELECT f.doc_id, d.path, d.risk_level, f.entity_type, COUNT(*) AS findings, "
        "ROUND(MAX(f.confidence), 3) AS max_confidence, ROUND(AVG(f.confidence), 3) AS avg_confidence "
        "FROM findings f JOIN documents d ON d.doc_id=f.doc_id AND d.scan_id=f.scan_id "
        "WHERE f.scan_id=? GROUP BY f.doc_id, f.entity_type ORDER BY f.doc_id, findings DESC",
        conn, params=(scan_id,))
    counts = pd.read_sql_query(
        "SELECT entity_type, COUNT(*) AS findings, COUNT(DISTINCT doc_id) AS documents, "
        "ROUND(AVG(confidence), 3) AS avg_confidence FROM findings WHERE scan_id=? "
        "GROUP BY entity_type ORDER BY findings DESC", conn, params=(scan_id,))
    if unique_by_type is not None:
        counts["unique_values"] = counts["entity_type"].map(lambda t: unique_by_type.get(t)).astype("Int64")
    paths = {"documents": export_dir / "documents.csv",
             "findings_summary": export_dir / "findings_summary.csv",
             "entity_counts": export_dir / "entity_counts.csv"}
    docs.to_csv(paths["documents"], index=False, encoding="utf-8-sig")  # BOM so Excel reads UTF-8
    summary.to_csv(paths["findings_summary"], index=False, encoding="utf-8-sig")
    counts.to_csv(paths["entity_counts"], index=False, encoding="utf-8-sig")
    return paths


# ---------------------------------------------------------------------------
# Read helpers used by the dashboard
# ---------------------------------------------------------------------------
def list_scans(db_path: Path) -> pd.DataFrame:
    if not Path(db_path).exists():
        return pd.DataFrame()
    with sqlite3.connect(str(db_path)) as conn:
        conn.executescript(SCHEMA)
        return pd.read_sql_query("SELECT * FROM scans WHERE finished_at IS NOT NULL ORDER BY scan_id DESC", conn)


def load_scan(db_path: Path, scan_id: int) -> Dict[str, pd.DataFrame]:
    with sqlite3.connect(str(db_path)) as conn:
        q = lambda sql: pd.read_sql_query(sql, conn, params=(scan_id,))
        return {
            "scan": q("SELECT * FROM scans WHERE scan_id=?"),
            "documents": q("SELECT * FROM documents WHERE scan_id=?"),
            "findings": q('SELECT doc_id, entity_type, confidence, masked_value, "start", "end" '
                          "FROM findings WHERE scan_id=?"),
            "skipped": q("SELECT path, error FROM skipped WHERE scan_id=?"),
            "redactions": q("SELECT doc_id, source, redacted_path FROM redactions WHERE scan_id=?"),
        }
