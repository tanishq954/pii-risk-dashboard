"""End-to-end: generate a small synthetic set, scan it, check the DB, CSVs, redactions and dashboard."""
import importlib.util
import os
import sqlite3

import pandas as pd
import pytest

from src import PROJECT_ROOT


@pytest.fixture(scope="module")
def scan_result(tmp_path_factory):
    from src.generate_sample_data import generate
    from src.scan import run_scan

    base = tmp_path_factory.mktemp("e2e")
    sample, out = base / "sample", base / "output"
    stats = generate(sample, n=30, seed=7)
    assert stats["files"] >= 25
    res = run_scan("folder", str(sample), workers=1, output_dir=str(out), show_progress=False)
    return {"res": res, "sample": sample, "out": out}


def test_database_has_rows(scan_result):
    db = scan_result["out"] / "pii_results.db"
    assert db.exists()
    with sqlite3.connect(db) as conn:
        docs = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        scans = conn.execute("SELECT docs_scanned, docs_skipped, finished_at FROM scans").fetchall()
        skipped = conn.execute("SELECT path FROM skipped").fetchall()
        levels = {r[0] for r in conn.execute("SELECT DISTINCT risk_level FROM documents")}
    assert docs >= 25 and findings > 0
    assert scans[0][0] == docs and scans[0][2]
    assert any("corrupt" in p for (p,) in skipped)  # the deliberately corrupt PDF was skipped
    assert {"High", "Clean"} <= levels


def test_csv_exports_have_rows(scan_result):
    exports = scan_result["out"] / "exports"
    for name in ["documents.csv", "findings_summary.csv", "entity_counts.csv", "accuracy.csv"]:
        df = pd.read_csv(exports / name)
        assert len(df) > 0, name


def test_no_raw_pii_stored(scan_result):
    """Every Aadhaar/PAN planted in the files must be absent from the database, CSVs and logs."""
    import re
    from src.ingest import ingest_folder

    records, _ = ingest_folder(scan_result["sample"])
    corpus = "\n".join(r["text"] for r in records)
    aadhaars = set(re.findall(r"\b[2-9]\d{3} \d{4} \d{4}\b", corpus))
    pans = set(re.findall(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b", corpus))
    assert aadhaars and pans
    with sqlite3.connect(scan_result["out"] / "pii_results.db") as conn:
        dump = "\n".join(str(row) for t in ["documents", "findings", "scans"]
                         for row in conn.execute(f"SELECT * FROM {t}"))
    dump += "".join(p.read_text(encoding="utf-8-sig") for p in (scan_result["out"] / "exports").glob("*.csv"))
    dump += (scan_result["out"] / "scan.log").read_text(encoding="utf-8")
    leaked = [v for v in aadhaars | pans if v in dump]
    assert not leaked, f"{len(leaked)} raw identifiers leaked"


def test_redacted_files_written(scan_result):
    red = list((scan_result["out"] / "redacted").glob("*.redacted.txt"))
    assert 0 < len(red) <= 10
    text = red[0].read_text(encoding="utf-8")
    assert "<" in text and ">" in text


def test_accuracy_computed(scan_result):
    acc = scan_result["res"]["stats"]["accuracy"]
    assert acc["files_evaluated"] >= 25
    assert acc["micro_precision"] > 0.8 and acc["micro_recall"] > 0.8


def test_dashboard_module_imports():
    spec = importlib.util.spec_from_file_location("dashboard_app", PROJECT_ROOT / "dashboard" / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # main() is guarded, so nothing renders on import
    assert callable(module.main)


def test_dashboard_renders_without_errors(scan_result):
    from streamlit.testing.v1 import AppTest

    os.environ["PII_DB_PATH"] = str(scan_result["out"] / "pii_results.db")
    try:
        at = AppTest.from_file(str(PROJECT_ROOT / "dashboard" / "app.py"), default_timeout=180)
        at.run()
        assert not at.exception, [e.value for e in at.exception]
        assert len(at.tabs) == 6
    finally:
        os.environ.pop("PII_DB_PATH", None)


def test_dashboard_empty_state(tmp_path):
    from streamlit.testing.v1 import AppTest

    os.environ["PII_DB_PATH"] = str(tmp_path / "missing.db")
    try:
        at = AppTest.from_file(str(PROJECT_ROOT / "dashboard" / "app.py"), default_timeout=60)
        at.run()
        assert not at.exception
        assert any("Run sample scan" in b.label for b in at.button)
    finally:
        os.environ.pop("PII_DB_PATH", None)
