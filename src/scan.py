"""Command-line entry point: ingest -> detect -> score -> store -> redact -> export.

Examples:
    python -m src.scan --source sample
    python -m src.scan --source folder --path "C:\\some\\folder"
    python -m src.scan --source enron --path data/raw/emails.csv --limit 5000
Options: --limit, --workers, --min-score, --no-redact, --output-dir
"""
from __future__ import annotations

import argparse
import csv
import logging
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import get_logger, load_config, resolve_path
from .compliance import (dpdp_max_penalty_inr, estimate_unique_individuals, exposure_index, format_eur,
                         format_inr, gdpr_max_fine_eur)
from .detector import build_analyzer, default_workers, detect_documents
from .ingest import ingest_enron_csv, ingest_folder
from .redact import redact_top_documents
from .risk import RISK_LEVELS, score_document
from . import storage

log = get_logger("scan")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Accuracy against ground truth
# ---------------------------------------------------------------------------
def evaluate(ground_truth: Path, root: Path, documents: List[Dict[str, Any]],
             evaluated: List[str]) -> Dict[str, Any]:
    """File-level precision/recall per entity type, plus risk-tier agreement.

    For each evaluated type and each file: TP if planted and detected,
    FP if detected but not planted, FN if planted but missed.
    """
    truth: Dict[str, Dict[str, Any]] = {}
    with ground_truth.open("r", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            truth[row["file"]] = {"planted": set(filter(None, row["planted_entities"].split(";"))),
                                  "expected_risk": row["expected_risk"]}

    counts = {t: Counter() for t in evaluated}
    tier_total = tier_match = 0
    confusion: Counter = Counter()
    for d in documents:
        rel = Path(d["path"]).resolve().relative_to(root.resolve()).as_posix()
        if rel not in truth:
            continue
        planted = truth[rel]["planted"]
        detected = set(d["entity_types"].split(";")) if d["entity_types"] else set()
        for t in evaluated:
            if t in planted and t in detected:
                counts[t]["tp"] += 1
            elif t in detected:
                counts[t]["fp"] += 1
            elif t in planted:
                counts[t]["fn"] += 1
        tier_total += 1
        tier_match += truth[rel]["expected_risk"] == d["risk_level"]
        confusion[(truth[rel]["expected_risk"], d["risk_level"])] += 1

    per_entity = []
    for t in evaluated:
        tp, fp, fn = counts[t]["tp"], counts[t]["fp"], counts[t]["fn"]
        p = tp / (tp + fp) if tp + fp else None
        r = tp / (tp + fn) if tp + fn else None
        f1 = 2 * p * r / (p + r) if p and r else None
        per_entity.append({"entity_type": t, "tp": tp, "fp": fp, "fn": fn,
                           "precision": round(p, 3) if p is not None else None,
                           "recall": round(r, 3) if r is not None else None,
                           "f1": round(f1, 3) if f1 is not None else None})
    tp = sum(c["tp"] for c in counts.values())
    fp = sum(c["fp"] for c in counts.values())
    fn = sum(c["fn"] for c in counts.values())
    micro_p = tp / (tp + fp) if tp + fp else 0.0
    micro_r = tp / (tp + fn) if tp + fn else 0.0
    return {
        "per_entity": per_entity,
        "micro_precision": round(micro_p, 3),
        "micro_recall": round(micro_r, 3),
        "risk_tier_accuracy": round(tier_match / tier_total, 3) if tier_total else None,
        "files_evaluated": tier_total,
        "tier_confusion": [{"expected": e, "predicted": p, "files": n} for (e, p), n in sorted(confusion.items())],
    }


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def run_scan(source: str, path: Optional[str] = None, limit: Optional[int] = None, workers: Optional[int] = None,
             min_score: Optional[float] = None, redact: bool = True, output_dir: Optional[str] = None,
             show_progress: bool = True) -> Dict[str, Any]:
    """Run a full scan and return a summary dict (also used by tests and the dashboard)."""
    cfg = load_config()
    t0 = time.perf_counter()
    out_dir = resolve_path(output_dir or cfg["paths"]["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(out_dir / "scan.log", encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.getLogger("pii").addHandler(file_handler)

    try:
        # 1. Ingest -------------------------------------------------------------
        if source == "sample":
            root = resolve_path(path or cfg["paths"]["sample_dir"])
            if not root.exists() or not any(root.rglob("*.*")):
                raise SystemExit(f"No sample data in {root}. Run: python -m src.generate_sample_data")
            docs, skipped = ingest_folder(root, limit)
            source_label = f"sample:{root}"
        elif source == "folder":
            if not path:
                raise SystemExit("--source folder requires --path")
            root = resolve_path(path)
            docs, skipped = ingest_folder(root, limit)
            source_label = f"folder:{root}"
        elif source == "enron":
            root = resolve_path(path or Path(cfg["paths"]["raw_dir"]) / "emails.csv")
            docs, skipped = ingest_enron_csv(root, limit)
            source_label = f"enron:{root}"
        else:
            raise SystemExit(f"Unknown source {source}")

        settings = {
            "source": source, "path": str(root), "limit": limit,
            "min_score": cfg["detection"]["min_score"] if min_score is None else min_score,
            "workers": workers or default_workers(),
            "redact": redact, "max_text_length": cfg["ingest"]["max_text_length"],
        }
        db_path = out_dir / cfg["paths"]["db_file"]
        conn = storage.connect(db_path)
        scan_id = storage.create_scan(conn, _now(), source_label, settings)
        log.info("Scan %d started: %d documents to analyse", scan_id, len(docs))

        # 2. Detect -------------------------------------------------------------
        analyzer = build_analyzer(cfg) if settings["workers"] == 1 or len(docs) < 20 else None
        settings["spacy_model"] = getattr(analyzer, "spacy_model_name", cfg["detection"]["spacy_model"])
        hmac_key = os.urandom(32)  # per-scan secret, never stored
        results = detect_documents(docs, settings["min_score"], settings["workers"], hmac_key, analyzer,
                                   show_progress=show_progress)

        # 3. Score --------------------------------------------------------------
        documents, findings_by_doc = [], {}
        unique_digests: Dict[str, set] = defaultdict(set)
        for d, r in zip(docs, results):
            s = score_document(r["findings"], cfg)
            findings_by_doc[d["doc_id"]] = r["findings"]
            for dg in r["digests"]:
                unique_digests[dg.split(":", 1)[0]].add(dg)
            documents.append({
                "doc_id": d["doc_id"], "path": d["source_path"], "file_type": d["file_type"],
                "sender": d["sender"], "date": d["date"], "subject": r["masked_subject"],
                "risk_score": s["risk_score"], "risk_level": s["risk_level"], "reason": s["reason"],
                "finding_count": len(r["findings"]), "char_count": d["char_count"], "truncated": d["truncated"],
                "toxic": s["toxic"], "entity_types": ";".join(sorted({f["entity_type"] for f in r["findings"]})),
                "masked_snippet": r["masked_snippet"],
            })

        # 4. Store --------------------------------------------------------------
        storage.save_results(conn, scan_id, documents, findings_by_doc, skipped)

        # 5. Redact top documents (remediation demo) ----------------------------
        redactions = []
        if redact:
            texts = {d["doc_id"]: d["text"] for d in docs}
            redactions = redact_top_documents(documents, texts, findings_by_doc,
                                              out_dir / cfg["paths"]["redacted_subdir"])
            storage.save_redactions(conn, scan_id, redactions)

        # 6. Aggregate stats ----------------------------------------------------
        unique_by_group = {k: len(v) for k, v in unique_digests.items()}
        unique_digests.clear()
        level_counts = Counter(d["risk_level"] for d in documents)
        entity_counts = Counter(f["entity_type"] for fs in findings_by_doc.values() for f in fs)
        scored_docs = sum(1 for d in documents if d["risk_level"] != "Clean")
        individuals = estimate_unique_individuals(unique_by_group)
        exposure = exposure_index(individuals, level_counts.get("High", 0), level_counts.get("Medium", 0),
                                  scored_docs, cfg)
        stats: Dict[str, Any] = {
            "level_counts": {lvl: level_counts.get(lvl, 0) for lvl in RISK_LEVELS},
            "entity_counts": dict(entity_counts.most_common()),
            "unique_identifiers_by_type": unique_by_group,
            "unique_identifiers_total": sum(unique_by_group.values()),
            "unique_individuals_estimate": individuals,
            "docs_with_pii": scored_docs,
            "total_findings": sum(entity_counts.values()),
            "truncated_docs": sum(1 for d in documents if d["truncated"]),
            "exposure_index": exposure,
            "dpdp_max_penalty_inr": dpdp_max_penalty_inr(cfg),
            "gdpr_max_fine_eur_default": gdpr_max_fine_eur(cfg["compliance"]["gdpr"]["default_turnover_eur"], cfg),
            "spacy_model": settings["spacy_model"],
            "redacted_files": len(redactions),
        }

        gt = root / "ground_truth.csv" if root.is_dir() else None
        if gt is not None and gt.exists():
            stats["accuracy"] = evaluate(gt, root, documents, cfg["evaluation"]["evaluated_entities"])

        elapsed = time.perf_counter() - t0
        stats["seconds"] = round(elapsed, 1)
        storage.finish_scan(conn, scan_id, _now(), len(documents), len(skipped), stats)

        # 7. Export -------------------------------------------------------------
        export_dir = out_dir / cfg["paths"]["exports_subdir"]
        exports = storage.export_csvs(conn, scan_id, export_dir,
                                      {t: unique_by_group.get({"IN_PHONE": "PHONE", "PHONE_NUMBER": "PHONE"}.get(t, t))
                                       for t in entity_counts})
        if "accuracy" in stats:
            acc_path = export_dir / "accuracy.csv"
            with acc_path.open("w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=["entity_type", "tp", "fp", "fn", "precision", "recall", "f1"])
                w.writeheader()
                w.writerows(stats["accuracy"]["per_entity"])
            exports["accuracy"] = acc_path
        conn.close()

        return {"scan_id": scan_id, "db_path": db_path, "out_dir": out_dir, "exports": exports,
                "documents": documents, "skipped": skipped, "stats": stats, "redactions": redactions,
                "elapsed": elapsed, "source": source_label}
    finally:
        logging.getLogger("pii").removeHandler(file_handler)
        file_handler.close()


# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------
def print_summary(res: Dict[str, Any]) -> None:
    s, docs = res["stats"], res["documents"]
    line = "=" * 72
    print(f"\n{line}\n PII RISK SCAN SUMMARY  (scan #{res['scan_id']})\n{line}")
    print(f" Source              : {res['source']}")
    print(f" Documents scanned   : {len(docs):,}")
    print(f" Documents skipped   : {len(res['skipped']):,}")
    for sk in res["skipped"][:5]:
        print(f"     - {Path(sk['path']).name}: {sk['error'][:70]}")
    pct = 100 * s["docs_with_pii"] / len(docs) if docs else 0
    print(f" Documents with PII  : {s['docs_with_pii']:,} ({pct:.1f}%)")
    print(f" Total findings      : {s['total_findings']:,}")
    print(f" Unique identifiers  : {s['unique_identifiers_total']:,} "
          f"(est. at least {s['unique_individuals_estimate']:,} individuals)")
    print(f" spaCy model         : {s['spacy_model']}")

    print("\n Findings by entity type")
    for t, n in s["entity_counts"].items():
        print(f"   {t:<15} {n:>7,}")

    print("\n Documents by risk level")
    for lvl in RISK_LEVELS:
        print(f"   {lvl:<8} {s['level_counts'].get(lvl, 0):>7,}")

    print("\n Top 5 riskiest files")
    for d in sorted(docs, key=lambda x: x["risk_score"], reverse=True)[:5]:
        print(f"   [{d['risk_level']:<6} {d['risk_score']:>5.1f}] {Path(d['path']).name}")
        print(f"       {d['reason']}")

    e = s["exposure_index"]
    print("\n Compliance exposure (Illustrative estimate for demonstration only, not legal advice.)")
    print(f"   Exposure index     : {e['index']} / 100 ({e['band']})")
    print(f"   DPDP Act ceiling   : up to {format_inr(s['dpdp_max_penalty_inr'])} per breach (ceiling, not a prediction)")
    print(f"   GDPR ceiling       : {format_eur(s['gdpr_max_fine_eur_default'])} at the default hypothetical turnover")

    if "accuracy" in s:
        a = s["accuracy"]
        print(f"\n Accuracy vs ground truth ({a['files_evaluated']} files, file-level)")
        print(f"   {'Entity':<15}{'Precision':>10}{'Recall':>9}{'F1':>7}{'TP':>6}{'FP':>5}{'FN':>5}")
        fmt = lambda v: f"{v:.2f}" if v is not None else "  - "
        for r in a["per_entity"]:
            print(f"   {r['entity_type']:<15}{fmt(r['precision']):>10}{fmt(r['recall']):>9}{fmt(r['f1']):>7}"
                  f"{r['tp']:>6}{r['fp']:>5}{r['fn']:>5}")
        print(f"   {'MICRO AVERAGE':<15}{a['micro_precision']:>10.2f}{a['micro_recall']:>9.2f}")
        print(f"   Risk-tier agreement with planted tier: {a['risk_tier_accuracy']:.1%}")

    print(f"\n Time taken          : {res['elapsed']:.1f} s")
    print(" Outputs")
    print(f"   Database   : {res['db_path']}")
    for name, p in res["exports"].items():
        print(f"   {name + '.csv':<18}: {p}")
    if res["redactions"]:
        print(f"   Redacted   : {len(res['redactions'])} files in {Path(res['redactions'][0]['redacted_path']).parent}")
    print("\n Next: streamlit run dashboard/app.py")
    print(line)


def main(argv=None) -> None:
    # Windows consoles default to cp1252; never crash on a non-ASCII character.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    cfg = load_config()
    ap = argparse.ArgumentParser(description="Scan documents for PII and score their risk.")
    ap.add_argument("--source", choices=["sample", "folder", "enron"], required=True)
    ap.add_argument("--path", help="folder to scan (folder/sample) or emails.csv (enron)")
    ap.add_argument("--limit", type=int, default=None,
                    help=f"max documents (enron default {cfg['ingest']['enron_default_limit']})")
    ap.add_argument("--workers", type=int, default=None,
                    help=f"parallel worker processes (default {default_workers()} on this machine)")
    ap.add_argument("--min-score", type=float, default=None,
                    help=f"minimum confidence 0-1 (default {cfg['detection']['min_score']})")
    ap.add_argument("--no-redact", action="store_true", help="skip writing redacted samples")
    ap.add_argument("--output-dir", default=None, help="output folder (default output/)")
    args = ap.parse_args(argv)
    if args.min_score is not None and not 0 <= args.min_score <= 1:
        ap.error("--min-score must be between 0 and 1")
    if args.source == "enron" and args.limit is None:
        args.limit = cfg["ingest"]["enron_default_limit"]

    res = run_scan(args.source, args.path, args.limit, args.workers, args.min_score,
                   redact=not args.no_redact, output_dir=args.output_dir)
    print_summary(res)


if __name__ == "__main__":  # required for multiprocessing on Windows
    main()
