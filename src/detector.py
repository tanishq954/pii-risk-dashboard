"""PII detection engine built on Microsoft Presidio.

Design points worth knowing for an interview:

* **One engine, loaded once.** Building an AnalyzerEngine loads a ~600 MB
  spaCy model, so it is created once per process (once in the main
  process, or once per worker when ``--workers`` > 1), never per file.
* **Masking at the source.** Findings leave this module with a masked
  preview (``XXXX XXXX 1234``) only. Raw values exist solely inside the
  in-memory text while it is being analysed.
* **Unique-individual counting without storing PII.** To estimate how
  many distinct people are affected, each identifier is turned into a
  keyed HMAC digest with a random per-scan key that is never written to
  disk, so the digests cannot be reversed after the scan ends.
* **Overlap resolution.** When recognizers disagree about the same span
  (e.g. a 10-digit number that is both a phone and an account number)
  the highest-confidence finding wins.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib
import multiprocessing as mp
import os
import platform
import re
from typing import Any, Dict, List, Optional

from tqdm import tqdm

from . import get_logger, load_config
from .recognizers import CUSTOM_ENTITIES, get_custom_recognizers

log = get_logger("detector")

# Built-in Presidio recognizers we keep (everything else is removed from the registry).
BUILTIN_ENTITIES = {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN",
                    "IBAN_CODE", "LOCATION", "DATE_TIME", "IP_ADDRESS"}

# Identifier types folded into one "group" when counting unique individuals
# (a mobile number found by IN_PHONE and PHONE_NUMBER is the same identifier).
_IDENTIFIER_GROUP = {"IN_PHONE": "PHONE", "PHONE_NUMBER": "PHONE"}


# ---------------------------------------------------------------------------
# spaCy model resolution with automatic fallback
# ---------------------------------------------------------------------------
def resolve_spacy_model(primary: str, fallback: str) -> str:
    """Return an installed spaCy model name, downloading if needed.

    Tries ``primary`` (en_core_web_lg); if it is missing and cannot be
    downloaded, logs a warning and falls back to ``fallback`` (en_core_web_sm).
    """
    import spacy.util

    for name in (primary, fallback):
        if spacy.util.is_package(name):
            if name != primary:
                log.warning("spaCy model %s unavailable - using fallback %s (lower NER accuracy)", primary, name)
            return name
        try:
            log.info("spaCy model %s not installed - attempting download", name)
            from spacy.cli import download
            download(name)
            importlib.invalidate_caches()
            if spacy.util.is_package(name):
                if name != primary:
                    log.warning("Using fallback spaCy model %s (lower NER accuracy)", name)
                return name
        except (Exception, SystemExit) as exc:  # spacy's CLI raises SystemExit on failure
            log.warning("Could not download spaCy model %s: %s", name, exc)
    raise RuntimeError(f"No spaCy model available. Run: python -m spacy download {fallback}")


# ---------------------------------------------------------------------------
# Engine construction
# ---------------------------------------------------------------------------
def build_analyzer(cfg: Optional[dict] = None):
    """Build a Presidio AnalyzerEngine with the custom Indian recognizers loaded."""
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    cfg = cfg or load_config()
    det = cfg["detection"]
    model = resolve_spacy_model(det["spacy_model"], det["fallback_spacy_model"])

    nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": det["language"], "model_name": model}],
        "ner_model_configuration": {
            "model_to_presidio_entity_mapping": {
                "PER": "PERSON", "PERSON": "PERSON",
                "LOC": "LOCATION", "GPE": "LOCATION", "FAC": "LOCATION",
                "DATE": "DATE_TIME", "TIME": "DATE_TIME",
            },
            "low_confidence_score_multiplier": 0.4,
            "low_score_entity_names": [],
            "labels_to_ignore": ["ORG", "ORGANIZATION", "NORP", "CARDINAL", "MONEY", "PERCENT",
                                 "QUANTITY", "ORDINAL", "EVENT", "WORK_OF_ART", "LAW", "LANGUAGE", "PRODUCT"],
        },
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()

    registry = RecognizerRegistry(supported_languages=[det["language"]])
    registry.load_predefined_recognizers(languages=[det["language"]], nlp_engine=nlp_engine)
    # Keep only the built-ins we want; drop US driver licence, crypto, URL, etc.
    registry.recognizers = [r for r in registry.recognizers
                            if set(r.supported_entities) & BUILTIN_ENTITIES]
    for rec in get_custom_recognizers():
        registry.add_recognizer(rec)

    analyzer = AnalyzerEngine(registry=registry, nlp_engine=nlp_engine,
                              supported_languages=[det["language"]])
    analyzer.spacy_model_name = model  # remembered for the scan settings record
    return analyzer


# ---------------------------------------------------------------------------
# Masking, de-duplication, normalisation
# ---------------------------------------------------------------------------
def mask_value(value: str, entity_type: str) -> str:
    """Return a masked preview that never reveals the full value.

    * Emails / UPI IDs keep the first character and the domain/handle.
    * Names and health terms keep only the first letter of each word.
    * Salaries hide every digit.
    * Identifiers keep the last 4 alphanumerics: ``XXXX XXXX 1234``.
    """
    value = value.strip()
    if entity_type in ("EMAIL_ADDRESS", "IN_UPI") and "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:1]}{'*' * max(len(local) - 1, 2)}@{domain}"
    if entity_type in ("PERSON", "HEALTH_INFO", "LOCATION"):
        return " ".join(w[:1] + "*" * max(len(w) - 1, 1) for w in value.split())
    if entity_type == "SALARY":
        # "(INR): 85000" -> "INR XXXXX": tidy the label punctuation, hide every digit
        value = re.sub(r"^[^\w₹$]+|\)?\s*[:=]\s*", lambda m: "" if m.start() == 0 else " ", value)
        return re.sub(r"\d", "X", value).strip()
    alnum_positions = [i for i, ch in enumerate(value) if ch.isalnum()]
    if len(alnum_positions) <= 4:
        return re.sub(r"[A-Za-z0-9]", "X", value)
    keep = set(alnum_positions[-4:])
    return "".join(ch if (i in keep or not ch.isalnum()) else "X" for i, ch in enumerate(value))


# NER-based types: fuzzy spans that must never swallow a structured identifier.
NER_ENTITIES = {"PERSON", "LOCATION", "DATE_TIME"}
# Generic built-in -> more specific custom recognizer for the same value.
GENERIC_TO_SPECIFIC = {"PHONE_NUMBER": "IN_PHONE"}
CARD_CONTEXT = ["card", "credit", "debit", "visa", "mastercard", "rupay", "amex", "charged"]


def _overlaps(a, b) -> bool:
    return a.start < b.end and b.start < a.end


def deduplicate(results: list, text: str = "") -> list:
    """Resolve overlapping detections so each character belongs to at most one finding.

    1. Generic vs specific: a PHONE_NUMBER on the same span as an IN_PHONE is
       merged into the IN_PHONE (keeping the higher score).
    2. Card vs account: a Luhn-valid number sitting next to "Account No" with
       no card vocabulary nearby is a bank account (1 in 10 random numbers pass Luhn).
    3. Structured findings (regex + checksum/context) are kept first, highest
       confidence wins; ties go to the custom Indian recognizers, then longer spans.
    4. NER findings (PERSON/LOCATION/DATE_TIME) are trimmed so they never cover a
       structured identifier (spaCy sometimes tags "Asha Rao - 98765 43210" as one
       PERSON or a phone number as a DATE), and are dropped if nothing sensible remains.
    """
    from .recognizers import BANK_CONTEXT, has_context

    specific = [r for r in results if r.entity_type in GENERIC_TO_SPECIFIC.values()]
    merged = []
    for r in results:
        target = GENERIC_TO_SPECIFIC.get(r.entity_type)
        match = next((s for s in specific if s.entity_type == target and _overlaps(s, r)), None) if target else None
        if match is not None:
            match.score = max(match.score, r.score)
            continue
        merged.append(r)

    accounts = [r for r in merged if r.entity_type == "BANK_ACCOUNT"]
    if accounts and text:
        merged = [r for r in merged if not (
            r.entity_type == "CREDIT_CARD" and any(_overlaps(r, a) for a in accounts)
            and has_context(text, r.start, r.end, BANK_CONTEXT, 40, 0)
            and not has_context(text, r.start, r.end, CARD_CONTEXT, 60, 20))]

    rank = lambda r: (r.score, r.entity_type in CUSTOM_ENTITIES, r.end - r.start)
    kept: list = []
    for r in sorted((r for r in merged if r.entity_type not in NER_ENTITIES), key=rank, reverse=True):
        if not any(_overlaps(r, k) for k in kept):
            kept.append(r)

    structured = sorted(kept, key=lambda k: k.start)
    for r in sorted((r for r in merged if r.entity_type in NER_ENTITIES), key=rank, reverse=True):
        # Split the NER span around structured findings and keep the longest piece.
        pieces, cursor = [], r.start
        for k in structured:
            if k.end <= r.start or k.start >= r.end:
                continue
            pieces.append((cursor, k.start))
            cursor = max(cursor, k.end)
        pieces.append((cursor, r.end))
        start, end = max(pieces, key=lambda p: p[1] - p[0])
        if text:  # strip separators such as " - " or ", " left at the edges
            while start < end and not text[start].isalnum():
                start += 1
            while end > start and not text[end - 1].isalnum():
                end -= 1
            piece = text[start:end]
            needs_alpha = r.entity_type in ("PERSON", "LOCATION")
            if end - start < 2 or (needs_alpha and not any(c.isalpha() for c in piece)):
                continue
        if end <= start:
            continue
        r.start, r.end = start, end
        if not any(_overlaps(r, k) for k in kept):
            kept.append(r)
    return sorted(kept, key=lambda r: r.start)


def normalise_identifier(value: str, entity_type: str) -> str:
    """Canonical form of an identifier so the same value counts once."""
    if entity_type in ("EMAIL_ADDRESS", "IN_UPI"):
        return value.strip().lower()
    if entity_type in ("IN_PAN", "IBAN_CODE"):
        return re.sub(r"\s", "", value).upper()
    digits = re.sub(r"\D", "", value)
    if entity_type in ("IN_PHONE", "PHONE_NUMBER"):
        return digits[-10:]
    return digits


def identifier_digest(value: str, entity_type: str, key: bytes) -> str:
    """Keyed hash of an identifier; irreversible once the per-scan key is discarded."""
    group = _IDENTIFIER_GROUP.get(entity_type, entity_type)
    msg = f"{group}:{normalise_identifier(value, entity_type)}".encode("utf-8")
    return f"{group}:{hmac.new(key, msg, hashlib.sha256).hexdigest()[:20]}"


def build_masked_snippet(text: str, findings: List[dict], max_chars: int, markers: bool = True) -> str:
    """Text preview with every finding replaced by its masked value.

    With ``markers=True`` each replacement is wrapped as ``[[ENTITY|masked]]``
    so the dashboard can highlight it.
    """
    out, pos = [], 0
    for f in findings:
        if f["start"] >= max_chars:
            break
        out.append(text[pos:f["start"]])
        out.append(f"[[{f['entity_type']}|{f['masked_value']}]]" if markers else f["masked_value"])
        pos = f["end"]
    if pos < max_chars:
        out.append(text[pos:max_chars])
    snippet = "".join(out)
    return snippet + (" ..." if len(text) > max_chars else "")


# ---------------------------------------------------------------------------
# Per-document analysis
# ---------------------------------------------------------------------------
def analyze_document(analyzer, doc: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
    """Run Presidio on one document and return masked findings + identifier digests."""
    text = doc.get("text") or ""
    findings: List[dict] = []
    digests: List[str] = []
    if text.strip():
        raw = analyzer.analyze(text=text, language=settings["language"], entities=settings["entities"],
                               score_threshold=settings["min_score"])
        for r in deduplicate(raw, text):
            value = text[r.start:r.end]
            findings.append({
                "entity_type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "confidence": round(float(r.score), 3),
                "masked_value": mask_value(value, r.entity_type),
            })
            if r.entity_type in settings["identifier_entities"]:
                digests.append(identifier_digest(value, r.entity_type, settings["hmac_key"]))

    subject = doc.get("subject") or ""
    masked_subject = subject
    if subject and text.startswith(subject):
        subject_findings = [f for f in findings if f["end"] <= len(subject)]
        masked_subject = build_masked_snippet(subject, subject_findings, len(subject), markers=False)

    return {
        "doc_id": doc["doc_id"],
        "findings": findings,
        "digests": digests,
        "masked_snippet": build_masked_snippet(text, findings, settings["snippet_chars"]),
        "masked_subject": masked_subject,
    }


# ---------------------------------------------------------------------------
# Multiprocessing plumbing (functions must be top level so Windows "spawn" can pickle them)
# ---------------------------------------------------------------------------
_WORKER_ANALYZER = None
_WORKER_SETTINGS: Dict[str, Any] = {}


def _init_worker(settings: Dict[str, Any]) -> None:
    """Pool initializer: each worker process builds its own engine exactly once."""
    global _WORKER_ANALYZER, _WORKER_SETTINGS
    _WORKER_SETTINGS = settings
    _WORKER_ANALYZER = build_analyzer()


def _worker_analyze(doc: Dict[str, Any]) -> Dict[str, Any]:
    return analyze_document(_WORKER_ANALYZER, doc, _WORKER_SETTINGS)


def default_workers() -> int:
    """1 on Windows (spawn start-up cost and memory), 2 elsewhere."""
    if platform.system() == "Windows":
        return 1
    return max(1, min(2, os.cpu_count() or 1))


def detect_documents(docs: List[Dict[str, Any]], min_score: Optional[float] = None,
                     workers: int = 1, hmac_key: Optional[bytes] = None,
                     analyzer=None, show_progress: bool = True) -> List[Dict[str, Any]]:
    """Detect PII in many documents, optionally in parallel, with a progress bar.

    Returns one result dict per input document, in the input order.
    """
    cfg = load_config()
    det = cfg["detection"]
    settings = {
        "language": det["language"],
        "entities": det["entities"],
        "min_score": det["min_score"] if min_score is None else min_score,
        "snippet_chars": det["snippet_chars"],
        "identifier_entities": set(cfg["compliance"]["individual_identifiers"]),
        "hmac_key": hmac_key or os.urandom(32),
    }
    if not docs:
        return []

    workers = max(1, int(workers))
    if workers == 1 or len(docs) < 20:
        analyzer = analyzer or build_analyzer(cfg)
        return [analyze_document(analyzer, d, settings)
                for d in tqdm(docs, desc="Detecting PII", unit="doc", disable=not show_progress)]

    log.info("Starting %d worker processes (each loads the spaCy model once)", workers)
    ctx = mp.get_context("spawn")  # identical behaviour on Windows, macOS and Linux
    order = {d["doc_id"]: i for i, d in enumerate(docs)}
    results: List[Optional[Dict[str, Any]]] = [None] * len(docs)
    with ctx.Pool(processes=workers, initializer=_init_worker, initargs=(settings,)) as pool:
        for res in tqdm(pool.imap_unordered(_worker_analyze, docs, chunksize=8), total=len(docs),
                        desc=f"Detecting PII ({workers} workers)", unit="doc", disable=not show_progress):
            results[order[res["doc_id"]]] = res
    return results  # type: ignore[return-value]
