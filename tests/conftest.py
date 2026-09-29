"""Shared pytest fixtures.

The Presidio engine loads a large spaCy model, so it is built once per
test session and reused by every recognizer test.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def analyzer():
    from src.detector import build_analyzer
    return build_analyzer()


@pytest.fixture(scope="session")
def detect(analyzer):
    """Return a function text -> {entity_type: [matched text, ...]} using the full pipeline."""
    from src import load_config
    from src.detector import analyze_document

    cfg = load_config()
    settings = {"language": "en", "entities": cfg["detection"]["entities"], "min_score": cfg["detection"]["min_score"],
                "snippet_chars": 500, "identifier_entities": set(cfg["compliance"]["individual_identifiers"]),
                "hmac_key": b"test-key"}

    def _detect(text: str) -> dict:
        res = analyze_document(analyzer, {"doc_id": "t", "text": text}, settings)
        out: dict = {}
        for f in res["findings"]:
            out.setdefault(f["entity_type"], []).append(text[f["start"]:f["end"]])
        return out

    return _detect
