"""PII Detector and Risk Dashboard.

Shared helpers used by every module: the project root and a cached
config.yaml loader, so all paths are resolved with pathlib and work the
same on Windows and macOS.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.yaml"


@lru_cache(maxsize=4)
def load_config(path: str | None = None) -> dict[str, Any]:
    """Load config.yaml (cached). Pass a path to load an alternative file."""
    cfg_path = Path(path) if path else CONFIG_PATH
    with cfg_path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def resolve_path(p: str | Path) -> Path:
    """Resolve a config-relative path against the project root."""
    p = Path(p)
    return p if p.is_absolute() else PROJECT_ROOT / p


def get_logger(name: str) -> logging.Logger:
    """Module logger with a consistent format (configured once)."""
    root = logging.getLogger("pii")
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S"))
        root.addHandler(handler)
        root.setLevel(logging.INFO)
    return logging.getLogger(f"pii.{name}")
