#!/usr/bin/env bash
# One-click demo for macOS / Linux:
#   venv -> install -> spaCy model -> sample data -> scan -> tests -> dashboard
# Set NO_DASHBOARD=1 to skip launching Streamlit at the end.
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONIOENCODING=utf-8

# 1. Find Python 3.11 (3.10-3.12 also work)
PYTHON=""
for candidate in python3.11 python3.12 python3.10 python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(0 if (3,10) <= sys.version_info[:2] <= (3,12) else 1)' 2>/dev/null; then
    PYTHON="$candidate"; break
  fi
done

if [ ! -x ".venv/bin/python" ]; then
  echo "[1/7] Creating virtual environment..."
  if [ -n "$PYTHON" ]; then
    "$PYTHON" -m venv .venv
  elif command -v uv >/dev/null 2>&1; then
    uv venv --python 3.11 .venv && uv pip install --python .venv/bin/python pip
  else
    echo "ERROR: Python 3.11 not found. Install it from https://www.python.org/downloads/"
    echo "       or install uv (https://docs.astral.sh/uv/) and re-run this script."
    exit 1
  fi
else
  echo "[1/7] Virtual environment already exists"
fi
PY=".venv/bin/python"
"$PY" -m pip --version >/dev/null 2>&1 || "$PY" -m ensurepip --upgrade

echo "[2/7] Installing requirements (first run takes a few minutes)..."
PIP_OPTS="--quiet --timeout 120 --retries 5"
"$PY" -m pip install $PIP_OPTS --upgrade pip || echo "NOTE: could not upgrade pip - continuing with the bundled version"
if ! "$PY" -m pip install $PIP_OPTS -r requirements.txt; then
  echo "Install failed (often a network timeout) - retrying once..."
  "$PY" -m pip install $PIP_OPTS -r requirements.txt
fi

echo "[3/7] Checking spaCy language model..."
if ! "$PY" -c "import spacy.util, sys; sys.exit(0 if spacy.util.is_package('en_core_web_lg') else 1)"; then
  if ! "$PY" -m spacy download en_core_web_lg; then
    echo "WARNING: en_core_web_lg download failed - falling back to en_core_web_sm (lower name accuracy)"
    "$PY" -m spacy download en_core_web_sm
  fi
fi

echo "[4/7] Generating synthetic sample data..."
"$PY" -m src.generate_sample_data

echo "[5/7] Scanning the sample data..."
"$PY" -m src.scan --source sample

echo "[6/7] Running tests..."
"$PY" -m pytest || echo "WARNING: some tests failed - see output above"

if [ "${NO_DASHBOARD:-0}" = "1" ]; then
  echo "[7/7] Skipping dashboard (NO_DASHBOARD=1). Start it with: .venv/bin/python -m streamlit run dashboard/app.py"
  exit 0
fi
echo "[7/7] Launching dashboard at http://localhost:8501 (Ctrl+C to stop)..."
"$PY" -m streamlit run dashboard/app.py
