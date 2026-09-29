@echo off
REM One-click demo for Windows:
REM   venv -^> install -^> spaCy model -^> sample data -^> scan -^> tests -^> dashboard
REM Set NO_DASHBOARD=1 to skip launching Streamlit at the end.
setlocal
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

if exist ".venv\Scripts\python.exe" goto venv_ready
echo [1/7] Creating virtual environment...
py -3.11 -m venv .venv >nul 2>&1
if exist ".venv\Scripts\python.exe" goto venv_ready
python -m venv .venv
if exist ".venv\Scripts\python.exe" goto venv_ready
echo ERROR: Python 3.11 was not found. Install it from https://www.python.org/downloads/
echo        and tick "Add python.exe to PATH" during installation.
goto fail

:venv_ready
set "PY=.venv\Scripts\python.exe"
echo [2/7] Installing requirements - first run takes a few minutes...
set "PIP_OPTS=--quiet --timeout 120 --retries 5"
"%PY%" -m pip install %PIP_OPTS% --upgrade pip
if errorlevel 1 echo NOTE: could not upgrade pip - continuing with the bundled version
"%PY%" -m pip install %PIP_OPTS% -r requirements.txt
if not errorlevel 1 goto deps_ready
echo Install failed - often a network timeout - retrying once...
"%PY%" -m pip install %PIP_OPTS% -r requirements.txt
if errorlevel 1 goto fail
:deps_ready

echo [3/7] Checking spaCy language model...
"%PY%" -c "import spacy.util, sys; sys.exit(0 if spacy.util.is_package('en_core_web_lg') else 1)"
if not errorlevel 1 goto model_ready
"%PY%" -m spacy download en_core_web_lg
if not errorlevel 1 goto model_ready
echo WARNING: en_core_web_lg download failed - falling back to en_core_web_sm
"%PY%" -m spacy download en_core_web_sm
if errorlevel 1 goto fail

:model_ready
echo [4/7] Generating synthetic sample data...
"%PY%" -m src.generate_sample_data
if errorlevel 1 goto fail

echo [5/7] Scanning the sample data...
"%PY%" -m src.scan --source sample --workers 1
if errorlevel 1 goto fail

echo [6/7] Running tests...
"%PY%" -m pytest
if errorlevel 1 echo WARNING: some tests failed - see output above

if "%NO_DASHBOARD%"=="1" goto done
echo [7/7] Launching dashboard at http://localhost:8501 - press Ctrl+C to stop...
"%PY%" -m streamlit run dashboard\app.py
goto done

:fail
echo.
echo The demo stopped because a step failed. Scroll up for the error message.
pause
exit /b 1

:done
endlocal
