"""PII Risk Dashboard (Streamlit).

Run from the project folder:
    streamlit run dashboard/app.py

Every number on every page is read from the SQLite database written by
``python -m src.scan``; nothing is hardcoded. Set the environment variable
PII_DB_PATH to point the dashboard at a different database.
"""
from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src import load_config, resolve_path  # noqa: E402
from src.compliance import (compliance_table, dpdp_max_penalty_inr, format_eur, format_inr,  # noqa: E402
                            gdpr_max_fine_eur, remediation_actions)
from src.risk import RISK_COLORS, RISK_LEVELS, friendly  # noqa: E402
from src.storage import list_scans, load_scan  # noqa: E402

CFG = load_config()
DISCLAIMER = CFG["compliance"]["disclaimer"]
BAR_COLOR = "#2a78d6"  # single hue for magnitude charts
LEVEL_ICONS = {"High": "🔴", "Medium": "🟠", "Low": "🟢", "Clean": "⚪"}


def db_path() -> Path:
    env = os.environ.get("PII_DB_PATH")
    return Path(env) if env else resolve_path(CFG["paths"]["output_dir"]) / CFG["paths"]["db_file"]


# ---------------------------------------------------------------------------
# Data access (cached, invalidated when the database file changes)
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def _scans(path: str, mtime: float) -> pd.DataFrame:
    return list_scans(Path(path))


@st.cache_data(show_spinner=False)
def _scan_data(path: str, scan_id: int, mtime: float) -> dict:
    data = load_scan(Path(path), scan_id)
    docs = data["documents"]
    if not docs.empty:
        docs["file_name"] = docs["path"].map(lambda p: Path(str(p)).name)
        docs["date_parsed"] = pd.to_datetime(docs["date"], errors="coerce", utc=True)
    return data


def _mtime(p: Path) -> float:
    return p.stat().st_mtime if p.exists() else 0.0


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
CSS = """
<style>
.block-container {padding-top: 2rem; max-width: 1300px;}
.kpi {border: 1px solid rgba(128,128,128,.25); border-radius: 10px; padding: 14px 16px; height: 100%;}
.kpi .label {font-size: .8rem; opacity: .75; text-transform: uppercase; letter-spacing: .03em;}
.kpi .value {font-size: 1.9rem; font-weight: 700; line-height: 1.2; margin-top: 4px;}
.kpi .sub {font-size: .8rem; opacity: .7; margin-top: 2px;}
.kpi.high {border-left: 5px solid #d03b3b;}
.disclaimer {font-size: .8rem; opacity: .8; font-style: italic; margin: 4px 0 12px 0;}
.snippet {white-space: pre-wrap; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: .82rem;
          line-height: 1.5; padding: 12px; border-radius: 8px; border: 1px solid rgba(128,128,128,.25);
          max-height: 420px; overflow-y: auto;}
.pii {background: rgba(208,59,59,.14); border-bottom: 2px solid #d03b3b; border-radius: 3px; padding: 0 2px;}
.pii small {font-size: .65rem; opacity: .75; margin-right: 3px;}
.badge {display: inline-block; padding: 2px 10px; border-radius: 12px; font-weight: 600; font-size: .85rem; color: #fff;}
</style>
"""


def kpi(col, label: str, value: str, sub: str = "", high: bool = False) -> None:
    col.markdown(f"<div class='kpi{' high' if high else ''}'><div class='label'>{html.escape(label)}</div>"
                 f"<div class='value'>{html.escape(value)}</div><div class='sub'>{html.escape(sub)}</div></div>",
                 unsafe_allow_html=True)


def disclaimer() -> None:
    st.markdown(f"<div class='disclaimer'>⚠️ {html.escape(DISCLAIMER)}</div>", unsafe_allow_html=True)


def badge(level: str) -> str:
    color = RISK_COLORS.get(level, "#9aa0a6")
    text_color = "#1a1a19" if level == "Medium" else "#ffffff"
    return f"<span class='badge' style='background:{color};color:{text_color}'>{LEVEL_ICONS.get(level, '')} {level}</span>"


def style_fig(fig: go.Figure, height: int = 340) -> go.Figure:
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=40, b=10), legend_title_text="",
                      font=dict(size=13), hoverlabel=dict(font_size=13))
    fig.update_xaxes(showgrid=True, gridcolor="rgba(128,128,128,.15)", zeroline=False)
    fig.update_yaxes(showgrid=False, zeroline=False)
    return fig


def title_case(text: str) -> str:
    """Upper-case the first letter only, so acronyms like PAN and UPI survive."""
    return text[:1].upper() + text[1:]


def pct(part: float, whole: float) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "0.0%"


def highlight_snippet(snippet: str) -> str:
    """Render ``[[TYPE|masked]]`` markers as highlighted spans (values are already masked)."""
    escaped = html.escape(snippet or "")
    return re.sub(r"\[\[([A-Z_]+)\|(.*?)\]\]",
                  lambda m: f"<span class='pii'><small>{m.group(1)}</small>{m.group(2)}</span>", escaped)


# ---------------------------------------------------------------------------
# Empty state: no scan yet
# ---------------------------------------------------------------------------
def render_empty_state() -> None:
    st.title("🛡️ PII Detector and Risk Dashboard")
    st.info("No scan results found yet. Run a scan from a terminal in the project folder:")
    st.code("python -m src.generate_sample_data\npython -m src.scan --source sample", language="bash")
    st.write("…or click the button below to generate the synthetic sample data and scan it now "
             "(takes about a minute).")
    if st.button("▶ Run sample scan now", type="primary"):
        with st.spinner("Generating synthetic data and scanning… this takes about a minute"):
            sample_dir = resolve_path(CFG["paths"]["sample_dir"])
            steps = []
            if not (sample_dir / "ground_truth.csv").exists():
                steps.append([sys.executable, "-m", "src.generate_sample_data"])
            steps.append([sys.executable, "-m", "src.scan", "--source", "sample", "--workers", "1"])
            env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
            for cmd in steps:
                proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, env=env,
                                      encoding="utf-8", errors="replace")
                if proc.returncode != 0:
                    st.error(f"Command failed: {' '.join(cmd[1:])}")
                    st.code((proc.stdout or "")[-3000:] + "\n" + (proc.stderr or "")[-3000:])
                    return
        st.cache_data.clear()
        st.success("Scan complete - loading results.")
        st.rerun()


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def page_executive(docs, findings, stats, scan_row) -> None:
    n = len(docs)
    levels = {lvl: int((docs["risk_level"] == lvl).sum()) if n else 0 for lvl in RISK_LEVELS}
    with_pii = n - levels["Clean"]
    turnover_eur = st.session_state.get("turnover_m", CFG["compliance"]["gdpr"]["default_turnover_eur"] / 1e6) * 1e6
    exposure = stats.get("exposure_index", {"index": 0, "band": "Low"})

    c = st.columns(4)
    skipped = int(scan_row.get("docs_skipped", 0))
    kpi(c[0], "Documents scanned", f"{n:,}", f"{skipped} unreadable file{'' if skipped == 1 else 's'} skipped")
    kpi(c[1], "Documents with PII", pct(with_pii, n), f"{with_pii:,} of {n:,} documents")
    kpi(c[2], "High-risk files", f"{levels['High']:,}", f"{pct(levels['High'], n)} of all documents", high=True)
    kpi(c[3], "Unique identifiers", f"{stats.get('unique_identifiers_total', 0):,}",
        f"≈ at least {stats.get('unique_individuals_estimate', 0):,} individuals")
    st.write("")
    c = st.columns(3)
    kpi(c[0], "Exposure index", f"{exposure['index']} / 100", f"{exposure['band']} - people affected × severity")
    kpi(c[1], "DPDP Act ceiling", format_inr(dpdp_max_penalty_inr()).replace("INR ", "₹"),
        "max. penalty per breach (security safeguards)")
    kpi(c[2], "GDPR ceiling", format_eur(gdpr_max_fine_eur(turnover_eur)),
        f"at hypothetical turnover {format_eur(turnover_eur)} (edit in Compliance View)")
    disclaimer()

    left, right = st.columns([1, 1.3])
    with left:
        if n:
            vals = [levels[l] for l in RISK_LEVELS]
            fig = go.Figure(go.Pie(labels=RISK_LEVELS, values=vals, hole=0.62,
                                   marker=dict(colors=[RISK_COLORS[l] for l in RISK_LEVELS],
                                               line=dict(color="rgba(255,255,255,0.9)", width=2)),
                                   sort=False, direction="clockwise", textinfo="value",
                                   hovertemplate="%{label}: %{value} documents (%{percent})<extra></extra>"))
            fig.update_layout(title="Documents by risk level",
                              annotations=[dict(text=f"<b>{n:,}</b><br>documents", showarrow=False, font_size=16)])
            st.plotly_chart(style_fig(fig, 360), width="stretch")
    with right:
        st.subheader("Summary for leadership")
        st.write(executive_text(docs, findings, stats, levels))


def executive_text(docs, findings, stats, levels) -> str:
    """3-4 sentence plain-English summary built only from scan numbers."""
    n = len(docs)
    if n == 0:
        return "The selected scan contains no documents."
    with_pii = n - levels["Clean"]
    parts = [f"Of {n:,} documents scanned, {levels['High']:,} ({pct(levels['High'], n)}) contain high-risk personal "
             f"data and a further {levels['Medium']:,} ({pct(levels['Medium'], n)}) are medium risk; "
             f"{with_pii:,} ({pct(with_pii, n)}) contain some personal data."]
    scored = findings[~findings["entity_type"].isin(CFG["risk"]["excluded_from_scoring"])] if not findings.empty else findings
    if not scored.empty:
        by_docs = scored.groupby("entity_type")["doc_id"].nunique().sort_values(ascending=False)
        top = [f"{friendly(t, 2)} ({int(c)} files)" for t, c in by_docs.head(3).items()]
        parts.append(f"The most widespread types are {', '.join(top[:-1]) + ' and ' + top[-1] if len(top) > 1 else top[0]}.")
    toxic = int(docs["toxic"].sum())
    if toxic:
        parts.append(f"{toxic:,} files link a person to health, salary or financial details - the combination "
                     f"that does the most harm if leaked - and together the scan found identifiers for at least "
                     f"{stats.get('unique_individuals_estimate', 0):,} distinct people.")
    high = docs[docs["risk_level"] == "High"]
    if not high.empty:
        ft = high["file_type"].value_counts()
        parts.append(f"High-risk data is concentrated in {ft.index[0].upper()} files ({int(ft.iloc[0])} of "
                     f"{len(high)}), so restricting access to those and masking identifiers is the fastest way "
                     f"to cut exposure.")
    return " ".join(parts)


def page_where(docs, findings) -> None:
    if docs.empty:
        st.info("No documents in this scan.")
        return
    include_noisy = st.toggle("Include DATE_TIME and LOCATION (stored, but not used for scoring)", value=False)
    f = findings if include_noisy else findings[~findings["entity_type"].isin(CFG["risk"]["excluded_from_scoring"])]

    c1, c2 = st.columns(2)
    with c1:
        if f.empty:
            st.info("No findings to chart.")
        else:
            counts = f.groupby("entity_type").agg(findings=("doc_id", "size"), documents=("doc_id", "nunique"))
            counts = counts.sort_values("findings").reset_index()
            counts["label"] = counts["entity_type"].map(lambda t: title_case(friendly(t, 2)))
            fig = px.bar(counts, x="findings", y="label", orientation="h", title="PII findings by entity type",
                         custom_data=["documents", "entity_type"], text="findings")
            fig.update_traces(marker_color=BAR_COLOR, textposition="outside", cliponaxis=False,
                              hovertemplate="%{y} (%{customdata[1]})<br>%{x:,} findings in %{customdata[0]} "
                                            "documents<extra></extra>")
            fig.update_layout(yaxis_title="", xaxis_title="Findings",
                              xaxis_range=[0, counts["findings"].max() * 1.15])
            st.plotly_chart(style_fig(fig, 460), width="stretch")
    with c2:
        ft = docs.groupby(["file_type", "risk_level"]).size().reset_index(name="documents")
        fig = px.bar(ft, x="documents", y="file_type", color="risk_level", orientation="h",
                     category_orders={"risk_level": RISK_LEVELS}, color_discrete_map=RISK_COLORS,
                     title="Documents by file type and risk level")
        fig.update_traces(marker_line_color="rgba(255,255,255,0.9)", marker_line_width=1,
                          hovertemplate="%{y}: %{x} documents<extra>%{fullData.name}</extra>")
        fig.update_layout(yaxis_title="", xaxis_title="Documents", barmode="stack",
                          legend=dict(orientation="h", yanchor="bottom", y=1.0, x=0), margin=dict(t=80))
        st.plotly_chart(style_fig(fig, 460), width="stretch")

    c3, c4 = st.columns(2)
    with c3:
        senders = docs[(docs["sender"].fillna("") != "") & docs["risk_level"].isin(["High", "Medium"])]
        if senders.empty:
            st.info("No sender metadata with medium/high-risk content (sender comes from email headers).")
        else:
            top = senders["sender"].value_counts().head(10).index
            s = senders[senders["sender"].isin(top)].groupby(["sender", "risk_level"]).size().reset_index(name="documents")
            order = senders["sender"].value_counts().head(10).index[::-1].tolist()
            fig = px.bar(s, x="documents", y="sender", color="risk_level", orientation="h",
                         category_orders={"sender": order, "risk_level": ["High", "Medium"]},
                         color_discrete_map=RISK_COLORS, title="Top 10 senders of sensitive data")
            fig.update_traces(marker_line_color="rgba(255,255,255,0.9)", marker_line_width=1,
                              hovertemplate="%{y}: %{x} documents<extra>%{fullData.name}</extra>")
            fig.update_layout(yaxis_title="", xaxis_title="High/medium-risk emails", barmode="stack",
                              legend=dict(orientation="h", yanchor="bottom", y=1.0, x=0), margin=dict(t=80))
            st.plotly_chart(style_fig(fig, 420), width="stretch")
    with c4:
        dated = docs.dropna(subset=["date_parsed"])
        dated = dated[dated["risk_level"] != "Clean"]
        if dated.empty:
            st.info("No dates available to build a timeline.")
        else:
            local = dated["date_parsed"].dt.tz_convert(None)
            span_months = (local.max() - local.min()).days / 30.4
            freq, label = ("Q", "quarter") if span_months > 18 else ("M", "month")
            dated = dated.assign(period=local.dt.to_period(freq).dt.to_timestamp())
            periods = pd.period_range(local.min(), local.max(), freq=freq).to_timestamp()
            levels_present = [l for l in ["High", "Medium", "Low"] if l in set(dated["risk_level"])]
            grid = pd.MultiIndex.from_product([periods, levels_present], names=["period", "risk_level"])
            tl = (dated.groupby(["period", "risk_level"]).size().reindex(grid, fill_value=0)
                  .reset_index(name="documents"))
            fig = px.line(tl, x="period", y="documents", color="risk_level", markers=True,
                          category_orders={"risk_level": ["High", "Medium", "Low"]}, color_discrete_map=RISK_COLORS,
                          title=f"Documents with personal data, by {label}")
            fig.update_traces(line_width=2, marker_size=8,
                              hovertemplate="%{y} documents<extra>%{fullData.name}</extra>")
            fig.update_layout(xaxis_title="", yaxis_title="Documents", hovermode="x unified",
                              legend=dict(orientation="h", yanchor="bottom", y=1.0, x=0), margin=dict(t=80))
            fig.update_yaxes(showgrid=True, gridcolor="rgba(128,128,128,.15)")
            st.plotly_chart(style_fig(fig, 420), width="stretch")


def page_explorer(docs, findings) -> None:
    if docs.empty:
        st.info("No documents in this scan.")
        return
    types_by_doc = findings.groupby("doc_id")["entity_type"].agg(set) if not findings.empty else pd.Series(dtype=object)
    c = st.columns([1.2, 1.4, 1, 1.4])
    levels = c[0].multiselect("Risk level", RISK_LEVELS, default=["High", "Medium"])
    ents = c[1].multiselect("Entity type", sorted(findings["entity_type"].unique()) if not findings.empty else [])
    ftypes = c[2].multiselect("File type", sorted(docs["file_type"].unique()))
    senders = sorted(s for s in docs["sender"].dropna().unique() if s)
    sender = c[3].selectbox("Sender", ["(any)"] + senders)
    query = st.text_input("Search file name, subject or reason", placeholder="e.g. payroll, Aadhaar, salary")

    view = docs
    if levels:
        view = view[view["risk_level"].isin(levels)]
    if ents:
        view = view[view["doc_id"].map(lambda d: bool(set(ents) & types_by_doc.get(d, set())))]
    if ftypes:
        view = view[view["file_type"].isin(ftypes)]
    if sender != "(any)":
        view = view[view["sender"] == sender]
    if query:
        q = query.lower()
        view = view[view["file_name"].str.lower().str.contains(q, regex=False)
                    | view["subject"].fillna("").str.lower().str.contains(q, regex=False)
                    | view["reason"].fillna("").str.lower().str.contains(q, regex=False)]
    view = view.sort_values("risk_score", ascending=False).reset_index(drop=True)
    st.caption(f"{len(view):,} of {len(docs):,} documents match. Select a row to see its findings.")

    table = view[["risk_level", "risk_score", "file_name", "file_type", "sender", "date", "finding_count", "reason"]].copy()
    table["risk_level"] = table["risk_level"].map(lambda l: f"{LEVEL_ICONS.get(l, '')} {l}")
    table["date"] = table["date"].fillna("").str[:10]
    event = st.dataframe(
        table, width="stretch", hide_index=True, height=360, on_select="rerun", selection_mode="single-row",
        column_config={"risk_level": "Risk", "risk_score": st.column_config.ProgressColumn("Score", min_value=0,
                       max_value=100, format="%.1f"), "file_name": "File", "file_type": "Type", "sender": "Sender",
                       "date": "Date", "finding_count": "Findings", "reason": st.column_config.TextColumn("Reason", width="large")})
    if view.empty:
        return
    rows = event.selection.rows if event and hasattr(event, "selection") else []
    doc = view.iloc[rows[0] if rows else 0]
    if not rows:
        st.caption("Showing the highest-risk match. Click a row above to inspect another document.")

    st.markdown(f"#### {html.escape(doc['file_name'])} &nbsp; {badge(doc['risk_level'])} &nbsp; "
                f"score **{doc['risk_score']:.1f}**", unsafe_allow_html=True)
    st.markdown(f"**Why:** {doc['reason']}")
    meta = [f"**Path:** `{doc['path']}`", f"**Type:** {doc['file_type']}"]
    if doc["sender"]:
        meta.append(f"**Sender:** {doc['sender']}")
    if doc["subject"]:
        meta.append(f"**Subject (masked):** {doc['subject']}")
    if doc["truncated"]:
        meta.append("**Note:** text was truncated to the configured maximum length")
    st.markdown(" · ".join(meta))

    left, right = st.columns([1, 1.4])
    doc_f = findings[findings["doc_id"] == doc["doc_id"]]
    with left:
        st.markdown("**Findings (masked values only)**")
        if doc_f.empty:
            st.write("No findings.")
        else:
            summary = doc_f.groupby("entity_type").agg(count=("entity_type", "size"),
                                                       avg_confidence=("confidence", "mean")).reset_index()
            summary = summary.sort_values("count", ascending=False)
            st.dataframe(summary, hide_index=True, width="stretch",
                         column_config={"avg_confidence": st.column_config.NumberColumn("Avg confidence", format="%.2f")})
            st.dataframe(doc_f[["entity_type", "masked_value", "confidence"]].head(200), hide_index=True,
                         width="stretch", height=240)
    with right:
        st.markdown("**Text preview (PII highlighted and masked)**")
        st.markdown(f"<div class='snippet'>{highlight_snippet(doc['masked_snippet'])}</div>", unsafe_allow_html=True)


def page_compliance(docs, findings, stats) -> None:
    disclaimer()
    if findings.empty:
        st.info("No personal data was found, so no regulatory categories apply to this scan.")
    else:
        counts = findings.groupby("entity_type").agg(findings=("doc_id", "size"), documents=("doc_id", "nunique"))
        table = pd.DataFrame(compliance_table(list(counts.index))).set_index("entity_type").join(counts)
        table = table.sort_values("findings", ascending=False).reset_index()
        st.subheader("Detected data mapped to DPDP Act 2023 and GDPR")
        st.caption("DPDP does not define a separate 'sensitive' category; identity, financial and health data are "
                   "flagged here as higher risk. GDPR Article 9 'special category' data (e.g. health) needs an "
                   "explicit legal basis.")
        st.dataframe(table, hide_index=True, width="stretch", column_config={
            "entity_type": "Entity", "dpdp_category": "DPDP category", "dpdp_higher_risk": "DPDP higher risk",
            "gdpr_category": "GDPR category", "gdpr_special_category": "GDPR Art. 9", "financial": "Financial"})

    st.subheader("Exposure calculator")
    g = CFG["compliance"]["gdpr"]
    c1, c2 = st.columns([1, 2])
    with c1:
        turnover_m = st.number_input("Hypothetical worldwide annual turnover (EUR million)", min_value=0.0,
                                     value=float(st.session_state.get("turnover_m", g["default_turnover_eur"] / 1e6)),
                                     step=50.0, key="turnover_input")
        st.session_state["turnover_m"] = turnover_m
    turnover = turnover_m * 1e6
    gdpr = gdpr_max_fine_eur(turnover)
    dpdp = dpdp_max_penalty_inr()
    rate = CFG["compliance"]["eur_to_inr"]
    with c2:
        c = st.columns(3)
        kpi(c[0], "GDPR ceiling", format_eur(gdpr),
            f"higher of EUR {g['fixed_cap_eur'] / 1e6:.0f}m or {g['turnover_pct']}% of turnover")
        kpi(c[1], "DPDP ceiling", format_inr(dpdp).replace("INR ", "₹"), f"≈ {format_eur(dpdp / rate)} at {rate:g} INR/EUR")
        e = stats.get("exposure_index", {"index": 0, "band": "Low", "scale_component": 0, "severity_component": 0})
        kpi(c[2], "Exposure index", f"{e['index']} / 100",
            f"{e['band']}: scale {e['scale_component']} + severity {e['severity_component']}")
    disclaimer()

    n = len(docs)
    special = findings[findings["entity_type"] == "HEALTH_INFO"]["doc_id"].nunique() if not findings.empty else 0
    fin_types = ["BANK_ACCOUNT", "CREDIT_CARD", "IN_UPI", "IBAN_CODE", "SALARY"]
    fin = findings[findings["entity_type"].isin(fin_types)]["doc_id"].nunique() if not findings.empty else 0
    st.markdown(
        f"- **{special:,}** documents ({pct(special, n)}) contain health information (GDPR special category).\n"
        f"- **{fin:,}** documents ({pct(fin, n)}) contain financial data (accounts, cards, UPI, salary).\n"
        f"- At least **{stats.get('unique_individuals_estimate', 0):,}** distinct individuals are identifiable "
        f"(largest unique count of any single identifier type; "
        f"{stats.get('unique_identifiers_total', 0):,} unique identifiers in total).")
    with st.expander("How the exposure index is calculated"):
        ec = CFG["compliance"]["exposure_index"]
        st.markdown(
            f"* **Scale (0-{ec['scale_weight']})**: log-scaled number of unique individuals relative to "
            f"{ec['reference_individuals']:,} people.\n"
            f"* **Severity (0-{ec['severity_weight']})**: share of documents with PII that are High risk "
            f"(Medium counts half).\n"
            "* Bands: < 25 Low, 25-50 Moderate, 50-75 High, 75+ Critical.")
    with st.expander("Other DPDP Act penalty ceilings (Schedule)"):
        other = CFG["compliance"]["dpdp"]["other_penalties_crore"]
        st.table(pd.DataFrame([{"Breach": k, "Maximum penalty": f"₹{v} crore"} for k, v in other.items()]))
        disclaimer()


def page_remediation(docs, findings, redactions, scan_row) -> None:
    settings = json.loads(scan_row.get("settings_json") or "{}")
    actions = remediation_actions(docs, findings, settings.get("path", ""), scan_row.get("finished_at"))
    st.subheader("Recommended actions")
    if not actions:
        st.success("No remediation actions needed - no personal data was detected.")
    for a in actions:
        icon = {"P1": "🔴", "P2": "🟠", "P3": "🔵"}[a["priority"]]
        with st.container(border=True):
            st.markdown(f"{icon} **{a['priority']} · {a['action']}**  \n<span style='opacity:.75'>{a['why']}</span>",
                        unsafe_allow_html=True)

    st.subheader("Redacted samples (remediation demo)")
    if redactions.empty:
        st.info("No redacted samples for this scan (it was run with --no-redact, or nothing needed redaction).")
        return
    st.caption("Top highest-risk documents with every detected value replaced by an <ENTITY_TYPE> tag.")
    for _, r in redactions.iterrows():
        p = Path(r["redacted_path"])
        c1, c2 = st.columns([3, 1])
        c1.markdown(f"`{p.name}`")
        if p.exists():
            content = p.read_text(encoding="utf-8", errors="replace")
            c2.download_button("Download", content, file_name=p.name, key=f"dl_{p.name}", width="stretch")
            with st.expander(f"Preview {p.name}"):
                st.code(content[:4000], language=None)
        else:
            c2.caption("file no longer on disk")


def page_about(stats, scan_row) -> None:
    source = str(scan_row.get("source", ""))
    is_enron = source.startswith("enron")
    st.markdown(f"""
### What is PII?
**Personally Identifiable Information** is any data that can identify a person on its own or combined with other
data: names, email addresses, phone numbers, government IDs (Aadhaar, PAN), bank and card details, salaries and
health information. Laws such as India's **DPDP Act 2023** and the EU **GDPR** require companies to know where this
data lives, protect it and delete it when no longer needed.

### How this tool works
1. **Ingest** - reads emails (.eml/.msg), text, Word, PDF, CSV and Excel files (or the Enron email CSV) into plain
   text. Spreadsheet rows are read as `Column: value` pairs so each value keeps its label.
2. **Detect** - Microsoft Presidio with the spaCy `{stats.get('spacy_model', 'en_core_web_lg')}` model finds names
   and places; custom recognizers find Indian identifiers using a pattern, nearby context words and validation
   (e.g. the Verhoeff checksum for Aadhaar, the holder-type letter for PAN). Findings below
   {json.loads(scan_row.get('settings_json') or '{{}}').get('min_score', CFG['detection']['min_score'])} confidence
   are dropped.
3. **Score** - each finding adds *weight × confidence*; files with many sensitive records get a volume bonus; a
   person or ID together with health, salary or financial data is always **High** ("toxic combination").
4. **Store & act** - results go to SQLite and CSV; the 10 riskiest files are redacted as a remediation example.
   Only **masked** values (e.g. `XXXX XXXX 1234`) are ever stored or shown.
""")
    weights = CFG["risk"]["weights"]
    excluded = set(CFG["risk"]["excluded_from_scoring"])
    wt = pd.DataFrame([{"Entity": k, "Meaning": title_case(friendly(k)), "Weight": v,
                        "Scored": "No (stored only)" if k in excluded else "Yes"} for k, v in weights.items()])
    th = CFG["risk"]["thresholds"]
    c1, c2 = st.columns([1.3, 1])
    with c1:
        st.markdown("**Sensitivity weights** (edit in `config.yaml`)")
        st.dataframe(wt.sort_values("Weight", ascending=False), hide_index=True, width="stretch",
                     height=35 * (len(wt) + 1) + 3)
    with c2:
        st.markdown(f"""**Risk levels**
- 🔴 **High**: score ≥ {th['high']} or a toxic combination
- 🟠 **Medium**: score ≥ {th['medium']}
- 🟢 **Low**: score below {th['medium']}
- ⚪ **Clean**: no scored findings

**Volume bonus**: {', '.join(f'+{b} at {m}+ sensitive records' for m, b in CFG['risk']['volume_bonus']['tiers'])}.
Score is capped at {CFG['risk']['max_score']}.""")

    acc = stats.get("accuracy")
    if acc:
        st.markdown(f"### Accuracy on this scan's ground truth ({acc['files_evaluated']} files)")
        st.caption("File-level: for each file and entity type, was a planted type found (recall) and was a found "
                   "type actually planted (precision)?")
        st.dataframe(pd.DataFrame(acc["per_entity"]), hide_index=True, width="stretch",
                     height=35 * (len(acc["per_entity"]) + 1) + 3)
        st.markdown(f"Micro-average precision **{acc['micro_precision']:.2f}**, recall **{acc['micro_recall']:.2f}**; "
                    f"risk tier matches the planted tier for **{acc['risk_tier_accuracy']:.0%}** of files.")

    st.markdown(f"""
### Data source for this scan
{"**Enron email corpus** (real, public US corporate email released during the FERC investigation). Indian identifiers such as Aadhaar or PAN are naturally rare in it." if is_enron else "**Synthetic data** generated by `src/generate_sample_data.py`. Every name, number and amount is fake; identifiers follow official formats (Aadhaar passes the Verhoeff checksum) but belong to nobody." if "sample" in source else f"**Your own folder**: `{source.split(':', 1)[-1]}`."}

### Limitations
- Pattern-based detection produces some **false positives** (e.g. a 12-digit order number that happens to pass the
  Aadhaar checksum) and **false negatives** (names spaCy does not recognise, unusual formats, scanned images - no OCR).
- Accuracy on synthetic data is optimistic because the templates are regular; real data will score lower.
- Unique-individual counts are an approximation (largest unique count of any one identifier type).
- Penalty figures are statutory **ceilings** used for illustration. {DISCLAIMER}
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    st.set_page_config(page_title="PII Risk Dashboard", page_icon="🛡️", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    path = db_path()
    scans = _scans(str(path), _mtime(path))
    if scans.empty:
        render_empty_state()
        return

    with st.sidebar:
        st.markdown("## 🛡️ PII Risk Dashboard")
        labels = {int(r.scan_id): f"#{r.scan_id} · {Path(str(r.source).split(':', 1)[-1]).name or r.source} · "
                                  f"{int(r.docs_scanned):,} docs · {str(r.finished_at)[:10]}"
                  for r in scans.itertuples()}
        scan_id = st.selectbox("Scan to view", list(labels), format_func=labels.get)
        row = scans[scans["scan_id"] == scan_id].iloc[0].to_dict()
        st.caption(f"Source: `{row['source']}`")
        st.caption(f"Database: `{path}`")
        if st.button("↻ Reload data"):
            st.cache_data.clear()
            st.rerun()
        st.divider()
        st.caption(DISCLAIMER)

    data = _scan_data(str(path), int(scan_id), _mtime(path))
    docs, findings = data["documents"], data["findings"]
    stats = json.loads(row.get("stats_json") or "{}")

    st.title("PII Detector and Risk Dashboard")
    st.caption(f"Scan #{scan_id} · {row['source']} · finished {str(row['finished_at'])[:19].replace('T', ' ')} UTC")
    tabs = st.tabs(["Executive Summary", "Where Is The Risk", "File Explorer", "Compliance View", "Remediation", "About"])
    with tabs[0]:
        page_executive(docs, findings, stats, row)
    with tabs[1]:
        page_where(docs, findings)
    with tabs[2]:
        page_explorer(docs, findings)
    with tabs[3]:
        page_compliance(docs, findings, stats)
    with tabs[4]:
        page_remediation(docs, findings, data["redactions"], row)
    with tabs[5]:
        page_about(stats, row)


if __name__ == "__main__":  # `streamlit run` executes this file as __main__
    main()
