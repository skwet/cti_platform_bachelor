"""
Shared NiceGUI layout: dark sidebar + topbar.
Every page calls:  with theme.layout('Дашборд'): ...body...
"""
from contextlib import contextmanager
from nicegui import ui

# ── Palette ───────────────────────────────────────────────────────────────────
BG       = "#0f172a"
SIDEBAR  = "#1e293b"
CARD     = "#1e293b"
BORDER   = "rgba(255,255,255,0.08)"
TEXT     = "#e2e8f0"
MUTED    = "#94a3b8"
PRIMARY  = "#3b82f6"
DANGER   = "#ef4444"
WARNING  = "#f59e0b"
SUCCESS  = "#10b981"

SEV_COLOR = {
    "critical": DANGER,
    "high":     WARNING,
    "medium":   "#f59e0b",
    "low":      SUCCESS,
    "unknown":  "#64748b",
}

NAV_ITEMS = [
    ("dashboard",   "Дашборд",   "/"),
    ("search",      "Аналіз IoC","/search"),
    ("list",        "База IoC",  "/iocs"),
]

# ── Global CSS ────────────────────────────────────────────────────────────────
GLOBAL_CSS = f"""
* {{ box-sizing: border-box; }}
html, body {{
    margin: 0; padding: 0;
    width: 100%; height: 100%;
}}
body, .nicegui-content {{
    background: {BG} !important;
    color: {TEXT};
    font-family: 'Inter', 'Segoe UI', sans-serif;
    margin: 0; padding: 0;
    min-height: 100vh;
    width: 100%;
}}
.nicegui-content {{
    padding: 0 !important;
    max-width: none !important;
    width: 100% !important;
}}
.sidebar {{
    background: {SIDEBAR};
    border-right: 1px solid {BORDER};
    width: 220px; min-height: 100vh;
    display: flex; flex-direction: column;
    position: fixed; top: 0; left: 0; z-index: 100;
}}
.sidebar-logo {{
    padding: 20px 18px 16px;
    font-size: 1.1rem; font-weight: 700;
    color: {TEXT};
    border-bottom: 1px solid {BORDER};
    display: flex; align-items: center; gap: 10px;
}}
.nav-link {{
    display: flex; align-items: center; gap: 10px;
    padding: 10px 18px;
    color: {MUTED};
    text-decoration: none;
    font-size: 0.9rem;
    border-radius: 6px;
    margin: 2px 8px;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
}}
.nav-link:hover {{ background: rgba(255,255,255,0.06); color: {TEXT}; }}
.nav-link.active {{ background: rgba(59,130,246,0.15); color: {PRIMARY}; }}
.main-wrap {{
    margin-left: 220px;
    display: flex; flex-direction: column; min-height: 100vh;
    flex: 1;
    width: calc(100vw - 220px);
    min-width: 0;
}}
.topbar {{
    background: {SIDEBAR};
    border-bottom: 1px solid {BORDER};
    padding: 12px 24px;
    display: flex; align-items: center; justify-content: space-between;
    width: 100%;
}}
.page-content {{
    padding: 24px;
    flex: 1;
    width: 100%;
    min-width: 0;
    overflow-x: hidden;
}}
.cti-card {{
    background: {CARD};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 16px;
}}
.stat-card {{
    background: {CARD};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 18px 20px;
    display: flex; align-items: center; gap: 16px;
}}
.stat-icon {{
    width: 44px; height: 44px; border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.3rem;
}}
.stat-icon.purple {{ background: rgba(139,92,246,0.15); color: #8b5cf6; }}
.stat-icon.red    {{ background: rgba(239,68,68,0.15);  color: {DANGER}; }}
.stat-icon.green  {{ background: rgba(16,185,129,0.15); color: {SUCCESS}; }}
.stat-icon.blue   {{ background: rgba(59,130,246,0.15); color: {PRIMARY}; }}
.badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 0.75rem; font-weight: 600;
}}
.badge-critical {{ background: rgba(239,68,68,0.15);  color: {DANGER};  border: 1px solid rgba(239,68,68,0.3); }}
.badge-high     {{ background: rgba(245,158,11,0.15); color: {WARNING}; border: 1px solid rgba(245,158,11,0.3); }}
.badge-medium   {{ background: rgba(245,158,11,0.10); color: #f59e0b;   border: 1px solid rgba(245,158,11,0.2); }}
.badge-low      {{ background: rgba(16,185,129,0.15); color: {SUCCESS}; border: 1px solid rgba(16,185,129,0.3); }}
.badge-unknown  {{ background: rgba(100,116,139,0.15);color: #64748b;   border: 1px solid rgba(100,116,139,0.3); }}
.badge-ip       {{ background: rgba(59,130,246,0.15); color: {PRIMARY}; border: 1px solid rgba(59,130,246,0.3); }}
.badge-domain   {{ background: rgba(139,92,246,0.15); color: #8b5cf6;   border: 1px solid rgba(139,92,246,0.3); }}
.badge-url      {{ background: rgba(236,72,153,0.15); color: #ec4899;   border: 1px solid rgba(236,72,153,0.3); }}
.badge-hash     {{ background: rgba(6,182,212,0.15);  color: #06b6d4;   border: 1px solid rgba(6,182,212,0.3); }}
.badge-email    {{ background: rgba(251,146,60,0.15); color: #fb923c;   border: 1px solid rgba(251,146,60,0.3); }}
.mono {{ font-family: 'JetBrains Mono', 'Fira Mono', monospace; font-size: 0.85rem; }}
.section-title {{
    font-size: 0.95rem; font-weight: 600; color: {TEXT};
    padding-bottom: 10px; border-bottom: 1px solid {BORDER};
    margin-bottom: 14px;
}}
.kv-row {{ display: flex; flex-direction: column; gap: 2px; }}
.kv-key {{ font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.5px; color: {MUTED}; }}
.kv-val {{ font-size: 0.88rem; color: {TEXT}; word-break: break-all; }}
/* Quasar overrides */
.q-field__control, .q-field__native {{ color: {TEXT} !important; }}
.q-table {{ background: {CARD} !important; color: {TEXT} !important; }}
.q-table th {{ color: {MUTED} !important; font-size: 0.75rem !important;
               text-transform: uppercase !important; letter-spacing: 0.4px !important; }}
.q-table td {{ border-color: {BORDER} !important; font-size: 0.85rem !important; }}
.q-table tbody tr:hover td {{ background: rgba(255,255,255,0.03) !important; }}
.q-tab {{ color: {MUTED} !important; }}
.q-tab--active {{ color: {PRIMARY} !important; }}
.q-tabs__content {{ border-bottom: 1px solid {BORDER}; }}
"""


def sev_badge_html(sev: str) -> str:
    s = (sev or "unknown").lower()
    return f'<span class="badge badge-{s}">{s.upper()}</span>'


def type_badge_html(t: str) -> str:
    t = (t or "").lower()
    if t.startswith("hash"):
        cls = "hash"
        label = t.replace("hash_", "").upper()
    else:
        cls = t
        label = t.upper()
    return f'<span class="badge badge-{cls}">{label}</span>'


def risk_color(score: float | None) -> str:
    if score is None:
        return "#64748b"
    if score >= 75:
        return DANGER
    if score >= 50:
        return WARNING
    if score >= 25:
        return "#f59e0b"
    return SUCCESS


@contextmanager
def layout(page_title: str, active_path: str = "/"):
    """Context manager that renders the sidebar + topbar and yields the content area."""
    ui.add_css(GLOBAL_CSS)

    with ui.row().style("width:100%;gap:0;min-height:100vh;flex-wrap:nowrap"):
        # ── Sidebar ──────────────────────────────────────────────────────────
        with ui.element("nav").classes("sidebar"):
            with ui.element("div").classes("sidebar-logo"):
                ui.icon("shield").style(f"color:{PRIMARY};font-size:1.4rem")
                ui.label("CTI Platform").style("font-size:1rem;font-weight:700")

            ui.space().style("height:8px")

            for icon, label, path in NAV_ITEMS:
                is_active = active_path == path
                cls = "nav-link active" if is_active else "nav-link"
                with ui.element("a").classes(cls).props(f'href="{path}"'):
                    ui.icon(icon).style("font-size:1.1rem")
                    ui.label(label)

        # ── Main wrapper ─────────────────────────────────────────────────────
        with ui.element("div").classes("main-wrap"):
            # Topbar
            with ui.element("div").classes("topbar"):
                ui.label(page_title).style(
                    f"font-size:1.1rem;font-weight:600;color:{TEXT}"
                )

            # Page content
            with ui.element("div").classes("page-content"):
                yield