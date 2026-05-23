"""
Спільний макет: темна тема, бічна панель, хедер.
"""
from contextlib import contextmanager
from nicegui import ui

PRIMARY = "#3b82f6"
DANGER  = "#ef4444"
WARNING = "#f59e0b"
SUCCESS = "#10b981"
MUTED   = "#94a3b8"
TEXT    = "#e2e8f0"
BG      = "#0f172a"
CARD    = "#1e293b"
BORDER  = "rgba(255,255,255,0.08)"

SEV_COLOR = {
    "critical": DANGER,
    "high":     WARNING,
    "medium":   "#f59e0b",
    "low":      SUCCESS,
    "unknown":  "#64748b",
}

CSS = f"""
body {{ background:{BG}; color:{TEXT}; font-family:sans-serif; margin:0; }}
.nicegui-content {{ padding:0 !important; max-width:none !important; }}
.sidebar {{
    position:fixed; top:0; left:0; width:200px; height:100vh;
    background:{CARD}; border-right:1px solid {BORDER};
    display:flex; flex-direction:column; z-index:10; padding:16px 8px;
}}
.nav-link {{
    display:flex; align-items:center; gap:8px; padding:8px 12px;
    color:{MUTED}; text-decoration:none; border-radius:6px; font-size:0.9rem;
}}
.nav-link:hover {{ background:rgba(255,255,255,0.05); color:{TEXT}; }}
.nav-link.active {{ background:rgba(59,130,246,0.15); color:{PRIMARY}; }}
.main {{ margin-left:200px; padding:24px; }}
.card {{
    background:{CARD}; border:1px solid {BORDER};
    border-radius:8px; padding:16px; margin-bottom:16px;
}}
.badge {{
    display:inline-block; padding:2px 8px; border-radius:4px;
    font-size:0.75rem; font-weight:600;
}}
.badge-critical {{ background:rgba(239,68,68,0.15); color:{DANGER}; }}
.badge-high     {{ background:rgba(245,158,11,0.15); color:{WARNING}; }}
.badge-medium   {{ background:rgba(245,158,11,0.10); color:#f59e0b; }}
.badge-low      {{ background:rgba(16,185,129,0.15); color:{SUCCESS}; }}
.badge-unknown  {{ background:rgba(100,116,139,0.15);color:#64748b; }}
.badge-ip       {{ background:rgba(59,130,246,0.15); color:{PRIMARY}; }}
.badge-domain   {{ background:rgba(139,92,246,0.15); color:#8b5cf6; }}
.badge-url      {{ background:rgba(236,72,153,0.15); color:#ec4899; }}
.badge-hash     {{ background:rgba(6,182,212,0.15);  color:#06b6d4; }}
.badge-email    {{ background:rgba(251,146,60,0.15); color:#fb923c; }}
.q-table        {{ background:{CARD} !important; color:{TEXT} !important; }}
.q-table th     {{ color:{MUTED} !important; font-size:0.8rem !important; }}
.q-table td     {{ border-color:{BORDER} !important; font-size:0.85rem !important; }}
"""

NAV = [
    ("dashboard", "Дашборд",  "/"),
    ("search",    "Аналіз",   "/search"),
    ("list",      "База IoC", "/iocs"),
]


def sev_badge(sev: str) -> str:
    s = (sev or "unknown").lower()
    return f'<span class="badge badge-{s}">{s.upper()}</span>'


def type_badge(t: str) -> str:
    t = (t or "").lower()
    cls = "hash" if t.startswith("hash") else t
    label = t.replace("hash_", "").upper()
    return f'<span class="badge badge-{cls}">{label}</span>'


def risk_color(score) -> str:
    if score is None: return "#64748b"
    if score >= 75:   return DANGER
    if score >= 50:   return WARNING
    if score >= 25:   return "#f59e0b"
    return SUCCESS


@contextmanager
def layout(title: str, active: str = "/"):
    ui.add_css(CSS)
    with ui.row().style("gap:0; width:100%; min-height:100vh"):
        # Sidebar
        with ui.element("nav").classes("sidebar"):
            ui.label("🛡️ CTI Platform").style(
                f"font-size:1rem; font-weight:700; color:{TEXT}; padding:4px 8px 20px"
            )
            for icon, label, path in NAV:
                cls = "nav-link active" if active == path else "nav-link"
                with ui.element("a").classes(cls).props(f'href="{path}"'):
                    ui.icon(icon).style("font-size:1.1rem")
                    ui.label(label)

        # Content
        with ui.element("div").classes("main").style("flex:1; min-width:0"):
            ui.label(title).style(
                f"font-size:1.2rem; font-weight:700; color:{TEXT}; margin-bottom:20px; display:block"
            )
            yield
