"""Focused offline checks for the static dashboard accessibility contract."""

from pathlib import Path


STATIC_ROOT = Path(__file__).resolve().parents[1] / "src" / "worksonmymachine" / "static"


def test_dashboard_exposes_accessible_regions_and_graph_fallback() -> None:
    html = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")

    assert 'class="skip-link"' in html
    assert 'id="scan-announcer"' in html
    assert 'role="dialog"' in html
    assert 'aria-modal="true"' in html
    assert 'aria-labelledby="drawer-title"' in html
    assert 'id="dependency-graph-text-summary"' in html
    assert 'id="dependency-graph-text-list"' in html
    assert '<details class="graph-text-alternative"' in html
    assert 'aria-live="polite"' in html


def test_dashboard_css_has_focus_reduced_motion_and_contrast_states() -> None:
    css = (STATIC_ROOT / "styles.css").read_text(encoding="utf-8")

    assert "button:focus-visible" in css
    assert '[tabindex="0"]:focus-visible' in css
    assert ".skip-link:focus" in css
    assert "prefers-reduced-motion: reduce" in css
    assert "forced-colors: active" in css
    assert ".severity-critical" in css
    assert ".status-fixed" in css
    assert ".status-open" in css


def test_dashboard_script_announces_scans_traps_drawer_focus_and_describes_graph() -> None:
    app = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")

    assert "function announceScan" in app
    assert "scan-announcer" in app
    assert "drawerReturnFocus" in app
    assert "focusableElements" in app
    assert 'event.key === "Tab"' in app
    assert 'aria-hidden", "false"' in app
    assert "renderGraphTextAlternative" in app
    assert "dependency-graph-text-summary" in app
    assert 'aria-labelledby="dependency-graph-svg-title"' in app
