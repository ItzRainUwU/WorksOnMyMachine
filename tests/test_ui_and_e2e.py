"""Phase 5 dashboard, API workflow, and final rebuildability guard tests."""

from pathlib import Path
import re

from fastapi.testclient import TestClient

from worksonmymachine.app import app


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_ROOT = PROJECT_ROOT / "demo_targets"
STATIC_ROOT = PROJECT_ROOT / "src" / "worksonmymachine" / "static"


def test_dashboard_and_static_assets_are_served_locally() -> None:
    client = TestClient(app)

    for path in ["/", "/static/styles.css", "/static/icons.js", "/static/app.js"]:
        response = client.get(path)
        assert response.status_code == 200, path

    assert "WorksOnMyMachine" in client.get("/").text
    dashboard_html = client.get("/").text
    assert 'href="/static/styles.css"' in dashboard_html
    assert 'src="/static/icons.js"' in dashboard_html
    assert 'src="/static/app.js"' in dashboard_html
    assert "text/css" in client.get("/static/styles.css").headers["content-type"]


def test_dashboard_assets_are_ascii_offline_and_svg_driven() -> None:
    assets = [
        STATIC_ROOT / "index.html",
        STATIC_ROOT / "styles.css",
        STATIC_ROOT / "icons.js",
        STATIC_ROOT / "app.js",
    ]
    external_patterns = [
        r"https://cdn\.",
        r"https://unpkg\.",
        r"https://cdnjs\.",
        r"https://fonts\.googleapis\.com",
        r"<script[^>]+src=[\"']https?://",
    ]

    for asset in assets:
        text = asset.read_text(encoding="utf-8")
        assert all(ord(character) < 128 for character in text), asset.name
        assert not any(re.search(pattern, text, re.IGNORECASE) for pattern in external_patterns)

    index = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
    icons = (STATIC_ROOT / "icons.js").read_text(encoding="utf-8")
    app_source = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")
    for name in [
        "logoCleanRoom",
        "radarScan",
        "autoHealBolt",
        "merkleTree",
        "dockerContainer",
        "terminalPrompt",
        "gitDiff",
        "shieldVerified",
        "shieldAlert",
        "cpuCompiler",
        "fileCode",
        "copyClipboard",
        "checkSuccess",
        "downloadCert",
        "lockClosed",
        "lockOpen",
        "slashPath",
        "caseSensitive",
        "lineEndings",
        "envKey",
        "chevronRight",
    ]:
        assert name in icons
    assert "renderRadialGauge" in icons
    assert "renderCertificationSeal" in icons
    assert "renderMerkleTreeSVG" in icons
    assert "<svg" in index or "<svg" in icons
    assert "stroke-width=\"1.75\"" in icons
    assert "/api/v1/audit" in app_source
    assert "await runAudit(false, true);" in app_source
    assert "await runAudit(true, true);" not in app_source
    assert "report.after_certificate, report.certificate, report.before_certificate, report" in app_source
    assert "/api/v1/upload" in app_source
    assert 'id="zip-upload-input"' in index
    assert 'id="zip-dropzone"' in index
    assert "dragover" in app_source
    assert "FormData" in app_source
    assert "zip-dropzone" in (STATIC_ROOT / "styles.css").read_text(encoding="utf-8")
    assert app_source.count("document.body.appendChild(link);") >= 2
    assert app_source.count("setTimeout(function () {") >= 2
    assert app_source.count("URL.revokeObjectURL(url);") >= 2
    assert "URL.revokeObjectURL(link.href);" not in app_source


def test_finding_register_has_large_set_controls_and_local_csv_export() -> None:
    index = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
    app_source = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (STATIC_ROOT / "styles.css").read_text(encoding="utf-8")

    for control in [
        'id="issue-sort"',
        'value="severity"',
        'value="path"',
        'value="rule"',
        'value="status"',
        'id="issue-sort-direction"',
        'id="issue-select-all"',
        'id="issue-clear-selection"',
        'id="issue-export-csv"',
        'id="issue-selection-count"',
        'id="issue-results-meta"',
    ]:
        assert control in index

    for marker in [
        "loadFindingFilters",
        "persistFindingFilters",
        "sortIssueEntries",
        "issuePageSize",
        "data-issue-page",
        "data-issue-selection",
        "findingsCsv",
        "text/csv;charset=utf-8",
        "downloadFindingsCsv",
    ]:
        assert marker in app_source
    assert 'window.localStorage.setItem(findingFilterStorageKey' in app_source
    assert 'request("/api/v1/' not in app_source[app_source.index("function downloadFindingsCsv"):app_source.index("function clientSarif")]
    assert ".issue-pagination" in styles
    assert ".issue-row-select" in styles


def test_dashboard_routes_and_run_history_workspace_are_local_and_addressable() -> None:
    index = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
    app_source = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (STATIC_ROOT / "styles.css").read_text(encoding="utf-8")

    for view in ["dashboard", "bugs", "dependency", "security"]:
        assert 'data-page-view="' + view + '"' in index
        assert 'data-view="' + view + '"' in index
    assert 'data-view="history"' in index
    assert 'data-page-view="history"' in index
    for element_id in [
        "run-history-list",
        "history-comparison",
        "history-run-count",
        "history-latest-target",
        "history-latest-time",
    ]:
        assert 'id="' + element_id + '"' in index

    for marker in [
        "URLSearchParams",
        "window.location.hash",
        "hashchange",
        "popstate",
        "syncRoute",
        "timestamp:",
        "findings:",
        "certificate:",
        "changed_files:",
        "artifacts:",
        "data-history-artifact",
    ]:
        assert marker in app_source
    assert ".history-workspace" in styles
    assert ".history-run-card" in styles


def test_all_demo_targets_complete_scan_parse_docker_and_autoheal_workflow() -> None:
    client = TestClient(app)
    targets = [
        "nightmare_ml_service",
        "case_sensitive_webapp",
        "rust_crypto_worker",
    ]

    snapshots = {}
    for name in targets:
        target = DEMO_ROOT / name
        snapshots[name] = {
            path.relative_to(target).as_posix(): path.read_bytes()
            for path in target.rglob("*")
            if path.is_file()
        }

        scan = client.post("/api/v1/scan", json={"target": name})
        parse = client.post("/api/v1/parse-log", json={"target": name})
        docker = client.post("/api/v1/heal-dockerfile", json={"target": name})
        audit = client.post(
            "/api/v1/audit", json={"target": name, "auto_heal": True}
        )

        assert scan.status_code == 200
        assert scan.json()["issues"]
        assert parse.status_code == 200
        if name in {"nightmare_ml_service", "rust_crypto_worker"}:
            assert parse.json()["diagnostics"]
        assert docker.status_code == 200
        assert docker.json()["unified_diff"]
        assert audit.status_code == 200
        audit_body = audit.json()
        assert audit_body["after_certificate"]["is_cleanroom_certified"] is True
        assert audit_body["after_certificate"]["linux_readiness_score"] == 100.0
        assert audit_body["after_certificate"]["dependency_lock_score"] == 100.0
        assert audit_body["timeline"]

    for name in targets:
        target = DEMO_ROOT / name
        current = {
            path.relative_to(target).as_posix(): path.read_bytes()
            for path in target.rglob("*")
            if path.is_file()
        }
        assert current == snapshots[name]


def test_phase_five_rebuildability_guards_remain_intact() -> None:
    requirements = {
        line.strip()
        for line in (PROJECT_ROOT / "requirements.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    lock = {
        line.strip()
        for line in (PROJECT_ROOT / "requirements.lock").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    env = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
    source_files = [
        *(
            file
            for file in (PROJECT_ROOT / "src").rglob("*.py")
            if file.name not in {"scanner.py", "apt_healer.py"}
        ),
        *((PROJECT_ROOT / "src" / "worksonmymachine" / "static").rglob("*")),
    ]
    source_text = "\n".join(
        file.read_text(encoding="utf-8")
        for file in source_files
        if file.is_file() and file.suffix.lower() in {".py", ".js", ".html", ".css"}
    )

    assert requirements <= lock
    assert (PROJECT_ROOT / ".python-version").read_text().strip() == "3.11.9"
    assert (PROJECT_ROOT / "runtime.txt").read_text().strip() == "python-3.11.9"
    assert "COPY src ./src" in (PROJECT_ROOT / "Dockerfile").read_text()
    assert "COPY demo_targets ./demo_targets" in (PROJECT_ROOT / "Dockerfile").read_text()
    assert "APP_HOST=0.0.0.0" in env
    assert "LLM_API_KEY=" in env
    assert "SECRET_MODEL_BUCKET=" not in env
    assert not re.search(r"(?:[A-Za-z]:\\\\|/Users/|/home/)", source_text)
