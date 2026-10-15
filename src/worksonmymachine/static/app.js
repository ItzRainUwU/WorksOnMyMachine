(function () {
  "use strict";

  var icons = window.CleanRoomIcons;
  var state = {
    target: "nightmare_ml_service",
    targets: [],
    report: null,
    analysis: null,
    comparison: null,
    activeTab: "landmines",
    events: [{ message: "clean room ready", level: "success" }],
    busy: false,
    toastTimer: null,
  };

  var targetDescriptions = {
    nightmare_ml_service: "Windows path, CRLF, and native wheel failure fixture.",
    case_sensitive_webapp: "Case-folded Python and JavaScript imports on Linux ext4.",
    rust_crypto_worker: "Rust, libffi, OpenSSL, and stale lockfile fixture.",
  };

  var logPresets = {
    python: "fatal error: Python.h: No such file or directory",
    postgres: "Error: pg_config executable not found\nfatal error: libpq-fe.h: No such file",
    opencv: "ImportError: libGL.so.1: cannot open shared object file",
    rust: "error: Cargo, the Rust package manager, is not installed\nfatal error: openssl/ssl.h: No such file or directory",
    mysql: "mysql_config not found\ncmake: command not found",
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function escapeHtml(value) {
    return icons && icons.escapeHtml
      ? icons.escapeHtml(value)
      : String(value == null ? "" : value)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
  }

  function icon(name, size, label) {
    return icons && icons.icon ? icons.icon(name, size, label) : "";
  }

  function safeArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function numberOr(value, fallback) {
    var number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  }

  function truncate(value, start, end) {
    var text = String(value || "pending");
    if (text.length <= start + end + 3) return text;
    return text.slice(0, start) + "..." + text.slice(-end);
  }

  function setText(id, value) {
    var element = byId(id);
    if (element) element.textContent = String(value == null ? "" : value);
  }

  function renderTargetDescription() {
    setText(
      "target-description",
      targetDescriptions[state.target] || "Workspace target selected for deterministic audit."
    );
  }

  function setConnection(label, tone) {
    setText("connection-label", label);
    var dot = byId("connection-dot");
    if (dot) {
      dot.classList.toggle("is-warning", tone === "warning");
      dot.classList.toggle("is-error", tone === "error");
    }
  }

  function showToast(message, isError) {
    var toast = byId("toast");
    if (!toast) return;
    window.clearTimeout(state.toastTimer);
    toast.textContent = message;
    toast.classList.toggle("is-error", Boolean(isError));
    toast.classList.add("is-visible");
    state.toastTimer = window.setTimeout(function () {
      toast.classList.remove("is-visible");
    }, 3600);
  }

  function logEvent(message, level) {
    state.events.push({ message: String(message), level: level || "info" });
    if (state.events.length > 24) state.events = state.events.slice(-24);
    renderTerminal();
  }

  function renderTerminal() {
    var output = byId("terminal-output");
    if (!output) return;
    output.textContent = state.events
      .map(function (entry) {
        var stamp = new Date().toISOString().slice(11, 19);
        return "[" + stamp + "] " + entry.message;
      })
      .join("\n");
    output.scrollTop = output.scrollHeight;
  }

  function hydrateIcons() {
    document.querySelectorAll(".icon-slot[data-icon]").forEach(function (slot) {
      var name = slot.getAttribute("data-icon");
      var size = Number(slot.getAttribute("data-size")) || 20;
      var label = slot.getAttribute("data-label") || "";
      slot.innerHTML = icon(name, size, label);
    });
  }

  async function request(path, options) {
    var init = Object.assign({}, options || {});
    init.headers = Object.assign({ Accept: "application/json" }, init.headers || {});
    if (init.body && typeof init.body !== "string") {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(init.body);
    }
    var response = await fetch(path, init);
    var payload = null;
    try {
      payload = await response.json();
    } catch (error) {
      payload = null;
    }
    if (!response.ok) {
      var detail = payload && (payload.detail || payload.message);
      throw new Error(detail || "Request failed with status " + response.status);
    }
    return payload;
  }

  function setBusy(buttonId, busy, label) {
    var button = byId(buttonId);
    if (!button) return;
    button.disabled = Boolean(busy);
    button.classList.toggle("is-loading", Boolean(busy));
    button.setAttribute("aria-busy", busy ? "true" : "false");
    if (label) setText(buttonId, label);
  }

  function readinessScore(report) {
    if (!report) return null;
    var certificate = report.certificate || {};
    if (Number.isFinite(Number(certificate.linux_readiness_score))) {
      return Number(certificate.linux_readiness_score);
    }
    var issues = safeArray(report.issues).length;
    return Math.max(0, 100 - issues * 8);
  }

  function severityClass(severity) {
    var normalized = String(severity || "medium").toLowerCase();
    return ["low", "medium", "high", "critical"].indexOf(normalized) >= 0
      ? normalized
      : "medium";
  }

  function renderIssueList() {
    var list = byId("issue-list");
    var report = state.report;
    var issues = report ? safeArray(report.issues) : [];
    setText("landmine-count", issues.length + (issues.length === 1 ? " finding" : " findings"));
    if (!list) return;
    if (!issues.length) {
      list.innerHTML =
        '<div class="empty-state">' +
        icon(report ? "checkSuccess" : "radarScan", 24) +
        "<strong>" +
        (report ? "No landmines detected" : "Awaiting target scan") +
        "</strong><span>" +
        (report
          ? "The scanner found no open portability assumptions in this target."
          : "Run an audit to classify paths, lockfiles, runtimes, and environment assumptions.") +
        "</span></div>";
      return;
    }
    list.innerHTML = issues
      .map(function (issue) {
        var severity = severityClass(issue.severity);
        var location = issue.file_path
          ? issue.file_path + (issue.line_number ? ":" + issue.line_number : "")
          : "target root";
        var evidence = safeArray(issue.evidence).slice(0, 2);
        return (
          '<article class="issue-row"><div class="issue-topline"><div class="issue-title">' +
          escapeHtml(issue.message || issue.issue_id || "Unclassified issue") +
          '</div><span class="severity severity-' +
          severity +
          '">' +
          escapeHtml(severity) +
          '</span></div><p class="issue-message">' +
          escapeHtml(issue.remediation || "Review this assumption before moving the build to a clean room.") +
          '</p><div class="issue-meta"><code>' +
          escapeHtml(location) +
          "</code>" +
          (issue.category ? "<span>" + escapeHtml(issue.category) + "</span>" : "") +
          evidence
            .map(function (item) {
              return "<span>" + escapeHtml(item) + "</span>";
            })
            .join("") +
          "</div></article>"
        );
      })
      .join("");
  }

  function renderReadiness() {
    var panel = byId("readiness-panel");
    var score = readinessScore(state.report);
    if (!panel) return;
    if (score == null) {
      panel.innerHTML =
        '<div class="empty-state"><span class="icon-slot" data-icon="radarScan" data-size="24"></span><strong>Readiness pending</strong><span>The first audit will combine landmines, dependency lock evidence, and Linux readiness.</span></div>';
      hydrateIcons();
      return;
    }
    var report = state.report || {};
    var certificate = report.certificate || {};
    var headline = score >= 85 ? "Clean room ready" : score >= 60 ? "Needs attention" : "Build risk detected";
    var copy =
      score >= 85
        ? "The target has strong deterministic evidence and can be promoted with confidence."
        : "Review the highlighted landmines and rerun auto-heal before promoting this target.";
     var beforeScore = report.before_certificate
       ? numberOr(report.before_certificate.linux_readiness_score, score)
       : score;
     panel.innerHTML =
       '<div class="score-layout">' +
       icons.renderRadialGauge(beforeScore, score, "Readiness", { size: 132 }) +
      '<div class="score-copy"><div class="eyebrow">Current signal</div><strong>' +
      escapeHtml(headline) +
      '</strong><p>' +
      escapeHtml(copy) +
      '</p><div class="metric-stack" style="margin-top:13px"><div class="metric-line"><span>Dependency lock</span><strong>' +
      escapeHtml(numberOr(certificate.dependency_lock_score, 0).toFixed(0) + "%") +
      '</strong></div><div class="metric-line"><span>Clean room</span><strong>' +
      (certificate.is_cleanroom_certified ? "verified" : "pending") +
      "</strong></div></div></div></div>";
    setText("readiness-headline", headline);
    setText("readiness-copy", copy);
  }

  function renderTelemetry() {
    var report = state.report;
    var score = readinessScore(report);
    var certificate = report && report.certificate ? report.certificate : {};
    var issues = report ? safeArray(report.issues) : [];
    setText("readiness-score", score == null ? "--" : Math.round(score) + "%");
    setText("readiness-meta", score == null ? "Waiting for first audit" : score >= 85 ? "Clean room ready" : "Needs attention");
    setText("open-issues", report ? issues.length : "--");
    setText("issues-meta", report ? (issues.length ? "Review findings below" : "No open landmines") : "No findings loaded");
    setText("root-hash", certificate.root_hash ? truncate(certificate.root_hash, 7, 4) : "pending");
    setText("root-meta", certificate.root_hash ? "Deterministic certificate root" : "Certificate not generated");
    setText("audit-state", state.busy ? "Running" : report ? "Complete" : "Idle");
    setText("audit-meta", report ? new Date(report.scanned_at || Date.now()).toLocaleString() : "Select scan to begin");
  }

  function renderAnalysis() {
    var panel = byId("analysis-panel");
    if (!panel) return;
    var analysis = state.analysis;
    if (!analysis && state.report) {
      analysis = {
        diagnostics: safeArray(state.report.compiler_diagnostics || state.report.diagnostics),
        apt_packages: [],
        apt_install_command: "",
        root_cause_summary: "Audit diagnostics loaded from the target.",
      };
    }
    if (!analysis) return;
    var packages = safeArray(analysis.apt_packages || analysis.recommended_apt_packages);
    var command = analysis.apt_install_command || "No apt package additions recommended.";
    panel.innerHTML =
      '<div class="analysis-banner">' +
      icon("cpuCompiler", 16) +
      "<span>" +
      escapeHtml(analysis.root_cause_summary || "No root cause summary returned by the parser.") +
      "</span></div>" +
      '<div class="eyebrow">Recommended packages</div><div class="package-cloud">' +
      (packages.length
        ? packages
            .map(function (item) {
              return '<span class="package-chip">' + escapeHtml(item) + "</span>";
            })
            .join("")
        : '<span class="muted-text">No package additions recommended.</span>') +
      '</div><div class="eyebrow">Install command</div><div class="command-block"><code>' +
      escapeHtml(command) +
      '</code><button class="icon-button" type="button" data-copy="' +
      escapeHtml(command) +
      '" aria-label="Copy install command">' +
      icon("copyClipboard", 15) +
      "</button></div>";
  }

  function renderDockerfile() {
    var panel = byId("dockerfile-panel");
    var badge = byId("dockerfile-badge");
    var report = state.report;
    var patch = report && (report.dockerfile_patch || safeArray(report.dockerfile_patches)[0]);
    if (!panel || !badge) return;
    if (!patch) {
      badge.className = "badge";
      badge.textContent = report ? "No patch" : "Not checked";
      panel.innerHTML =
        '<div class="empty-state"><span class="icon-slot" data-icon="fileCode" data-size="24"></span><strong>' +
        (report ? "No Dockerfile patch required" : "Dockerfile evidence pending") +
        "</strong><span>" +
        (report ? "The audit did not return a Dockerfile repair proposal." : "Run a scan to inspect deterministic base images and package layers.") +
        "</span></div>";
      hydrateIcons();
      return;
    }
    var applied = Boolean(patch.applied);
    badge.className = "badge " + (applied ? "badge-success" : "badge-warning");
    badge.textContent = applied ? "Applied in stage" : "Proposal ready";
    var changes = safeArray(patch.changes);
    var diff = patch.unified_diff || patch.diff || "";
    panel.innerHTML =
      '<div class="analysis-banner">' +
      icon(applied ? "checkSuccess" : "dockerContainer", 16) +
      "<span>" +
      escapeHtml(patch.confidence != null ? "Repair confidence " + Math.round(Number(patch.confidence) * 100) + "%." : "Deterministic Dockerfile repair evidence returned.") +
      "</span></div>" +
      '<div class="eyebrow">Proposed changes</div><div class="issue-list" style="margin-top:9px">' +
      (changes.length
        ? changes
            .slice(0, 5)
            .map(function (change) {
              return '<div class="issue-row"><div class="issue-title">' + escapeHtml(change) + "</div></div>";
            })
            .join("")
        : '<div class="issue-row"><div class="issue-title">No textual changes reported</div></div>') +
      "</div>" +
      (diff ? '<pre class="diff-code">' + renderDiffText(diff) + "</pre>" : "");
  }

  function renderCertificate() {
    var report = state.report;
    var certificate = report && report.certificate;
    var tree = byId("merkle-tree");
    var seal = byId("certificate-seal");
    var metrics = byId("certificate-metrics");
    if (!tree || !seal || !metrics) return;
    if (!certificate) {
      tree.innerHTML = '<div class="empty-state"><span class="icon-slot" data-icon="merkleTree" data-size="24"></span><strong>Merkle root pending</strong><span>Generate or load an audit certificate to render the evidence tree.</span></div>';
      seal.innerHTML = '<div class="empty-state"><span class="icon-slot" data-icon="shieldAlert" data-size="24"></span><strong>Certificate pending</strong><span>Run an audit to see verification state and root hash.</span></div>';
      hydrateIcons();
      return;
    }
     tree.innerHTML = icons.renderMerkleTreeSVG(certificate, state.comparison || { rootHash: certificate.root_hash });
    seal.innerHTML = icons.renderCertificationSeal(certificate);
    metrics.innerHTML =
      '<div class="metric-line"><span>Runtime</span><strong>' +
      escapeHtml(certificate.runtime || "unknown") +
      '</strong></div><div class="metric-line"><span>Lock score</span><strong>' +
      escapeHtml(numberOr(certificate.dependency_lock_score, 0).toFixed(0) + "%") +
      '</strong></div><div class="metric-line"><span>Linux readiness</span><strong>' +
      escapeHtml(numberOr(certificate.linux_readiness_score, 0).toFixed(0) + "%") +
      "</strong></div>";
  }

  function renderDiffText(text) {
    return String(text || "")
      .split("\n")
      .map(function (line) {
        var safe = escapeHtml(line);
        if (line.indexOf("+") === 0 && line.indexOf("+++") !== 0) return '<span class="diff-add">' + safe + "</span>";
        if (line.indexOf("-") === 0 && line.indexOf("---") !== 0) return '<span class="diff-remove">' + safe + "</span>";
        return safe;
      })
      .join("\n");
  }

  function renderDiff() {
    var panel = byId("diff-panel");
    if (!panel) return;
    var report = state.report;
    var comparison = state.comparison;
    var diffs = report ? safeArray(report.unified_diffs) : [];
    var files = comparison
      ? [].concat(
          safeArray(comparison.modified_files),
          safeArray(comparison.added_files),
          safeArray(comparison.removed_files),
          safeArray(comparison.line_ending_drifts)
        )
      : [];
    if (!diffs.length && !files.length) return;
    panel.innerHTML =
      (comparison
        ? '<div class="analysis-banner">' +
          icon(comparison.merkle_match ? "checkSuccess" : "gitDiff", 16) +
          "<span>" +
          (comparison.merkle_match
            ? "The healed certificate matches the baseline root."
            : "Certificate drift detected. Review modified paths before promotion.") +
          (comparison.score_delta != null ? " Score delta: " + escapeHtml(comparison.score_delta) + "." : "") +
          "</span></div>"
        : "") +
      '<div class="diff-list">' +
      files
        .slice(0, 12)
        .map(function (path) {
          return '<div class="diff-item"><div class="diff-topline"><span class="diff-title">' + escapeHtml(path) + '</span><span class="pill pill-warning">changed</span></div></div>';
        })
        .join("") +
      diffs
        .slice(0, 5)
        .map(function (diff) {
          return '<pre class="diff-code">' + renderDiffText(diff) + "</pre>";
        })
        .join("") +
      "</div>";
  }

  function renderDiagnostics() {
    var panel = byId("diagnostic-panel");
    if (!panel) return;
    var diagnostics = state.analysis
      ? safeArray(state.analysis.diagnostics)
      : state.report
        ? safeArray(state.report.compiler_diagnostics || state.report.diagnostics)
        : [];
    if (!diagnostics.length) return;
    panel.innerHTML = '<div class="diagnostic-list">' +
      diagnostics
        .slice(0, 10)
        .map(function (diagnostic) {
          var severity = severityClass(diagnostic.severity);
          var location = diagnostic.file_path
            ? diagnostic.file_path + (diagnostic.line_number ? ":" + diagnostic.line_number : "")
            : "build output";
          return '<article class="diagnostic-row"><div class="diagnostic-topline"><div class="diagnostic-title">' +
            escapeHtml(diagnostic.message || diagnostic.error_signature || "Compiler diagnostic") +
            '</div><span class="severity severity-' + severity + '">' + escapeHtml(severity) +
            '</span></div><p class="diagnostic-message">' + escapeHtml(diagnostic.root_cause_explanation || diagnostic.tool || "normalized compiler output") +
            '</p><div class="diagnostic-meta"><code>' + escapeHtml(location) + "</code>" +
            (diagnostic.code ? '<span>' + escapeHtml(diagnostic.code) + '</span>' : "") +
            '</div></article>';
        })
        .join("") + "</div>";
  }

  function renderAll() {
    renderTelemetry();
    renderIssueList();
    renderReadiness();
    renderAnalysis();
    renderDockerfile();
    renderCertificate();
    renderDiff();
    renderDiagnostics();
    hydrateIcons();
  }

  function selectTab(name) {
    var tabName = name || "landmines";
    state.activeTab = tabName;
    document.querySelectorAll("[data-tab]").forEach(function (button) {
      var selected = button.getAttribute("data-tab") === tabName;
      button.classList.toggle("is-active", selected);
      button.setAttribute("aria-selected", selected ? "true" : "false");
    });
    document.querySelectorAll("[data-tab-target]").forEach(function (button) {
      button.classList.toggle("is-active", button.getAttribute("data-tab-target") === tabName);
    });
    document.querySelectorAll("[data-panel]").forEach(function (panel) {
      panel.classList.toggle("is-active", panel.getAttribute("data-panel") === tabName);
    });
  }

  function setDrawer(open) {
    var drawer = byId("terminal-drawer");
    var toggle = byId("drawer-toggle");
    if (!drawer) return;
    drawer.classList.toggle("is-open", open);
    drawer.setAttribute("aria-hidden", open ? "false" : "true");
    if (toggle) toggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  async function loadTargets() {
    try {
      var payload = await request("/api/v1/targets", { method: "GET" });
      state.targets = safeArray(payload && payload.targets);
      var select = byId("target-select");
      if (select) {
        select.replaceChildren();
        var options = state.targets.slice();
        if (options.indexOf(state.target) < 0) options.unshift(state.target);
        options.forEach(function (target) {
          var option = document.createElement("option");
          option.value = target;
          option.textContent = target;
          option.title = targetDescriptions[target] || "Workspace target";
          option.selected = target === state.target;
          select.appendChild(option);
        });
      }
      setConnection("API online", "success");
      renderTargetDescription();
      logEvent("loaded " + state.targets.length + " target(s)", "success");
    } catch (error) {
      setConnection("API unavailable", "warning");
      logEvent("target discovery unavailable: " + error.message, "warning");
      showToast("Target discovery is unavailable. The default target remains selected.", false);
    }
  }

  async function runAudit(autoHeal, quiet) {
    if (state.busy) return;
    state.busy = true;
    setBusy("scan-button", true);
    setBusy("heal-button", true);
    setConnection(autoHeal ? "Healing target" : "Auditing target", "warning");
    setText("audit-state", autoHeal ? "Healing" : "Running");
    logEvent((autoHeal ? "auto-heal" : "audit") + " started for " + state.target, "info");
    try {
      var report = await request("/api/v1/audit", {
        method: "POST",
        body: { target: state.target, auto_heal: Boolean(autoHeal) },
      });
      state.report = report || null;
      state.analysis = null;
      state.comparison = null;
      setConnection("API online", "success");
      logEvent((autoHeal ? "auto-heal" : "audit") + " complete", "success");
      renderAll();
      if (!quiet) showToast(autoHeal ? "Auto-heal evidence is ready." : "Target audit is ready.", false);
    } catch (error) {
      setConnection("Audit failed", "error");
      setText("audit-state", "Unavailable");
      logEvent("audit failed: " + error.message, "error");
      if (!quiet) showToast("Audit failed: " + error.message, true);
    } finally {
      state.busy = false;
      setBusy("scan-button", false);
      setBusy("heal-button", false);
      renderTelemetry();
    }
  }

  async function parseLog() {
    if (state.busy) return;
    setBusy("parse-log-button", true);
    logEvent("parsing build log for " + state.target, "info");
    try {
      state.analysis = await request("/api/v1/parse-log", {
        method: "POST",
        body: { target: state.target },
      });
      setConnection("API online", "success");
      logEvent("compiler telemetry received", "success");
      renderAnalysis();
      renderDiagnostics();
      selectTab("apt");
      showToast("Compiler telemetry parsed.", false);
    } catch (error) {
      logEvent("parse failed: " + error.message, "error");
      showToast("Build log parse failed: " + error.message, true);
    } finally {
      setBusy("parse-log-button", false);
    }
  }

  async function parseCustomLog() {
    var editor = byId("compiler-log-editor");
    var text = editor ? editor.value.trim() : "";
    if (!text) {
      showToast("Enter a compiler trace or choose a preset.", true);
      return;
    }
    setBusy("run-sandbox-button", true);
    logEvent("parsing custom compiler trace", "info");
    try {
      state.analysis = await request("/api/v1/parse-log", {
        method: "POST",
        body: { log_text: text },
      });
      renderAnalysis();
      renderDiagnostics();
      logEvent("custom compiler trace normalized", "success");
      showToast("Custom compiler trace parsed.", false);
    } catch (error) {
      logEvent("custom parse failed: " + error.message, "error");
      showToast("Custom parse failed: " + error.message, true);
    } finally {
      setBusy("run-sandbox-button", false);
    }
  }

  function downloadCertificate() {
    var certificate = state.report && state.report.certificate;
    if (!certificate) {
      showToast("Generate a certificate first.", true);
      return;
    }
    var blob = new Blob([JSON.stringify(certificate, null, 2)], { type: "application/json" });
    var link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = state.target + "-cleanroom-certificate.json";
    link.click();
    URL.revokeObjectURL(link.href);
    logEvent("certificate JSON downloaded", "success");
  }

  async function certify() {
    if (state.busy) return;
    setBusy("certify-button", true);
    logEvent("generating certificate for " + state.target, "info");
    try {
      var certificate = await request("/api/v1/certify", {
        method: "POST",
        body: { target: state.target },
      });
      if (!state.report) state.report = { target: state.target, issues: [] };
      state.report.certificate = certificate;
      state.report.merkle_root = certificate.root_hash;
      setConnection("API online", "success");
      logEvent("certificate generated", "success");
      renderAll();
      selectTab("certificate");
      showToast("Certificate evidence is ready.", false);
    } catch (error) {
      logEvent("certificate failed: " + error.message, "error");
      showToast("Certificate generation failed: " + error.message, true);
    } finally {
      setBusy("certify-button", false);
    }
  }

  async function compare() {
    if (state.busy) return;
    setBusy("compare-button", true);
    logEvent("comparing baseline and healed certificates", "info");
    try {
      state.comparison = await request("/api/v1/compare", {
        method: "POST",
        body: { target: state.target, auto_heal: true },
      });
      logEvent("comparison evidence received", "success");
      renderDiff();
      selectTab("sandbox");
      showToast("Certificate comparison is ready.", false);
    } catch (error) {
      logEvent("comparison failed: " + error.message, "error");
      showToast("Comparison failed: " + error.message, true);
    } finally {
      setBusy("compare-button", false);
    }
  }

  async function copyText(value) {
    try {
      await navigator.clipboard.writeText(value);
      showToast("Command copied to clipboard.", false);
    } catch (error) {
      showToast("Clipboard access is unavailable.", true);
    }
  }

  function bindEvents() {
    byId("scan-button").addEventListener("click", function () {
      runAudit(false, false);
    });
    byId("heal-button").addEventListener("click", function () {
      runAudit(true, false);
    });
    byId("parse-log-button").addEventListener("click", parseLog);
    byId("run-sandbox-button").addEventListener("click", parseCustomLog);
    byId("certify-button").addEventListener("click", certify);
    byId("copy-certificate-button").addEventListener("click", function () {
      var certificate = state.report && state.report.certificate;
      if (certificate) copyText(JSON.stringify(certificate, null, 2));
      else showToast("Generate a certificate first.", true);
    });
    byId("download-certificate-button").addEventListener("click", downloadCertificate);
    byId("compare-button").addEventListener("click", compare);
    byId("target-select").addEventListener("change", function (event) {
      state.target = event.target.value || "nightmare_ml_service";
      state.report = null;
      state.analysis = null;
      state.comparison = null;
      renderAll();
      logEvent("target changed to " + state.target, "info");
      runAudit(false, false);
    });
    byId("compiler-jump").addEventListener("click", function () {
      selectTab("sandbox");
      byId("compiler-log-editor").focus();
    });
    document.querySelectorAll("[data-log-preset]").forEach(function (button) {
      button.addEventListener("click", function () {
        var editor = byId("compiler-log-editor");
        if (editor) editor.value = logPresets[button.getAttribute("data-log-preset")] || "";
        selectTab("sandbox");
      });
    });
    document.querySelectorAll("[data-tab], [data-tab-target]").forEach(function (button) {
      button.addEventListener("click", function () {
        selectTab(button.getAttribute("data-tab") || button.getAttribute("data-tab-target"));
      });
    });
    byId("terminal-toggle").addEventListener("click", function () {
      setDrawer(true);
    });
    byId("drawer-toggle").addEventListener("click", function () {
      var drawer = byId("terminal-drawer");
      setDrawer(!drawer.classList.contains("is-open"));
    });
    byId("drawer-close").addEventListener("click", function () {
      setDrawer(false);
    });
    document.addEventListener("click", function (event) {
      var copyButton = event.target.closest ? event.target.closest("[data-copy]") : null;
      if (copyButton) copyText(copyButton.getAttribute("data-copy") || "");
    });
  }

  async function bootstrap() {
    hydrateIcons();
    bindEvents();
    renderTargetDescription();
    renderTerminal();
    renderAll();
    await loadTargets();
    await runAudit(true, true);
  }

  window.cleanRoomApp = {
    state: state,
    runAudit: runAudit,
    parseLog: parseLog,
    certify: certify,
    compare: compare,
    selectTab: selectTab,
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }
})();
