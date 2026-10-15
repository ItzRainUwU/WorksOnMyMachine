(function () {
  "use strict";

  var icons = window.CleanRoomIcons;
  var state = {
    target: "nightmare_ml_service",
    targets: [],
    report: null,
    analysis: null,
    comparison: null,
    auditWasAutoHealed: false,
    events: [{ message: "clean room ready", level: "success" }],
    busy: false,
    toastTimer: null,
  };

  var targetDescriptions = {
    nightmare_ml_service: "Windows paths, CRLF, native wheels, and Dockerfile drift.",
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

  function on(id, eventName, handler) {
    var element = byId(id);
    if (element) element.addEventListener(eventName, handler);
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
    var select = byId("target-select");
    if (select) select.title = targetDescriptions[state.target] || "Workspace target";
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
    if (state.events.length > 28) state.events = state.events.slice(-28);
    renderTerminal();
  }

  function renderTerminal() {
    var output = byId("terminal-output");
    if (!output) return;
    output.textContent = state.events
      .map(function (entry) {
        var stamp = new Date().toISOString().slice(11, 19);
        var tag = String(entry.level || "info").toUpperCase();
        return "[" + stamp + "] [" + tag + "] " + entry.message;
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

  function setBusy(buttonId, busy) {
    var button = byId(buttonId);
    if (!button) return;
    button.disabled = Boolean(busy);
    button.classList.toggle("is-loading", Boolean(busy));
    button.setAttribute("aria-busy", busy ? "true" : "false");
  }

  function readinessScore(report) {
    if (!report) return null;
    var certificate = report.certificate || {};
    if (Number.isFinite(Number(certificate.linux_readiness_score))) {
      return Number(certificate.linux_readiness_score);
    }
    return Math.max(0, 100 - safeArray(report.issues).length * 8);
  }

  function severityClass(severity) {
    var normalized = String(severity || "medium").toLowerCase();
    return ["low", "medium", "high", "critical"].indexOf(normalized) >= 0 ? normalized : "medium";
  }

  function issueText(issue) {
    return [issue.category, issue.message, issue.remediation, issue.file_path, safeArray(issue.evidence).join(" ")]
      .join(" ")
      .toLowerCase();
  }

  function affectedOs(issue) {
    var text = issueText(issue);
    if (text.indexOf("windows") >= 0 || text.indexOf("backslash") >= 0 || text.indexOf("crlf") >= 0 || text.indexOf("host path") >= 0) return "Windows / Linux";
    if (text.indexOf("mac") >= 0 || text.indexOf("darwin") >= 0) return "macOS / Linux";
    if (text.indexOf("case") >= 0 || text.indexOf("import") >= 0 || text.indexOf("linux") >= 0) return "Linux ext4";
    if (text.indexOf("docker") >= 0 || text.indexOf("apt") >= 0 || text.indexOf("compiler") >= 0 || text.indexOf("native") >= 0) return "Linux build";
    return "Cross-OS";
  }

  function issueIsFixed(issue) {
    var report = state.report;
    if (!report || !state.auditWasAutoHealed || !report.after_certificate) return false;
    var remaining = safeArray(report.after_certificate.issues);
    if (!remaining.length) return Boolean(report.reproducible || report.after_certificate.is_cleanroom_certified);
    return !remaining.some(function (item) {
      return item.issue_id === issue.issue_id;
    });
  }

  function issueLocation(issue) {
    if (!issue || !issue.file_path) return "target root";
    return issue.file_path + (issue.line_number ? ":" + issue.line_number : "");
  }

  function renderIssueList() {
    var list = byId("issue-list");
    var report = state.report;
    var issues = report ? safeArray(report.issues) : [];
    var openIssues = issues.filter(function (issue) { return !issueIsFixed(issue); });
    setText("landmine-count", issues.length + (issues.length === 1 ? " FINDING" : " FINDINGS"));
    if (!list) return;
    if (!issues.length) {
      list.innerHTML = '<div class="empty-state">' + icon(report ? "checkSuccess" : "radarScan", 25) + "<strong>" + (report ? "No landmines detected" : "Awaiting target scan") + "</strong><span>" + (report ? "The scanner found no open portability assumptions in this target." : "Run an audit to classify paths, lockfiles, runtimes, and environment assumptions.") + "</span></div>";
      hydrateIcons();
      return;
    }
    list.innerHTML = '<div class="table-scroll"><table class="issues-table"><thead><tr><th>ID</th><th>Severity</th><th>OS affected</th><th>Description</th><th>File / path</th><th>Status</th></tr></thead><tbody>' +
      issues.map(function (issue) {
        var severity = severityClass(issue.severity);
        var fixed = issueIsFixed(issue);
        var description = issue.remediation || "Review this assumption before moving the build to a clean room.";
        return '<tr><td><code>' + escapeHtml(issue.issue_id || "WOM-000") + '</code></td><td><span class="severity severity-' + severity + '">' + escapeHtml(severity) + '</span></td><td><span class="os-chip">' + escapeHtml(affectedOs(issue)) + '</span></td><td><div class="issue-desc"><strong>' + escapeHtml(issue.message || "Unclassified issue") + '</strong><span>' + escapeHtml(description) + '</span></div></td><td><span class="issue-path" title="' + escapeHtml(issueLocation(issue)) + '">' + escapeHtml(issueLocation(issue)) + '</span></td><td><span class="issue-status ' + (fixed ? "status-fixed" : "status-open") + '">' + (fixed ? "AUTO-HEALED" : "OPEN") + '</span></td></tr>';
      }).join("") + '</tbody></table></div>';
    setText("issues-meta", report ? openIssues.length + " open / " + (issues.length - openIssues.length) + " healed" : "No findings loaded");
  }

  function renderReadiness() {
    var panel = byId("readiness-panel");
    var score = readinessScore(state.report);
    if (!panel) return;
    if (score == null) {
      panel.innerHTML = '<div class="readiness-mini"><div class="readiness-ring"><strong>--</strong><span>%</span></div><div><strong>Waiting for audit</strong><p>Readiness combines landmines, dependency locks, and Linux evidence.</p></div></div>';
      return;
    }
    var headline = score >= 85 ? "Clean room ready" : score >= 60 ? "Needs attention" : "Build risk detected";
    var copy = score >= 85 ? "The target has strong deterministic evidence and can be promoted with confidence." : "Review the highlighted landmines and rerun auto-heal before promoting this target.";
    panel.innerHTML = '<div class="readiness-mini"><div class="readiness-ring" style="border-color:' + (score >= 85 ? "var(--teal)" : "var(--amber)") + '"><strong>' + Math.round(score) + '</strong><span>%</span></div><div><strong>' + escapeHtml(headline) + '</strong><p>' + escapeHtml(copy) + '</p></div></div>';
  }

  function renderTelemetry() {
    var report = state.report;
    var score = readinessScore(report);
    var certificate = report && report.certificate ? report.certificate : {};
    var issues = report ? safeArray(report.issues) : [];
    var openIssues = issues.filter(function (issue) { return !issueIsFixed(issue); }).length;
    var auditLabel = state.busy ? "RUNNING" : report ? "COMPLETE" : "IDLE";
    setText("readiness-score", score == null ? "--" : Math.round(score) + "%");
    setText("readiness-meta", score == null ? "Waiting for first audit" : score >= 85 ? "Clean room ready" : "Needs attention");
    setText("open-issues", report ? openIssues : "--");
    setText("issues-meta", report ? openIssues + " open / " + (issues.length - openIssues) + " healed" : "No findings loaded");
    setText("root-hash", certificate.root_hash ? truncate(certificate.root_hash, 7, 4) : "PENDING");
    setText("root-meta", certificate.root_hash ? "Deterministic certificate root" : "Certificate not generated");
    setText("audit-state", auditLabel);
    setText("audit-meta", report ? new Date(report.scanned_at || Date.now()).toLocaleString() : "Awaiting first audit");
    setText("audit-state-card", auditLabel);
    setText("audit-meta-card", report ? "Last run " + new Date(report.scanned_at || Date.now()).toLocaleTimeString() : "Select scan to begin");
    var readinessMeter = byId("readiness-meter");
    if (readinessMeter) readinessMeter.style.width = (score == null ? 0 : Math.max(0, Math.min(100, score))) + "%";
    var issuesMeter = byId("issues-meter");
    if (issuesMeter) issuesMeter.style.width = (issues.length ? Math.min(100, openIssues * 12) : 0) + "%";
    var auditMeter = byId("audit-meter");
    if (auditMeter) auditMeter.style.width = state.busy ? "55%" : report ? "100%" : "0%";
  }

  function renderAnalysis() {
    var panel = byId("analysis-panel");
    if (!panel) return;
    var analysis = state.analysis;
    if (!analysis && state.report) {
      analysis = { diagnostics: safeArray(state.report.compiler_diagnostics || state.report.diagnostics), apt_packages: [], apt_install_command: "", root_cause_summary: "Audit diagnostics loaded from the target." };
    }
    if (!analysis) return;
    var packages = safeArray(analysis.apt_packages || analysis.recommended_apt_packages);
    var command = analysis.apt_install_command || "No apt package additions recommended.";
    panel.innerHTML = '<div class="analysis-banner">' + icon("cpuCompiler", 15) + '<span>' + escapeHtml(analysis.root_cause_summary || "No root cause summary returned by the parser.") + '</span></div><div class="eyebrow">RECOMMENDED PACKAGES</div><div class="package-cloud">' + (packages.length ? packages.map(function (item) { return '<span class="package-chip">' + escapeHtml(item) + '</span>'; }).join("") : '<span class="muted-text">No package additions recommended.</span>') + '</div><div class="eyebrow">INSTALL COMMAND</div><div class="command-block"><code>' + escapeHtml(command) + '</code><button class="icon-button" type="button" data-copy="' + escapeHtml(command) + '" aria-label="Copy install command">' + icon("copyClipboard", 14) + '</button></div>';
    hydrateIcons();
  }

  function diffText(text) {
    return String(text || "").split("\n").map(function (line) {
      var safe = escapeHtml(line);
      if (line.indexOf("+") === 0 && line.indexOf("+++") !== 0) return '<span class="diff-add">' + safe + '</span>';
      if (line.indexOf("-") === 0 && line.indexOf("---") !== 0) return '<span class="diff-remove">' + safe + '</span>';
      return safe;
    }).join("\n");
  }

  function renderDockerfile() {
    var panel = byId("dockerfile-panel");
    var badge = byId("dockerfile-badge");
    var report = state.report;
    if (!panel || !badge) return;
    var patch = report && (report.dockerfile_patch || safeArray(report.dockerfile_patches)[0]);
    var reportDiffs = report ? safeArray(report.unified_diffs) : [];
    var patchDiff = patch && (patch.unified_diff || patch.diff) ? [patch.unified_diff || patch.diff] : [];
    var allDiffs = patchDiff.concat(reportDiffs).filter(function (diff, index, collection) { return diff && collection.indexOf(diff) === index; });
    var dockerDiffs = allDiffs.filter(function (diff) { return /dockerfile/i.test(diff); });
    var displayDiffs = dockerDiffs.length ? dockerDiffs : allDiffs;
    if (!displayDiffs.length) {
      badge.textContent = report ? "NO PATCH" : "NOT CHECKED";
      badge.className = "table-count";
      panel.innerHTML = '<div class="empty-state"><span class="icon-slot" data-icon="fileCode" data-size="25"></span><strong>' + (report ? "No Dockerfile diff returned" : "Dockerfile evidence pending") + '</strong><span>' + (report ? "The audit did not return a Dockerfile repair proposal." : "Run auto-heal to inspect deterministic base images and package layers.") + '</span></div>';
      hydrateIcons();
      return;
    }
    var applied = Boolean(patch && patch.applied);
    badge.className = "table-count";
    badge.textContent = applied ? "APPLIED" : "PATCH READY";
    var confidence = patch && patch.confidence != null ? "Repair confidence " + Math.round(Number(patch.confidence) * 100) + "%." : "Unified diff evidence from the isolated healing stage.";
    var changes = patch ? safeArray(patch.changes) : [];
    var comparisonBanner = state.comparison ? '<div class="analysis-banner">' + icon(state.comparison.merkle_match ? "checkSuccess" : "gitDiff", 15) + '<span>' + (state.comparison.merkle_match ? "Healed certificate matches the baseline root." : "Certificate drift detected after healing.") + '</span></div>' : '';
    panel.innerHTML = comparisonBanner + '<div class="analysis-banner">' + icon(applied ? "checkSuccess" : "gitDiff", 15) + '<span>' + escapeHtml(confidence) + '</span></div>' + (changes.length ? '<div class="diff-list">' + changes.slice(0, 4).map(function (change) { return '<div class="diff-item"><div class="diff-topline"><span class="diff-title">' + escapeHtml(change) + '</span><span class="pill">changed</span></div></div>'; }).join("") + '</div>' : '') + '<div class="diff-list" style="margin-top:8px">' + displayDiffs.slice(0, 3).map(function (diff) { return '<pre class="diff-code">' + diffText(diff) + '</pre>'; }).join("") + '</div>';
  }

  function renderCertificate() {
    var report = state.report;
    var certificate = report && report.certificate;
    var tree = byId("merkle-tree");
    var seal = byId("certificate-seal");
    var metrics = byId("certificate-metrics");
    if (!tree || !seal || !metrics) return;
    if (!certificate) {
      tree.innerHTML = "Merkle root pending";
      seal.innerHTML = '<div class="empty-state compact-empty"><span class="icon-slot" data-icon="shieldAlert" data-size="22"></span><strong>Certificate pending</strong><span>Generate a deterministic Merkle proof after the audit.</span></div>';
      metrics.innerHTML = '<div class="metric-line"><span>Runtime</span><strong>--</strong></div><div class="metric-line"><span>Lock score</span><strong>--</strong></div><div class="metric-line"><span>Linux readiness</span><strong>--</strong></div>';
      hydrateIcons();
      return;
    }
    tree.innerHTML = icons.renderMerkleTreeSVG(certificate, state.comparison || { rootHash: certificate.root_hash });
    seal.innerHTML = icons.renderCertificationSeal(certificate);
    metrics.innerHTML = '<div class="metric-line"><span>Runtime</span><strong>' + escapeHtml(certificate.runtime || "unknown") + '</strong></div><div class="metric-line"><span>Lock score</span><strong>' + escapeHtml(numberOr(certificate.dependency_lock_score, 0).toFixed(0) + "%") + '</strong></div><div class="metric-line"><span>Linux readiness</span><strong>' + escapeHtml(numberOr(certificate.linux_readiness_score, 0).toFixed(0) + "%") + '</strong></div>';
  }

  function renderComparison() {
    var panel = byId("comparison-panel");
    if (!panel || !state.comparison) return;
    var comparison = state.comparison;
    panel.innerHTML = '<div class="analysis-banner">' + icon(comparison.merkle_match ? "checkSuccess" : "gitDiff", 15) + '<span>' + (comparison.merkle_match ? "The healed certificate matches the baseline root." : "Certificate drift detected. Review modified paths before promotion.") + (comparison.score_delta != null ? " Score delta: " + escapeHtml(comparison.score_delta) + "." : "") + '</span></div>';
    hydrateIcons();
  }

  function renderDiagnostics() {
    var panel = byId("diagnostic-panel");
    if (!panel) return;
    var diagnostics = state.analysis ? safeArray(state.analysis.diagnostics) : state.report ? safeArray(state.report.compiler_diagnostics || state.report.diagnostics) : [];
    if (!diagnostics.length) {
      panel.innerHTML = "";
      return;
    }
    panel.innerHTML = '<div class="diagnostic-list">' + diagnostics.slice(0, 8).map(function (diagnostic) {
      var severity = severityClass(diagnostic.severity);
      var location = diagnostic.file_path ? diagnostic.file_path + (diagnostic.line_number ? ":" + diagnostic.line_number : "") : "build output";
      return '<article class="diagnostic-row"><div class="diagnostic-topline"><div class="diagnostic-title">' + escapeHtml(diagnostic.message || diagnostic.error_signature || "Compiler diagnostic") + '</div><span class="severity severity-' + severity + '">' + escapeHtml(severity) + '</span></div><p class="diagnostic-message">' + escapeHtml(diagnostic.root_cause_explanation || diagnostic.tool || "normalized compiler output") + '</p><div class="diagnostic-meta">' + escapeHtml(location) + (diagnostic.code ? " / " + escapeHtml(diagnostic.code) : "") + '</div></article>';
    }).join("") + '</div>';
  }

  function renderAll() {
    renderTelemetry();
    renderIssueList();
    renderReadiness();
    renderAnalysis();
    renderDockerfile();
    renderCertificate();
    renderComparison();
    renderDiagnostics();
    hydrateIcons();
  }

  function selectTab(name, shouldScroll) {
    var tabName = name || "landmines";
    var targetMap = { landmines: "bugs-panel", apt: "docker-panel", sandbox: "analysis-tool", certificate: "certificate-tool", logs: "logs" };
    document.querySelectorAll("[data-tab-target]").forEach(function (button) {
      button.classList.toggle("is-active", button.getAttribute("data-tab-target") === tabName);
    });
    if (shouldScroll !== false) {
      var target = byId(targetMap[tabName] || tabName);
      if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
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
      setConnection("ENGINE ONLINE", "success");
      renderTargetDescription();
      logEvent("loaded " + state.targets.length + " target(s)", "success");
    } catch (error) {
      setConnection("API UNAVAILABLE", "warning");
      logEvent("target discovery unavailable: " + error.message, "warning");
      showToast("Target discovery is unavailable. The default target remains selected.", false);
    }
  }

  async function runAudit(autoHeal, quiet) {
    if (state.busy) return;
    state.busy = true;
    state.auditWasAutoHealed = Boolean(autoHeal);
    setBusy("scan-button", true);
    setBusy("heal-button", true);
    setConnection(autoHeal ? "HEALING TARGET" : "AUDITING TARGET", "warning");
    setText("audit-state", autoHeal ? "HEALING" : "RUNNING");
    setText("audit-state-card", autoHeal ? "HEALING" : "RUNNING");
    renderTelemetry();
    logEvent((autoHeal ? "auto-heal" : "audit") + " started for " + state.target, "info");
    try {
      var report = await request("/api/v1/audit", { method: "POST", body: { target: state.target, auto_heal: Boolean(autoHeal) } });
      state.report = report || null;
      state.analysis = null;
      state.comparison = null;
      setConnection("ENGINE ONLINE", "success");
      logEvent((autoHeal ? "auto-heal" : "audit") + " complete", "success");
      renderAll();
      if (!quiet) showToast(autoHeal ? "Auto-heal evidence is ready." : "Target audit is ready.", false);
    } catch (error) {
      setConnection("AUDIT FAILED", "error");
      setText("audit-state", "UNAVAILABLE");
      setText("audit-state-card", "ERROR");
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
      state.analysis = await request("/api/v1/parse-log", { method: "POST", body: { target: state.target } });
      setConnection("ENGINE ONLINE", "success");
      logEvent("compiler telemetry received", "success");
      renderAnalysis();
      renderDiagnostics();
      selectTab("sandbox", false);
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
      state.analysis = await request("/api/v1/parse-log", { method: "POST", body: { log_text: text } });
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
      var certificate = await request("/api/v1/certify", { method: "POST", body: { target: state.target } });
      if (!state.report) state.report = { target: state.target, issues: [] };
      state.report.certificate = certificate;
      state.report.merkle_root = certificate.root_hash;
      setConnection("ENGINE ONLINE", "success");
      logEvent("certificate generated", "success");
      renderAll();
      selectTab("certificate", false);
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
      state.comparison = await request("/api/v1/compare", { method: "POST", body: { target: state.target, auto_heal: true } });
      logEvent("comparison evidence received", "success");
      renderDockerfile();
      renderComparison();
      selectTab("apt", false);
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
      showToast("Copied to clipboard.", false);
    } catch (error) {
      showToast("Clipboard access is unavailable.", true);
    }
  }

  function bindEvents() {
    on("scan-button", "click", function () { runAudit(false, false); });
    on("heal-button", "click", function () { runAudit(true, false); });
    on("parse-log-button", "click", parseLog);
    on("run-sandbox-button", "click", parseCustomLog);
    on("certify-button", "click", certify);
    on("copy-certificate-button", "click", function () {
      var certificate = state.report && state.report.certificate;
      if (certificate) copyText(JSON.stringify(certificate, null, 2)); else showToast("Generate a certificate first.", true);
    });
    on("download-certificate-button", "click", downloadCertificate);
    on("compare-button", "click", compare);
    on("target-select", "change", function (event) {
      state.target = event.target.value || "nightmare_ml_service";
      state.report = null;
      state.analysis = null;
      state.comparison = null;
      state.auditWasAutoHealed = false;
      renderTargetDescription();
      renderAll();
      logEvent("target changed to " + state.target, "info");
      runAudit(false, false);
    });
    document.querySelectorAll("[data-refresh-audit]").forEach(function (button) {
      button.addEventListener("click", function () { runAudit(false, false); });
    });
    document.querySelectorAll("[data-log-preset]").forEach(function (button) {
      button.addEventListener("click", function () {
        var editor = byId("compiler-log-editor");
        if (editor) editor.value = logPresets[button.getAttribute("data-log-preset")] || "";
        selectTab("sandbox", false);
      });
    });
    document.querySelectorAll("[data-tab-target]").forEach(function (button) {
      button.addEventListener("click", function () { selectTab(button.getAttribute("data-tab-target"), true); });
    });
    on("terminal-toggle", "click", function () {
      setDrawer(true);
      selectTab("logs", true);
    });
    on("drawer-toggle", "click", function () {
      var drawer = byId("terminal-drawer");
      setDrawer(!drawer || !drawer.classList.contains("is-open"));
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

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bootstrap); else bootstrap();
})();
