(function () {
  "use strict";

  var icons = window.CleanRoomIcons;
  var state = {
    target: "workspace",
    targets: [],
    report: null,
    analysis: null,
    comparison: null,
    buildVerification: null,
    newOnly: false,
    history: [],
    selectedHistoryId: null,
    auditWasAutoHealed: false,
    issueFilter: "all",
    issueSearch: "",
    issueSortKey: "severity",
    issueSortDirection: "desc",
    issuePage: 1,
    issuePageSize: 25,
    selectedIssueKeys: {},
    selectedHealedFilePath: null,
    issueDetailRequestId: 0,
    activeView: "dashboard",
    pendingRoute: null,
    drawerReturnFocus: null,
    popoverReturnFocus: null,
    events: [{ message: "clean room ready", level: "success", time: new Date() }],
    busy: false,
    toastTimer: null,
  };

  var targetDescriptions = {
    workspace: "Current WorksOnMyMachine workspace.",
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

  var findingFilterStorageKey = "worksonmymachine.findingFilters";
  var findingSortKeys = ["severity", "path", "rule", "status"];

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

  function iconClass(name, size, className, label) {
    return icon(name, size, label).replace('class="cr-icon"', 'class="cr-icon ' + className + '"');
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
    return text.slice(0, start) + "..." + (end ? text.slice(-end) : "");
  }

  function nowStamp() {
    var date = new Date();
    return date.getFullYear() + "-" + String(date.getMonth() + 1).padStart(2, "0") + "-" + String(date.getDate()).padStart(2, "0") + " " + String(date.getHours()).padStart(2, "0") + ":" + String(date.getMinutes()).padStart(2, "0") + ":" + String(date.getSeconds()).padStart(2, "0");
  }

  function setText(id, value) {
    var element = byId(id);
    if (element) element.textContent = String(value == null ? "" : value);
  }

  function announceScan(message) {
    var announcer = byId("scan-announcer");
    if (announcer) announcer.textContent = String(message || "");
  }

  function focusableElements(container) {
    if (!container) return [];
    return Array.prototype.slice.call(container.querySelectorAll("a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex=\"-1\"])"));
  }

  function restoreFocus(element) {
    if (element && typeof element.focus === "function" && document.contains(element)) element.focus();
  }

  function loadHistory() {
    try {
      var stored = JSON.parse(window.localStorage.getItem("worksonmymachine.auditHistory") || "[]");
      state.history = Array.isArray(stored) ? stored.slice(0, 12) : [];
    } catch (error) {
      state.history = [];
    }
  }

  function persistHistory() {
    try {
      window.localStorage.setItem("worksonmymachine.auditHistory", JSON.stringify(state.history.slice(0, 12)));
    } catch (error) {
      logEvent("audit history storage unavailable", "warning");
    }
  }

  function loadFindingFilters() {
    try {
      var stored = JSON.parse(window.localStorage.getItem(findingFilterStorageKey) || "null");
      if (!stored || typeof stored !== "object") return;
      if (["all", "critical", "high", "fixed"].indexOf(stored.issueFilter) >= 0) state.issueFilter = stored.issueFilter;
      if (typeof stored.issueSearch === "string") state.issueSearch = stored.issueSearch.slice(0, 240);
      if (findingSortKeys.indexOf(stored.issueSortKey) >= 0) state.issueSortKey = stored.issueSortKey;
      if (["asc", "desc"].indexOf(stored.issueSortDirection) >= 0) state.issueSortDirection = stored.issueSortDirection;
      var page = Number(stored.issuePage);
      if (Number.isInteger(page) && page > 0) state.issuePage = page;
    } catch (error) {
      // A disabled or malformed local storage entry should not block the register.
    }
  }

  function persistFindingFilters() {
    try {
      window.localStorage.setItem(findingFilterStorageKey, JSON.stringify({
        issueFilter: state.issueFilter,
        issueSearch: state.issueSearch,
        issueSortKey: state.issueSortKey,
        issueSortDirection: state.issueSortDirection,
        issuePage: state.issuePage,
      }));
    } catch (error) {
      // Filtering remains fully usable when browser storage is unavailable.
    }
  }

  function certificateHistoryMetadata(report) {
    var certificate = selectedCertificate(report);
    var verified = Boolean(certificate.is_cleanroom_certified || certificate.verified);
    return {
      status: certificate.root_hash ? (verified ? "verified" : "generated") : "pending",
      root_hash: certificate.root_hash || null,
      verified: verified,
    };
  }

  function artifactHistoryMetadata(target) {
    var safeTarget = String(target || "workspace").replace(/[^A-Za-z0-9._-]+/g, "-");
    return [
      { kind: "json", label: "JSON", filename: safeTarget + "-audit.json", downloadable: true },
      { kind: "certificate", label: "Certificate", filename: safeTarget + "-certificate.json", downloadable: true },
      { kind: "patch", label: "Patch", filename: safeTarget + "-healed.patch", downloadable: true },
      { kind: "sarif", label: "SARIF", filename: safeTarget + "-audit.sarif", downloadable: true },
      { kind: "markdown", label: "Markdown", filename: safeTarget + "-audit.md", downloadable: true },
    ];
  }

  function changedFilesForReport(report) {
    var paths = healedFileDiffs(report).map(function (entry) { return entry.path; });
    var patch = report && (report.dockerfile_patch || safeArray(report.dockerfile_patches)[0]);
    if (patch && patch.file_path) paths.push(normalizeFilePath(patch.file_path));
    return paths.filter(function (path, index, values) { return path && values.indexOf(path) === index; });
  }

  function saveAuditHistory() {
    if (!state.report) return;
    var report = state.report;
    var id = String(report.target || state.target) + "|" + String(report.scanned_at || "");
    var timestamp = report.scanned_at || new Date().toISOString();
    var record = {
      id: id,
      target: state.target,
      scanned_at: timestamp,
      timestamp: timestamp,
      auto_heal: Boolean(state.auditWasAutoHealed),
      new_only: Boolean(state.newOnly),
      readiness: readinessScore(report),
      findings: displayIssues().length,
      issue_count: displayIssues().length,
      certificate: certificateHistoryMetadata(report),
      changed_files: changedFilesForReport(report),
      artifacts: artifactHistoryMetadata(state.target),
      report: report,
      build_verification: state.buildVerification,
    };
    var existing = state.history.findIndex(function (item) { return item.id === id; });
    if (existing >= 0) state.history.splice(existing, 1);
    state.history.unshift(record);
    state.history = state.history.slice(0, 12);
    state.selectedHistoryId = id;
    persistHistory();
  }

  function selectHistory(id, options) {
    var record = state.history.find(function (item) { return item.id === id; });
    if (!record || !record.report) return;
    state.selectedHistoryId = record.id;
    state.target = record.target || "workspace";
    state.report = record.report;
    state.analysis = null;
    state.comparison = null;
    state.auditWasAutoHealed = Boolean(record.auto_heal);
    state.newOnly = Boolean(record.new_only);
    state.buildVerification = record.build_verification || null;
    var select = byId("target-select");
    if (select) {
      var option = Array.prototype.find.call(select.options, function (item) { return item.value === state.target; });
      if (!option) {
        option = document.createElement("option");
        option.value = state.target;
        option.textContent = state.target === "workspace" ? "Current workspace" : state.target;
        select.appendChild(option);
      }
      select.value = state.target;
    }
    var baselineToggle = byId("new-only-toggle");
    if (baselineToggle) baselineToggle.checked = state.newOnly;
    renderTargetDescription();
    renderAll();
    if (!options || options.syncUrl !== false) syncRoute(state.activeView, { run: record.id });
  }

  function renderTargetDescription() {
    var description = targetDescriptions[state.target] || "Workspace target selected for deterministic audit.";
    var select = byId("target-select");
    if (select) select.title = description;
    setText("settings-target-description", description);
    setText("build-target", state.target);
    var pathInput = byId("target-path-input");
    if (pathInput && document.activeElement !== pathInput) pathInput.value = state.target;
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
    state.toastTimer = window.setTimeout(function () { toast.classList.remove("is-visible"); }, 3600);
  }

  function logEvent(message, level) {
    state.events.push({ message: String(message), level: level || "info", time: new Date() });
    if (state.events.length > 30) state.events = state.events.slice(-30);
    renderTerminal();
  }

  function renderTerminal() {
    var output = byId("terminal-output");
    if (!output) return;
    output.textContent = state.events.map(function (entry) {
      var date = entry.time instanceof Date ? entry.time : new Date(entry.time || Date.now());
      var stamp = date.getFullYear() + "-" + String(date.getMonth() + 1).padStart(2, "0") + "-" + String(date.getDate()).padStart(2, "0") + " " + String(date.getHours()).padStart(2, "0") + ":" + String(date.getMinutes()).padStart(2, "0") + ":" + String(date.getSeconds()).padStart(2, "0");
      return stamp + " [" + String(entry.level || "info").toUpperCase() + "] " + entry.message;
    }).join("\n");
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
    try { payload = await response.json(); } catch (error) { payload = null; }
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

  function selectedCertificate(report) {
    if (!report) return {};
    return report.after_certificate || report.certificate || report.before_certificate || {};
  }

  function readinessScore(report) {
    if (!report) return null;
    var sources = [report.after_certificate, report.certificate, report.before_certificate, report];
    for (var index = 0; index < sources.length; index += 1) {
      var source = sources[index];
      if (!source) continue;
      var raw = source.linux_readiness_score;
      if (raw == null || raw === "") raw = source.readiness_score;
      if (raw == null || raw === "") continue;
      var value = Number(raw);
      if (Number.isFinite(value)) return value;
    }
    return Math.max(0, 100 - safeArray(report.issues).length * 8);
  }

  function dependencyScore(report) {
    var certificate = selectedCertificate(report);
    if (!report) return null;
    return Number.isFinite(Number(certificate.dependency_lock_score)) ? Number(certificate.dependency_lock_score) : null;
  }

  function renderGauge(id, score) {
    var element = byId(id);
    if (!element) return;
    var numeric = Number(score);
    var ready = Number.isFinite(numeric);
    numeric = ready ? Math.max(0, Math.min(100, numeric)) : 0;
    var radius = 28;
    var circumference = 2 * Math.PI * radius;
    var offset = circumference * (1 - numeric / 100);
    element.innerHTML = '<svg class="kpi-gauge-svg" viewBox="0 0 68 68" aria-hidden="true"><circle class="kpi-gauge-track" cx="34" cy="34" r="28"></circle><circle class="kpi-gauge-value" cx="34" cy="34" r="28" stroke-dasharray="' + circumference.toFixed(2) + '" stroke-dashoffset="' + offset.toFixed(2) + '"></circle></svg><span>' + (ready ? Math.round(numeric) + "%" : "--") + '</span>';
    element.setAttribute("aria-label", ready ? Math.round(numeric) + " percent" : "Score pending");
  }

  function dependencyMetrics(report, certificate) {
    var source = (report && (report.dependency_telemetry || report.dependency_metrics)) || certificate.dependency_metrics || {};
    return {
      total: source.total == null ? "--" : source.total,
      direct: source.direct == null ? "--" : source.direct,
      transitive: source.transitive == null ? "--" : source.transitive,
      pinned: source.pinned == null ? "--" : source.pinned,
      floating: source.floating == null ? "--" : source.floating,
      vulnerabilityStatus: source.vulnerability_status || "unavailable",
    };
  }

  function renderKpis() {
    var report = state.report;
    var certificate = selectedCertificate(report);
    var readiness = readinessScore(report);
    var dependency = dependencyScore(report);
    renderGauge("readiness-gauge", readiness);
    renderGauge("dependency-gauge", dependency);
    setText("readiness-meta", readiness == null ? "Awaiting scan results" : readiness >= 85 ? "Passed all compatibility checks" : "Compatibility checks need review");
    setText("dependency-meta", dependency == null ? "Lock evidence pending" : dependency >= 85 ? "All dependencies secure and up to date" : "Dependency lock needs review");
    var metrics = dependencyMetrics(report, certificate);
    setText("dep-total", metrics.total);
    setText("dep-direct", metrics.direct);
    setText("dep-transitive", metrics.transitive);
    setText("dependency-pin-status", "Pinned " + metrics.pinned + " / Floating " + metrics.floating + " / Vuln DB " + metrics.vulnerabilityStatus);
    setText("root-hash", certificate.root_hash ? truncate(certificate.root_hash, 19, 0) : "pending");
    setText("root-meta", certificate.root_hash ? "Immutable build fingerprint" : "Immutable build fingerprint pending");
    var certified = Boolean(certificate.is_cleanroom_certified || certificate.verified);
    setText("certificate-meta", certified ? "Cryptographic attestation passed" : "Cryptographic attestation pending");
    setText("certificate-status", certified ? "SLSA Level 3  /  Reproducible  /  Verified" : "SLSA Level 3  /  Reproducible  /  Pending");
  }

  function severityClass(severity) {
    var normalized = String(severity || "medium").toLowerCase();
    return ["low", "medium", "high", "critical"].indexOf(normalized) >= 0 ? normalized : "medium";
  }

  function issueText(issue) {
    return [issueRule(issue), issue.category, issue.message, issue.remediation, issue.file_path, safeArray(issue.evidence).join(" ")].join(" ").toLowerCase();
  }

  function affectedPlatforms(issue) {
    var text = issueText(issue);
    var platforms = [];
    if (text.indexOf("windows") >= 0 || text.indexOf("backslash") >= 0 || text.indexOf("crlf") >= 0 || text.indexOf("win") >= 0) platforms.push("windows");
    if (text.indexOf("mac") >= 0 || text.indexOf("darwin") >= 0 || text.indexOf("apple") >= 0) platforms.push("apple");
    if (text.indexOf("linux") >= 0 || text.indexOf("case") >= 0 || text.indexOf("native") >= 0 || text.indexOf("docker") >= 0 || text.indexOf("apt") >= 0) platforms.push("linux");
    if (!platforms.length) platforms = ["linux", "windows", "apple"];
    return platforms.filter(function (platform, index) { return platforms.indexOf(platform) === index; });
  }

  function issueIsFixed(issue) {
    var report = state.report;
    if (!report || !state.auditWasAutoHealed || !report.after_certificate) return false;
    if (issue && issue.postHeal) return false;
    var remaining = safeArray(report.after_certificate.issues);
    return !remaining.some(function (item) { return issueFingerprint(item) === issueFingerprint(issue); });
  }

  function issueFingerprint(issue) {
    return [issue && issue.issue_id, issue && issue.file_path, issue && issue.line_number, issue && issue.message].join("|");
  }

  function issueRule(issue) {
    return String(issue && (issue.rule_id || issue.rule || issue.ruleId || issue.category || issue.issue_id) || "unclassified");
  }

  function issueStatus(issue) {
    return issueIsFixed(issue) ? "fixed" : "open";
  }

  function issueSelectionKey(issue, index) {
    return issueFingerprint(issue) + "#" + String(index);
  }

  function issueSortValue(issue, key) {
    if (key === "severity") return { low: 1, medium: 2, high: 3, critical: 4 }[severityClass(issue && issue.severity)] || 0;
    if (key === "path") return String(issue && issue.file_path || "").toLowerCase();
    if (key === "rule") return issueRule(issue).toLowerCase();
    if (key === "status") return issueStatus(issue) === "fixed" ? 1 : 0;
    return "";
  }

  function sortIssueEntries(entries) {
    var direction = state.issueSortDirection === "asc" ? 1 : -1;
    return entries.slice().sort(function (left, right) {
      var leftValue = issueSortValue(left.issue, state.issueSortKey);
      var rightValue = issueSortValue(right.issue, state.issueSortKey);
      var result;
      if (typeof leftValue === "number" && typeof rightValue === "number") result = leftValue - rightValue;
      else result = String(leftValue).localeCompare(String(rightValue), undefined, { numeric: true, sensitivity: "base" });
      if (result === 0) result = left.index - right.index;
      return result * direction;
    });
  }

  function issueEntriesForExport() {
    var issues = displayIssues();
    return sortIssueEntries(issues.filter(issueMatches).map(function (issue) {
      return { issue: issue, index: issues.indexOf(issue) };
    }));
  }

  function displayIssues() {
    var report = state.report;
    var baseline = report ? safeArray(report.issues) : [];
    if (!report || !state.auditWasAutoHealed || !report.after_certificate) return baseline;
    var baselineFingerprints = baseline.map(issueFingerprint);
    var remaining = safeArray(report.after_certificate.issues)
      .filter(function (issue) { return baselineFingerprints.indexOf(issueFingerprint(issue)) < 0; })
      .map(function (issue) { return Object.assign({}, issue, { postHeal: true }); });
    return baseline.concat(remaining);
  }

  function issueLocation(issue) {
    return issue && issue.file_path ? issue.file_path + (issue.line_number ? ":" + issue.line_number : "") : "target root";
  }

  function issueDisplayId(issue, index) {
    var source = String(issue && issue.issue_id || "");
    return /^WM-\d+$/i.test(source) ? source.toUpperCase() : "WM-" + String(index + 1).padStart(3, "0");
  }

  function issueMatches(issue) {
    var fixed = issueIsFixed(issue);
    var severity = severityClass(issue.severity);
    var filterPass = state.issueFilter === "all" || (state.issueFilter === "fixed" && fixed) || (state.issueFilter === severity && severity === state.issueFilter);
    var query = state.issueSearch.trim().toLowerCase();
    var queryPass = !query || issueText(issue).indexOf(query) >= 0 || String(issue.issue_id || "").toLowerCase().indexOf(query) >= 0;
    return filterPass && queryPass;
  }

  function renderIssueCounts(issues) {
    var critical = issues.filter(function (issue) { return severityClass(issue.severity) === "critical"; }).length;
    var high = issues.filter(function (issue) { return severityClass(issue.severity) === "high"; }).length;
    var fixed = issues.filter(issueIsFixed).length;
    setText("filter-all-count", issues.length);
    setText("filter-critical-count", critical);
    setText("filter-high-count", high);
    setText("filter-fixed-count", fixed);
  }

  function renderIssueList() {
    var list = byId("issue-list");
    var issues = displayIssues();
    if (!list) return;
    renderIssueCounts(issues);
    var filtered = issues.filter(issueMatches);
    var entries = sortIssueEntries(filtered.map(function (issue) {
      return { issue: issue, index: issues.indexOf(issue) };
    }));
    var knownKeys = {};
    issues.forEach(function (issue, index) { knownKeys[issueSelectionKey(issue, index)] = true; });
    Object.keys(state.selectedIssueKeys).forEach(function (key) {
      if (!knownKeys[key]) delete state.selectedIssueKeys[key];
    });
    var pageCount = Math.max(1, Math.ceil(entries.length / state.issuePageSize));
    state.issuePage = Math.min(Math.max(1, state.issuePage), pageCount);
    var pageStart = (state.issuePage - 1) * state.issuePageSize;
    var pageEntries = entries.slice(pageStart, pageStart + state.issuePageSize);
    var selectedVisible = pageEntries.filter(function (entry) { return state.selectedIssueKeys[issueSelectionKey(entry.issue, entry.index)]; }).length;
    var selectedTotal = Object.keys(state.selectedIssueKeys).length;
    var selectAll = byId("issue-select-all");
    if (selectAll) {
      selectAll.checked = pageEntries.length > 0 && selectedVisible === pageEntries.length;
      selectAll.indeterminate = selectedVisible > 0 && selectedVisible < pageEntries.length;
    }
    var sort = byId("issue-sort");
    if (sort) sort.value = state.issueSortKey;
    var direction = byId("issue-sort-direction");
    if (direction) {
      direction.textContent = state.issueSortDirection.toUpperCase();
      direction.setAttribute("aria-label", "Sort direction: " + state.issueSortDirection);
    }
    var search = byId("issue-search");
    if (search && document.activeElement !== search) search.value = state.issueSearch;
    document.querySelectorAll("[data-issue-filter]").forEach(function (button) {
      var active = button.getAttribute("data-issue-filter") === state.issueFilter;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", active ? "true" : "false");
    });
    var issueFilterButton = byId("issue-filter-button");
    if (issueFilterButton) issueFilterButton.setAttribute("aria-pressed", state.issueFilter === "fixed" ? "true" : "false");
    list.setAttribute("aria-live", "polite");
    var rangeStart = entries.length ? pageStart + 1 : 0;
    var rangeEnd = Math.min(pageStart + pageEntries.length, entries.length);
    setText("issue-selection-count", selectedTotal + " selected");
    setText("issue-results-meta", entries.length ? "Showing " + rangeStart + "-" + rangeEnd + " of " + entries.length : "0 findings");
    if (!entries.length) {
      list.innerHTML = '<div class="empty-state">' + icon(state.report ? "checkSuccess" : "bug", 25) + '<strong>' + (state.report ? "No matching findings" : "Awaiting repository scan") + '</strong><span>' + (state.report ? "Adjust the issue filter or search term." : "Run Auto-Heal & Certify to load cross-platform evidence.") + '</span></div>';
      hydrateIcons();
      return;
    }
    list.innerHTML = '<div class="table-scroll"><table class="issues-table"><thead><tr><th class="issue-select-column"><span class="sr-only">Select</span></th><th>ID</th><th>Severity</th><th>Rule</th><th>OS affected</th><th>Description</th><th>File / path</th><th>Status</th></tr></thead><tbody>' + pageEntries.map(function (entry) {
      var issue = entry.issue;
      var originalIndex = entry.index;
      var severity = severityClass(issue.severity);
      var fixed = issueIsFixed(issue);
      var selectionKey = issueSelectionKey(issue, originalIndex);
      var platforms = affectedPlatforms(issue).map(function (platform) {
        var names = { linux: "linuxLogo", windows: "windowsLogo", apple: "appleLogo" };
        return iconClass(names[platform], 15, platform + "-logo", platform);
      }).join("");
      var description = issue.remediation || "Review this assumption before moving the build to a clean room.";
      return '<tr data-issue-index="' + originalIndex + '" tabindex="0" role="button" aria-label="Open issue ' + escapeHtml(issueDisplayId(issue, originalIndex)) + ': ' + escapeHtml(issue.message || "Unclassified issue") + '"><td class="issue-select-column"><input class="issue-row-select" type="checkbox" data-issue-selection="' + escapeHtml(selectionKey) + '" aria-label="Select ' + escapeHtml(issueDisplayId(issue, originalIndex)) + '"' + (state.selectedIssueKeys[selectionKey] ? ' checked' : '') + '></td><td><code>' + escapeHtml(issueDisplayId(issue, originalIndex)) + '</code></td><td><span class="severity severity-' + severity + '">' + escapeHtml(severity) + '</span></td><td><code class="issue-rule" title="' + escapeHtml(issueRule(issue)) + '">' + escapeHtml(issueRule(issue)) + '</code></td><td><span class="os-icons" aria-label="Affected platforms">' + platforms + '</span></td><td><div class="issue-desc"><strong>' + escapeHtml(issue.message || "Unclassified issue") + '</strong><span>' + escapeHtml(description) + '</span></div></td><td><span class="issue-path" title="' + escapeHtml(issueLocation(issue)) + '">' + escapeHtml(issueLocation(issue)) + '</span></td><td><span class="issue-status ' + (fixed ? "status-fixed" : "status-open") + '">' + (fixed ? "FIXED" : "OPEN") + '</span></td></tr>';
    }).join("") + '</tbody></table></div><div class="issue-pagination" aria-label="Finding pagination"><button class="button button-dark button-small issue-page-button" type="button" data-issue-page="prev"' + (state.issuePage <= 1 ? ' disabled' : '') + '>Previous</button><span>Page ' + state.issuePage + ' of ' + pageCount + '</span><button class="button button-dark button-small issue-page-button" type="button" data-issue-page="next"' + (state.issuePage >= pageCount ? ' disabled' : '') + '>Next</button></div>';
    list.querySelectorAll("[data-issue-index]").forEach(function (row) {
      row.addEventListener("click", function (event) { if (event.target.closest && event.target.closest("input")) return; openIssueDetail(row.getAttribute("data-issue-index")); });
      row.addEventListener("keydown", function (event) { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openIssueDetail(row.getAttribute("data-issue-index")); } });
    });
    list.querySelectorAll("[data-issue-selection]").forEach(function (checkbox) {
      checkbox.addEventListener("change", function () {
        var key = checkbox.getAttribute("data-issue-selection");
        if (checkbox.checked) state.selectedIssueKeys[key] = true;
        else delete state.selectedIssueKeys[key];
        renderIssueList();
      });
    });
    list.querySelectorAll("[data-issue-page]").forEach(function (button) {
      button.addEventListener("click", function () {
        if (button.disabled) return;
        state.issuePage += button.getAttribute("data-issue-page") === "next" ? 1 : -1;
        persistFindingFilters();
        renderIssueList();
      });
    });
    hydrateIcons();
  }

  function renderAuditState() {
    var report = state.report;
    var readiness = readinessScore(report);
    var label = state.busy ? (state.auditWasAutoHealed ? "Auto-Heal & Certify" : "Scanning") : report ? "Complete" : "Ready";
    setText("audit-state", label);
    setText("audit-meta", report ? "Last run " + new Date(report.scanned_at || Date.now()).toLocaleTimeString() : "Waiting for run");
    var checklist = {
      scan: Boolean(report),
      dependencies: Boolean(report && dependencyScore(report) != null),
      tests: Boolean(report && report.certificate),
      heal: Boolean(report && state.auditWasAutoHealed),
      build: Boolean(state.buildVerification && state.buildVerification.status === "passed"),
      certificate: Boolean(report && report.certificate),
    };
    document.querySelectorAll("[data-check]").forEach(function (item) {
      item.classList.toggle("is-pending", !checklist[item.getAttribute("data-check")]);
    });
    if (report) {
      setText("build-diff-count", safeArray(report.unified_diffs).length);
    }
    return readiness;
  }

  function renderReportJson() {
    var reportNode = byId("report-json");
    if (reportNode) reportNode.textContent = state.report ? JSON.stringify(state.report, null, 2) : "No audit report loaded.";
  }

  function renderHistory() {
    var list = byId("history-list");
    if (!list) return;
    if (!state.history.length) {
      list.innerHTML = '<div class="history-empty">No saved audit runs yet. Completed audits will appear here automatically.</div>';
      return;
    }
    list.innerHTML = state.history.map(function (record) {
      var date = new Date(record.timestamp || record.scanned_at || Date.now()).toLocaleString();
      var readiness = record.readiness == null ? "--" : Math.round(Number(record.readiness)) + "%";
      var findings = record.findings == null ? record.issue_count || 0 : record.findings;
      return '<button class="history-item ' + (record.id === state.selectedHistoryId ? "is-active" : "") + '" type="button" data-history-id="' + escapeHtml(record.id) + '"><span><strong>' + escapeHtml(record.target || "workspace") + '</strong><small>' + escapeHtml(date) + ' / ' + escapeHtml(String(findings)) + ' findings</small></span><em>' + escapeHtml(readiness) + '</em></button>';
    }).join("");
    list.querySelectorAll("[data-history-id]").forEach(function (button) {
      button.addEventListener("click", function () { selectHistory(button.getAttribute("data-history-id")); });
    });
  }

  function historyFindingCount(record) {
    if (!record) return 0;
    if (Array.isArray(record.findings)) return record.findings.length;
    return numberOr(record.findings, numberOr(record.issue_count, 0));
  }

  function historyCertificate(record) {
    if (record && record.certificate && typeof record.certificate === "object") return record.certificate;
    var certificate = selectedCertificate(record && record.report);
    return certificateHistoryMetadata(record && record.report);
  }

  function historyChangedFiles(record) {
    if (record && Array.isArray(record.changed_files)) return record.changed_files;
    return changedFilesForReport(record && record.report);
  }

  function historyArtifacts(record) {
    if (record && Array.isArray(record.artifacts) && record.artifacts.length) return record.artifacts;
    return artifactHistoryMetadata(record && record.target);
  }

  function historyDate(record) {
    return new Date(record && (record.timestamp || record.scanned_at) || Date.now()).toLocaleString();
  }

  function renderHistoryComparison() {
    var panel = byId("history-comparison");
    var status = byId("history-selection-status");
    if (!panel) return;
    var selectedIndex = state.history.findIndex(function (record) { return record.id === state.selectedHistoryId; });
    if (selectedIndex < 0) {
      if (status) status.textContent = "No run selected";
      panel.innerHTML = '<div class="empty-state compact-empty"><strong>Select a saved run</strong><span>Run metadata and historical deltas will appear here.</span></div>';
      return;
    }
    var record = state.history[selectedIndex];
    var previous = state.history[selectedIndex + 1] || null;
    var certificate = historyCertificate(record);
    var changedFiles = historyChangedFiles(record);
    var readiness = record.readiness == null ? "--" : Math.round(Number(record.readiness)) + "%";
    var findings = historyFindingCount(record);
    var readinessDelta = previous && record.readiness != null && previous.readiness != null ? numberOr(record.readiness, 0) - numberOr(previous.readiness, 0) : null;
    var findingDelta = previous ? findings - historyFindingCount(previous) : null;
    if (status) status.textContent = (record.target || "workspace") + " / " + historyDate(record);
    panel.innerHTML = '<div class="history-selected-header"><div><span class="drawer-kicker">AUDIT RECEIPT</span><strong>' + escapeHtml(record.target || "workspace") + '</strong><small>' + escapeHtml(historyDate(record)) + '</small></div><span class="history-certificate-badge history-certificate-' + escapeHtml(String(certificate.status || "pending")) + '">' + escapeHtml(String(certificate.status || "pending").toUpperCase()) + '</span></div>' +
      '<div class="history-detail-grid"><div><span>Readiness</span><strong>' + escapeHtml(readiness) + '</strong></div><div><span>Findings</span><strong>' + escapeHtml(String(findings)) + '</strong></div><div><span>Changed files</span><strong>' + escapeHtml(String(changedFiles.length)) + '</strong></div><div><span>Certificate</span><strong>' + escapeHtml(String(certificate.status || "pending")) + '</strong></div></div>' +
      '<div class="history-delta"><span class="drawer-kicker">COMPARISON</span><p>' + (previous ? "Compared with " + escapeHtml(previous.target || "workspace") + " from " + escapeHtml(historyDate(previous)) + ": readiness " + escapeHtml(readinessDelta == null ? "--" : (readinessDelta >= 0 ? "+" : "") + readinessDelta.toFixed(0) + " points") + ", findings " + escapeHtml(findingDelta == null ? "--" : (findingDelta >= 0 ? "+" : "") + findingDelta) + "." : "This is the earliest saved run; a later run will add a comparison baseline.") + '</p></div>' +
      '<div class="history-files"><span class="drawer-kicker">CHANGED FILES</span>' + (changedFiles.length ? '<ul>' + changedFiles.map(function (path) { return '<li><code>' + escapeHtml(path) + '</code></li>'; }).join("") + '</ul>' : '<p class="muted-text">No changed files recorded for this run.</p>') + '</div>' +
      '<div class="history-artifacts"><span class="drawer-kicker">DOWNLOADABLE ARTIFACTS</span><div class="button-row">' + historyArtifacts(record).map(function (artifact) { return '<button class="button button-dark button-small" type="button" data-history-artifact="' + escapeHtml(artifact.kind) + '" data-history-id="' + escapeHtml(record.id) + '">' + escapeHtml(artifact.label || artifact.kind) + '</button>'; }).join("") + '</div></div>';
  }

  function renderRunHistory() {
    var list = byId("run-history-list");
    if (!list) return;
    setText("history-run-count", state.history.length);
    setText("history-latest-target", state.history.length ? state.history[0].target || "workspace" : "--");
    setText("history-latest-time", state.history.length ? historyDate(state.history[0]) : "--");
    if (!state.history.length) {
      list.innerHTML = '<div class="history-empty">No saved audit runs yet. Completed audits will appear here automatically.</div>';
      renderHistoryComparison();
      return;
    }
    list.innerHTML = state.history.map(function (record) {
      var certificate = historyCertificate(record);
      var changedFiles = historyChangedFiles(record);
      var readiness = record.readiness == null ? "--" : Math.round(Number(record.readiness)) + "%";
      return '<article class="history-run-card ' + (record.id === state.selectedHistoryId ? "is-active" : "") + '"><button class="history-run-select" type="button" data-history-id="' + escapeHtml(record.id) + '"><span><strong>' + escapeHtml(record.target || "workspace") + '</strong><small>' + escapeHtml(historyDate(record)) + '</small></span><em>' + escapeHtml(readiness) + '</em></button><div class="history-run-meta"><span>' + escapeHtml(String(historyFindingCount(record))) + ' findings</span><span>' + escapeHtml(String(changedFiles.length)) + ' changed</span><span class="history-certificate-badge history-certificate-' + escapeHtml(String(certificate.status || "pending")) + '">' + escapeHtml(String(certificate.status || "pending")) + '</span></div></article>';
    }).join("");
    list.querySelectorAll("[data-history-id]").forEach(function (button) {
      button.addEventListener("click", function () { selectHistory(button.getAttribute("data-history-id")); });
    });
    renderHistoryComparison();
  }

  function renderBuildVerification() {
    var result = state.buildVerification;
    var card = byId("build-verification-card");
    var status = byId("build-verification-status");
    var output = byId("build-verification-log");
    if (!card || !status || !output) return;
    card.classList.remove("is-passed", "is-failed", "is-blocked");
    if (!result) {
      setText("build-verification-status", "NOT RUN");
      output.textContent = "No staged build has been requested.";
      return;
    }
    var normalized = String(result.status || "unknown").toLowerCase();
    card.classList.toggle("is-passed", normalized === "passed");
    card.classList.toggle("is-failed", normalized === "failed" || normalized === "timed_out");
    card.classList.toggle("is-blocked", normalized === "blocked");
    setText("build-verification-status", normalized.replace(/_/g, " ").toUpperCase());
    output.textContent = (result.detail || "") + (result.output ? "\n\n" + result.output : "");
  }

  function unifiedDiffText(diff) {
    if (typeof diff === "string") return diff;
    if (!diff || typeof diff !== "object") return "";
    return String(diff.unified_diff || diff.diff || diff.patch || "");
  }

  function normalizeFilePath(path) {
    var normalized = String(path || "").trim().replace(/\\/g, "/");
    if (!normalized || normalized === "/dev/null" || normalized === "dev/null") return "";
    normalized = normalized.replace(/^\.\//, "");
    if (normalized.indexOf("a/") === 0 || normalized.indexOf("b/") === 0) normalized = normalized.slice(2);
    return normalized;
  }

  function unifiedDiffHeaderPath(line) {
    var value = String(line || "").replace(/^(?:---|\+\+\+)\s+/, "").trim();
    if (!value) return "";
    var tab = value.indexOf("\t");
    if (tab >= 0) value = value.slice(0, tab);
    if (value.length > 1 && value.charAt(0) === '"' && value.charAt(value.length - 1) === '"') value = value.slice(1, -1);
    return normalizeFilePath(value);
  }

  function unifiedDiffPath(diff) {
    var text = unifiedDiffText(diff);
    var lines = text.split("\n");
    var oldPath = "";
    var newPath = "";
    lines.some(function (line) {
      if (!oldPath && /^---\s+/.test(line)) oldPath = unifiedDiffHeaderPath(line);
      if (!newPath && /^\+\+\+\s+/.test(line)) newPath = unifiedDiffHeaderPath(line);
      return Boolean(oldPath && newPath);
    });
    if (newPath) return newPath;
    if (oldPath) return oldPath;
    var gitHeader = text.match(/^diff --git\s+\S+\s+(\S+)$/m);
    return gitHeader ? normalizeFilePath(gitHeader[1]) : "";
  }

  function healedFileDiffs(report) {
    var seen = {};
    return safeArray(report && report.unified_diffs).map(function (diff, index) {
      return { path: unifiedDiffPath(diff), diff: unifiedDiffText(diff), index: index };
    }).filter(function (entry) {
      if (!entry.path || !entry.diff || seen[entry.path]) return false;
      seen[entry.path] = true;
      return true;
    });
  }

  function issueIndexForFile(path) {
    var normalized = normalizeFilePath(path);
    if (!normalized) return -1;
    return displayIssues().findIndex(function (issue) {
      return normalizeFilePath(issue && issue.file_path) === normalized;
    });
  }

  function renderBuildReport() {
    var panel = byId("build-report-panel");
    if (!panel) return;
    var entries = healedFileDiffs(state.report);
    var selected = entries.find(function (entry) { return entry.path === state.selectedHealedFilePath; });
    if (!selected) state.selectedHealedFilePath = null;
    var chips = entries.map(function (entry) {
      var issueIndex = issueIndexForFile(entry.path);
      var action = issueIndex >= 0 ? "Open issue detail" : "View healed file diff";
      return '<button class="package-chip healed-file-chip" type="button" data-healed-file="' + escapeHtml(entry.path) + '" aria-label="' + escapeHtml(action + ": " + entry.path) + '" title="' + escapeHtml(action) + '" aria-pressed="' + (entry.path === state.selectedHealedFilePath ? "true" : "false") + '">' + escapeHtml(entry.path) + '</button>';
    }).join("");
    var selectedMarkup = selected ? '<div class="drawer-kicker">SELECTED HEALED FILE</div><div class="healed-file-selection"><code>' + escapeHtml(selected.path) + '</code></div><pre class="source-context" id="build-healed-file-diff">' + diffText(selected.diff) + '</pre>' : '';
    panel.innerHTML = '<div class="build-report-copy">Build verification is opt-in and runs only against a temporary staged copy.</div>' + (entries.length ? '<div class="drawer-kicker">HEALED FILES</div><div class="package-cloud healed-file-chips" aria-label="Healed files">' + chips + '</div>' : '<div class="muted-text">No healed file diffs returned.</div>') + selectedMarkup;
  }

  function dependencyPackages(report) {
    var packages = [];
    var analysis = state.analysis || {};
    packages = packages.concat(safeArray(analysis.apt_packages || analysis.recommended_apt_packages));
    safeArray(report && (report.diagnostics || report.compiler_diagnostics)).forEach(function (diagnostic) {
      packages = packages.concat(safeArray(diagnostic.recommended_apt_packages));
    });
    return packages.map(function (item) { return String(item || "").trim(); }).filter(Boolean).filter(function (item, index, values) { return values.indexOf(item) === index; }).slice(0, 12);
  }

  function dockerBaseEvidence(report, fileNodes) {
    var sources = [];
    var patch = report && (report.dockerfile_patch || safeArray(report.dockerfile_patches)[0]);
    if (patch) sources.push(patch.before_content || "", patch.after_content || "", patch.patched_content || "", patch.unified_diff || patch.diff || "");
    safeArray(report && report.unified_diffs).filter(function (diff) { return /dockerfile/i.test(diff); }).forEach(function (diff) { sources.push(diff); });
    var bases = [];
    sources.join("\n").split("\n").forEach(function (line) {
      var match = line.match(/^\+?\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i);
      if (match && bases.indexOf(match[1]) < 0) bases.push(match[1]);
    });
    if (!bases.length && fileNodes.some(function (node) { return /^dockerfile(?:\.|$)/i.test(String(node.path || "").split("/").pop()); })) bases.push("Dockerfile base pending");
    return bases.slice(0, 4);
  }

  function graphNodeMarkup(node) {
    var width = 190;
    var fullLabel = String(node.label || "pending");
    var fullMeta = String(node.meta || node.kind || "");
    var label = truncate(fullLabel, 26, 0);
    var meta = truncate(fullMeta, 30, 0);
    return '<g class="graph-node graph-node-' + escapeHtml(node.kind) + '" transform="translate(' + node.x + ' ' + node.y + ')"><title>' + escapeHtml(fullLabel + " | " + fullMeta) + '</title><rect width="' + width + '" height="52" rx="5"></rect><text x="12" y="22">' + escapeHtml(label) + '</text><text class="graph-node-meta" x="12" y="39">' + escapeHtml(meta) + '</text></g>';
  }

  function graphEdgeMarkup(from, to) {
    var startX = from.x + 190;
    var startY = from.y + 26;
    var endX = to.x;
    var endY = to.y + 26;
    var control = Math.max(30, (endX - startX) * 0.42);
    return '<path class="graph-edge" d="M ' + startX + ' ' + startY + ' C ' + (startX + control) + ' ' + startY + ', ' + (endX - control) + ' ' + endY + ', ' + endX + ' ' + endY + '"></path>';
  }

  function renderGraphTextAlternative(nodes, relationships, summary) {
    setText("dependency-graph-text-summary", summary);
    var list = byId("dependency-graph-text-list");
    if (!list) return;
    if (!nodes.length) {
      list.innerHTML = "<li>Run an audit to create a text alternative for the dependency evidence.</li>";
      return;
    }
    var nodeItems = nodes.map(function (node) {
      return "<li><strong>" + escapeHtml(node.label) + "</strong>: " + escapeHtml(node.meta || node.kind) + "</li>";
    });
    var relationshipItems = relationships.map(function (relationship) {
      return "<li>" + escapeHtml(relationship.from.label) + " connects to " + escapeHtml(relationship.to.label) + ".</li>";
    });
    list.innerHTML = nodeItems.concat(relationshipItems).join("");
  }

  function renderDependencyGraph() {
    var panel = byId("dependency-graph");
    var status = byId("dependency-graph-status");
    if (!panel) return;
    var report = state.report;
    var certificate = selectedCertificate(report);
    var fileNodes = safeArray(certificate.file_nodes);
    var manifests = safeArray(report && report.dependency_telemetry && report.dependency_telemetry.manifests);
    var packageNames = dependencyPackages(report);
    var dockerBases = dockerBaseEvidence(report, fileNodes);
    var evidenceCount = fileNodes.length + manifests.length + packageNames.length + dockerBases.length;
    if (!report && !state.analysis) {
      if (status) status.textContent = "Awaiting audit evidence";
      renderGraphTextAlternative([], [], "No dependency evidence is available yet.");
      panel.innerHTML = '<div class="empty-state compact-empty">' + icon("dependencyGraph", 25) + '<strong>No dependency evidence yet</strong><span>Run an audit to map certificate files, manifests, parsed packages, and Docker base evidence.</span></div>';
      hydrateIcons();
      return;
    }
    if (!evidenceCount) {
      if (status) status.textContent = "No graphable evidence returned";
      renderGraphTextAlternative([], [], "The current report returned no graphable dependency evidence.");
      panel.innerHTML = '<div class="empty-state compact-empty">' + icon("dependencyGraph", 25) + '<strong>Nothing to graph yet</strong><span>The current report has no file, manifest, package, or Docker evidence. Run a scan or parse a compiler trace to add evidence.</span></div>';
      return;
    }

    var target = { kind: "target", label: state.target, meta: "active workspace target", x: 40, y: 36 };
    var certificateNode = { kind: "certificate", label: certificate.root_hash ? "CleanRoom certificate" : "Certificate pending", meta: certificate.root_hash || "audit proof", x: 290, y: 36 };
    var allFiles = fileNodes.slice(0, 14);
    manifests.filter(function (manifest) { return !allFiles.some(function (node) { return node.path === manifest; }); }).slice(0, 6).forEach(function (manifest) {
      allFiles.push({ path: manifest, digest: "lock evidence", has_crlf: false });
    });
    var splitCols = allFiles.length > 7;
    var graphFiles = allFiles.map(function (node, index) {
      var col = splitCols ? (index % 2) : 0;
      var row = splitCols ? Math.floor(index / 2) : index;
      var xPos = col === 1 ? 810 : 550;
      return {
        kind: "file",
        label: node.path,
        meta: (node.has_crlf ? "file / CRLF / " : "file / ") + String(node.digest || "pending"),
        x: xPos,
        y: 36 + row * 64
      };
    });
    var rightColX = splitCols ? 1070 : 830;
    var packages = packageNames.map(function (name, index) {
      return { kind: "package", label: name, meta: "apt package / parsed build evidence", x: rightColX, y: 36 + index * 64 };
    });
    var dockerNodes = dockerBases.map(function (base, index) {
      return { kind: "docker", label: base, meta: "Docker base evidence", x: rightColX, y: 36 + (packageNames.length + index) * 64 };
    });
    var nodes = [target, certificateNode].concat(graphFiles, packages, dockerNodes);
    var relationships = [{ from: target, to: certificateNode }];
    var edges = [graphEdgeMarkup(target, certificateNode)];
    function connect(from, to) {
      relationships.push({ from: from, to: to });
      edges.push(graphEdgeMarkup(from, to));
    }
    graphFiles.forEach(function (node) { connect(certificateNode, node); });
    packages.forEach(function (node) { connect(certificateNode, node); });
    dockerNodes.forEach(function (node) { connect(certificateNode, node); });
    if (graphFiles.length && packages.length) {
      packages.forEach(function (node, index) { connect(graphFiles[index % graphFiles.length], node); });
    }
    if (dockerNodes.length) {
      var dockerFile = graphFiles.find(function (node) { return /^dockerfile(?:\.|$)/i.test(node.label.split("/").pop()); });
      if (dockerFile) dockerNodes.forEach(function (node) { connect(dockerFile, node); });
    }
    var maxY = Math.max.apply(null, nodes.map(function (node) { return node.y + 52; }));
    var width = splitCols ? 1340 : 1120;
    var totalHeight = Math.max(380, maxY + 36);
    panel.innerHTML = '<svg viewBox="0 0 ' + width + ' ' + totalHeight + '" style="min-width:' + width + 'px; height:' + totalHeight + 'px;" role="img" aria-labelledby="dependency-graph-svg-title" aria-describedby="dependency-graph-text-summary"><title id="dependency-graph-svg-title">Dependency evidence graph for ' + escapeHtml(state.target) + '</title><desc>Nodes show the active target, certificate, files, packages, and Docker base evidence. Connections show evidence relationships.</desc><g aria-hidden="true">' + edges.join("") + nodes.map(graphNodeMarkup).join("") + '</g></svg>';
    renderGraphTextAlternative(nodes, relationships, nodes.length + " evidence nodes and " + relationships.length + " relationships for " + state.target + ".");
    if (status) status.textContent = nodes.length + " evidence nodes / " + relationships.length + " relationships";
  }

  function renderOverview() {
    var report = state.report;
    var certificate = selectedCertificate(report);
    var issues = displayIssues();
    var telemetry = report && report.dependency_telemetry ? report.dependency_telemetry : {};
    setText("overview-target", state.target);
    setText("overview-issue-count", issues.length);
    setText("overview-issue-meta", report ? (issues.length ? "Review required" : "No findings returned") : "Awaiting scan");
    setText("overview-manifest-count", safeArray(telemetry.manifests).length);
    setText("overview-docker-status", report ? (certificate.dockerfile_hardened ? "Hardened" : "Review") : "--");
    setText("overview-docker-meta", report ? "Docker base posture" : "Evidence pending");
    setText("overview-run-time", report ? new Date(report.scanned_at || Date.now()).toLocaleTimeString() : "--");
    setText("overview-run-meta", report ? "Last audit completed" : "No audit recorded");
    setText("overview-callout", report ? (issues.length ? "Open the Cross-OS Bugs register to inspect findings and source evidence." : "No cross-platform findings returned. Dependency and certificate evidence are ready to inspect.") : "Run an audit to populate deterministic file, dependency, and Docker evidence.");
  }

  function issueDiff(issue) {
    var report = state.report;
    if (!report || !issue || !issue.file_path) return "";
    var path = normalizeFilePath(issue.file_path);
    var entry = healedFileDiffs(report).find(function (item) { return item.path === path; });
    return entry ? entry.diff : "";
  }

  function renderIssueDetail(issue) {
    if (!issue) return;
    var requestId = state.issueDetailRequestId + 1;
    state.issueDetailRequestId = requestId;
    setText("issue-detail-title", issue.message || issue.issue_id || "Issue detail");
    setText("issue-detail-id", issue.issue_id || "unclassified");
    setText("issue-detail-rule", issue.issue_id || "unclassified");
    setText("issue-detail-severity", String(issue.severity || "medium").toUpperCase());
    setText("issue-detail-category", issue.category || "unclassified");
    setText("issue-detail-location", issueLocation(issue));
    setText("issue-detail-message", issue.message || "No issue message returned.");
    setText("issue-detail-remediation", issue.remediation || "No remediation returned.");
    var status = byId("issue-detail-status");
    var fixed = issueIsFixed(issue);
    if (status) {
      status.textContent = fixed ? "FIXED" : "OPEN";
      status.classList.toggle("status-fixed", fixed);
      status.classList.toggle("status-open", !fixed);
    }
    setText("issue-detail-state", !state.report || !state.report.after_certificate ? "Not evaluated; this was a scan-only result." : fixed ? "Fixed in the staged copy; no matching post-heal finding remains." : "Still present after auto-heal; remains OPEN.");
    setText("issue-detail-why", "Loading rule explanation...");
    setText("issue-detail-scenario", "Loading cross-platform scenario...");
    setText("issue-detail-verification", "Loading after-scan verification...");
    var evidence = byId("issue-detail-evidence");
    if (evidence) evidence.innerHTML = "<li>Loading redacted evidence...</li>";
    var diff = byId("issue-detail-diff");
    var diffValue = issueDiff(issue);
    if (diff) diff.innerHTML = diffValue ? diffText(diffValue) : "No file diff recorded for this issue.";
    var source = byId("issue-detail-source");
    if (source) source.textContent = issue.file_path ? "Loading source context..." : "This finding has no file path context.";
    setDrawerView("issue");
    var explanationIssue = Object.assign({}, issue);
    delete explanationIssue.postHeal;
    request("/api/v1/finding-explanation", { method: "POST", body: { target: state.target, issue: explanationIssue, auto_heal: Boolean(state.auditWasAutoHealed) } }).then(function (explanation) {
      if (requestId !== state.issueDetailRequestId) return;
      setText("issue-detail-id", explanation.rule_id || explanation.issue && explanation.issue.issue_id || issue.issue_id || "unclassified");
      setText("issue-detail-rule", explanation.rule && explanation.rule.id || explanation.rule_id || "unclassified");
      setText("issue-detail-category", explanation.category || explanation.rule && explanation.rule.category || "unclassified");
      setText("issue-detail-message", explanation.issue && explanation.issue.message || issue.message || "No issue message returned.");
      setText("issue-detail-why", explanation.why_detected || "No rule explanation returned.");
      setText("issue-detail-scenario", explanation.likely_cross_platform_scenario || "No cross-platform scenario returned.");
      setText("issue-detail-remediation", explanation.remediation || "No remediation returned.");
      var explanationStatus = explanation.status || {};
      var stateLabel = explanationStatus.state || explanation.post_heal_status || "not_evaluated";
      setText("issue-detail-state", explanationStatus.detail || stateLabel.replace(/_/g, " "));
      if (status) {
        status.textContent = stateLabel === "fixed" ? "FIXED" : stateLabel === "open" ? "OPEN" : stateLabel.replace(/_/g, " ").toUpperCase();
        status.classList.toggle("status-fixed", stateLabel === "fixed");
        status.classList.toggle("status-open", stateLabel !== "fixed");
      }
      var verification = explanation.after_scan_verification || {};
      var verificationSummary = verification.summary || {};
      var verificationText = verification.status ? String(verification.status).replace(/_/g, " ").toUpperCase() : "NOT EVALUATED";
      if (verification.performed) verificationText += " / " + String(verification.mode || "scan") + " scan";
      if (verification.certificate_status) verificationText += " / certificate " + verification.certificate_status;
      if (verificationSummary.remaining_findings != null) verificationText += " / " + verificationSummary.remaining_findings + " remaining";
      setText("issue-detail-verification", verificationText + (verification.verification_hash ? " / " + truncate(verification.verification_hash, 12, 0) : ""));
      var explanationEvidence = safeArray(explanation.evidence || explanation.issue && explanation.issue.evidence);
      if (evidence) evidence.innerHTML = explanationEvidence.length ? explanationEvidence.map(function (item) { return "<li>" + escapeHtml(item) + "</li>"; }).join("") : "<li>No redacted evidence recorded.</li>";
      var context = explanation.source_context;
      if (source) {
        if (!context || context.available === false) source.textContent = context && context.reason ? context.reason : "This finding has no file path context.";
        else source.textContent = safeArray(context.lines).map(function (line) { return String(line.number).padStart(4, " ") + " | " + line.text; }).join("\n") || "No source context returned.";
      }
    }).catch(function (error) {
      if (requestId !== state.issueDetailRequestId) return;
      setText("issue-detail-why", "Explanation unavailable: " + error.message);
      setText("issue-detail-scenario", "No cross-platform scenario returned.");
      setText("issue-detail-verification", "After-scan verification unavailable.");
      if (source) source.textContent = issue.file_path ? "Loading source context..." : "This finding has no file path context.";
      if (issue.file_path) {
        request("/api/v1/issue-context", { method: "POST", body: { target: state.target, file_path: issue.file_path, line_number: issue.line_number || null } }).then(function (context) {
          if (requestId !== state.issueDetailRequestId || !source) return;
          source.textContent = safeArray(context.lines).map(function (line) { return String(line.number).padStart(4, " ") + " | " + line.text; }).join("\n") || "No source context returned.";
        }).catch(function (contextError) {
          if (requestId === state.issueDetailRequestId && source) source.textContent = "Source context unavailable: " + contextError.message;
        });
      }
    });
  }

  function openIssueDetail(index, options) {
    var issue = displayIssues()[Number(index)];
    if (issue) {
      if (!options || options.trigger !== false) state.drawerReturnFocus = options && options.trigger || document.activeElement;
      renderIssueDetail(issue);
      if (!options || options.syncUrl !== false) syncRoute("bugs", { issue: issue.issue_id || issueDisplayId(issue, Number(index)) });
    }
  }

  function openHealedFile(path) {
    var entry = healedFileDiffs(state.report).find(function (item) { return item.path === normalizeFilePath(path); });
    if (!entry) return;
    state.selectedHealedFilePath = entry.path;
    var issueIndex = issueIndexForFile(entry.path);
    if (issueIndex >= 0) {
      renderBuildReport();
      openIssueDetail(issueIndex);
      return;
    }
    renderBuildReport();
    selectView("build");
  }

  function diffText(text) {
    return String(text || "").split("\n").map(function (line) {
      var safe = escapeHtml(line);
      if (line.indexOf("+") === 0 && line.indexOf("+++") !== 0) return '<span class="diff-add">' + safe + '</span>';
      if (line.indexOf("-") === 0 && line.indexOf("---") !== 0) return '<span class="diff-remove">' + safe + '</span>';
      return safe;
    }).join("\n");
  }

  function parseUnifiedDiff(text) {
    var left = [];
    var right = [];
    String(text || "").split("\n").forEach(function (line) {
      if (!line || line.indexOf("--- ") === 0 || line.indexOf("+++ ") === 0 || line.indexOf("@@") === 0 || line.indexOf("diff ") === 0 || line.indexOf("index ") === 0) return;
      if (line.indexOf("-") === 0) left.push({ text: line.slice(1), kind: "removed" });
      else if (line.indexOf("+") === 0) right.push({ text: line.slice(1), kind: "added" });
      else if (line.indexOf(" ") === 0) {
        left.push({ text: line.slice(1), kind: "context" });
        right.push({ text: line.slice(1), kind: "context" });
      }
    });
    var rows = [];
    var leftNumber = 0;
    var rightNumber = 0;
    var length = Math.max(left.length, right.length);
    for (var index = 0; index < length; index += 1) {
      var leftLine = left[index] || { text: "", kind: "empty" };
      var rightLine = right[index] || { text: "", kind: "empty" };
      if (leftLine.kind !== "empty") leftNumber += 1;
      if (rightLine.kind !== "empty") rightNumber += 1;
      rows.push({ left: leftLine, right: rightLine, leftNumber: leftLine.kind === "empty" ? "" : leftNumber, rightNumber: rightLine.kind === "empty" ? "" : rightNumber });
    }
    return rows;
  }

  function contentDiffRows(before, after) {
    var oldLines = String(before || "").split("\n");
    var newLines = String(after || "").split("\n");
    var rows = [];
    var length = Math.max(oldLines.length, newLines.length);
    for (var index = 0; index < length; index += 1) {
      var oldText = oldLines[index];
      var newText = newLines[index];
      rows.push({ left: { text: oldText == null ? "" : oldText, kind: oldText == null ? "empty" : oldText === newText ? "context" : "removed" }, right: { text: newText == null ? "" : newText, kind: newText == null ? "empty" : oldText === newText ? "context" : "added" }, leftNumber: oldText == null ? "" : index + 1, rightNumber: newText == null ? "" : index + 1 });
    }
    return rows;
  }

  function diffLineMarkup(line, number) {
    var className = line.kind === "removed" ? " is-removed" : line.kind === "added" ? " is-added" : "";
    var mark = line.kind === "removed" ? "-" : line.kind === "added" ? "+" : "";
    return '<div class="diff-line' + className + '"><span class="diff-number">' + escapeHtml(number) + '</span><span class="diff-mark">' + mark + '</span><span class="diff-code">' + escapeHtml(line.text) + '</span></div>';
  }

  function renderSideBySide(rows) {
    return '<div class="diff-columns"><div class="diff-column"><div class="diff-column-header">Before (broken)</div>' + rows.map(function (row) { return diffLineMarkup(row.left, row.leftNumber); }).join("") + '</div><div class="diff-column"><div class="diff-column-header">After (healed)</div>' + rows.map(function (row) { return diffLineMarkup(row.right, row.rightNumber); }).join("") + '</div></div>';
  }

  function merkleLeaves(certificate) {
    var leaves = [];
    function collect(items, depth) {
      safeArray(items).slice(0, 8).forEach(function (node) {
        var children = safeArray(node && node.children);
        if (children.length && depth < 3) collect(children, depth + 1);
        else leaves.push(node);
      });
    }
    collect(certificate && certificate.file_nodes, 0);
    return leaves.slice(0, 5);
  }

  function renderMerkleHashChips(certificate) {
    var leaves = merkleLeaves(certificate);
    if (!leaves.length) return "";
    return '<div class="merkle-hash-chips" aria-label="File node hashes"><div class="drawer-kicker">FILE NODE HASHES</div><div class="package-cloud">' + leaves.map(function (node) {
      var path = String(node && node.path || "file node");
      var digest = String(node && (node.digest || node.raw_sha256) || "pending");
      return '<span class="package-chip merkle-hash-chip" title="' + escapeHtml(path + " SHA-256 " + digest) + '">' + escapeHtml(path) + ' <code>' + escapeHtml(truncate(digest, 10, 0)) + '</code></span>';
    }).join("") + '</div></div>';
  }

  function renderDockerfile() {
    var panel = byId("dockerfile-panel");
    var badge = byId("dockerfile-badge");
    var report = state.report;
    if (!panel || !badge) return;
    var patch = report && (report.dockerfile_patch || safeArray(report.dockerfile_patches)[0]);
    var reportDiffs = report ? safeArray(report.unified_diffs) : [];
    var patchDiff = patch && (patch.unified_diff || patch.diff) ? patch.unified_diff || patch.diff : "";
    var sourceDiff = patchDiff || reportDiffs.filter(function (diff) { return /dockerfile/i.test(diff); })[0] || reportDiffs[0] || "";
    var rows = patch && (patch.before_content || patch.after_content) ? contentDiffRows(patch.before_content, patch.after_content || patch.patched_content) : parseUnifiedDiff(sourceDiff);
    if (!rows.length) {
      badge.textContent = report ? "NO PATCH" : "PENDING";
      panel.innerHTML = '<div class="empty-state"><span class="icon-slot" data-icon="fileCode" data-size="25"></span><strong>' + (report ? "No Dockerfile diff returned" : "Dockerfile evidence pending") + '</strong><span>' + (report ? "The audit did not return a Dockerfile repair proposal." : "Run auto-heal to inspect the isolated Dockerfile patch.") + '</span></div>';
      hydrateIcons();
      setText("diff-minus", "-0");
      setText("diff-plus", "+0");
      return;
    }
    var removed = rows.filter(function (row) { return row.left.kind === "removed"; }).length;
    var added = rows.filter(function (row) { return row.right.kind === "added"; }).length;
    badge.textContent = patch && patch.applied ? "APPLIED" : "AUTO-HEALED";
    setText("diff-minus", "-" + removed);
    setText("diff-plus", "+" + added);
    var beforeHash = report && report.before_certificate && report.before_certificate.root_hash ? truncate(report.before_certificate.root_hash, 7, 0) : "baseline";
    var afterHash = selectedCertificate(report).root_hash ? truncate(selectedCertificate(report).root_hash, 7, 0) : "staged";
    setText("diff-summary", "Auto-healed changes (" + beforeHash + " -> " + afterHash + ")");
    panel.innerHTML = renderSideBySide(rows);
  }

  function renderCertificate() {
    var certificate = selectedCertificate(state.report);
    var seal = byId("certificate-seal");
    var metrics = byId("certificate-metrics");
    var tree = byId("merkle-tree");
    if (!seal || !metrics || !tree) return;
    if (!state.report || !certificate.root_hash) {
      seal.innerHTML = '<div class="empty-state compact-empty"><strong>Certificate pending</strong><span>Generate a deterministic Merkle proof after the audit.</span></div>';
      metrics.innerHTML = '<div class="metric-line"><span>Runtime</span><strong>--</strong></div><div class="metric-line"><span>Lock score</span><strong>--</strong></div><div class="metric-line"><span>Linux readiness</span><strong>--</strong></div>';
      tree.innerHTML = "";
      return;
    }
    seal.innerHTML = icons.renderCertificationSeal(certificate);
    metrics.innerHTML = '<div class="metric-line"><span>Runtime</span><strong>' + escapeHtml(certificate.runtime || "unknown") + '</strong></div><div class="metric-line"><span>Lock score</span><strong>' + escapeHtml(numberOr(certificate.dependency_lock_score, 0).toFixed(0) + "%") + '</strong></div><div class="metric-line"><span>Linux readiness</span><strong>' + escapeHtml(numberOr(certificate.linux_readiness_score, 0).toFixed(0) + "%") + '</strong></div>';
    tree.innerHTML = icons.renderMerkleTreeSVG(certificate, state.comparison || { rootHash: certificate.root_hash }) + renderMerkleHashChips(certificate);
  }

  function renderAll() {
    renderKpis();
    renderOverview();
    renderIssueList();
    renderDockerfile();
    renderCertificate();
    renderDependencyGraph();
    renderReportJson();
    renderHistory();
    renderRunHistory();
    renderBuildReport();
    renderBuildVerification();
    renderAuditState();
    hydrateIcons();
  }

  function setDrawerView(view) {
    var drawer = byId("detail-drawer");
    if (!drawer) return;
    if (view !== "issue") {
      selectView(view);
      return;
    }
    if (!drawer.classList.contains("is-open")) state.drawerReturnFocus = document.activeElement;
    drawer.classList.add("is-open");
    drawer.setAttribute("aria-hidden", "false");
    var main = byId("app-main");
    var sidebar = document.querySelector(".sidebar");
    [main, sidebar].forEach(function (element) {
      if (!element) return;
      element.setAttribute("aria-hidden", "true");
      element.setAttribute("inert", "");
      if ("inert" in element) element.inert = true;
    });
    document.querySelectorAll("[data-drawer-view]").forEach(function (panel) {
      panel.classList.toggle("is-active", panel.getAttribute("data-drawer-view") === view);
    });
    setText("drawer-title", "Issue detail");
    var closeButton = byId("drawer-close");
    if (closeButton) closeButton.focus();
  }

  function closeDrawer(restore) {
    var drawer = byId("detail-drawer");
    if (!drawer) return;
    var wasOpen = drawer.classList.contains("is-open");
    drawer.classList.remove("is-open");
    drawer.setAttribute("aria-hidden", "true");
    var main = byId("app-main");
    var sidebar = document.querySelector(".sidebar");
    [main, sidebar].forEach(function (element) {
      if (!element) return;
      element.removeAttribute("aria-hidden");
      element.removeAttribute("inert");
      if ("inert" in element) element.inert = false;
    });
    if (restore === false) state.drawerReturnFocus = null;
    if (wasOpen && restore !== false) {
      var returnFocus = state.drawerReturnFocus;
      state.drawerReturnFocus = null;
      restoreFocus(returnFocus);
    }
  }

  function closeDrawerFromUser() {
    closeDrawer();
    syncRoute(state.activeView);
  }

  function setTargetPopover(open) {
    var popover = byId("target-path-popover");
    var toggle = byId("workspace-target-toggle");
    if (!popover) return;
    var wasOpen = popover.classList.contains("is-open");
    if (open && !popover.classList.contains("is-open")) state.popoverReturnFocus = document.activeElement;
    popover.classList.toggle("is-open", open);
    popover.setAttribute("aria-hidden", open ? "false" : "true");
    if (toggle) toggle.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) {
      var input = byId("target-path-input");
      if (input) {
        input.value = state.target;
        input.focus();
        input.select();
      }
    } else if (wasOpen) {
      var returnFocus = state.popoverReturnFocus;
      state.popoverReturnFocus = null;
      restoreFocus(returnFocus || toggle);
    }
  }

  function routeView(value) {
    var knownViews = ["dashboard", "bugs", "dependency", "sandbox", "build", "security", "reports", "history", "settings"];
    var candidate = String(value || "").replace(/^\/+/, "").toLowerCase();
    return knownViews.indexOf(candidate) >= 0 ? candidate : "dashboard";
  }

  function readRoute() {
    var searchParams = new URLSearchParams(window.location.search || "");
    var hash = String(window.location.hash || "").replace(/^#/, "");
    var hashParts = hash.split("?");
    var hashParams = new URLSearchParams(hashParts.slice(1).join("?"));
    var view = hashParts[0] || searchParams.get("view") || searchParams.get("workspace") || "dashboard";
    if (hashParts[0] === "") view = hashParams.get("view") || hashParams.get("workspace") || view;
    return {
      view: routeView(view),
      issue: hashParams.get("issue") || searchParams.get("issue") || "",
      run: hashParams.get("run") || searchParams.get("run") || "",
    };
  }

  function syncRoute(view, options) {
    if (!window.location) return;
    var route = "#" + routeView(view);
    var query = [];
    if (options && options.issue) query.push("issue=" + encodeURIComponent(options.issue));
    if (options && options.run) query.push("run=" + encodeURIComponent(options.run));
    if (query.length) route += "?" + query.join("&");
    if (window.location.hash === route) return;
    if (options && options.replace && window.history && window.history.replaceState) window.history.replaceState(null, "", route);
    else window.location.hash = route;
  }

  function openIssueDetailByToken(token, options) {
    var issues = displayIssues();
    var normalized = String(token || "").toLowerCase();
    var index = issues.findIndex(function (issue, issueIndex) {
      return String(issue && issue.issue_id || "").toLowerCase() === normalized || issueDisplayId(issue, issueIndex).toLowerCase() === normalized;
    });
    if (index < 0 && /^\d+$/.test(normalized)) index = Number(normalized);
    if (index >= 0 && issues[index]) openIssueDetail(index, options);
  }

  function restoreRoute() {
    var route = state.pendingRoute || readRoute();
    state.pendingRoute = route;
    selectView(route.view, { syncUrl: false });
    if (route.run) selectHistory(route.run, { syncUrl: false });
    if (route.issue && state.report) openIssueDetailByToken(route.issue, { syncUrl: false });
  }

  function handleRouteChange() {
    state.pendingRoute = readRoute();
    restoreRoute();
  }

  function normalizeWorkspaceTarget(value) {
    var normalized = String(value || "").trim();
    if (!normalized || normalized === "." || normalized === "./") return "workspace";
    if (normalized.indexOf("./") === 0) normalized = normalized.slice(2);
    if (
      normalized.indexOf("\\") >= 0 ||
      normalized.indexOf("/") === 0 ||
      /^[A-Za-z]:/.test(normalized) ||
      normalized.split("/").some(function (part) { return !part || part === "." || part === ".."; })
    ) {
      throw new Error("Use a normalized relative path inside the workspace.");
    }
    return normalized;
  }

  function useWorkspaceTarget() {
    var input = byId("target-path-input");
    try {
      state.target = normalizeWorkspaceTarget(input && input.value);
    } catch (error) {
      showToast(error.message, true);
      return;
    }
    var select = byId("target-select");
    if (select) {
      var option = Array.prototype.find.call(select.options, function (item) { return item.value === state.target; });
      if (!option) {
        option = document.createElement("option");
        option.value = state.target;
        option.textContent = state.target;
        select.appendChild(option);
      }
      select.value = state.target;
    }
    setTargetPopover(false);
    state.report = null;
    state.analysis = null;
    state.comparison = null;
    state.buildVerification = null;
    state.auditWasAutoHealed = false;
    updateDeleteTargetButton();
    renderUploadedTargetsList();
    renderTargetDescription();
    renderAll();
    logEvent("workspace target changed to " + state.target, "info");
    runAudit(false, false);
  }

  function setZipUploadStatus(message, tone) {
    var status = byId("zip-upload-status");
    if (!status) return;
    status.textContent = message || "";
    status.className = "zip-upload-status" + (tone ? " is-" + tone : "");
  }

  async function uploadZip(file) {
    if (!file) return;
    var dropzone = byId("zip-dropzone");
    var input = byId("zip-upload-input");
    var name = String(file.name || "");
    if (!/\.zip$/i.test(name)) {
      setZipUploadStatus("Choose a .zip archive.", "error");
      return;
    }
    if (dropzone) {
      dropzone.classList.add("is-uploading");
      dropzone.setAttribute("aria-busy", "true");
    }
    setZipUploadStatus("Uploading and validating " + name + "...", "loading");
    try {
      var form = new FormData();
      form.append("file", file, name);
      var response = await fetch("/api/v1/upload", {
        method: "POST",
        headers: { Accept: "application/json" },
        body: form,
      });
      var payload = null;
      try { payload = await response.json(); } catch (error) { payload = null; }
      if (!response.ok) {
        throw new Error(payload && (payload.detail || payload.message) || "Upload failed with status " + response.status);
      }
      await loadTargets();
      state.target = payload.target;
      state.report = null;
      state.analysis = null;
      state.comparison = null;
      state.buildVerification = null;
      state.auditWasAutoHealed = false;
      state.selectedHealedFilePath = null;
      var select = byId("target-select");
      if (select) select.value = state.target;
      updateDeleteTargetButton();
      renderUploadedTargetsList();
      renderTargetDescription();
      renderAll();
      setTargetPopover(false);
      logEvent("uploaded " + name + " as " + state.target, "success");
      setZipUploadStatus("Upload complete. Starting audit...", "success");
      await runAudit(false, false);
    } catch (error) {
      logEvent("ZIP upload failed: " + error.message, "error");
      setZipUploadStatus(error.message || "ZIP upload failed.", "error");
      showToast(error.message || "ZIP upload failed.", true);
    } finally {
      if (input) input.value = "";
      if (dropzone) {
        dropzone.classList.remove("is-uploading");
        dropzone.setAttribute("aria-busy", "false");
      }
    }
  }

  function selectView(view, options) {
    var requested = view || "dashboard";
    requested = routeView(requested);
    closeDrawer(false);
    document.querySelectorAll("[data-page-view]").forEach(function (page) {
      var active = page.getAttribute("data-page-view") === requested;
      page.classList.toggle("is-active", active);
      page.hidden = !active;
    });
    var navView = requested === "sandbox" ? "dependency" : requested;
    document.querySelectorAll(".nav-item[data-view]").forEach(function (button) { button.classList.toggle("is-active", button.getAttribute("data-view") === navView); });
    state.activeView = requested;
    if (requested === "dependency") renderDependencyGraph();
    if (!options || options.syncUrl !== false) syncRoute(requested, options);
  }

  function isUploadedTarget(target) {
    return Boolean(target && (target.indexOf(".worksonmymachine/uploads") === 0 || target.indexOf("upload-") >= 0));
  }

  function friendlyTargetName(target) {
    if (!target) return "";
    if (target === "workspace") return "Current workspace";
    if (target.indexOf("demo_targets/") === 0) return target.replace("demo_targets/", "");
    if (isUploadedTarget(target)) {
      var parts = target.split("/");
      var last = parts[parts.length - 1];
      if (last.indexOf("upload-") === 0) return "Upload: " + last.substring(0, 16) + "...";
      return "Upload: " + last;
    }
    return target;
  }

  function updateDeleteTargetButton() {
    var btn = byId("delete-target-btn");
    if (!btn) return;
    if (isUploadedTarget(state.target)) {
      btn.hidden = false;
      btn.title = "Delete uploaded project: " + friendlyTargetName(state.target);
    } else {
      btn.hidden = true;
    }
  }

  function renderUploadedTargetsList() {
    var section = byId("uploaded-targets-section");
    var list = byId("uploaded-targets-list");
    if (!section || !list) return;

    var uploads = state.targets.filter(isUploadedTarget);
    if (!uploads.length) {
      section.hidden = true;
      list.replaceChildren();
      return;
    }

    section.hidden = false;
    list.replaceChildren();
    uploads.forEach(function (target) {
      var item = document.createElement("div");
      item.className = "uploaded-target-item" + (target === state.target ? " is-active" : "");

      var infoBtn = document.createElement("button");
      infoBtn.type = "button";
      infoBtn.className = "uploaded-target-info";
      infoBtn.title = "Switch active target to " + target;
      infoBtn.innerHTML = '<span class="uploaded-target-name">' + escapeHtml(friendlyTargetName(target)) + '</span>' +
        (target === state.target ? '<span class="uploaded-target-active-pill">ACTIVE</span>' : '');
      infoBtn.addEventListener("click", function () {
        selectTargetByName(target);
        setTargetPopover(false);
      });

      var delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "delete-upload-item-btn";
      delBtn.title = "Delete " + friendlyTargetName(target);
      delBtn.setAttribute("aria-label", "Delete " + friendlyTargetName(target));
      delBtn.innerHTML = '<span class="icon-slot" data-icon="closeDismiss" data-size="12"></span>';
      delBtn.addEventListener("click", function (evt) {
        evt.stopPropagation();
        deleteUploadTarget(target);
      });

      item.appendChild(infoBtn);
      item.appendChild(delBtn);
      list.appendChild(item);
    });
  }

  function selectTargetByName(target) {
    if (state.busy || state.target === target) return;
    state.target = target;
    var select = byId("target-select");
    if (select) select.value = state.target;
    state.report = null;
    state.analysis = null;
    state.comparison = null;
    state.buildVerification = null;
    state.auditWasAutoHealed = false;
    updateDeleteTargetButton();
    renderUploadedTargetsList();
    renderTargetDescription();
    renderAll();
    logEvent("target changed to " + state.target, "info");
    runAudit(false, false);
  }

  async function deleteUploadTarget(target) {
    if (state.busy) return;
    var name = friendlyTargetName(target);
    try {
      await request("/api/v1/targets?target=" + encodeURIComponent(target), { method: "DELETE" });
      showToast("Deleted " + name, false);
      logEvent("deleted upload " + target, "info");
      if (state.target === target) {
        state.target = "workspace";
        await loadTargets();
        await runAudit(false, false);
      } else {
        await loadTargets();
      }
    } catch (error) {
      showToast("Failed to delete upload: " + error.message, true);
      logEvent("failed to delete upload: " + error.message, "error");
    }
  }

  async function clearAllUploads() {
    if (state.busy) return;
    try {
      var res = await request("/api/v1/uploads", { method: "DELETE" });
      showToast("Deleted " + (res && res.deleted_count != null ? res.deleted_count : "all") + " uploaded project(s)", false);
      logEvent("cleared all uploaded projects", "info");
      if (isUploadedTarget(state.target)) {
        state.target = "workspace";
        await loadTargets();
        await runAudit(false, false);
      } else {
        await loadTargets();
      }
    } catch (error) {
      showToast("Failed to clear uploads: " + error.message, true);
    }
  }

  async function loadTargets() {
    try {
      var payload = await request("/api/v1/targets?scope=workspace", { method: "GET" });
      state.targets = safeArray(payload && payload.targets);
      if (!state.report && state.target === "workspace" && payload && typeof payload.default_target === "string") state.target = payload.default_target;
      var select = byId("target-select");
      if (select) {
        select.replaceChildren();
        var allTargets = state.targets.slice();
        if (allTargets.indexOf(state.target) < 0) allTargets.unshift(state.target);

        var workspaceList = [];
        var demoList = [];
        var uploadList = [];
        var otherList = [];

        allTargets.forEach(function (target) {
          if (target === "workspace") {
            workspaceList.push(target);
          } else if (target.indexOf("demo_targets/") === 0) {
            demoList.push(target);
          } else if (isUploadedTarget(target)) {
            uploadList.push(target);
          } else {
            otherList.push(target);
          }
        });

        if (workspaceList.length) {
          workspaceList.forEach(function (target) {
            var opt = document.createElement("option");
            opt.value = target;
            opt.textContent = "Current workspace";
            opt.selected = target === state.target;
            select.appendChild(opt);
          });
        }

        if (demoList.length) {
          var demoGroup = document.createElement("optgroup");
          demoGroup.label = "DEMO BENCHMARKS";
          demoList.forEach(function (target) {
            var opt = document.createElement("option");
            opt.value = target;
            opt.textContent = target.replace("demo_targets/", "");
            opt.selected = target === state.target;
            demoGroup.appendChild(opt);
          });
          select.appendChild(demoGroup);
        }

        if (uploadList.length) {
          var uploadGroup = document.createElement("optgroup");
          uploadGroup.label = "UPLOADED PROJECTS";
          uploadList.forEach(function (target) {
            var opt = document.createElement("option");
            opt.value = target;
            opt.textContent = friendlyTargetName(target);
            opt.selected = target === state.target;
            uploadGroup.appendChild(opt);
          });
          select.appendChild(uploadGroup);
        }

        if (otherList.length) {
          var otherGroup = document.createElement("optgroup");
          otherGroup.label = "OTHER TARGETS";
          otherList.forEach(function (target) {
            var opt = document.createElement("option");
            opt.value = target;
            opt.textContent = target;
            opt.selected = target === state.target;
            otherGroup.appendChild(opt);
          });
          select.appendChild(otherGroup);
        }
      }
      renderUploadedTargetsList();
      updateDeleteTargetButton();
      setConnection("All Systems Operational", "success");
      renderTargetDescription();
      logEvent("loaded " + state.targets.length + " target(s)", "success");
    } catch (error) {
      setConnection("API Unavailable", "warning");
      logEvent("target discovery unavailable: " + error.message, "warning");
      showToast("Target discovery is unavailable. The default target remains selected.", false);
    }
  }

  async function runAudit(autoHeal, quiet) {
    if (state.busy) return;
    var auditTarget = state.target;
    state.busy = true;
    announceScan((autoHeal ? "Auto-heal and certification" : "Repository scan") + " started for " + auditTarget + ".");
    state.auditWasAutoHealed = Boolean(autoHeal);
    setBusy("scan-button", true);
    setBusy("heal-button", true);
    setConnection(autoHeal ? "Auto-Heal Running" : "Scan Running", "warning");
    renderAll();
    logEvent((autoHeal ? "auto-heal" : "audit") + " started for " + auditTarget, "info");
    try {
      var report = await request("/api/v1/audit", { method: "POST", body: { target: auditTarget, auto_heal: Boolean(autoHeal), new_only: Boolean(state.newOnly) } });
      if (state.target !== auditTarget) return;
      state.report = report;
      state.analysis = null;
      state.comparison = null;
      state.buildVerification = null;
      setConnection("All Systems Operational", "success");
      logEvent((autoHeal ? "auto-heal" : "audit") + " complete", "success");
      announceScan((autoHeal ? "Auto-heal and certification" : "Repository scan") + " complete for " + auditTarget + ". Findings: " + safeArray(state.report && state.report.issues).length + ".");
      saveAuditHistory();
      renderAll();
      if (!quiet) showToast(autoHeal ? "Auto-heal evidence is ready." : "Repository audit is ready.", false);
    } catch (error) {
      if (state.target !== auditTarget) return;
      setConnection("Audit Failed", "error");
      logEvent("audit failed: " + error.message, "error");
      announceScan((autoHeal ? "Auto-heal and certification" : "Repository scan") + " failed: " + error.message);
      if (!quiet) showToast("Audit failed: " + error.message, true);
    } finally {
      state.busy = false;
      setBusy("scan-button", false);
      setBusy("heal-button", false);
      renderAll();
      if (state.target !== auditTarget) runAudit(false, false);
    }
  }

  async function parseLog() {
    setBusy("parse-log-button", true);
    logEvent("parsing build log for " + state.target, "info");
    try {
      state.analysis = await request("/api/v1/parse-log", { method: "POST", body: { target: state.target } });
      logEvent("compiler telemetry received", "success");
      renderAnalysis();
      renderDependencyGraph();
      selectView("sandbox");
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
      renderDependencyGraph();
      logEvent("custom compiler trace normalized", "success");
      showToast("Custom compiler trace parsed.", false);
    } catch (error) {
      logEvent("custom parse failed: " + error.message, "error");
      showToast("Custom parse failed: " + error.message, true);
    } finally {
      setBusy("run-sandbox-button", false);
    }
  }

  function renderAnalysis() {
    var panel = byId("analysis-panel");
    if (!panel || !state.analysis) return;
    var analysis = state.analysis;
    var packages = safeArray(analysis.apt_packages || analysis.recommended_apt_packages);
    var command = analysis.apt_install_command || "No apt package additions recommended.";
    panel.innerHTML = '<div class="analysis-banner">' + icon("cpuCompiler", 15) + '<span>' + escapeHtml(analysis.root_cause_summary || "No root cause summary returned by the parser.") + '</span></div><div class="drawer-kicker">RECOMMENDED PACKAGES</div><div class="package-cloud">' + (packages.length ? packages.map(function (item) { return '<span class="package-chip">' + escapeHtml(item) + '</span>'; }).join("") : '<span class="muted-text">No package additions recommended.</span>') + '</div><div class="drawer-kicker">INSTALL COMMAND</div><div class="command-block"><code>' + escapeHtml(command) + '</code><button class="icon-button" type="button" data-copy="' + escapeHtml(command) + '" aria-label="Copy install command">' + icon("copyClipboard", 14) + '</button></div><div id="diagnostic-panel"></div>';
    var diagnosticPanel = byId("diagnostic-panel");
    var diagnostics = safeArray(analysis.diagnostics);
    if (diagnosticPanel && diagnostics.length) {
      diagnosticPanel.innerHTML = '<div class="diagnostic-list">' + diagnostics.slice(0, 8).map(function (diagnostic) { return '<article class="diagnostic-row"><div class="diagnostic-topline"><div class="diagnostic-title">' + escapeHtml(diagnostic.message || diagnostic.error_signature || "Compiler diagnostic") + '</div><span class="severity severity-' + severityClass(diagnostic.severity) + '">' + escapeHtml(diagnostic.severity || "high") + '</span></div><p class="diagnostic-message">' + escapeHtml(diagnostic.root_cause_explanation || diagnostic.tool || "normalized compiler output") + '</p><div class="diagnostic-meta">' + escapeHtml(diagnostic.file_path || "build output") + '</div></article>'; }).join("") + '</div>';
    }
    hydrateIcons();
  }

  function downloadCertificate() {
    var certificate = selectedCertificate(state.report);
    if (!certificate.root_hash) {
      showToast("Generate a certificate first.", true);
      return;
    }
    var blob = new Blob([JSON.stringify(certificate, null, 2)], { type: "application/json" });
    var link = document.createElement("a");
    var url = URL.createObjectURL(blob);
    link.href = url;
    link.download = state.target + "-cleanroom-certificate.json";
    document.body.appendChild(link);
    link.click();
    setTimeout(function () {
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }, 1000);
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
      saveAuditHistory();
      logEvent("certificate generated", "success");
      renderAll();
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
    setBusy("build-compare-button", true);
    logEvent("comparing baseline and healed certificates", "info");
    try {
      state.comparison = await request("/api/v1/compare", { method: "POST", body: { target: state.target, auto_heal: true } });
      logEvent("comparison evidence received", "success");
      saveAuditHistory();
      renderCertificate();
      showToast("Certificate comparison is ready.", false);
    } catch (error) {
      logEvent("comparison failed: " + error.message, "error");
      showToast("Comparison failed: " + error.message, true);
    } finally {
      setBusy("compare-button", false);
      setBusy("build-compare-button", false);
    }
  }

  async function verifyBuild() {
    if (state.busy) return;
    setBusy("verify-build-button", true);
    logEvent("starting staged Docker build for " + state.target, "info");
    setText("build-verification-status", "RUNNING");
    try {
      state.buildVerification = await request("/api/v1/verify-build", { method: "POST", body: { target: state.target, auto_heal: true } });
      logEvent("staged build " + state.buildVerification.status, state.buildVerification.status === "passed" ? "success" : "warning");
      saveAuditHistory();
      renderAll();
      showToast("Staged build " + state.buildVerification.status + ".", state.buildVerification.status === "failed" || state.buildVerification.status === "timed_out");
    } catch (error) {
      logEvent("staged build failed: " + error.message, "error");
      showToast("Staged build failed: " + error.message, true);
    } finally {
      setBusy("verify-build-button", false);
      renderBuildVerification();
      renderAuditState();
    }
  }

  async function copyText(value, successMessage) {
    try {
      await navigator.clipboard.writeText(value);
      showToast(successMessage || "Copied to clipboard.", false);
    } catch (error) {
      showToast("Clipboard access is unavailable.", true);
    }
  }

  function downloadText(filename, content, type) {
    var blob = new Blob([content], { type: type || "text/plain" });
    var link = document.createElement("a");
    var url = URL.createObjectURL(blob);
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    setTimeout(function () {
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }, 1000);
    logEvent(filename + " downloaded", "success");
  }

  function csvCell(value) {
    return '"' + String(value == null ? "" : value).replace(/"/g, '""') + '"';
  }

  function findingsCsv(entries) {
    var lines = [["ID", "Severity", "Rule", "Status", "Path", "Line", "Category", "Message"]];
    entries.forEach(function (entry) {
      var issue = entry.issue;
      lines.push([
        issueDisplayId(issue, entry.index),
        severityClass(issue.severity),
        issueRule(issue),
        issueStatus(issue),
        issue.file_path || "",
        issue.line_number || "",
        issue.category || "",
        issue.message || "",
      ]);
    });
    return lines.map(function (line) { return line.map(csvCell).join(","); }).join("\r\n") + "\r\n";
  }

  function downloadFindingsCsv() {
    var entries = issueEntriesForExport();
    var selected = entries.filter(function (entry) { return state.selectedIssueKeys[issueSelectionKey(entry.issue, entry.index)]; });
    var selectedCount = Object.keys(state.selectedIssueKeys).length;
    if (selectedCount) entries = selected;
    if (!entries.length) {
      showToast(selectedCount ? "No selected findings match the current filters." : "No findings match the current filters.", true);
      return;
    }
    var targetName = state.target.replace(/[^A-Za-z0-9._-]+/g, "-");
    downloadText(targetName + "-findings.csv", findingsCsv(entries), "text/csv;charset=utf-8");
    showToast("Exported " + entries.length + " finding" + (entries.length === 1 ? "" : "s") + " to CSV.", false);
  }

  function clientSarif(report) {
    var results = safeArray(report && report.issues).map(function (issue) {
      var level = { critical: "error", high: "error", medium: "warning", low: "note" }[String(issue.severity || "medium").toLowerCase()] || "warning";
      var result = { ruleId: issue.issue_id, level: level, message: { text: issue.message }, properties: { category: issue.category } };
      if (issue.file_path) result.locations = [{ physicalLocation: { artifactLocation: { uri: issue.file_path }, region: { startLine: issue.line_number || 1 } } }];
      return result;
    });
    return JSON.stringify({ "$schema": "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs: [{ tool: { driver: { name: "WorksOnMyMachine", version: "0.1.0" } }, results: results }] }, null, 2) + "\n";
  }

  function clientMarkdown(report) {
    var certificate = selectedCertificate(report);
    var lines = ["# WorksOnMyMachine audit: `" + (report.target || state.target) + "`", "", "- Readiness: **" + numberOr(certificate.linux_readiness_score, 0).toFixed(2) + "/100**", "- Reproducible: **" + (report.reproducible ? "yes" : "no") + "**", "- Findings: **" + safeArray(report.issues).length + "**", "", "| ID | Severity | Category | File | Line | Message |", "| --- | --- | --- | --- | ---: | --- |"];
    safeArray(report.issues).forEach(function (issue) { lines.push("| `" + issue.issue_id + "` | `" + issue.severity + "` | `" + issue.category + "` | `" + (issue.file_path || "-") + "` | " + (issue.line_number || "-") + " | " + String(issue.message || "").replace(/\|/g, "\\|") + " |"); });
    if (!report.issues || !report.issues.length) lines.push("| - | - | - | - | - | No findings |");
    return lines.join("\n") + "\n";
  }

  function exportArtifact(kind) {
    if (!state.report) {
      showToast("Run an audit first.", true);
      return;
    }
    var targetName = state.target.replace(/[^A-Za-z0-9._-]+/g, "-");
    if (kind === "json") downloadText(targetName + "-audit.json", JSON.stringify(state.report, null, 2) + "\n", "application/json");
    if (kind === "certificate") downloadText(targetName + "-certificate.json", JSON.stringify(selectedCertificate(state.report), null, 2) + "\n", "application/json");
    if (kind === "patch") downloadText(targetName + "-healed.patch", safeArray(state.report.unified_diffs).join("\n"), "text/x-diff");
    if (kind === "sarif") downloadText(targetName + "-audit.sarif", clientSarif(state.report), "application/sarif+json");
    if (kind === "markdown") downloadText(targetName + "-audit.md", clientMarkdown(state.report), "text/markdown");
  }

  function bindEvents() {
    on("scan-button", "click", function () { runAudit(false, false); });
    on("heal-button", "click", function () { runAudit(true, false); });
    on("parse-log-button", "click", parseLog);
    on("run-sandbox-button", "click", parseCustomLog);
    on("certify-button", "click", certify);
    on("compare-button", "click", compare);
    on("build-compare-button", "click", compare);
    on("download-certificate-button", "click", downloadCertificate);
    on("copy-root-button", "click", function () {
      var root = selectedCertificate(state.report).root_hash;
      if (root) copyText(root, "Merkle root copied."); else showToast("Generate a certificate first.", true);
    });
    on("copy-certificate-button", "click", function () {
      var certificate = selectedCertificate(state.report);
      if (certificate.root_hash) copyText(JSON.stringify(certificate, null, 2), "Certificate JSON copied."); else showToast("Generate a certificate first.", true);
    });
    on("copy-report-button", "click", function () { if (state.report) copyText(JSON.stringify(state.report, null, 2), "Audit report copied."); else showToast("Run an audit first.", true); });
    on("download-json-button", "click", function () { exportArtifact("json"); });
    on("download-report-certificate-button", "click", function () { exportArtifact("certificate"); });
    on("download-patch-button", "click", function () { exportArtifact("patch"); });
    on("download-sarif-button", "click", function () { exportArtifact("sarif"); });
    on("download-markdown-button", "click", function () { exportArtifact("markdown"); });
    on("issue-export-csv", "click", downloadFindingsCsv);
    on("issue-clear-selection", "click", function () {
      state.selectedIssueKeys = {};
      renderIssueList();
    });
    on("issue-select-all", "change", function (event) {
      var issues = displayIssues();
      var entries = sortIssueEntries(issues.filter(issueMatches).map(function (issue) {
        return { issue: issue, index: issues.indexOf(issue) };
      }));
      var pageStart = (state.issuePage - 1) * state.issuePageSize;
      entries.slice(pageStart, pageStart + state.issuePageSize).forEach(function (entry) {
        var key = issueSelectionKey(entry.issue, entry.index);
        if (event.target.checked) state.selectedIssueKeys[key] = true;
        else delete state.selectedIssueKeys[key];
      });
      renderIssueList();
    });
    on("new-only-toggle", "change", function (event) {
      state.newOnly = Boolean(event.target.checked);
      if (state.report) runAudit(state.auditWasAutoHealed, false);
    });
    on("view-file-button", "click", function () { selectView("build"); });
    on("drawer-close", "click", closeDrawerFromUser);
    on("terminal-toggle", "click", function () { selectView("reports"); });
    on("open-sandbox-button", "click", function () { selectView("sandbox"); });
    on("workspace-target-toggle", "click", function () {
      var popover = byId("target-path-popover");
      setTargetPopover(!popover || !popover.classList.contains("is-open"));
    });
    on("use-target-button", "click", useWorkspaceTarget);
    on("zip-upload-input", "change", function (event) {
      uploadZip(event.target.files && event.target.files[0]);
    });
    on("zip-dropzone", "keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        var input = byId("zip-upload-input");
        if (input) input.click();
      }
    });
    on("zip-dropzone", "dragenter", function (event) {
      event.preventDefault();
      event.currentTarget.classList.add("is-dragging");
    });
    on("zip-dropzone", "dragover", function (event) {
      event.preventDefault();
      event.dataTransfer.dropEffect = "copy";
      event.currentTarget.classList.add("is-dragging");
    });
    on("zip-dropzone", "dragleave", function (event) {
      if (event.currentTarget.contains(event.relatedTarget)) return;
      event.currentTarget.classList.remove("is-dragging");
    });
    on("zip-dropzone", "drop", function (event) {
      event.preventDefault();
      event.currentTarget.classList.remove("is-dragging");
      uploadZip(event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0]);
    });
    on("target-path-input", "keydown", function (event) {
      if (event.key === "Enter") useWorkspaceTarget();
      if (event.key === "Escape") setTargetPopover(false);
    });
    on("delete-target-btn", "click", function () {
      if (isUploadedTarget(state.target)) {
        deleteUploadTarget(state.target);
      }
    });
    on("clear-all-uploads-btn", "click", function () {
      clearAllUploads();
    });
    on("target-select", "change", function (event) {
      state.target = event.target.value || "workspace";
      state.report = null;
      state.analysis = null;
      state.comparison = null;
      state.buildVerification = null;
      state.auditWasAutoHealed = false;
      updateDeleteTargetButton();
      renderUploadedTargetsList();
      renderTargetDescription();
      renderAll();
      logEvent("target changed to " + state.target, "info");
      runAudit(false, false);
    });
    on("issue-search", "input", function (event) { state.issueSearch = event.target.value || ""; state.issuePage = 1; persistFindingFilters(); renderIssueList(); });
    document.querySelectorAll("[data-issue-filter]").forEach(function (button) {
      button.addEventListener("click", function () {
        state.issueFilter = button.getAttribute("data-issue-filter") || "all";
        state.issuePage = 1;
        persistFindingFilters();
        renderIssueList();
      });
    });
    on("issue-filter-button", "click", function () {
      state.issueFilter = state.issueFilter === "all" ? "fixed" : "all";
      state.issuePage = 1;
      persistFindingFilters();
      renderIssueList();
    });
    on("issue-sort", "change", function (event) {
      state.issueSortKey = findingSortKeys.indexOf(event.target.value) >= 0 ? event.target.value : "severity";
      state.issuePage = 1;
      persistFindingFilters();
      renderIssueList();
    });
    on("issue-sort-direction", "click", function () {
      state.issueSortDirection = state.issueSortDirection === "asc" ? "desc" : "asc";
      state.issuePage = 1;
      persistFindingFilters();
      renderIssueList();
    });
    on("verify-build-button", "click", function () { selectView("build"); verifyBuild(); });
    document.querySelectorAll("[data-view]").forEach(function (button) { button.addEventListener("click", function () { selectView(button.getAttribute("data-view")); }); });
    document.querySelectorAll("[data-log-preset]").forEach(function (button) { button.addEventListener("click", function () { var editor = byId("compiler-log-editor"); if (editor) editor.value = logPresets[button.getAttribute("data-log-preset")] || ""; }); });
    document.addEventListener("click", function (event) {
      var historyArtifactButton = event.target.closest ? event.target.closest("[data-history-artifact]") : null;
      if (historyArtifactButton) {
        event.preventDefault();
        var historyRecordId = historyArtifactButton.getAttribute("data-history-id") || "";
        var historyRecord = state.history.find(function (record) { return record.id === historyRecordId; });
        if (historyRecord) {
          selectHistory(historyRecord.id);
          exportArtifact(historyArtifactButton.getAttribute("data-history-artifact") || "json");
        }
        return;
      }
      var healedFileButton = event.target.closest ? event.target.closest("[data-healed-file]") : null;
      if (healedFileButton) {
        event.preventDefault();
        openHealedFile(healedFileButton.getAttribute("data-healed-file") || "");
        return;
      }
      var copyButton = event.target.closest ? event.target.closest("[data-copy]") : null;
      if (copyButton) copyText(copyButton.getAttribute("data-copy") || "");
      var popover = byId("target-path-popover");
      var toggle = byId("workspace-target-toggle");
      if (popover && popover.classList.contains("is-open") && !popover.contains(event.target) && event.target !== toggle && (!toggle || !toggle.contains(event.target))) setTargetPopover(false);
    });
    document.addEventListener("keydown", function (event) {
      var drawer = byId("detail-drawer");
      if (event.key === "Escape" && drawer && drawer.classList.contains("is-open")) {
        event.preventDefault();
        closeDrawerFromUser();
        return;
      }
      if (event.key === "Tab" && drawer && drawer.classList.contains("is-open")) {
        var focusable = focusableElements(drawer);
        if (!focusable.length) {
          event.preventDefault();
          drawer.focus();
          return;
        }
        var first = focusable[0];
        var last = focusable[focusable.length - 1];
        if (!drawer.contains(document.activeElement)) {
          event.preventDefault();
          first.focus();
        } else if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
        return;
      }
      var popover = byId("target-path-popover");
      if (event.key === "Escape" && popover && popover.classList.contains("is-open")) {
        event.preventDefault();
        setTargetPopover(false);
      }
    });
    window.addEventListener("hashchange", handleRouteChange);
    window.addEventListener("popstate", handleRouteChange);
  }

  async function bootstrap() {
    loadHistory();
    loadFindingFilters();
    state.pendingRoute = readRoute();
    hydrateIcons();
    bindEvents();
    selectView(state.pendingRoute.view, { syncUrl: false });
    renderTargetDescription();
    renderTerminal();
    renderAll();
    await loadTargets();
    await runAudit(false, true);
    restoreRoute();
  }

  window.cleanRoomApp = {
    state: state,
    runAudit: runAudit,
    parseLog: parseLog,
    certify: certify,
    compare: compare,
    verifyBuild: verifyBuild,
    selectView: selectView,
    downloadFindingsCsv: downloadFindingsCsv,
    findingsCsv: findingsCsv,
  };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bootstrap); else bootstrap();
})();
