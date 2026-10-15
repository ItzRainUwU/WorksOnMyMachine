(function () {
  "use strict";

  var iconSequence = 0;

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function nextIds() {
    iconSequence += 1;
    return {
      gradient: "clean-room-gradient-" + iconSequence,
      glow: "clean-room-glow-" + iconSequence,
    };
  }

  function svgShell(body, size, label, viewBox) {
    var ids = nextIds();
    var title = label ? "<title>" + escapeHtml(label) + "</title>" : "";
    return (
      '<svg class="cr-icon" width="' +
      escapeHtml(size || 20) +
      '" height="' +
      escapeHtml(size || 20) +
      '" viewBox="' +
      (viewBox || "0 0 24 24") +
      '" fill="none" xmlns="http://www.w3.org/2000/svg" role="' +
      (label ? "img" : "presentation") +
      '"' +
      (label ? ' aria-label="' + escapeHtml(label) + '"' : ' aria-hidden="true"') +
      '>' +
      title +
      "<defs>" +
      '<linearGradient id="' +
      ids.gradient +
      '" x1="4" y1="3" x2="21" y2="22" gradientUnits="userSpaceOnUse">' +
      '<stop stop-color="#8B7CFF"/><stop offset="0.52" stop-color="#50D8FF"/><stop offset="1" stop-color="#5DE3A1"/>' +
      "</linearGradient>" +
      '<filter id="' +
      ids.glow +
      '" x="-50%" y="-50%" width="200%" height="200%">' +
      '<feGaussianBlur stdDeviation="1.4" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>' +
      "</filter>" +
      "</defs>" +
      '<g stroke="url(#' +
      ids.gradient +
      ')" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" filter="url(#' +
      ids.glow +
      ')">' +
      body +
      "</g></svg>"
    );
  }

  function iconFactory(body) {
    return function (size, label) {
      return svgShell(body, size || 20, label || "");
    };
  }

  var icons = {
    logoCleanRoom: iconFactory(
      '<path d="M12 2.8 20 7.2v9.6L12 21.2 4 16.8V7.2z"/><path d="m8 9.4 4-2.2 4 2.2-4 2.2z"/><path d="M12 11.6v6.7"/>'
    ),
    radarScan: iconFactory(
      '<circle cx="12" cy="12" r="8.4"/><path d="M12 12 18.2 7.9"/><path d="M4.3 12h2.1M17.6 12h2.1M12 4.3v2.1"/><path d="M7.4 17.4a6.9 6.9 0 0 1-2-3.7"/>'
    ),
    autoHealBolt: iconFactory(
      '<path d="m13.6 2.8-7 10.1h5.1l-1.2 8.3 7-10.1h-5.1z"/><path d="M4 5.7h2.5M17.5 18.3H20M18.2 4.6l1.4-1.4M4.4 19.4l1.4-1.4"/>'
    ),
    merkleTree: iconFactory(
      '<rect x="9.2" y="2.8" width="5.6" height="4.2" rx="1"/><rect x="3" y="16.8" width="5.6" height="4.2" rx="1"/><rect x="9.2" y="16.8" width="5.6" height="4.2" rx="1"/><rect x="15.4" y="16.8" width="5.6" height="4.2" rx="1"/><path d="M12 7v3.1M5.8 16.5v-3.1h12.4v3.1M12 10.1v3.3M18.2 13.2v3.3"/>'
    ),
    dockerContainer: iconFactory(
      '<path d="M3 8.2h14.8v8.1H3z"/><path d="M6.7 8.2V5.4h2.6v2.8M10.6 8.2V5.4h2.6v2.8M14.5 8.2V5.4h2.6v2.8"/><path d="M17.8 11.7c1.5-.7 2.8-.4 3.5.3-.7 1.2-2 1.9-3.8 1.9H3"/>'
    ),
    terminalPrompt: iconFactory(
      '<rect x="2.8" y="4" width="18.4" height="16" rx="2"/><path d="m6.5 9 3 3-3 3M12 15h4.8"/>'
    ),
    gitDiff: iconFactory(
      '<path d="M7 3.2v17.6M17 3.2v17.6"/><path d="M7 6.4h4M7 12h3M17 8.8h-4M17 15.6h-4"/><circle cx="7" cy="6.4" r="1.4"/><circle cx="17" cy="15.6" r="1.4"/>'
    ),
    shieldVerified: iconFactory(
      '<path d="M12 2.7 19.2 5v5.8c0 4.2-2.9 7.9-7.2 10.2-4.3-2.3-7.2-6-7.2-10.2V5z"/><path d="m8.2 11.9 2.3 2.3 5.3-5.3"/>'
    ),
    shieldAlert: iconFactory(
      '<path d="M12 2.7 19.2 5v5.8c0 4.2-2.9 7.9-7.2 10.2-4.3-2.3-7.2-6-7.2-10.2V5z"/><path d="M12 7.9v4.6M12 15.5v.1"/>'
    ),
    cpuCompiler: iconFactory(
      '<rect x="6.4" y="6.4" width="11.2" height="11.2" rx="1.5"/><path d="M9.5 9.5h5v5h-5zM9.5 2.8v3.4M14.5 2.8v3.4M9.5 17.8v3.4M14.5 17.8v3.4M2.8 9.5h3.4M2.8 14.5h3.4M17.8 9.5h3.4M17.8 14.5h3.4"/>'
    ),
    fileCode: iconFactory(
      '<path d="M6 2.8h7l5 5v13.4H6z"/><path d="M13 2.8v5h5M10.2 12.1 8 14.3l2.2 2.2M13.8 12.1l2.2 2.2-2.2 2.2"/>'
    ),
    copyClipboard: iconFactory(
      '<rect x="8.2" y="7" width="11.4" height="13.5" rx="1.5"/><path d="M15.8 7V5.2A1.8 1.8 0 0 0 14 3.4H5.9a1.8 1.8 0 0 0-1.8 1.8v10.2a1.8 1.8 0 0 0 1.8 1.8h2.3"/>'
    ),
    checkSuccess: iconFactory(
      '<circle cx="12" cy="12" r="8.8"/><path d="m7.7 12.1 2.8 2.8 5.8-6"/>'
    ),
    downloadCert: iconFactory(
      '<path d="M5 3.2h10l3.5 3.5v14.1H5z"/><path d="M15 3.2v3.5h3.5M12 9.2v7.2M9.3 13.8 12 16.5l2.7-2.7"/>'
    ),
    lockClosed: iconFactory(
      '<rect x="5" y="10.2" width="14" height="10.3" rx="1.8"/><path d="M8 10.2V7a4 4 0 0 1 8 0v3.2"/>'
    ),
    lockOpen: iconFactory(
      '<rect x="5" y="10.2" width="14" height="10.3" rx="1.8"/><path d="M8 10.2V7a4 4 0 0 1 7.2-2.4"/>'
    ),
    slashPath: iconFactory(
      '<path d="M7 3.5 17 20.5M4.6 6.2h5.1M14.3 17.8h5.1"/>'
    ),
    caseSensitive: iconFactory(
      '<path d="M4.8 17.2h5.8M5.8 14.8l2-6.5 2 6.5M6.6 12.5h2.4M13.2 11.7v5.5M13.2 10.1v.1M17.2 17.2c-2.5 0-3.7-1.1-3.7-2.7s1.3-2.5 3.7-2.5c1.2 0 2.1.2 2.7.5v4.7"/>'
    ),
    lineEndings: iconFactory(
      '<path d="M4.2 4.2v15.6M4.2 19.8h5.4M10.5 8.2h9.3M10.5 12h6.5M10.5 15.8h9.3"/>'
    ),
    envKey: iconFactory(
      '<circle cx="8.2" cy="12" r="4.4"/><path d="m11.5 15.2 7.7 5.2M15.2 17.8l1.8-2.4M17.7 19.5l1.8-2.4"/>'
    ),
    chevronRight: iconFactory('<path d="m9 5 7 7-7 7"/>'),
  };

  function renderIcon(name, size, label) {
    var factory = icons[name] || icons.fileCode;
    return factory(size || 20, label || "");
  }

  function renderRadialGauge(scoreBefore, scoreAfter, label, options) {
    var dualMode = typeof scoreAfter === "number";
    if (!dualMode) {
      options = label || {};
      label = typeof scoreAfter === "string" ? scoreAfter : "Readiness";
      scoreAfter = scoreBefore;
    } else {
      options = options || {};
    }
    var numeric = Number(scoreAfter);
    var beforeNumeric = Number(scoreBefore);
    if (!Number.isFinite(numeric)) numeric = 0;
    numeric = Math.max(0, Math.min(100, numeric));
    if (!Number.isFinite(beforeNumeric)) beforeNumeric = numeric;
    beforeNumeric = Math.max(0, Math.min(100, beforeNumeric));
    var size = Number(options.size) || 132;
    var radius = 48;
    var circumference = 2 * Math.PI * radius;
    var beforeCircumference = 2 * Math.PI * 42;
    var offset = circumference * (1 - numeric / 100);
    var ids = nextIds();
    var tone = options.tone || (numeric >= 85 ? "success" : numeric >= 60 ? "warning" : "danger");
    return (
      '<div class="radial-gauge radial-gauge-' +
      escapeHtml(tone) +
      '" style="--gauge-size:' +
      escapeHtml(size) +
      'px" role="img" aria-label="' +
      escapeHtml((label || "Readiness") + " " + Math.round(numeric) + " percent") +
      '">' +
      '<svg viewBox="0 0 112 112" width="' +
      escapeHtml(size) +
      '" height="' +
      escapeHtml(size) +
      '" fill="none" xmlns="http://www.w3.org/2000/svg">' +
      "<defs>" +
      '<linearGradient id="' +
      ids.gradient +
      '" x1="18" y1="8" x2="94" y2="102" gradientUnits="userSpaceOnUse"><stop stop-color="#8B7CFF"/><stop offset="0.55" stop-color="#50D8FF"/><stop offset="1" stop-color="#5DE3A1"/></linearGradient>' +
      '<filter id="' +
      ids.glow +
      '" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="2" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>' +
      "</defs>" +
       '<circle class="gauge-track" cx="56" cy="56" r="48" stroke-width="1.75"/>' +
       (dualMode
         ? '<circle class="gauge-before" cx="56" cy="56" r="42" stroke-width="1.75" stroke-dasharray="' +
            beforeCircumference.toFixed(2) +
           '" stroke-dashoffset="' +
           (beforeCircumference * (1 - beforeNumeric / 100)).toFixed(2) +
           '" transform="rotate(-90 56 56)"/>'
         : "") +
      '<circle class="gauge-value" cx="56" cy="56" r="48" stroke="url(#' +
      ids.gradient +
      ')" stroke-width="1.75" stroke-linecap="round" stroke-dasharray="' +
      circumference.toFixed(2) +
      '" stroke-dashoffset="' +
      offset.toFixed(2) +
      '" transform="rotate(-90 56 56)" filter="url(#' +
      ids.glow +
      ')"/>' +
      '</svg><div class="gauge-center"><strong>' +
       Math.round(numeric) +
       '</strong><span>%</span></div><div class="gauge-label">' +
       escapeHtml(label || "Readiness") +
       (dualMode
         ? "<small>" + Math.round(beforeNumeric) + "% -> " + Math.round(numeric) + "%</small>"
         : "") +
       "</div></div>"
    );
  }

  function renderCertificationSeal(certificate, certHash, options) {
    options = options || {};
    if (typeof certificate === "boolean") {
      certificate = {
        is_cleanroom_certified: certificate,
        root_hash: certHash || "pending",
      };
    }
    certificate = certificate || {};
    var verified = Boolean(
      certificate.is_cleanroom_certified || certificate.verified
    );
    var hash = String(certificate.root_hash || certificate.merkle_root || "pending");
    var shortHash = hash.length > 18 ? hash.slice(0, 10) + "..." + hash.slice(-6) : hash;
    var status = verified ? "Verified evidence" : "Evidence pending";
    var iconName = verified ? "shieldVerified" : "shieldAlert";
    return (
      '<div class="cert-seal ' +
      (verified ? "cert-seal-verified" : "cert-seal-pending") +
      '" role="img" aria-label="' +
      escapeHtml(status) +
      '"><div class="cert-seal-ring">' +
      renderIcon(iconName, options.iconSize || 34, status) +
      '</div><div class="cert-seal-copy"><span class="eyebrow">Certificate status</span><strong>' +
      escapeHtml(status) +
      '</strong><code>' +
      escapeHtml(shortHash) +
      "</code></div></div>"
    );
  }

  function renderMerkleTreeSVG(nodes, comparison) {
    var options = {};
    if (!Array.isArray(nodes) && nodes && typeof nodes === "object") {
      options.rootHash = nodes.root_hash || nodes.merkle_root || "root pending";
      options.comparison = comparison || {};
      nodes = nodes.file_nodes || [];
    } else {
      options = comparison || {};
    }
    var source = Array.isArray(nodes) ? nodes : [];
    var drift = options.comparison || {};
    var modifiedPaths = (drift.modified_files || []).concat(drift.added_files || []);
    var lineEndingPaths = drift.line_ending_drifts || [];
    function leafColor(path) {
      if (lineEndingPaths.indexOf(path) >= 0) return "#f59e0b";
      if (modifiedPaths.indexOf(path) >= 0) return "#06b6d4";
      return "#10b981";
    }
    var leaves = [];
    function collect(items, depth) {
      items.slice(0, 8).forEach(function (node) {
        var children = Array.isArray(node.children) ? node.children : [];
        if (children.length && depth < 3) {
          collect(children, depth + 1);
        } else {
          leaves.push(node);
        }
      });
    }
    collect(source, 0);
    if (!leaves.length) leaves = [{ path: "awaiting evidence", digest: "pending" }];
    leaves = leaves.slice(0, 5);
    var rootHash = String(options.rootHash || "root pending");
    var width = 540;
    var height = 190;
    var rootX = width / 2;
    var leafStart = 94;
    var leafGap = leaves.length === 1 ? 0 : 360 / (leaves.length - 1);
    var left = (width - (leaves.length - 1) * leafGap) / 2;
    var lines = leaves
      .map(function (_, index) {
        var x = left + index * leafGap;
        return '<path d="M' + rootX + ' 55 V74 H' + x + ' V102"/>';
      })
      .join("");
    var leafMarkup = leaves
      .map(function (node, index) {
        var x = left + index * leafGap;
        var path = String(node.path || "file node");
        var digest = String(node.digest || "pending");
         var displayPath = path.length > 19 ? path.slice(0, 17) + "..." : path;
         var displayDigest = digest.length > 12 ? digest.slice(0, 10) + "..." : digest;
         var color = leafColor(path);
         return (
          '<g class="merkle-leaf" data-path="' + escapeHtml(path) + '"><title>' +
          escapeHtml(path + " SHA-256 " + digest) +
          '</title><rect stroke="' + color + '" x="' +
          (x - 48) +
          '" y="102" width="96" height="48" rx="8"/><text x="' +
          x +
          '" y="122" text-anchor="middle">' +
          escapeHtml(displayPath) +
          '</text><text class="merkle-digest" x="' +
          x +
          '" y="138" text-anchor="middle">' +
          escapeHtml(displayDigest) +
          "</text></g>"
        );
      })
      .join("");
    var ids = nextIds();
    return (
      '<svg class="merkle-tree-svg" viewBox="0 0 ' +
      width +
      " " +
      height +
      '" role="img" aria-label="Merkle evidence tree" fill="none" xmlns="http://www.w3.org/2000/svg">' +
      "<defs>" +
      '<linearGradient id="' +
      ids.gradient +
      '" x1="80" y1="30" x2="450" y2="160" gradientUnits="userSpaceOnUse"><stop stop-color="#8B7CFF"/><stop offset="0.55" stop-color="#50D8FF"/><stop offset="1" stop-color="#5DE3A1"/></linearGradient>' +
      '<filter id="' +
      ids.glow +
      '" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="2" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>' +
      "</defs>" +
      '<g stroke="url(#' +
      ids.gradient +
      ')" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" filter="url(#' +
      ids.glow +
      ')">' +
      lines +
      '<rect x="' +
      (rootX - 76) +
      '" y="18" width="152" height="37" rx="10" fill="rgba(139,124,255,.12)"/><circle cx="' +
      rootX +
      '" cy="36" r="7" fill="rgba(80,216,255,.18)"/>' +
      '</g><text class="merkle-root-label" x="' +
      rootX +
      '" y="40" text-anchor="middle">' +
      escapeHtml(rootHash.length > 22 ? rootHash.slice(0, 19) + "..." : rootHash) +
      "</text>" +
      leafMarkup +
      "</svg>"
    );
  }

  window.CleanRoomIcons = {
    icons: icons,
    escapeHtml: escapeHtml,
    icon: renderIcon,
    renderRadialGauge: renderRadialGauge,
    renderCertificationSeal: renderCertificationSeal,
    renderMerkleTreeSVG: renderMerkleTreeSVG,
  };
  window.renderRadialGauge = renderRadialGauge;
  window.renderCertificationSeal = renderCertificationSeal;
  window.renderMerkleTreeSVG = renderMerkleTreeSVG;
})();
