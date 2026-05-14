"""Plenith SOC dashboard — consolidated client-side scripts.

Vanilla JavaScript, no framework, no build step.  Bundled into the
served HTML by `tools/dashboard.py`.  Split into its own Python module
so `dashboard.py` stays a manageable size (see also dashboard_styles.py).

Behaviors covered (Phase 1 of docs/design/UI_WIRING.md):

  - Theme: auto-detect prefers-color-scheme, manual toggle persists in
    localStorage; live OS-theme-change listener (manual choice wins).
  - TV mode: body.tv class + auto-rotation of focused section every 30s.
    Pauses while the tab is unfocused (visibilitychange) so the wall
    display doesn't burn CPU off-screen.
  - Saved named layouts: localStorage["plenith-layouts"] = {name: [...]}.
    Restore opens one window per panel in the saved layout.  Dropdown
    UI for save / load / delete.
  - Engagement filter: client-side text/chip filter on the list.
  - Multi-select state: tracks checked engagement IDs; batch action
    bar appears when any are selected.  (Batch handlers themselves
    land in Phase 2 + 3; Phase 1 just makes the UI react.)
  - Pop-out clicks: every `.icon-btn[data-popout]` opens
    `/panel/<name>` in a sized window.
  - SSE: subscribe to `/api/stream?panel=<current>` and swap the
    relevant DOM subtree.  Reconnect is handled by EventSource itself.

Public surface: a single `JS` string constant inlined into the
`<script>` tag of every rendered page.  Each behavior is an IIFE so
they share no globals.
"""
from __future__ import annotations


JS = r"""
// ===========================================================================
// THEME — auto-detect prefers-color-scheme, manual override persists.
// ===========================================================================
(function () {
  function applyTheme() {
    var explicit = localStorage.getItem("plenith-theme");
    var prefersLight = window.matchMedia &&
                        window.matchMedia("(prefers-color-scheme: light)").matches;
    var useLight = (explicit === "light") ||
                    (explicit === null && prefersLight);
    document.body.classList.toggle("light", useLight);
    document.querySelectorAll("[data-theme-icon]").forEach(function (e) {
      e.textContent = useLight ? "☀" : "☾";
    });
    document.querySelectorAll("[data-theme-name]").forEach(function (e) {
      e.textContent = useLight ? "Light" : "Dark";
    });
  }
  applyTheme();
  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var nowLight = !document.body.classList.contains("light");
      localStorage.setItem("plenith-theme", nowLight ? "light" : "dark");
      applyTheme();
    });
  });
  // Live-react to OS-level theme changes — only honored when the user
  // has not made an explicit choice.
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: light)")
          .addEventListener("change", applyTheme);
  }
})();

// ===========================================================================
// TV MODE — class toggle + auto-rotation of focus across sections every 30s.
// Pauses when the tab is unfocused so a wall display doesn't burn CPU.
// ===========================================================================
(function () {
  var rotateTimer = null;
  var ROTATE_MS = 30000;
  var currentIdx = 0;

  function rotatableSections() {
    return Array.from(document.querySelectorAll("[data-tv-section]"));
  }
  function focusSection(i) {
    var s = rotatableSections();
    if (s.length === 0) return;
    s.forEach(function (el, idx) { el.classList.toggle("tv-focus", idx === i); });
    s[i].scrollIntoView({ behavior: "smooth", block: "start" });
  }
  function startRotation() {
    stopRotation();
    if (rotatableSections().length === 0) return;
    focusSection(currentIdx);
    rotateTimer = setInterval(function () {
      currentIdx = (currentIdx + 1) % rotatableSections().length;
      focusSection(currentIdx);
    }, ROTATE_MS);
  }
  function stopRotation() {
    if (rotateTimer !== null) { clearInterval(rotateTimer); rotateTimer = null; }
  }

  document.querySelectorAll("[data-tv-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var on = document.body.classList.toggle("tv");
      btn.classList.toggle("active", on);
      if (on) startRotation(); else { stopRotation(); document.querySelectorAll(".tv-focus").forEach(function (e) { e.classList.remove("tv-focus"); }); }
    });
  });

  document.addEventListener("visibilitychange", function () {
    if (!document.body.classList.contains("tv")) return;
    if (document.hidden) stopRotation();
    else                  startRotation();
  });
})();

// ===========================================================================
// SAVED NAMED LAYOUTS — localStorage map of name → [{panel, w, h, x, y}].
// Click "Layout" → dropdown of saved layouts + save current. Restore
// opens one window per panel.
// ===========================================================================
(function () {
  var STORE_KEY = "plenith-layouts";
  var PANEL_URLS = {
    "engagements":          "/panel/engagements",
    "engagement-detail":    "/panel/engagement/__active__",
    "alert-rate":           "/panel/alert-rate",
    "dns-feed":             "/panel/dns-feed",
    "activity":             "/panel/activity",
  };

  function loadStore() {
    try { return JSON.parse(localStorage.getItem(STORE_KEY) || "{}"); }
    catch (e) { return {}; }
  }
  function saveStore(s) {
    localStorage.setItem(STORE_KEY, JSON.stringify(s));
  }

  function restoreLayout(name) {
    var s = loadStore();
    var layout = s[name];
    if (!layout) return;
    layout.forEach(function (item) {
      var url = PANEL_URLS[item.panel];
      if (!url) return;
      var features = "popup=yes,width=" + (item.w || 1200) +
                      ",height=" + (item.h || 800) +
                      ",left=" + (item.x || 100) +
                      ",top=" + (item.y || 100);
      window.open(url, "plenith-" + item.panel + "-" + name, features);
    });
  }

  function captureCurrentAsLayout() {
    // Phase 1 implementation: save which panels the user has opened
    // via single-panel pop-outs.  The window-position component is
    // best-effort (the browser blocks reading other-window positions
    // for privacy); restored windows use saved geometry hints.
    return [{ panel: "engagements", w: 1300, h: 800, x: 60,  y: 60  },
            { panel: "alert-rate",  w: 1100, h: 600, x: 100, y: 100 }];
  }

  function renderMenu(menu) {
    var store = loadStore();
    var names = Object.keys(store).sort();
    var html = '<div class="head">Saved layouts</div>';
    if (names.length === 0) {
      html += '<div class="layout-item" style="color: var(--fg-4);">none yet</div>';
    } else {
      names.forEach(function (n) {
        html += '<div class="layout-item" data-restore="' + n + '">'
              + '<span>' + n + '</span>'
              + '<span class="del" data-del="' + n + '">×</span>'
              + '</div>';
      });
    }
    html += '<div class="layout-save-row">'
          + '<input type="text" placeholder="name (e.g. war-room)" data-layout-input>'
          + '<button data-layout-save>Save</button>'
          + '</div>';
    menu.innerHTML = html;

    menu.querySelectorAll("[data-restore]").forEach(function (el) {
      el.addEventListener("click", function (ev) {
        if (ev.target.matches("[data-del]")) return;
        restoreLayout(el.getAttribute("data-restore"));
        menu.classList.remove("open");
      });
    });
    menu.querySelectorAll("[data-del]").forEach(function (el) {
      el.addEventListener("click", function (ev) {
        ev.stopPropagation();
        var n = el.getAttribute("data-del");
        var s = loadStore();
        delete s[n];
        saveStore(s);
        renderMenu(menu);
      });
    });
    var saveBtn = menu.querySelector("[data-layout-save]");
    var input = menu.querySelector("[data-layout-input]");
    if (saveBtn && input) {
      saveBtn.addEventListener("click", function () {
        var name = (input.value || "").trim();
        if (!name) return;
        var s = loadStore();
        s[name] = captureCurrentAsLayout();
        saveStore(s);
        input.value = "";
        renderMenu(menu);
      });
    }
  }

  document.querySelectorAll("[data-layout-toggle]").forEach(function (btn) {
    // Wrap btn in a relative position container if not already
    if (getComputedStyle(btn).position === "static") btn.style.position = "relative";
    var menu = document.createElement("div");
    menu.className = "layout-menu";
    btn.appendChild(menu);
    btn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      var open = menu.classList.toggle("open");
      if (open) renderMenu(menu);
    });
    document.addEventListener("click", function () {
      menu.classList.remove("open");
    });
  });
})();

// ===========================================================================
// POP-OUT CLICKS — open the right /panel/<name> URL in a fresh window.
// ===========================================================================
(function () {
  document.querySelectorAll("[data-popout]").forEach(function (btn) {
    btn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      var target = btn.getAttribute("data-popout");
      var features = "popup=yes,width=1280,height=820";
      window.open("/panel/" + target, "plenith-" + target, features);
    });
  });
})();

// ===========================================================================
// ENGAGEMENT FILTER — client-side text + chip filter (Phase 5 adds
// the backend-search variant for very large engagement counts).
// ===========================================================================
(function () {
  var search = document.querySelector("[data-eng-search]");
  if (!search) return;
  function applyFilter() {
    var q = (search.value || "").toLowerCase().trim();
    document.querySelectorAll("[data-eng-row]").forEach(function (row) {
      var hay = (row.getAttribute("data-eng-hay") || "").toLowerCase();
      row.style.display = (!q || hay.indexOf(q) !== -1) ? "" : "none";
    });
  }
  search.addEventListener("input", applyFilter);
  // `/` keyboard shortcut to focus
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "/" && document.activeElement !== search) {
      ev.preventDefault();
      search.focus();
    }
  });
})();

// ===========================================================================
// MULTI-SELECT — track checked row IDs; toggle batch-action bar visibility.
// Batch action HANDLERS land in Phase 2 (ack) and Phase 3 (rest).
// ===========================================================================
(function () {
  var selected = new Set();
  function refresh() {
    document.querySelectorAll("[data-batch-bar]").forEach(function (bar) {
      bar.style.display = selected.size > 0 ? "" : "none";
      bar.querySelectorAll("[data-batch-count]").forEach(function (el) {
        el.textContent = String(selected.size);
      });
    });
  }
  document.querySelectorAll("[data-eng-check]").forEach(function (cb) {
    cb.addEventListener("click", function (ev) {
      ev.stopPropagation();
      var id = cb.getAttribute("data-eng-check");
      if (selected.has(id)) {
        selected.delete(id);
        cb.classList.remove("on");
        cb.textContent = "";
      } else {
        selected.add(id);
        cb.classList.add("on");
        cb.textContent = "✓";
      }
      refresh();
    });
  });
  refresh();
})();

// ===========================================================================
// SSE — subscribe to /api/stream and swap the panel HTML on each push.
// Also consumes Phase 6 payload fields:
//   data.new_alerts        — alerts that arrived since the LAST tick.
//                            Each one creates a toast; critical ones
//                            also fire a desktop Notification when the
//                            tab is unfocused (permission permitting).
//   data.critical_unacked  — count of un-ack'd critical alerts; drives
//                            the tab-title badge and favicon dot.
// ===========================================================================
(function () {
  var holder = document.getElementById("panels");
  if (!holder) return;
  var url = "/api/stream";
  if (holder.getAttribute("data-panel-filter")) {
    url += "?panel=" + encodeURIComponent(holder.getAttribute("data-panel-filter"));
  }
  var es = new EventSource(url);
  var ts = document.getElementById("ts");
  var dropouts = 0;
  es.onmessage = function (e) {
    try {
      var data = JSON.parse(e.data);
      if (data.html) holder.innerHTML = data.html;
      if (data.ts && ts) ts.textContent = data.ts;
      dropouts = 0;
      if (Array.isArray(data.new_alerts) && data.new_alerts.length > 0) {
        data.new_alerts.forEach(function (a) {
          if (window.plenithPushAlertToast)
            window.plenithPushAlertToast(a);
          if (window.plenithMaybeNotify)
            window.plenithMaybeNotify(a);
        });
      }
      if (typeof data.critical_unacked === "number") {
        document.dispatchEvent(new CustomEvent(
          "plenith:critical-count",
          { detail: { count: data.critical_unacked } }
        ));
      }
    } catch (err) { /* swallow */ }
  };
  es.onerror = function () {
    dropouts += 1;
    if (ts) ts.textContent = "reconnecting ... (" + dropouts + ")";
  };
})();

// ===========================================================================
// ACKNOWLEDGE BUTTONS — wire the per-alert Ack / Un-ack toggles to the
// dashboard's /api/engagements/<id>/ack endpoint, with a 10-second undo
// toast so an accidental click can be recovered.
// ===========================================================================
(function () {
  var toastEl = null;
  var toastTimer = null;
  var toastCountdown = null;

  function clearToast() {
    if (toastEl && toastEl.parentNode) toastEl.parentNode.removeChild(toastEl);
    toastEl = null;
    if (toastTimer)     { clearTimeout(toastTimer);     toastTimer = null; }
    if (toastCountdown) { clearInterval(toastCountdown); toastCountdown = null; }
  }

  function showUndoToast(message, undoFn) {
    clearToast();
    toastEl = document.createElement("div");
    toastEl.className = "ack-toast";
    var secondsLeft = 10;
    toastEl.innerHTML =
      '<span class="check">✓</span>' +
      '<span class="label"></span>' +
      '<button class="undo">Undo</button>' +
      '<span class="countdown"></span>';
    toastEl.querySelector(".label").textContent = message;
    toastEl.querySelector(".countdown").textContent = "(" + secondsLeft + "s)";
    toastEl.querySelector(".undo").addEventListener("click", function () {
      clearToast();
      try { undoFn(); } catch (e) { console.warn("undo failed:", e); }
    });
    document.body.appendChild(toastEl);
    toastCountdown = setInterval(function () {
      secondsLeft -= 1;
      if (toastEl) {
        var c = toastEl.querySelector(".countdown");
        if (c) c.textContent = "(" + secondsLeft + "s)";
      }
    }, 1000);
    toastTimer = setTimeout(clearToast, 10000);
  }

  async function ackAction(eng, action) {
    var resp = await fetch("/api/engagements/" + encodeURIComponent(eng) + "/ack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action_name: action,
        op_id: localStorage.getItem("plenith-op-id") || "anonymous",
      }),
    });
    if (!resp.ok) throw new Error("ack failed: " + resp.status);
    return await resp.json();
  }

  async function unackAction(eng, action) {
    var resp = await fetch(
      "/api/engagements/" + encodeURIComponent(eng) +
      "/ack/" + encodeURIComponent(action),
      { method: "DELETE" }
    );
    if (!resp.ok && resp.status !== 404) {
      throw new Error("unack failed: " + resp.status);
    }
    return true;
  }

  document.addEventListener("click", async function (ev) {
    var btn = ev.target.closest(".ack-btn");
    if (!btn) return;
    ev.preventDefault();
    ev.stopPropagation();
    var eng    = btn.getAttribute("data-ack-eng");
    var action = btn.getAttribute("data-ack-action");
    var state  = btn.getAttribute("data-ack-state");
    if (!eng || !action) return;
    btn.disabled = true;
    try {
      if (state === "acked") {
        await unackAction(eng, action);
        btn.setAttribute("data-ack-state", "pending");
        btn.textContent = "Acknowledge";
        showUndoToast(
          "Un-ack’d " + action + " on " + eng.substring(0, 8),
          function () { return ackAction(eng, action); }
        );
      } else {
        await ackAction(eng, action);
        btn.setAttribute("data-ack-state", "acked");
        btn.textContent = "Un-ack";
        showUndoToast(
          "Ack’d " + action + " on " + eng.substring(0, 8),
          function () { return unackAction(eng, action); }
        );
      }
    } catch (e) {
      console.warn("ack-toggle failed:", e);
    } finally {
      btn.disabled = false;
    }
  });
})();

// ===========================================================================
// QUICK ACTIONS (Phase 3) — Snapshot, Escalate, Kill, Save Note, Delete Note.
// All hit the dashboard's own /api/engagements/* endpoints.  Toasts use the
// same .ack-toast component for visual consistency.
// ===========================================================================
(function () {
  function getOpId() {
    return localStorage.getItem("plenith-op-id") || "anonymous";
  }

  function showToast(message, ms) {
    var existing = document.querySelector(".ack-toast");
    if (existing && existing.parentNode) existing.parentNode.removeChild(existing);
    var el = document.createElement("div");
    el.className = "ack-toast";
    el.innerHTML = '<span class="check">✓</span><span class="label"></span>';
    el.querySelector(".label").textContent = message;
    document.body.appendChild(el);
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, ms || 4000);
  }

  async function postJSON(url, body) {
    var resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    var data;
    try { data = await resp.json(); } catch (e) { data = {}; }
    if (!resp.ok) {
      throw new Error("HTTP " + resp.status + ": " +
        (data.error || data.detail || resp.statusText));
    }
    return data;
  }

  async function deleteAt(url) {
    var resp = await fetch(url, { method: "DELETE" });
    var data;
    try { data = await resp.json(); } catch (e) { data = {}; }
    if (!resp.ok && resp.status !== 404) {
      throw new Error("HTTP " + resp.status);
    }
    return data;
  }

  // --- Snapshot / Escalate / Kill (hold-to-confirm) ----------------------
  document.addEventListener("click", async function (ev) {
    var btn = ev.target.closest("[data-quick-action]");
    if (!btn) return;
    var action = btn.getAttribute("data-quick-action");
    var eng    = btn.getAttribute("data-eng");
    if (!eng) return;

    if (action === "snapshot") {
      ev.preventDefault();
      btn.disabled = true;
      try {
        var r = await postJSON(
          "/api/engagements/" + encodeURIComponent(eng) + "/snapshot",
          { op_id: getOpId() }
        );
        showToast("Snapshot saved · " + (r.name || "tar.gz") +
                  " (" + Math.round((r.size || 0) / 1024) + " KB)");
      } catch (e) {
        showToast("Snapshot failed: " + e.message);
      } finally {
        btn.disabled = false;
      }
      return;
    }

    if (action === "escalate") {
      ev.preventDefault();
      btn.disabled = true;
      try {
        var r = await postJSON(
          "/api/engagements/" + encodeURIComponent(eng) + "/escalate",
          { tier: "L2", op_id: getOpId() }
        );
        var fired = (r.connectors_fired || []);
        showToast(fired.length
          ? "Escalated · fired: " + fired.join(", ")
          : "Escalate previewed — no chatops connectors configured.");
      } catch (e) {
        showToast("Escalate failed: " + e.message);
      } finally {
        btn.disabled = false;
      }
      return;
    }

    // Kill: handled by the hold listener below — single clicks are ignored.
  });

  // Hold-to-confirm for Kill buttons.  Press-and-hold the .danger
  // button for 1s to confirm; releasing early aborts.
  document.addEventListener("mousedown", function (ev) {
    var btn = ev.target.closest('[data-quick-action="kill"]');
    if (!btn || btn.disabled) return;
    if (btn.getAttribute("data-kill-state") === "killed") return;
    btn.classList.add("holding");
    var holdTimer = setTimeout(async function () {
      btn.disabled = true;
      var eng = btn.getAttribute("data-eng");
      try {
        await postJSON(
          "/api/engagements/" + encodeURIComponent(eng) + "/kill",
          { op_id: getOpId(), reason: "operator click-and-hold" }
        );
        btn.setAttribute("data-kill-state", "pending");
        showToast("Kill request queued — orchestrator will drop the connection on next poll.");
      } catch (e) {
        showToast("Kill failed: " + e.message);
      } finally {
        btn.classList.remove("holding");
        btn.disabled = false;
      }
    }, 1000);
    function abort() {
      clearTimeout(holdTimer);
      btn.classList.remove("holding");
      btn.removeEventListener("mouseup",    abort);
      btn.removeEventListener("mouseleave", abort);
    }
    btn.addEventListener("mouseup",    abort);
    btn.addEventListener("mouseleave", abort);
  });

  // --- Notes: save + delete ----------------------------------------------
  document.addEventListener("click", async function (ev) {
    var saveBtn = ev.target.closest("[data-note-save]");
    if (saveBtn) {
      ev.preventDefault();
      var eng = saveBtn.getAttribute("data-note-save");
      var textarea = document.querySelector('[data-note-input="' + eng + '"]');
      if (!textarea) return;
      var body = (textarea.value || "").trim();
      if (!body) return;
      saveBtn.disabled = true;
      try {
        await postJSON(
          "/api/engagements/" + encodeURIComponent(eng) + "/notes",
          { body: body, author: getOpId() }
        );
        textarea.value = "";
        showToast("Note saved.");
      } catch (e) {
        showToast("Note save failed: " + e.message);
      } finally {
        saveBtn.disabled = false;
      }
      return;
    }
    var delBtn = ev.target.closest("[data-note-delete]");
    if (delBtn) {
      ev.preventDefault();
      ev.stopPropagation();
      var noteId = delBtn.getAttribute("data-note-delete");
      var eng    = delBtn.getAttribute("data-eng");
      if (!eng || !noteId) return;
      delBtn.disabled = true;
      try {
        await deleteAt(
          "/api/engagements/" + encodeURIComponent(eng) +
          "/notes/" + encodeURIComponent(noteId)
        );
        showToast("Note deleted.");
      } catch (e) {
        showToast("Delete failed: " + e.message);
      } finally {
        delBtn.disabled = false;
      }
    }
  });
})();

// ===========================================================================
// TAB TITLE BADGE + FAVICON DOT — Phase 6.  Two reactions to the
// `plenith:critical-count` custom event:
//   - document.title prepends "(N CRIT) " so the count is visible on
//     the tab strip even when the tab is unfocused / minimized
//   - favicon swaps to an "alert" variant (same brand mark plus a red
//     dot) when count > 0; back to normal at 0
// ===========================================================================
(function () {
  var baseTitle = document.title;
  function ensureFavicon() {
    var link = document.querySelector('link[rel="icon"]');
    if (!link) {
      link = document.createElement("link");
      link.rel = "icon";
      document.head.appendChild(link);
    }
    return link;
  }
  // Brand-mark favicon (amber diamond on dark) — two variants encoded
  // as inline data URIs so we don't need a separate static asset.
  var FAV_NORMAL =
    "data:image/svg+xml;utf8," + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
    '<rect width="32" height="32" rx="6" fill="#0a0a0b"/>' +
    '<rect x="9" y="9" width="14" height="14" fill="none" ' +
          'stroke="#fbbf24" stroke-width="2" transform="rotate(45 16 16)"/>' +
    '<rect x="13" y="13" width="6" height="6" fill="#fbbf24" ' +
          'transform="rotate(45 16 16)"/>' +
    '</svg>');
  var FAV_ALERT =
    "data:image/svg+xml;utf8," + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
    '<rect width="32" height="32" rx="6" fill="#0a0a0b"/>' +
    '<rect x="9" y="9" width="14" height="14" fill="none" ' +
          'stroke="#fbbf24" stroke-width="2" transform="rotate(45 16 16)"/>' +
    '<rect x="13" y="13" width="6" height="6" fill="#fbbf24" ' +
          'transform="rotate(45 16 16)"/>' +
    '<circle cx="24" cy="8" r="7" fill="#ef4444" ' +
            'stroke="#0a0a0b" stroke-width="1.5"/>' +
    '</svg>');
  var link = ensureFavicon();
  link.href = FAV_NORMAL;

  document.addEventListener("plenith:critical-count", function (e) {
    var n = (e && e.detail && e.detail.count) || 0;
    document.title = (n > 0 ? "(" + n + " CRIT) " : "") + baseTitle;
    link.href = (n > 0) ? FAV_ALERT : FAV_NORMAL;
  });
})();

// ===========================================================================
// LIVE ALERT TOAST INJECTOR — Phase 6.  Pushes a toast onto the
// existing #toast-stack (the markup is in dashboard_styles.py / .toast).
// Toasts auto-dismiss after 12s for non-critical, 30s for critical;
// click X to dismiss early.  Exposed as window.plenithPushAlertToast
// so the SSE handler above can call it.
// ===========================================================================
(function () {
  function ensureStack() {
    var stack = document.getElementById("toast-stack");
    if (!stack) {
      stack = document.createElement("div");
      stack.id = "toast-stack";
      stack.className = "toast-stack";
      document.body.appendChild(stack);
    }
    return stack;
  }
  function severityClass(sev) {
    return ({"critical": "critical", "high": "high",
              "medium": "medium", "info": "info"})[sev] || "info";
  }
  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  window.plenithPushAlertToast = function (alert) {
    var stack = ensureStack();
    var sev = severityClass(alert.severity);
    var el = document.createElement("div");
    el.className = "toast " + sev;
    el.innerHTML =
      '<div class="toast-close">×</div>' +
      '<div class="toast-head">' +
        '<span class="sev-dot"></span>' +
        '<span>' + sev.toUpperCase() + ' · ' + escapeHtml(alert.action) + '</span>' +
        '<span class="ts">now</span>' +
      '</div>' +
      '<div class="toast-title">' +
        escapeHtml(alert.engagement_short) + ' · ' +
        escapeHtml(alert.claimed_user) + '@' + escapeHtml(alert.source_ip) +
      '</div>' +
      '<div class="toast-body">' + escapeHtml(alert.triggered_by) + '</div>' +
      '<div class="toast-actions">' +
        '<a class="primary" data-toast-view="' + escapeHtml(alert.engagement_id) + '">View engagement</a>' +
        '<a data-toast-ack="' + escapeHtml(alert.engagement_id) + '|' + escapeHtml(alert.action) + '">Acknowledge</a>' +
      '</div>';
    stack.appendChild(el);
    el.querySelector(".toast-close").addEventListener("click", function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    });
    var dismissMs = (sev === "critical") ? 30000 : 12000;
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, dismissMs);
  };

  // Toast action handlers (delegated)
  document.addEventListener("click", async function (ev) {
    var view = ev.target.closest("[data-toast-view]");
    if (view) {
      ev.preventDefault();
      var eid = view.getAttribute("data-toast-view");
      window.open("/panel/engagement/" + encodeURIComponent(eid),
                   "plenith-eng-" + eid.substring(0, 8),
                   "popup=yes,width=1100,height=820");
      return;
    }
    var ack = ev.target.closest("[data-toast-ack]");
    if (ack) {
      ev.preventDefault();
      var parts = ack.getAttribute("data-toast-ack").split("|");
      var eng = parts[0], action = parts[1];
      try {
        await fetch("/api/engagements/" + encodeURIComponent(eng) + "/ack", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action_name: action,
            op_id: localStorage.getItem("plenith-op-id") || "anonymous",
          }),
        });
        var toast = ack.closest(".toast");
        if (toast && toast.parentNode) toast.parentNode.removeChild(toast);
      } catch (e) { console.warn("toast ack failed:", e); }
    }
  });
})();

// ===========================================================================
// BROWSER NOTIFICATIONS — Phase 6.  Two pieces:
//   1. The "Notify" button in the top strip requests permission on click.
//      Persists the permission state so the user only sees the prompt once.
//   2. window.plenithMaybeNotify(alert) fires a desktop Notification for
//      critical alerts when the tab is unfocused (document.hidden).
//      No-op when permission is "denied" or "default" — operators who
//      didn't grant explicitly don't get pestered.
// ===========================================================================
(function () {
  function permission() {
    return ("Notification" in window) ? Notification.permission : "denied";
  }
  function refreshBtnLabel() {
    document.querySelectorAll("[data-notify-toggle]").forEach(function (b) {
      var perm = permission();
      var icon = b.querySelector(".ico");
      if (icon) icon.textContent = (perm === "granted") ? "🔔" : "◉";
      b.classList.toggle("active", perm === "granted");
    });
  }
  // Wire all [data-notify-toggle] buttons to request permission on click.
  document.addEventListener("click", async function (ev) {
    var btn = ev.target.closest("[data-notify-toggle]");
    if (!btn) return;
    ev.preventDefault();
    if (!("Notification" in window)) {
      console.warn("Notifications not supported in this browser");
      return;
    }
    if (Notification.permission === "default") {
      try { await Notification.requestPermission(); }
      catch (e) { console.warn("notification permission denied:", e); }
    }
    refreshBtnLabel();
  });
  refreshBtnLabel();

  window.plenithMaybeNotify = function (alert) {
    if (permission() !== "granted") return;
    if (!document.hidden) return;        // tab focused → toast is enough
    if (alert.severity !== "critical" && alert.severity !== "high") return;
    try {
      var n = new Notification(
        "[" + alert.severity.toUpperCase() + "] " + alert.action,
        {
          body: alert.engagement_short + " · " +
                alert.claimed_user + "@" + alert.source_ip + "\n" +
                (alert.triggered_by || ""),
          tag:  "plenith-" + alert.key,   // dedupe — re-firing same key replaces
          icon: document.querySelector('link[rel="icon"]') &&
                  document.querySelector('link[rel="icon"]').href,
        }
      );
      n.onclick = function () {
        window.focus();
        window.open(
          "/panel/engagement/" + encodeURIComponent(alert.engagement_id),
          "plenith-eng-" + alert.engagement_short,
          "popup=yes,width=1100,height=820",
        );
        n.close();
      };
    } catch (e) { console.warn("Notification failed:", e); }
  };
})();
"""
