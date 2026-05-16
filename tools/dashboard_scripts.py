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
// SCROLL RESTORATION — off. This is a live/TV dashboard: a manual
// browser refresh must give a clean top-of-page view, not the browser
// silently restoring the operator's previous scroll (which on this
// ~3-viewport page reads as "the dashboard jumps on every refresh").
// Pre-existing browser default; unrelated to the SSE morph.
// ===========================================================================
if ("scrollRestoration" in history) history.scrollRestoration = "manual";

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
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      b.setAttribute("aria-pressed", useLight ? "true" : "false");
      b.setAttribute("aria-label",
        useLight ? "Switch to dark theme" : "Switch to light theme");
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
      btn.setAttribute("aria-pressed", on ? "true" : "false");
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
// MAIN-GRID ARRANGEMENT — drag panels to reorder, save named arrangements.
// Each panel carries data-panel-id; rows are marked data-grid-row.  The
// active arrangement (auto-saved on every drag) and named arrangements
// both live in localStorage and are re-applied after every SSE swap so
// the panels don't snap back to default order every 3 seconds.
//
// Rows preserve their panel COUNT (main always has 2 panels, bottom
// always has 3) — cross-row drags swap one for one, keeping the grid
// proportions intact.
// ===========================================================================
(function () {
  var STORE_KEY     = "plenith-arrangements";        // named map
  var STORE_CURRENT = "plenith-arrangement-current"; // live active arrangement

  function loadStore() {
    try { return JSON.parse(localStorage.getItem(STORE_KEY) || "{}"); }
    catch (e) { return {}; }
  }
  function saveStore(s) {
    localStorage.setItem(STORE_KEY, JSON.stringify(s));
  }
  function loadCurrent() {
    try { return JSON.parse(localStorage.getItem(STORE_CURRENT) || "null"); }
    catch (e) { return null; }
  }
  function saveCurrent(arrangement) {
    if (arrangement) localStorage.setItem(STORE_CURRENT, JSON.stringify(arrangement));
    else localStorage.removeItem(STORE_CURRENT);
  }

  // Read the current panel-to-row mapping from the DOM.
  function captureArrangement() {
    var out = {};
    document.querySelectorAll("[data-grid-row]").forEach(function (row) {
      var name = row.getAttribute("data-grid-row");
      var ids = [];
      row.querySelectorAll(":scope > .panel[data-panel-id]").forEach(function (p) {
        ids.push(p.getAttribute("data-panel-id"));
      });
      out[name] = ids;
    });
    return out;
  }

  // Apply a saved arrangement to the live DOM (moves panel nodes between
  // rows / reorders within a row).  Panels not mentioned in the arrangement
  // are left where they are; unknown ids are skipped.
  function applyArrangement(arrangement) {
    if (!arrangement) return;
    Object.keys(arrangement).forEach(function (rowName) {
      var row = document.querySelector(
        "[data-grid-row=\"" + rowName + "\"]");
      if (!row) return;
      var desiredIds = arrangement[rowName];
      if (!Array.isArray(desiredIds)) return;
      desiredIds.forEach(function (id) {
        var panel = document.querySelector(
          ".panel[data-panel-id=\"" + id + "\"]");
        if (!panel) return;
        // Append moves the node (it's the same DOM element) — this both
        // pulls it from its current parent and places it in the desired
        // order within the new parent.
        row.appendChild(panel);
      });
    });
  }
  // Exposed so the SSE handler can re-run after each panel-swap render.
  window.plenithApplyArrangement = function () {
    applyArrangement(loadCurrent());
  };

  // ----- Drag and drop ----------------------------------------------------
  var draggingId = null;

  document.addEventListener("dragstart", function (ev) {
    var handle = ev.target.closest("[data-drag-handle]");
    if (!handle) return;
    var panel = handle.closest(".panel[data-panel-id]");
    if (!panel) return;
    draggingId = panel.getAttribute("data-panel-id");
    panel.classList.add("dragging");
    if (ev.dataTransfer) {
      ev.dataTransfer.effectAllowed = "move";
      ev.dataTransfer.setData("text/plain", draggingId);
    }
  });
  document.addEventListener("dragend", function (ev) {
    document.querySelectorAll(".panel.dragging").forEach(function (p) {
      p.classList.remove("dragging");
    });
    document.querySelectorAll(".panel.drop-target").forEach(function (p) {
      p.classList.remove("drop-target");
    });
    draggingId = null;
  });
  document.addEventListener("dragover", function (ev) {
    if (!draggingId) return;
    var target = ev.target.closest(".panel[data-panel-id]");
    if (!target) return;
    if (target.getAttribute("data-panel-id") === draggingId) return;
    ev.preventDefault();
    if (ev.dataTransfer) ev.dataTransfer.dropEffect = "move";
    document.querySelectorAll(".panel.drop-target").forEach(function (p) {
      if (p !== target) p.classList.remove("drop-target");
    });
    target.classList.add("drop-target");
  });
  document.addEventListener("dragleave", function (ev) {
    var target = ev.target.closest(".panel.drop-target");
    if (!target) return;
    // Only drop the indicator if we've actually left this panel (not just
    // crossed into one of its children).
    if (!target.contains(ev.relatedTarget)) target.classList.remove("drop-target");
  });
  document.addEventListener("drop", function (ev) {
    if (!draggingId) return;
    var target = ev.target.closest(".panel[data-panel-id]");
    if (!target) return;
    var targetId = target.getAttribute("data-panel-id");
    if (targetId === draggingId) return;
    ev.preventDefault();
    _swapPanels(draggingId, targetId);
    target.classList.remove("drop-target");
  });

  // Shared swap helper — used by both drag-and-drop AND the keyboard
  // picker below.  Same-row reorder and cross-row swap both work
  // because we just move two DOM nodes around their respective parents.
  function _swapPanels(srcId, dstId) {
    if (!srcId || !dstId || srcId === dstId) return;
    var dragged = document.querySelector(
      ".panel[data-panel-id=\"" + srcId + "\"]");
    var target = document.querySelector(
      ".panel[data-panel-id=\"" + dstId + "\"]");
    if (!dragged || !target) return;
    var draggedParent = dragged.parentNode;
    var draggedNext   = dragged.nextSibling;
    var targetParent  = target.parentNode;
    var targetNext    = target.nextSibling;
    targetParent.insertBefore(dragged,
      targetNext === dragged ? targetNext.nextSibling : targetNext);
    draggedParent.insertBefore(target,
      draggedNext === target ? draggedNext.nextSibling : draggedNext);
    saveCurrent(captureArrangement());
  }
  window.plenithSwapPanels = _swapPanels;

  // ----- Keyboard rearrange picker --------------------------------------
  // Drag-and-drop is mouse/touch only.  Keyboard users press Enter or
  // Space on a panel-header's ⋮⋮ handle to open a small picker listing
  // the other panel slots; arrow keys + Enter pick a destination.
  function _humanLabelFor(panel) {
    // .panel-header has the drag handle as its first child span, then
    // the title span.  Skip the drag handle when fishing for the label.
    var hdr = panel.querySelector(".panel-header > span:not(.drag-handle)");
    return hdr ? hdr.textContent.trim() : panel.getAttribute("data-panel-id");
  }
  function _openMovePicker(srcHandle) {
    var srcPanel = srcHandle.closest(".panel[data-panel-id]");
    if (!srcPanel) return;
    var srcId = srcPanel.getAttribute("data-panel-id");
    // Close any existing picker first.
    _closeMovePicker();
    var menu = document.createElement("div");
    menu.className = "move-picker";
    menu.setAttribute("role", "menu");
    menu.setAttribute("aria-label", "Move panel — pick a destination");
    var srcLabel = _humanLabelFor(srcPanel);
    var header = document.createElement("div");
    header.className = "move-picker-head";
    header.textContent = "Swap “" + srcLabel + "” with:";
    menu.appendChild(header);
    var others = Array.from(
      document.querySelectorAll(".panel[data-panel-id]")
    ).filter(function (p) {
      return p.getAttribute("data-panel-id") !== srcId;
    });
    others.forEach(function (p, idx) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "move-picker-item";
      btn.setAttribute("role", "menuitem");
      btn.setAttribute("data-move-dest", p.getAttribute("data-panel-id"));
      btn.textContent = _humanLabelFor(p);
      menu.appendChild(btn);
    });
    var hint = document.createElement("div");
    hint.className = "move-picker-hint";
    hint.textContent = "↑↓ to navigate · Enter to swap · Esc to cancel";
    menu.appendChild(hint);
    document.body.appendChild(menu);
    // Position the menu near the source handle
    var rect = srcHandle.getBoundingClientRect();
    menu.style.left = Math.max(8, rect.left) + "px";
    menu.style.top  = (rect.bottom + 6) + "px";
    menu._srcId = srcId;
    menu._srcHandle = srcHandle;
    // Focus the first item
    var first = menu.querySelector("[data-move-dest]");
    if (first) first.focus();
  }
  function _closeMovePicker(restoreFocus) {
    var menu = document.querySelector(".move-picker");
    if (!menu) return;
    var handle = menu._srcHandle;
    menu.parentNode.removeChild(menu);
    if (restoreFocus && handle) handle.focus();
  }

  document.addEventListener("keydown", function (ev) {
    // ev.target may be Document (synthetic events) which lacks closest;
    // guard so we don't throw before the picker-keys logic below.
    var hasClosest = ev.target && typeof ev.target.closest === "function";
    var handle = hasClosest ? ev.target.closest("[data-drag-handle]") : null;
    // Open the picker when Enter/Space is pressed while a drag handle
    // has focus.  preventDefault stops Space from scrolling the page.
    if (handle && !document.querySelector(".move-picker") &&
        (ev.key === "Enter" || ev.key === " " || ev.code === "Space")) {
      ev.preventDefault();
      _openMovePicker(handle);
      return;
    }
    // While the picker is open: arrow keys cycle items, Enter swaps,
    // Esc cancels.
    var menu = document.querySelector(".move-picker");
    if (!menu) return;
    var items = Array.from(menu.querySelectorAll("[data-move-dest]"));
    var current = items.indexOf(document.activeElement);
    if (ev.key === "Escape") {
      ev.preventDefault();
      _closeMovePicker(true);
      return;
    }
    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      if (items.length) items[(current + 1) % items.length].focus();
      return;
    }
    if (ev.key === "ArrowUp") {
      ev.preventDefault();
      if (items.length) items[(current - 1 + items.length) % items.length].focus();
      return;
    }
    if (ev.key === "Enter" || ev.key === " " || ev.code === "Space") {
      if (current < 0) return;
      ev.preventDefault();
      var dst = items[current].getAttribute("data-move-dest");
      _swapPanels(menu._srcId, dst);
      _closeMovePicker(true);
    }
  });
  // Click on a picker item activates it (mouse user opens picker via
  // keyboard, then clicks the destination).
  document.addEventListener("click", function (ev) {
    var item = ev.target.closest(".move-picker [data-move-dest]");
    if (item) {
      ev.preventDefault();
      ev.stopPropagation();
      var menu = item.closest(".move-picker");
      _swapPanels(menu._srcId, item.getAttribute("data-move-dest"));
      _closeMovePicker(true);
      return;
    }
    // Click outside the picker closes it without swapping.
    if (document.querySelector(".move-picker") &&
        !ev.target.closest(".move-picker") &&
        !ev.target.closest("[data-drag-handle]")) {
      _closeMovePicker(false);
    }
  });

  // ----- Layout dropdown — save / restore / delete named arrangements ----
  function renderMenu(menu) {
    var store = loadStore();
    var names = Object.keys(store).sort();
    var html = '<div class="head">Saved arrangements</div>';
    if (names.length === 0) {
      html += '<div class="layout-item" style="color: var(--fg-4);">'
            + 'Drag panels to rearrange, then save</div>';
    } else {
      names.forEach(function (n) {
        html += '<div class="layout-item" data-restore="' + n + '">'
              + '<span>' + n + '</span>'
              + '<span class="del" data-del="' + n + '" '
              +       'title="Delete arrangement">×</span>'
              + '</div>';
      });
    }
    if (loadCurrent()) {
      html += '<div class="layout-item" data-reset '
            +       'style="color: var(--fg-3); font-style: italic;">'
            + '<span>↺ Reset to default</span></div>';
    }
    html += '<div class="layout-save-row">'
          + '<input type="text" id="layout-save-input" name="layout-save"'
          + ' autocomplete="off" placeholder="save current as…"'
          + ' data-layout-input>'
          + '<button data-layout-save>Save</button>'
          + '</div>';
    menu.innerHTML = html;

    menu.querySelectorAll("[data-restore]").forEach(function (el) {
      el.addEventListener("click", function (ev) {
        if (ev.target.matches("[data-del]")) return;
        var n = el.getAttribute("data-restore");
        var s = loadStore();
        if (!s[n]) return;
        applyArrangement(s[n]);
        saveCurrent(s[n]);
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
    var resetEl = menu.querySelector("[data-reset]");
    if (resetEl) {
      resetEl.addEventListener("click", function () {
        saveCurrent(null);
        // Default arrangement = page-load DOM order.  Easiest way to
        // get back to it without round-tripping the server is a full
        // reload.
        window.location.reload();
      });
    }
    var saveBtn = menu.querySelector("[data-layout-save]");
    var input = menu.querySelector("[data-layout-input]");
    if (saveBtn && input) {
      saveBtn.addEventListener("click", function () {
        var name = (input.value || "").trim();
        if (!name) return;
        var s = loadStore();
        s[name] = captureArrangement();
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
      // Clicks INSIDE the menu (e.g. on the rename input or Save button)
      // bubble up through here too — don't toggle the menu in that case.
      // Just stopPropagation so the outside-click handler doesn't close
      // the menu either, and let inner handlers run.
      if (menu.contains(ev.target) && ev.target !== menu) {
        ev.stopPropagation();
        return;
      }
      ev.stopPropagation();
      var open = menu.classList.toggle("open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      if (open) {
        renderMenu(menu);
        // Auto-focus the rename input so the operator can type
        // immediately without a second click.
        var input = menu.querySelector("[data-layout-input]");
        if (input) setTimeout(function () { input.focus(); }, 0);
      }
    });
    // Submit-on-Enter convenience; Escape closes the menu.
    menu.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") {
        ev.preventDefault();
        menu.classList.remove("open");
        btn.setAttribute("aria-expanded", "false");
        btn.focus();
        return;
      }
      if (ev.key !== "Enter") return;
      var input = ev.target.closest("[data-layout-input]");
      if (!input) return;
      ev.preventDefault();
      var saveBtn = menu.querySelector("[data-layout-save]");
      if (saveBtn) saveBtn.click();
    });
    document.addEventListener("click", function () {
      if (menu.classList.contains("open")) {
        menu.classList.remove("open");
        btn.setAttribute("aria-expanded", "false");
      }
    });
  });
})();

// ===========================================================================
// POP-OUT CLICKS — open the right /panel/<name> URL in a fresh window.
// Event-delegated so re-renders (SSE swaps #panels every tick) don't
// strip the handler off the new icon nodes.
// ===========================================================================
(function () {
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-popout]");
    if (!btn) return;
    ev.stopPropagation();
    var target = btn.getAttribute("data-popout");
    var features = "popup=yes,width=1280,height=820";
    window.open("/panel/" + target, "plenith-" + target, features);
  });
})();

// ===========================================================================
// ENGAGEMENT FILTER + MULTI-SELECT — both have to survive SSE re-renders.
// State lives in module-level closures + the input's *value* is reflected
// in a sessionStorage key so re-renders restore what the operator typed.
// `window.plenithReapplyClientState()` is called after every SSE update
// to put the value back, apply the filter, and restore checked rows.
// ===========================================================================
(function () {
  // Persistent state across SSE re-renders
  var STORE_QUERY    = "plenith-filter-query";
  var STORE_CHIP     = "plenith-filter-chip";     // severity: "all" | "critical" | "llm"
  var STORE_TIME     = "plenith-filter-time";     // time:     "any" | "active" | "1h" | "today" | "week" | "older"
  var STORE_SELECTED = "plenith-multi-select";

  function loadSelected() {
    try {
      var s = JSON.parse(sessionStorage.getItem(STORE_SELECTED) || "[]");
      return new Set(Array.isArray(s) ? s : []);
    } catch (e) { return new Set(); }
  }
  function saveSelected(s) {
    sessionStorage.setItem(STORE_SELECTED, JSON.stringify(Array.from(s)));
  }

  function currentQuery() {
    return sessionStorage.getItem(STORE_QUERY) || "";
  }
  function setQuery(q) {
    sessionStorage.setItem(STORE_QUERY, q || "");
  }
  function currentChip() {
    return sessionStorage.getItem(STORE_CHIP) || "all";
  }
  function setChip(c) {
    sessionStorage.setItem(STORE_CHIP, c || "all");
  }
  function currentTime() {
    var v = sessionStorage.getItem(STORE_TIME);
    return ["any", "active", "1h", "today", "week", "older"].indexOf(v) >= 0 ? v : "any";
  }
  function setTime(t) { sessionStorage.setItem(STORE_TIME, t || "any"); }

  function chipMatches(row, chip) {
    if (chip === "all") return true;
    if (chip === "critical") return row.getAttribute("data-eng-crit") === "1";
    if (chip === "llm")      return row.getAttribute("data-eng-llm")  === "1";
    // Back-compat: a stored "last-1h" from a previous session should
    // still work — treat it as the new "1h" time bucket.
    if (chip === "last-1h") {
      var ts = parseInt(row.getAttribute("data-eng-last") || "0", 10);
      if (!ts) return false;
      return (Date.now() / 1000 - ts) <= 3600;
    }
    return true;
  }
  function timeMatches(row, bucket) {
    if (bucket === "any") return true;
    var ts = parseInt(row.getAttribute("data-eng-last") || "0", 10);
    if (!ts) return bucket === "older";
    var ageS = Date.now() / 1000 - ts;
    switch (bucket) {
      case "active": return ageS <= 300;          // 5 min
      case "1h":     return ageS <= 3600;
      case "today":  return ageS <= 86400;
      case "week":   return ageS <= 604800;
      case "older":  return ageS  > 604800;
      default:       return true;
    }
  }

  function applyFilter() {
    var q = currentQuery().toLowerCase().trim();
    var chip = currentChip();
    var time = currentTime();
    var total = 0, visible = 0;
    document.querySelectorAll("[data-eng-row]").forEach(function (row) {
      total += 1;
      var hay = (row.getAttribute("data-eng-hay") || "").toLowerCase();
      var hitText = !q || hay.indexOf(q) !== -1;
      var hitChip = chipMatches(row, chip);
      var hitTime = timeMatches(row, time);
      var hit = hitText && hitChip && hitTime;
      row.style.display = hit ? "" : "none";
      if (hit) visible += 1;
    });
    // Reflect the active chip in the chip strip — only one chip is
    // active at a time; SSE swaps re-render the chips so we have to
    // re-apply the class every render.
    document.querySelectorAll("[data-filter-chip]").forEach(function (c) {
      var isActive = c.getAttribute("data-filter-chip") === chip;
      c.classList.toggle("active", isActive);
      c.setAttribute("aria-pressed", isActive ? "true" : "false");
    });
    document.querySelectorAll("[data-filter-time]").forEach(function (c) {
      var isActive = c.getAttribute("data-filter-time") === time;
      c.classList.toggle("active", isActive);
      c.setAttribute("aria-pressed", isActive ? "true" : "false");
    });
    // Surface the match count on the panel header so it's obvious the
    // filter is working (otherwise with one matching row vs one total
    // you can't tell whether anything happened).
    var counter = document.querySelector("[data-filter-count]");
    if (counter) {
      var filtering = q || chip !== "all" || time !== "any";
      counter.textContent = filtering
        ? "filter: " + visible + " of " + total
        : total + " total";
    }
    var search = document.querySelector("[data-eng-search]");
    if (search && search.value !== currentQuery() &&
        document.activeElement !== search) {
      // Only restore the value when the search isn't focused — otherwise
      // we'd overwrite mid-keystroke (this happens in the SSE re-apply
      // path; the live input event handler handles the typing case).
      search.value = currentQuery();
    }
  }

  function applyMultiselect() {
    var selected = loadSelected();
    document.querySelectorAll("[data-eng-check]").forEach(function (cb) {
      var id = cb.getAttribute("data-eng-check");
      if (selected.has(id)) {
        cb.classList.add("on");
        cb.textContent = "✓";
      } else {
        cb.classList.remove("on");
        cb.textContent = "";
      }
    });
    document.querySelectorAll("[data-batch-bar]").forEach(function (bar) {
      bar.style.display = selected.size > 0 ? "" : "none";
      bar.querySelectorAll("[data-batch-count]").forEach(function (el) {
        el.textContent = String(selected.size);
      });
    });
  }

  // Exposed so the SSE handler can re-run these after each swap
  window.plenithReapplyClientState = function () {
    // Order matters: arrangement (DOM re-order) BEFORE selection (which
    // refetches detail.html if needed) and filter (which iterates rows).
    if (window.plenithApplyArrangement)
      window.plenithApplyArrangement();
    applyFilter();
    applyMultiselect();
    if (window.plenithApplyEngagementSelection)
      window.plenithApplyEngagementSelection();
    if (window.plenithApplyConfidenceTrend)
      window.plenithApplyConfidenceTrend();
  };

  // Filter input — event-delegated since #panels is re-rendered.
  document.addEventListener("input", function (ev) {
    var search = ev.target.closest("[data-eng-search]");
    if (!search) return;
    setQuery(search.value || "");
    applyFilter();
  });

  // Filter chips — single-select; clicking the already-active chip
  // resets to "all" (cheap toggle-off without a separate clear button).
  document.addEventListener("click", function (ev) {
    var chip = ev.target.closest("[data-filter-chip]");
    if (!chip) return;
    ev.stopPropagation();
    var name = chip.getAttribute("data-filter-chip") || "all";
    if (currentChip() === name && name !== "all") name = "all";
    setChip(name);
    applyFilter();
  });

  // Time-bucket chips — same single-select behavior; clicking the
  // active chip resets to "any" (the no-time-filter default).
  document.addEventListener("click", function (ev) {
    var chip = ev.target.closest("[data-filter-time]");
    if (!chip) return;
    ev.stopPropagation();
    var name = chip.getAttribute("data-filter-time") || "any";
    if (currentTime() === name && name !== "any") name = "any";
    setTime(name);
    applyFilter();
  });

  // Multi-select checkbox clicks
  document.addEventListener("click", function (ev) {
    var cb = ev.target.closest("[data-eng-check]");
    if (!cb) return;
    ev.stopPropagation();
    var id = cb.getAttribute("data-eng-check");
    var selected = loadSelected();
    if (selected.has(id)) selected.delete(id); else selected.add(id);
    saveSelected(selected);
    applyMultiselect();
  });

  // `/` keyboard shortcut to focus the search box
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "/" && ev.target.tagName !== "INPUT" && ev.target.tagName !== "TEXTAREA") {
      var search = document.querySelector("[data-eng-search]");
      if (search) { ev.preventDefault(); search.focus(); }
    }
  });

  // First-page-load: apply any persisted state
  document.addEventListener("DOMContentLoaded", function () {
    window.plenithReapplyClientState();
  });
  // And immediately for synchronous-load case
  if (document.readyState !== "loading") {
    setTimeout(function () { window.plenithReapplyClientState(); }, 0);
  }

  // -----------------------------------------------------------------------
  // ENGAGEMENT ROW CLICK → swap the detail panel.  Selection is persisted
  // in sessionStorage and re-applied after every SSE swap (the server-side
  // renderer always picks engs[0] as selected, so without this the panel
  // would flick back to the first engagement every 3s).
  //
  // The detail.html response includes a <template data-export-strip> at
  // the top — we use it to also replace the audit/IoC/sigma/etc. anchors
  // in the panel header so they point at the newly-selected engagement
  // instead of staying on engs[0].
  // -----------------------------------------------------------------------

  var STORE_SELECTED_EID = "plenith-selected-eid";
  var pendingFetchSeq = 0;

  function getSelectedEid() {
    return sessionStorage.getItem(STORE_SELECTED_EID) || "";
  }
  function setSelectedEid(eid) {
    if (eid) sessionStorage.setItem(STORE_SELECTED_EID, eid);
    else sessionStorage.removeItem(STORE_SELECTED_EID);
    // Tell the SSE IIFE to reopen its EventSource with the new
    // `?selected=` query param so the server-rendered detail panel
    // matches our pick on the next tick (no more flip-flop).
    document.dispatchEvent(new CustomEvent("plenith:selection-changed",
                                            { detail: { eid: eid } }));
  }

  function findDetailPanel() {
    var p = document.querySelector("[data-detail-panel]");
    if (p) return p;
    // Fallback for older renders / panels without the tag
    var found = null;
    document.querySelectorAll(".main .panel").forEach(function (pp) {
      if (pp.querySelector(".detail-header")) found = pp;
    });
    if (found) return found;
    var panels = document.querySelectorAll(".main > .panel");
    return panels.length >= 2 ? panels[1] : null;
  }

  async function loadDetail(detailPanel, eid) {
    if (!detailPanel || !eid) return;
    var seq = ++pendingFetchSeq;
    var url = "/api/engagements/" + encodeURIComponent(eid) + "/detail.html";
    var resp, htmlText;
    try {
      resp = await fetch(url, { headers: { "Accept": "text/html" } });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      htmlText = await resp.text();
    } catch (e) {
      console.warn("Failed to load engagement detail:", e);
      return;
    }
    // Discard stale responses (newer click already in flight)
    if (seq !== pendingFetchSeq) return;
    // The latest detail panel might be a different DOM node after an
    // intervening SSE swap — re-resolve.
    var panel = findDetailPanel();
    if (!panel) return;

    var wrapper = document.createElement("div");
    wrapper.innerHTML = htmlText;
    // Pluck out the export-strip template (if present) and use it to
    // replace the existing audit/IoC/sigma anchors in the panel header.
    var stripTpl = wrapper.querySelector("template[data-export-strip]");
    if (stripTpl) {
      var host = panel.querySelector("[data-export-host]");
      if (host) {
        // Remove only the export anchors; preserve the popout icon.
        host.querySelectorAll("a.filter").forEach(function (a) { a.remove(); });
        var popBtn = host.querySelector("[data-popout]");
        var frag = stripTpl.content.cloneNode(true);
        if (popBtn) host.insertBefore(frag, popBtn);
        else host.appendChild(frag);
      }
      stripTpl.remove();
    }
    // Swap body — keep the panel-header in place, replace everything
    // below it with the fresh content.
    var header = panel.querySelector(".panel-header");
    panel.innerHTML = "";
    if (header) panel.appendChild(header);
    while (wrapper.firstChild) panel.appendChild(wrapper.firstChild);
    panel.setAttribute("data-current-eid", eid);

    // Update the popout target so ↗ opens the right engagement.
    var popBtn2 = panel.querySelector(".panel-header [data-popout]");
    if (popBtn2) popBtn2.setAttribute("data-popout", "engagement/" + eid);
  }

  function applyEngagementSelection() {
    var eid = getSelectedEid();
    if (!eid) return;
    // Mark the matching row (if visible after filter/render)
    var matched = false;
    document.querySelectorAll("[data-eng-row]").forEach(function (r) {
      var rid = r.getAttribute("data-eng-id");
      var hit = rid === eid;
      r.classList.toggle("selected", hit);
      if (hit) matched = true;
    });
    if (!matched) return;
    var panel = findDetailPanel();
    if (!panel) return;
    if (panel.getAttribute("data-current-eid") === eid) return;
    loadDetail(panel, eid);
  }
  window.plenithApplyEngagementSelection = applyEngagementSelection;

  document.addEventListener("click", function (ev) {
    if (ev.target.closest("[data-eng-check], [data-popout], .filter, .ack-btn, button, a, input, textarea")) {
      return;
    }
    var row = ev.target.closest("[data-eng-row]");
    if (!row) return;
    var eid = row.getAttribute("data-eng-id");
    if (!eid) return;
    setSelectedEid(eid);
    document.querySelectorAll("[data-eng-row]").forEach(function (r) {
      r.classList.toggle("selected", r === row);
    });
    var panel = findDetailPanel();
    if (panel) loadDetail(panel, eid);
  });
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
  var panelFilter = holder.getAttribute("data-panel-filter") || "";
  function buildUrl() {
    var params = [];
    if (panelFilter) {
      params.push("panel=" + encodeURIComponent(panelFilter));
    }
    // Main dashboard only: pin the operator's chosen engagement so the
    // server-rendered detail panel matches their pick — eliminates the
    // visible flip between engagements when the list reorders mid-tick.
    if (!panelFilter) {
      var sel = sessionStorage.getItem("plenith-selected-eid") || "";
      if (sel) params.push("selected=" + encodeURIComponent(sel));
    }
    return "/api/stream" + (params.length ? "?" + params.join("&") : "");
  }
  var es = new EventSource(buildUrl());
  // Reopen the EventSource whenever the selected engagement changes
  // so the server-side render switches in lockstep with the click.
  // Use a custom event the row-click handler dispatches; cross-tab
  // changes via localStorage `storage` event are also caught.
  function reopenStream() {
    try { es.close(); } catch (_) {}
    es = new EventSource(buildUrl());
    bindEs();
  }
  document.addEventListener("plenith:selection-changed", reopenStream);
  window.addEventListener("storage", function (ev) {
    if (ev.key === "plenith-selected-eid") reopenStream();
  });
  var ts = document.getElementById("ts");
  var dropouts = 0;
  // Skip the panel swap while the operator is actively focused on ANY
  // interactive element inside #panels.  The swap replaces every child
  // node — including the element being typed into OR tabbed through —
  // which is the bug that made the search box / notes textarea
  // un-typeable, AND broke keyboard tab-chain navigation across the
  // action buttons (the focused button disappears between renders, so
  // the user can never reach Kill).  New alerts and the critical-count
  // badge still update from the same SSE payload; only the in-panel
  // HTML render is paused until focus leaves.
  function shouldSkipSwap() {
    var active = document.activeElement;
    if (!active || active === document.body) return false;
    if (!holder.contains(active)) return false;
    var tag = active.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
    if (tag === "BUTTON" || tag === "A") return true;
    if (active.isContentEditable) return true;
    if (active.hasAttribute("tabindex") &&
        active.getAttribute("tabindex") !== "-1") return true;
    return false;
  }

  // Cheap content fingerprint so we can skip a swap when the server-
  // rendered HTML is byte-identical to what we already have.  Strips
  // the "last refresh HH:MM:SS" timestamp first because it changes every
  // tick even when nothing else did.
  var lastHtmlHash = 0;
  function fp(s) {
    s = String(s).replace(/last refresh <span id="ts">[^<]*<\/span>/g, "");
    // djb2-ish hash, plenty for change-detection
    var h = 5381;
    for (var i = 0; i < s.length; i++) {
      h = ((h << 5) + h + s.charCodeAt(i)) | 0;
    }
    return h;
  }

  // Old behavior: blow away all of #panels every tick. The full
  // destroy/recreate of the (growing) command-timeline subtree is what
  // snapped the page scroll down to the command section as commands
  // streamed in — even in TV mode. Kept as the fallback path.
  function blanketSwap(html) {
    holder.innerHTML = html;
    if (window.plenithReapplyClientState)
      window.plenithReapplyClientState();
  }

  // Targeted patch: when the same engagement is still selected, keep
  // the LIVE command-timeline node and only prepend the rows that are
  // new (keyed by data-cmd-ts; newest-first). The timeline node is
  // moved — never destroyed — so the browser keeps its scroll anchor
  // and the page no longer jumps. Everything else in #panels is small
  // / fixed-height. A scroll ANCHOR (pin a surviving timeline row to
  // its exact viewport offset) zeroes any residual drift from those
  // subtrees changing height above the fold.
  function morphSwap(html) {
    var tmp = document.createElement("div");
    tmp.innerHTML = html;

    // Capture a scroll anchor BEFORE mutating: the topmost timeline row
    // that is ACTUALLY IN THE VIEWPORT — i.e. the row the operator is
    // reading. It survives the morph (existing rows are never
    // destroyed), so afterward we pin it back to the same viewport
    // offset. Critical: a row merely having bottom > 0 also matches
    // rows far BELOW the fold; anchoring to one of those while the
    // operator is at the top (reading the list/filter, timeline
    // off-screen) makes every prepend push the page DOWN a notch,
    // dragging them to the timeline a tick at a time. So require the
    // row to intersect the viewport (top < innerHeight). If none does,
    // anchorEl stays null and we just hold the exact scroll position.
    var anchorEl = null, anchorTop = 0;
    var preTl = holder.querySelector("[data-cmd-timeline]");
    if (preTl) {
      var prs = preTl.querySelectorAll("[data-cmd-ts]");
      var vh = window.innerHeight;
      for (var ai = 0; ai < prs.length; ai++) {
        var rc = prs[ai].getBoundingClientRect();
        if (rc.bottom > 0 && rc.top < vh) {
          anchorEl = prs[ai]; anchorTop = rc.top; break;
        }
      }
    }

    var liveDetail = holder.querySelector("[data-detail-panel]");
    var newDetail  = tmp.querySelector("[data-detail-panel]");
    if (liveDetail && newDetail) {
      var eidA = liveDetail.getAttribute("data-current-eid") || "";
      var eidB = newDetail.getAttribute("data-current-eid") || "";
      if (eidA && eidA === eidB) {
        var liveTl = liveDetail.querySelector("[data-cmd-timeline]");
        var newTl  = newDetail.querySelector("[data-cmd-timeline]");
        if (liveTl && newTl) {
          var seen = {};
          var lr = liveTl.querySelectorAll("[data-cmd-ts]");
          for (var i = 0; i < lr.length; i++)
            seen[lr[i].getAttribute("data-cmd-ts")] = 1;
          var inc = newTl.querySelectorAll("[data-cmd-ts]");
          var add = [];
          for (var j = 0; j < inc.length; j++)
            if (!seen[inc[j].getAttribute("data-cmd-ts")]) add.push(inc[j]);
          // Rows render newest-first; prepend in reverse so order holds.
          for (var k = add.length - 1; k >= 0; k--)
            liveTl.insertBefore(add[k].cloneNode(true), liveTl.firstChild);
          // We only ever prepend, so over a long unattended (TV-mode)
          // session the DOM timeline would grow without bound. Trim the
          // oldest (bottom) rows to a sane cap — keeps memory/layout
          // flat for multi-hour displays.
          var keep = 60;
          var allRows = liveTl.querySelectorAll("[data-cmd-ts]");
          for (var t = allRows.length - 1; t >= keep; t--)
            allRows[t].remove();
          // Substitute the preserved (now-patched) live timeline node
          // into the incoming subtree so the wholesale section swap
          // below relocates it instead of recreating it.
          newTl.parentNode.replaceChild(liveTl, newTl);
        }
      }
    }

    // Replace #panels children by NODE MOVE (not innerHTML — that would
    // re-serialize and lose the preserved live timeline node identity).
    var sy = window.scrollY || document.documentElement.scrollTop || 0;
    holder.replaceChildren.apply(
      holder, Array.prototype.slice.call(tmp.childNodes));
    if (anchorEl && anchorEl.isConnected) {
      // Pin the row the operator was reading back to its exact offset.
      window.scrollBy(0, anchorEl.getBoundingClientRect().top - anchorTop);
    } else {
      // No surviving anchor (engagement switched / no timeline) — best
      // effort: clamp the prior scrollY to the new document height.
      var maxY = Math.max(0,
        document.documentElement.scrollHeight - window.innerHeight);
      window.scrollTo(0, Math.min(sy, maxY));
    }

    if (window.plenithReapplyClientState)
      window.plenithReapplyClientState();
  }

  function applySwap(html) {
    // Never worse than today: any morph failure falls back to the
    // proven blanket swap (the demo path must not break).
    try { morphSwap(html); }
    catch (e) { blanketSwap(html); }
  }

  // Client-side alert dedup.  The server's per-connection seen-set
  // resets on every reconnect (e.g. when the operator clicks a row and
  // the EventSource is re-opened with ?selected=).  Without a stable
  // client-side set, in-flight alerts arriving right after a reconnect
  // get classified as "historical" by the new connection and silently
  // dropped from the toast/chime path.  We persist the seen keys in
  // sessionStorage (per-tab) so reconnects within the same tab dedup
  // correctly while a fresh page load starts a clean slate.
  var ALERT_KEYS_STORE = "plenith-alert-keys-seen";
  var alertKeysSeen = (function () {
    try {
      var raw = sessionStorage.getItem(ALERT_KEYS_STORE);
      if (!raw) return new Set();
      var arr = JSON.parse(raw);
      return new Set(Array.isArray(arr) ? arr : []);
    } catch (e) { return new Set(); }
  })();
  function persistAlertKeys() {
    try {
      sessionStorage.setItem(ALERT_KEYS_STORE,
                              JSON.stringify(Array.from(alertKeysSeen)));
    } catch (e) { /* storage full or disabled */ }
  }
  function markAndToast(alertObj) {
    // Pre-filter happens in the caller (willToast list build); here
    // we just fire the toast + chime + notification and mark seen.
    // Skipping the .has() check fixes a race where the
    // all_alert_keys absorption added the key first, then markAndToast
    // bailed and the toast never fired.
    if (!alertObj) return;
    alertKeysSeen.add(alertObj.key);
    if (window.plenithPushAlertToast) window.plenithPushAlertToast(alertObj);
    if (window.plenithMaybeNotify)    window.plenithMaybeNotify(alertObj);
  }

  function bindEs() {
    es.onmessage = function (e) {
      try {
        var data = JSON.parse(e.data);
        if (data.html && !shouldSkipSwap()) {
          var h = fp(data.html);
          if (h !== lastHtmlHash) {
            lastHtmlHash = h;
            // No View Transition wrapper: that was a band-aid for the
            // jittery full-#panels innerHTML replace. applySwap now
            // morphs in place (preserved timeline node + scroll
            // restore), which is smooth by construction; wrapping a
            // whole-panel VT around it would re-animate the very layout
            // delta we just eliminated.
            applySwap(data.html);
          }
        }
        if (data.ts && ts) ts.textContent = data.ts;
        dropouts = 0;
        // Build list of unseen alerts FIRST, then toast them, THEN
        // absorb the rest of all_alert_keys.  Order matters: if we
        // absorbed first, markAndToast would find every key already
        // "seen" and bail before chime/toast/notification ever ran.
        var willToast = [];
        if (Array.isArray(data.new_alerts)) {
          data.new_alerts.forEach(function (a) {
            if (a && !alertKeysSeen.has(a.key)) willToast.push(a);
          });
        }
        if (willToast.length) {
          willToast.forEach(markAndToast);
        }
        // Now absorb all currently-known keys so a reconnect doesn't
        // re-toast historical events as if they were new.
        if (Array.isArray(data.all_alert_keys)) {
          data.all_alert_keys.forEach(function (k) {
            alertKeysSeen.add(k);
          });
        }
        if (willToast.length) persistAlertKeys();
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
  }
  bindEs();
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

  // Optimistic DOM updates after an ack/un-ack — the SSE re-render is
  // paused while focus is on the just-clicked button (see shouldSkipSwap),
  // so without this the visible counts wouldn't decrement until the user
  // tabbed away.  Exposed on window so the batch Ack-all handler can
  // call it after each loop iteration too.
  function applyAckStateLocally(eng, action, acked) {
    // 1) Per-alert button state
    var btn = document.querySelector(
      '.ack-btn[data-ack-eng="' + eng + '"][data-ack-action="' + action + '"]');
    if (btn) {
      btn.setAttribute("data-ack-state", acked ? "acked" : "pending");
      btn.textContent = acked ? "Un-ack" : "Acknowledge";
      // Row dim — matches the .alert.acked rendering from the server
      var row = btn.closest(".alert");
      if (row) row.classList.toggle("acked", acked);
    }
    // 2) Acknowledge-all button — recompute pending list from visible
    //    per-alert buttons rather than mutating the cached attribute,
    //    so undo/redo cycles stay consistent.
    var ackAll = document.querySelector(
      '[data-quick-action="ack-all"][data-eng="' + eng + '"]');
    if (ackAll) {
      var pending = [];
      document.querySelectorAll(
        '.ack-btn[data-ack-eng="' + eng + '"][data-ack-state="pending"]'
      ).forEach(function (b) {
        var a = b.getAttribute("data-ack-action");
        if (a) pending.push(a);
      });
      ackAll.setAttribute("data-pending-actions", pending.join(" "));
      var badge = ackAll.querySelector(".dim2");
      var n = pending.length;
      if (badge) badge.textContent = n ? "(" + n + ")" : "";
      if (n === 0) {
        ackAll.setAttribute("disabled", "");
        ackAll.setAttribute("title", "No pending alerts to acknowledge");
      } else {
        ackAll.removeAttribute("disabled");
        ackAll.setAttribute(
          "title",
          "Ack " + n + " pending alert(s) in this engagement");
      }
    }
    // 3) "Alerts (N pending / M)" header counter — see the panel-header
    //    rendering; the pending span carries data-alerts-pending so we
    //    can update it without re-rendering the whole header.
    var pendingHeader = document.querySelector(
      '[data-alerts-pending][data-eng="' + eng + '"]');
    if (pendingHeader) {
      var p = document.querySelectorAll(
        '.ack-btn[data-ack-eng="' + eng + '"][data-ack-state="pending"]'
      ).length;
      pendingHeader.textContent = p;
    }
  }
  window.plenithApplyAckStateLocally = applyAckStateLocally;

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
        applyAckStateLocally(eng, action, false);
        showUndoToast(
          "Un-ack’d " + action + " on " + eng.substring(0, 8),
          function () { return ackAction(eng, action); }
        );
      } else {
        await ackAction(eng, action);
        applyAckStateLocally(eng, action, true);
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

    if (action === "ack-all") {
      ev.preventDefault();
      var raw = btn.getAttribute("data-pending-actions") || "";
      var pending = raw.split(/\s+/).filter(function (s) { return s.length > 0; });
      if (!pending.length) {
        showToast("No pending alerts to acknowledge.");
        return;
      }
      btn.disabled = true;
      var ok = 0, fail = 0, firstErr = "";
      for (var i = 0; i < pending.length; i++) {
        try {
          await postJSON(
            "/api/engagements/" + encodeURIComponent(eng) + "/ack",
            { action_name: pending[i], op_id: getOpId() }
          );
          ok += 1;
          // Optimistic per-alert + counter update on each successful ack,
          // matching the per-button click handler so the visible state
          // doesn't wait for the next SSE re-render.
          if (window.plenithApplyAckStateLocally)
            window.plenithApplyAckStateLocally(eng, pending[i], true);
        } catch (e) {
          fail += 1;
          if (!firstErr) firstErr = pending[i] + ": " + e.message;
        }
      }
      if (fail === 0) {
        showToast("Acked " + ok + " alert(s)");
      } else {
        showToast("Acked " + ok + "/" + (ok + fail) + " — first failure: " + firstErr, 8000);
      }
      btn.disabled = false;
      return;
    }

    if (action === "isolate") {
      ev.preventDefault();
      var ip = btn.getAttribute("data-ip") || "";
      if (!ip) { showToast("Cannot isolate: source IP missing"); return; }
      // No hold-to-confirm but it IS a state mutation — bounce off the
      // browser's native confirm() so a stray click doesn't blackhole
      // the operator's own home IP during a demo.
      if (!confirm("Mark " + ip + " as failed MFA?\n" +
                   "This writes state-docker/mfa/" + ip + ".fail; " +
                   "the orchestrator's routing layer will treat this IP as " +
                   "untrusted on its next decision.")) return;
      btn.disabled = true;
      try {
        var r = await postJSON(
          "/mfa/decisions/" + encodeURIComponent(ip),
          { decision: "fail", reason: "operator isolate from dashboard",
            op_id: getOpId() }
        );
        showToast("Isolated " + ip + " · wrote " +
                  ((r.path || "").split(/[\\/]/).pop() || "decision file"));
      } catch (e) {
        showToast("Isolate failed: " + e.message);
      } finally {
        btn.disabled = false;
      }
      return;
    }

    // Kill: handled by the hold listener below — single clicks are ignored.
  });

  // Hold-to-confirm for Kill buttons.  Mouse / touch / stylus all work
  // via Pointer Events; keyboard support uses Space-and-hold (the SR
  // user can tab to the button, then hold Space for 1 second to fire).
  // Releasing early aborts.

  // Shared hold-trigger: starts the 1s timer, returns an `abort` fn the
  // caller invokes when the user releases or focus leaves.
  function _startKillHold(btn, reason) {
    btn.classList.add("holding");
    var fired = false;
    var holdTimer = setTimeout(async function () {
      fired = true;
      btn.disabled = true;
      var eng = btn.getAttribute("data-eng");
      try {
        await postJSON(
          "/api/engagements/" + encodeURIComponent(eng) + "/kill",
          { op_id: getOpId(), reason: reason }
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
    return function abort() {
      if (fired) return;
      clearTimeout(holdTimer);
      btn.classList.remove("holding");
    };
  }

  document.addEventListener("pointerdown", function (ev) {
    var btn = ev.target.closest('[data-quick-action="kill"]');
    if (!btn || btn.disabled) return;
    if (btn.getAttribute("data-kill-state") === "killed") return;
    if (ev.button !== undefined && ev.button !== 0) return;
    ev.preventDefault();
    var pid = ev.pointerId;
    try { btn.setPointerCapture(pid); } catch (e) {}
    var abort = _startKillHold(btn, "operator click-and-hold");
    function teardown(e) {
      if (e && e.pointerId !== pid) return;
      abort();
      try { btn.releasePointerCapture(pid); } catch (_) {}
      btn.removeEventListener("pointerup",     teardown);
      btn.removeEventListener("pointerleave",  teardown);
      btn.removeEventListener("pointercancel", teardown);
    }
    btn.addEventListener("pointerup",     teardown);
    btn.addEventListener("pointerleave",  teardown);
    btn.addEventListener("pointercancel", teardown);
  });

  // Keyboard equivalent: Space-and-hold for 1 second.  We preventDefault
  // on keydown to suppress the synthetic click that Space normally fires
  // on a <button> when released.  Holding fires the same kill flow as
  // mouse / touch.  Releasing Space or blurring the button aborts.
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== " " && ev.code !== "Space") return;
    var btn = ev.target.closest('[data-quick-action="kill"]');
    if (!btn || btn.disabled) return;
    if (btn.getAttribute("data-kill-state") === "killed") return;
    if (ev.repeat) { ev.preventDefault(); return; }
    if (btn._killHoldAbort) return;  // already holding from previous keydown
    ev.preventDefault();
    btn._killHoldAbort = _startKillHold(btn, "operator key-and-hold");
    function teardown() {
      if (btn._killHoldAbort) btn._killHoldAbort();
      btn._killHoldAbort = null;
      btn.removeEventListener("keyup", teardown);
      btn.removeEventListener("blur",  teardown);
    }
    btn.addEventListener("keyup", function (ke) {
      if (ke.key === " " || ke.code === "Space") teardown();
    });
    btn.addEventListener("blur", teardown);
  });

  // --- Notes markdown toolbar -------------------------------------------
  // Operates on the textarea's current selection and dispatches an
  // `input` event so any other listener (e.g. character counters) sees
  // the change.  All transforms are reversible by re-clicking the same
  // button on a previously-wrapped selection.
  function findNoteTextarea(toolbarEl) {
    var eng = toolbarEl.getAttribute("data-note-toolbar");
    if (!eng) return null;
    return document.querySelector('[data-note-input="' + eng + '"]');
  }
  function applyInlineWrap(ta, marker) {
    var s = ta.selectionStart, e = ta.selectionEnd, v = ta.value;
    var sel = v.slice(s, e);
    var inside = v.slice(s - marker.length, s) === marker &&
                 v.slice(e, e + marker.length) === marker;
    if (inside) {
      // Strip surrounding markers
      ta.value = v.slice(0, s - marker.length) + sel + v.slice(e + marker.length);
      ta.selectionStart = s - marker.length;
      ta.selectionEnd   = e - marker.length;
    } else if (sel) {
      ta.value = v.slice(0, s) + marker + sel + marker + v.slice(e);
      ta.selectionStart = s + marker.length;
      ta.selectionEnd   = e + marker.length;
    } else {
      // No selection: insert paired markers and place cursor between
      ta.value = v.slice(0, s) + marker + marker + v.slice(e);
      ta.selectionStart = ta.selectionEnd = s + marker.length;
    }
  }
  function applyLinePrefix(ta, prefix) {
    var s = ta.selectionStart, e = ta.selectionEnd, v = ta.value;
    // Expand selection to whole lines so the prefix toggle is per-line.
    var lineStart = v.lastIndexOf("\n", s - 1) + 1;
    var lineEnd = v.indexOf("\n", e);
    if (lineEnd === -1) lineEnd = v.length;
    var block = v.slice(lineStart, lineEnd);
    // Toggle: if every line already has the prefix, strip it. Else add.
    var lines = block.split("\n");
    var all = lines.every(function (l) { return l.indexOf(prefix) === 0; });
    var transformed = lines.map(function (l) {
      return all ? l.slice(prefix.length) : prefix + l;
    }).join("\n");
    ta.value = v.slice(0, lineStart) + transformed + v.slice(lineEnd);
    ta.selectionStart = lineStart;
    ta.selectionEnd   = lineStart + transformed.length;
  }
  function runMd(kind, ta) {
    if (kind === "bold")   applyInlineWrap(ta, "**");
    else if (kind === "italic") applyInlineWrap(ta, "*");
    else if (kind === "code")   applyInlineWrap(ta, "`");
    else if (kind === "list")   applyLinePrefix(ta, "- ");
    else if (kind === "quote")  applyLinePrefix(ta, "> ");
    ta.dispatchEvent(new Event("input", { bubbles: true }));
    ta.focus();
  }
  document.addEventListener("click", function (ev) {
    var tb = ev.target.closest("[data-md]");
    if (!tb) return;
    var toolbar = tb.closest("[data-note-toolbar]");
    if (!toolbar) return;
    ev.preventDefault();
    var ta = findNoteTextarea(toolbar);
    if (!ta) return;
    runMd(tb.getAttribute("data-md"), ta);
  });
  // Keyboard shortcuts inside the textarea
  document.addEventListener("keydown", function (ev) {
    var ta = ev.target.closest("[data-note-input]");
    if (!ta) return;
    if (!(ev.ctrlKey || ev.metaKey)) return;
    var kind = null;
    if (ev.key === "b" || ev.key === "B") kind = "bold";
    else if (ev.key === "i" || ev.key === "I") kind = "italic";
    else if (ev.key === "e" || ev.key === "E") kind = "code";
    if (!kind) return;
    ev.preventDefault();
    runMd(kind, ta);
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

  // --- Batch action bar -------------------------------------------------
  // Snapshot / Escalate over the multi-select set.  We loop client-side
  // (one POST per engagement) because the server only batches /ack today;
  // adding /batch/snapshot etc. server-side would need orchestration
  // (rate-limit, concurrency cap) we don't want to litigate yet.
  function loadSelectedSet() {
    try {
      var s = JSON.parse(sessionStorage.getItem("plenith-multi-select") || "[]");
      return Array.isArray(s) ? s : [];
    } catch (e) { return []; }
  }
  function clearSelectedSet() {
    sessionStorage.setItem("plenith-multi-select", "[]");
    if (window.plenithReapplyClientState) window.plenithReapplyClientState();
  }
  async function batchPost(verb, body) {
    var ids = loadSelectedSet();
    if (!ids.length) return;
    var ok = 0, fail = 0;
    var failReasons = [];
    for (var i = 0; i < ids.length; i++) {
      try {
        await postJSON(
          "/api/engagements/" + encodeURIComponent(ids[i]) + "/" + verb,
          Object.assign({ op_id: getOpId() }, body || {})
        );
        ok += 1;
      } catch (e) {
        fail += 1;
        failReasons.push(ids[i].slice(0, 8) + ": " + e.message);
      }
    }
    if (fail === 0) {
      showToast(verb + " · " + ok + " of " + ids.length + " succeeded");
    } else {
      showToast(verb + " · " + ok + "/" + ids.length + " ok, " +
                fail + " failed (" + failReasons[0] + (fail > 1 ? ", …" : "") + ")",
                8000);
    }
  }

  document.addEventListener("click", async function (ev) {
    var btn = ev.target.closest("[data-batch-action]");
    if (!btn) return;
    ev.preventDefault();
    var action = btn.getAttribute("data-batch-action");
    if (action === "clear") { clearSelectedSet(); return; }
    var ids = loadSelectedSet();
    if (!ids.length) return;
    btn.disabled = true;
    try {
      if (action === "snapshot") {
        await batchPost("snapshot", {});
      } else if (action === "escalate") {
        await batchPost("escalate", { tier: "L2" });
      } else {
        showToast("Unknown batch action: " + action);
      }
    } finally {
      btn.disabled = false;
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
  // Brand-mark favicon — unified Plenith "Trap-Bracket" D mark (brand
  // green tile, cream glyph), matching the website favicon exactly so
  // product + site share one identity.  Two variants (normal + a red
  // critical-count pip) encoded inline so no static asset is needed.
  var FAV_GLYPH =
    '<g fill="none" stroke="#f5f2ec" stroke-width="2.75" ' +
       'stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M12.5 7.5 H7.5 V24.5 H12.5"/>' +
    '<path d="M19.5 7.5 H24.5 V24.5 H19.5"/>' +
    '</g>' +
    '<circle cx="16" cy="16" r="2.75" fill="#f5f2ec"/>';
  var FAV_NORMAL =
    "data:image/svg+xml;utf8," + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
    '<rect width="32" height="32" rx="6" fill="#2c4d3f"/>' +
    FAV_GLYPH +
    '</svg>');
  var FAV_ALERT =
    "data:image/svg+xml;utf8," + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
    '<rect width="32" height="32" rx="6" fill="#2c4d3f"/>' +
    FAV_GLYPH +
    '<circle cx="24" cy="8" r="7" fill="#ef4444" ' +
            'stroke="#2c4d3f" stroke-width="1.5"/>' +
    '</svg>');
  var link = ensureFavicon();
  link.href = FAV_NORMAL;

  document.addEventListener("plenith:critical-count", function (e) {
    var n = (e && e.detail && e.detail.count) || 0;
    document.title = (n > 0 ? "(" + n + " CRIT) " : "") + baseTitle;
    link.href = (n > 0) ? FAV_ALERT : FAV_NORMAL;
    // Topbar Notify badge — lives outside #panels so SSE swaps never
    // touch it.  Drive its text + visibility from the same event.
    document.querySelectorAll("[data-notify-badge]").forEach(function (b) {
      b.textContent = String(n);
      if (n > 0) b.removeAttribute("hidden");
      else b.setAttribute("hidden", "");
    });
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
      // Default to polite for the stack; per-toast severity can override
      // by setting aria-live="assertive" on the individual toast element.
      stack.setAttribute("role", "log");
      stack.setAttribute("aria-live", "polite");
      stack.setAttribute("aria-atomic", "false");
      stack.setAttribute("aria-label", "Plenith alerts and notifications");
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
  // Web Audio API chime — severity-keyed pitches so the operator hears
  // critical alerts differently from medium ones.  Gated by the same
  // localStorage flag the Notify button toggles (off by default to
  // avoid surprising the operator on first visit).
  //
  // Browsers gate AudioContext behind a user gesture, and the context
  // starts in "suspended" state until that gesture resumes it.  We do
  // two things to make chimes reliable:
  //   1. ALWAYS wait for resume() to complete before scheduling the
  //      first beep, so the first chime isn't silently dropped because
  //      the schedule landed in the past.
  //   2. Bind a one-shot page-wide gesture listener that resumes the
  //      context when localStorage says audio is enabled but the
  //      context got suspended again (e.g. after a page reload).
  var _audioCtx = null;
  function _ctx() {
    if (_audioCtx) return _audioCtx;
    var AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return null;
    try { _audioCtx = new AC(); } catch (e) { return null; }
    return _audioCtx;
  }
  function _beep(freq, durMs, when) {
    var ctx = _ctx();
    if (!ctx) return;
    // Add a small offset so scheduling never lands in the past relative
    // to currentTime (which advances even between resume + schedule).
    var t0 = ctx.currentTime + 0.02 + (when || 0);
    var osc = ctx.createOscillator();
    var gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.value = freq;
    gain.gain.setValueAtTime(0, t0);
    gain.gain.linearRampToValueAtTime(0.18, t0 + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, t0 + durMs / 1000);
    osc.connect(gain).connect(ctx.destination);
    osc.start(t0);
    osc.stop(t0 + durMs / 1000 + 0.02);
  }
  function _scheduleChime(sev) {
    if (sev === "critical") {
      _beep(1180, 140, 0);
      _beep(1180, 140, 0.18);
      _beep(1480, 220, 0.38);
    } else if (sev === "high") {
      _beep(880,  160, 0);
      _beep(1175, 240, 0.16);
    } else if (sev === "medium") {
      _beep(660, 220, 0);
    } else {
      _beep(520, 160, 0);
    }
  }
  function _playChime(sev) {
    if (localStorage.getItem("plenith-audio-enabled") !== "1") return;
    var ctx = _ctx();
    if (!ctx) return;
    if (ctx.state === "suspended") {
      // Defer the schedule until resume() actually completes so the
      // first chime after enabling audio isn't silently dropped.
      try {
        ctx.resume().then(function () { _scheduleChime(sev); }, function () {});
      } catch (_) {}
    } else {
      _scheduleChime(sev);
    }
  }
  window.plenithPlayAlertChime = _playChime;

  // Page-wide one-shot resume.  If audio is enabled in localStorage
  // from a prior session but the AudioContext came up suspended (every
  // page reload does this), the FIRST user gesture anywhere on the
  // page kicks it back into "running" so the next SSE-driven chime
  // works without the operator having to click Notify again.
  (function () {
    function tryResume() {
      if (localStorage.getItem("plenith-audio-enabled") !== "1") return;
      var ctx = _ctx();
      if (ctx && ctx.state === "suspended") {
        try { ctx.resume(); } catch (_) {}
      }
    }
    ["click", "keydown", "pointerdown", "touchstart"].forEach(function (ev) {
      document.addEventListener(ev, tryResume, { capture: true, passive: true });
    });
  })();

  window.plenithPushAlertToast = function (alert) {
    var stack = ensureStack();
    var sev = severityClass(alert.severity);
    // Chime moved to the row-pulse path (driven by DOM-diff of row
    // counts) so the audible cue stays in lockstep with the visible
    // row flash, and survives SSE reconnect races where the
    // new_alerts payload would otherwise drop the event.
    var el = document.createElement("div");
    el.className = "toast " + sev;
    // Per-toast politeness override: critical/high alerts interrupt
    // active screen-reader narration; medium/info are polite.
    if (sev === "critical" || sev === "high") {
      el.setAttribute("role", "alert");
      el.setAttribute("aria-live", "assertive");
    }
    el.innerHTML =
      '<div class="toast-close" aria-label="Dismiss notification">×</div>' +
      '<div class="toast-head">' +
        '<span class="sev-dot" aria-hidden="true"></span>' +
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
      b.setAttribute("aria-pressed", perm === "granted" ? "true" : "false");
      b.setAttribute("aria-label",
        perm === "granted" ? "Disable desktop notifications" :
        perm === "denied"  ? "Notifications blocked by browser settings" :
                              "Enable desktop notifications for critical alerts");
    });
  }
  function escapeForToast(s) {
    return String(s).replace(/[<>&"]/g, function (c) {
      return ({"<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;"})[c];
    });
  }
  function statusToast(message, kind) {
    var stack = document.getElementById("toast-stack");
    if (!stack) {
      stack = document.createElement("div");
      stack.id = "toast-stack";
      stack.className = "toast-stack";
      stack.setAttribute("role", "log");
      stack.setAttribute("aria-live", "polite");
      stack.setAttribute("aria-atomic", "false");
      stack.setAttribute("aria-label", "Plenith alerts and notifications");
      document.body.appendChild(stack);
    }
    var el = document.createElement("div");
    el.className = "toast " + (kind || "info");
    el.innerHTML =
      '<div class="toast-close">×</div>' +
      '<div class="toast-head"><span class="sev-dot"></span>' +
      '<span>' + escapeForToast(message) + '</span></div>';
    stack.appendChild(el);
    el.querySelector(".toast-close").addEventListener("click", function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    });
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 6000);
  }
  // Wire all [data-notify-toggle] buttons to request permission on click.
  // Always surfaces a toast so the operator gets visible feedback even
  // when the permission is already "granted" or already "denied" (the
  // browser silently skips re-prompts in those states).  Also turns on
  // the audio chime in localStorage so the operator hears critical
  // alerts even while the tab IS focused (the desktop Notification only
  // fires when tab is hidden).
  document.addEventListener("click", async function (ev) {
    var btn = ev.target.closest("[data-notify-toggle]");
    if (!btn) return;
    ev.preventDefault();
    // First click → enable audio chime regardless of Notification API
    // outcome (chimes work even when browser notifications are denied).
    // User-gesture is also what unlocks the AudioContext.
    localStorage.setItem("plenith-audio-enabled", "1");
    if (window.plenithPlayAlertChime) window.plenithPlayAlertChime("medium");
    if (!("Notification" in window)) {
      statusToast("Audio chime enabled. Browser does not support desktop notifications.", "info");
      refreshBtnLabel();
      return;
    }
    var before = Notification.permission;
    if (before === "default") {
      try {
        var result = await Notification.requestPermission();
        if (result === "granted") {
          statusToast("Notifications + audio chime enabled — critical alerts pop & beep.", "info");
        } else {
          statusToast("Browser notifications declined. Audio chime is still on.", "info");
        }
      } catch (e) {
        statusToast("Permission request failed: " + e.message + " (audio still on)", "high");
      }
    } else if (before === "granted") {
      statusToast("Audio + notifications already enabled. Test chime played.", "info");
      try {
        new Notification("Plenith SOC", {
          body: "Notifications are working. Critical alerts will pop when this tab is unfocused.",
          tag:  "plenith-test",
        });
      } catch (e) { /* swallow */ }
    } else {
      statusToast("Browser notifications blocked, but audio chime is on.", "info");
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

// ===========================================================================
// COUNTER-AI GAUGE TREND (fallback)
// The server now renders the real per-command confidence history into
// .gauge-trend-server.  This module only fills the legacy
// `.gauge-trend` placeholder (when no server-rendered history exists
// yet — fresh engagement, first-tick) using the localStorage baseline
// approximation.  Once server data arrives, the static SVG sparkline
// + delta-label take over and this becomes a no-op.
// ===========================================================================
(function () {
  var STORE_KEY = "plenith-conf-baseline";
  var WINDOW_S  = 240;
  var EPS       = 0.02;

  function loadAll() {
    try { return JSON.parse(sessionStorage.getItem(STORE_KEY) || "{}"); }
    catch (e) { return {}; }
  }
  function saveAll(s) { sessionStorage.setItem(STORE_KEY, JSON.stringify(s)); }
  function fmt(v) { return (Math.round(v * 100) / 100).toFixed(2); }

  window.plenithApplyConfidenceTrend = function () {
    var all = loadAll();
    var nowS = Date.now() / 1000;
    document.querySelectorAll("[data-trend-eid]").forEach(function (el) {
      // Skip server-rendered trend slots — they have real history.
      if (el.classList.contains("gauge-trend-server") &&
          (el.querySelector("svg.gauge-spark") || el.textContent.trim())) {
        return;
      }
      var eid  = el.getAttribute("data-trend-eid");
      var conf = parseFloat(el.getAttribute("data-trend-conf") || "0");
      if (!eid || isNaN(conf)) return;
      var entry = all[eid];
      var html  = "";
      if (entry && typeof entry.conf === "number") {
        var d = conf - entry.conf;
        if (Math.abs(d) >= EPS) {
          var cls   = d > 0 ? "up" : "down";
          var arrow = d > 0 ? "▲" : "▼";
          html = '<span class="' + cls + '">' + arrow + ' ' +
                 fmt(entry.conf) + ' → ' + fmt(conf) + '</span>';
        } else {
          html = '<span class="dim">steady</span>';
        }
        if (nowS - entry.ts >= WINDOW_S) {
          all[eid] = { conf: conf, ts: nowS };
          saveAll(all);
        }
      } else {
        html = '<span class="dim">new</span>';
        all[eid] = { conf: conf, ts: nowS };
        saveAll(all);
      }
      el.innerHTML = html;
    });
  };
})();

// ===========================================================================
// FILE-DIFF MODAL
// Click a row in the "Files modified" section to fetch baseline +
// current content from /api/engagements/<id>/file-diff?path=... and
// show them side-by-side in a modal.  Reuses the export-modal chrome
// so Esc / click-outside / Close all work the same way.
// ===========================================================================
(function () {
  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function ensureFileDiffModal() {
    var m = document.getElementById("file-diff-modal");
    if (m) return m;
    m = document.createElement("div");
    m.id = "file-diff-modal";
    m.className = "export-modal";
    m.setAttribute("hidden", "");
    m.innerHTML =
      '<div class="export-modal-backdrop" data-modal-close></div>' +
      '<div class="export-modal-card file-diff-card" role="dialog" aria-modal="true">' +
        '<div class="export-modal-head">' +
          '<span class="export-modal-title">File diff</span>' +
          '<span class="export-modal-meta dim mono"></span>' +
          '<div class="export-modal-actions">' +
            '<span class="filter" data-modal-close>Close (Esc)</span>' +
          '</div>' +
        '</div>' +
        '<div class="file-diff-body">' +
          '<div class="file-diff-pane">' +
            '<div class="file-diff-pane-head">' +
              '<span class="file-diff-pane-label">Baseline (planted)</span>' +
              '<span class="file-diff-pane-size dim2 mono"></span>' +
            '</div>' +
            '<pre class="file-diff-pre" data-pane="baseline" tabindex="0"></pre>' +
          '</div>' +
          '<div class="file-diff-pane">' +
            '<div class="file-diff-pane-head">' +
              '<span class="file-diff-pane-label">Current (attacker-modified)</span>' +
              '<span class="file-diff-pane-size dim2 mono"></span>' +
            '</div>' +
            '<pre class="file-diff-pre" data-pane="current" tabindex="0"></pre>' +
          '</div>' +
        '</div>' +
      '</div>';
    document.body.appendChild(m);
    m.addEventListener("click", function (ev) {
      if (ev.target.closest("[data-modal-close]")) m.setAttribute("hidden", "");
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && !m.hasAttribute("hidden")) {
        m.setAttribute("hidden", "");
      }
    });
    return m;
  }
  async function openFileDiffModal(eng, path) {
    var m = ensureFileDiffModal();
    m.querySelector(".export-modal-title").textContent = "File diff · " + path;
    m.querySelector(".export-modal-meta").textContent =
      eng.slice(0, 8) + "  ·  loading…";
    var basePre = m.querySelector('[data-pane="baseline"]');
    var curPre  = m.querySelector('[data-pane="current"]');
    basePre.textContent = "";
    curPre.textContent  = "";
    m.removeAttribute("hidden");
    try {
      var url = "/api/engagements/" + encodeURIComponent(eng) +
                "/file-diff?path=" + encodeURIComponent(path);
      var resp = await fetch(url, { headers: { "Accept": "application/json" } });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      var data = await resp.json();
      var bsize = data.baseline_size;
      var csize = data.current_size;
      m.querySelector(".export-modal-meta").textContent =
        eng.slice(0, 8) +
        "  ·  baseline " + (bsize == null ? "(none)" : bsize + " B") +
        " → current " + (data.deleted ? "(deleted)" :
                          csize == null ? "(none)" : csize + " B");
      m.querySelectorAll(".file-diff-pane-size")[0].textContent =
        bsize == null ? "(no baseline planted)" : bsize + " B";
      m.querySelectorAll(".file-diff-pane-size")[1].textContent =
        data.deleted ? "deleted by attacker" :
        csize == null ? "(no current content)" : csize + " B";
      basePre.textContent = data.baseline == null ? "(no baseline)" : data.baseline;
      curPre.textContent  = data.deleted ? "(file deleted by attacker)" :
                            data.current == null ? "(no current)" : data.current;
    } catch (e) {
      basePre.textContent = "Failed to load: " + e.message;
      curPre.textContent  = "";
    }
  }
  // Event-delegated so the rows survive every SSE swap.
  document.addEventListener("click", function (ev) {
    var row = ev.target.closest("[data-file-mod-row]");
    if (!row) return;
    ev.stopPropagation();
    openFileDiffModal(row.getAttribute("data-eng"),
                       row.getAttribute("data-file-path"));
  });
})();

// ===========================================================================
// ALERT-ROW ↔ COMMAND TIMELINE LINKING + COMMAND INSPECT MODAL
// Clicking an alert row scrolls the matching command row into view and
// flashes it.  Clicking a command row opens a modal showing the full
// command + response_source + response_preview.  Both surface details
// the row markup deliberately truncates.
// ===========================================================================
(function () {
  function findCmdRowByTs(ts) {
    if (!ts) return null;
    // Search globally — a popped-out engagement window has its own
    // detail panel + timeline, and the main page swaps panels via SSE.
    return document.querySelector('[data-cmd-row][data-cmd-ts="' + ts + '"]');
  }
  function flash(el) {
    if (!el) return;
    el.classList.remove("cmd-flash");
    // force reflow so the animation restarts when the class is re-added
    void el.offsetWidth;
    el.classList.add("cmd-flash");
    setTimeout(function () { el.classList.remove("cmd-flash"); }, 1800);
  }
  document.addEventListener("click", function (ev) {
    // Don't capture clicks on the Acknowledge button inside the row.
    if (ev.target.closest("button, a")) return;
    var row = ev.target.closest("[data-alert-row]");
    if (!row) return;
    var ts = row.getAttribute("data-alert-ts");
    var cmd = findCmdRowByTs(ts);
    if (!cmd) {
      // Surface a hint instead of silently doing nothing — alerts can
      // fire on events with no matching command (auth events, etc.).
      if (window.plenithPushAlertToast || window.plenithStatusToast) {
        // soft toast — reuse the ack-toast helper if loaded
        var t = document.createElement("div");
        t.className = "ack-toast";
        t.innerHTML = '<span class="label">No matching command in the visible timeline window.</span>';
        document.body.appendChild(t);
        setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 3000);
      }
      return;
    }
    cmd.scrollIntoView({ behavior: "smooth", block: "center" });
    flash(cmd);
  });

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function ensureCmdModal() {
    var m = document.getElementById("command-modal");
    if (m) return m;
    m = document.createElement("div");
    m.id = "command-modal";
    m.className = "export-modal";        // reuse styles
    m.setAttribute("hidden", "");
    m.innerHTML =
      '<div class="export-modal-backdrop" data-modal-close></div>' +
      '<div class="export-modal-card" role="dialog" aria-modal="true">' +
        '<div class="export-modal-head">' +
          '<span class="export-modal-title">Command</span>' +
          '<span class="export-modal-meta dim mono"></span>' +
          '<div class="export-modal-actions">' +
            '<span class="filter" data-modal-close>Close (Esc)</span>' +
          '</div>' +
        '</div>' +
        '<div class="export-modal-body"><pre class="export-modal-pre" tabindex="0"></pre></div>' +
      '</div>';
    document.body.appendChild(m);
    m.addEventListener("click", function (ev) {
      if (ev.target.closest("[data-modal-close]")) m.setAttribute("hidden", "");
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && !m.hasAttribute("hidden")) m.setAttribute("hidden", "");
    });
    return m;
  }
  function openCommandModal(row) {
    var m = ensureCmdModal();
    var ts   = row.getAttribute("data-cmd-ts-display") || "—";
    var src  = row.getAttribute("data-cmd-src") || "?";
    var cmd  = row.getAttribute("data-cmd-text") || "";
    var resp = row.getAttribute("data-cmd-resp") || "";
    m.querySelector(".export-modal-title").textContent =
      "Command · " + (src.split("+")[0] || "?");
    m.querySelector(".export-modal-meta").textContent = ts + "  ·  source: " + src;
    var pre = m.querySelector(".export-modal-pre");
    pre.innerHTML =
      '<strong>$ ' + escapeHtml(cmd) + '</strong>\n\n' +
      (resp
        ? escapeHtml(resp) + (resp.length >= 200
            ? '\n\n<span class="dim">— response preview truncated at 200 chars; see ' +
              'session log for full output —</span>'
            : '')
        : '<span class="dim">(no response body captured)</span>');
    m.removeAttribute("hidden");
    setTimeout(function () {
      try { pre.focus({ preventScroll: true }); } catch (_) { pre.focus(); }
    }, 0);
  }
  document.addEventListener("click", function (ev) {
    if (ev.target.closest("button, a, [data-modal-close]")) return;
    var row = ev.target.closest("[data-cmd-row]");
    if (!row) return;
    openCommandModal(row);
  });
})();

// ===========================================================================
// EXPORT-LINK MODAL PREVIEW
// Plain click on an audit / IoC / Sigma / STIX / narrate link in the
// detail-panel header opens an in-page modal with the export's content.
// Cmd/Ctrl/Shift/middle-click bypass the handler so the browser still
// opens the link in a new tab (or downloads it) — that's the muscle-
// memory escape hatch.  Downloads (`.csv` / `.yaml`) get the preview
// too, with a "Download" button so the operator can still save the file.
// ===========================================================================
(function () {
  function isModifierClick(ev) {
    // Modifier keys + middle-click → respect browser default (new tab / DL)
    return ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey ||
           ev.button === 1 || ev.which === 2;
  }
  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function ensureModal() {
    var m = document.getElementById("export-modal");
    if (m) return m;
    m = document.createElement("div");
    m.id = "export-modal";
    m.className = "export-modal";
    m.setAttribute("hidden", "");
    m.innerHTML =
      '<div class="export-modal-backdrop" data-modal-close></div>' +
      '<div class="export-modal-card" role="dialog" aria-modal="true">' +
        '<div class="export-modal-head">' +
          '<span class="export-modal-title">Export preview</span>' +
          '<span class="export-modal-meta dim mono"></span>' +
          '<div class="export-modal-actions">' +
            '<a class="filter" data-modal-newtab target="_blank">Open in new tab</a>' +
            '<a class="filter" data-modal-download>Download</a>' +
            '<span class="filter" data-modal-close>Close (Esc)</span>' +
          '</div>' +
        '</div>' +
        '<div class="export-modal-body"><pre class="export-modal-pre" tabindex="0"></pre></div>' +
      '</div>';
    document.body.appendChild(m);
    m.addEventListener("click", function (ev) {
      if (ev.target.closest("[data-modal-close]")) closeModal();
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && !m.hasAttribute("hidden")) closeModal();
    });
    return m;
  }
  function closeModal() {
    var m = document.getElementById("export-modal");
    if (m) m.setAttribute("hidden", "");
  }
  function prettyByContentType(text, contentType) {
    if (!contentType) return text;
    if (contentType.indexOf("json") !== -1) {
      try { return JSON.stringify(JSON.parse(text), null, 2); }
      catch (e) { return text; }
    }
    return text;
  }
  function inferTitle(href) {
    if (/\/audit$/.test(href))     return "Plaintext audit";
    if (/\/narrate$/.test(href))   return "Narrative summary";
    if (/\/ioc\.json$/.test(href)) return "IoC bundle (JSON)";
    if (/\/ioc\.csv$/.test(href))  return "IoC bundle (CSV)";
    if (/\/ioc\.stix$/.test(href)) return "STIX 2.1 bundle";
    if (/\/sigma\.yaml$/.test(href)) return "Sigma rule(s) (YAML)";
    return "Export preview";
  }
  function isDownloadable(href) {
    return /\.(csv|yaml)$/.test(href);
  }
  async function openInModal(href, anchorEl) {
    var m = ensureModal();
    var title = inferTitle(href);
    m.querySelector(".export-modal-title").textContent = title;
    var pre = m.querySelector(".export-modal-pre");
    var meta = m.querySelector(".export-modal-meta");
    pre.textContent = "Loading…";
    meta.textContent = href;
    var nt = m.querySelector("[data-modal-newtab]");
    nt.setAttribute("href", href);
    var dl = m.querySelector("[data-modal-download]");
    if (isDownloadable(href)) {
      dl.setAttribute("href", href);
      dl.setAttribute("download", "");
      dl.style.display = "";
    } else {
      dl.style.display = "none";
      dl.removeAttribute("href");
    }
    m.removeAttribute("hidden");
    // Focus the pre so Esc / arrows / ctrl-A target it
    setTimeout(function () {
      try { pre.focus({ preventScroll: true }); } catch (e) { pre.focus(); }
    }, 0);

    try {
      var resp = await fetch(href, { headers: { "Accept": "*/*" } });
      var ct = resp.headers.get("content-type") || "";
      var body = await resp.text();
      // Truncate very large bodies — 1.5 MB cap
      var MAX = 1500000;
      var truncated = body.length > MAX;
      if (truncated) body = body.slice(0, MAX);
      pre.textContent = prettyByContentType(body, ct);
      meta.textContent = href +
        "  ·  " + (ct.split(";")[0] || "?") +
        "  ·  " + body.length + " bytes" +
        (truncated ? "  ·  truncated, use Open in new tab for full content" : "");
    } catch (e) {
      pre.textContent = "Failed to load: " + e.message;
      meta.textContent = href + "  ·  error";
    }
  }

  // Event-delegated so this works after every SSE swap and inside popouts.
  document.addEventListener("click", function (ev) {
    var a = ev.target.closest("a.filter[href*=\"/api/engagements/\"]");
    if (!a) return;
    // Only intercept the export links that live in the panel header's
    // [data-export-host] container (or any element marked as export host)
    // so we don't change behavior of other .filter anchors elsewhere.
    if (!ev.target.closest("[data-export-host]")) return;
    if (isModifierClick(ev)) return;        // respect new-tab / DL modifier
    ev.preventDefault();
    var href = a.getAttribute("href");
    if (href) openInModal(href, a);
  });

  // Expose so other code (e.g. toast-action links) could reuse.
  window.plenithOpenExportModal = openInModal;
})();

// ===========================================================================
// ENGAGEMENT-LIST SORT + PAGINATION
// Drives the sort chip strip + page-size strip + prev/next controls in
// the /panel/engagements popout.  State persists in localStorage so a
// sibling tab stays in sync.  Sort + paginate happen in-DOM after every
// SSE swap — no server-side query plumbing needed for the popout's
// engagement scale (a few hundred max).
// ===========================================================================
(function () {
  function findSortStrip() { return document.querySelector("[data-eng-sort-strip]"); }
  if (!findSortStrip()) return;

  var STORE_SORT_FIELD  = "plenith-eng-sort-field";
  var STORE_SORT_DIR    = "plenith-eng-sort-dir";
  var STORE_PAGE_SIZE   = "plenith-eng-page-size";
  var STORE_PAGE        = "plenith-eng-page";

  var FIELDS = ["last_seen", "first_seen", "dwell", "cmds", "alerts", "conf"];
  var SIZES  = ["10", "25", "50", "all"];

  function getField() {
    var v = localStorage.getItem(STORE_SORT_FIELD);
    return FIELDS.indexOf(v) >= 0 ? v : "last_seen";
  }
  function setField(v) { localStorage.setItem(STORE_SORT_FIELD, v); }
  function getDir() {
    var v = localStorage.getItem(STORE_SORT_DIR);
    return (v === "asc" || v === "desc") ? v : "desc";
  }
  function setDir(v) { localStorage.setItem(STORE_SORT_DIR, v); }
  function getPageSize() {
    var v = localStorage.getItem(STORE_PAGE_SIZE);
    return SIZES.indexOf(v) >= 0 ? v : "25";
  }
  function setPageSize(v) { localStorage.setItem(STORE_PAGE_SIZE, v); }
  function getPage() {
    var v = parseInt(localStorage.getItem(STORE_PAGE) || "1", 10);
    return isNaN(v) || v < 1 ? 1 : v;
  }
  function setPage(v) { localStorage.setItem(STORE_PAGE, String(v)); }

  function _attr(row, name, fallback) {
    var v = row.getAttribute(name);
    if (v === null || v === "") return fallback;
    var n = parseFloat(v);
    return isNaN(n) ? fallback : n;
  }
  function rowSortKey(row, field) {
    switch (field) {
      case "first_seen": return _attr(row, "data-eng-first", 0);
      case "dwell":      return _attr(row, "data-eng-dwell", 0);
      case "cmds":       return _attr(row, "data-eng-cmds", 0);
      case "alerts":     return _attr(row, "data-eng-alerts", 0);
      case "conf":       return _attr(row, "data-eng-conf", 0);
      case "last_seen":
      default:           return _attr(row, "data-eng-last", 0);
    }
  }

  function applyEngSortAndPage() {
    var list = document.querySelector("[data-eng-list]");
    if (!list) return;
    var field = getField();
    var dir   = getDir();
    var pageSize = getPageSize();
    var page  = getPage();
    var rows  = Array.from(list.querySelectorAll(":scope > [data-eng-row]"));
    if (!rows.length) {
      _renderPageInfo(0, 0, 0, 1, 1);
      return;
    }
    // Sort
    rows.sort(function (a, b) {
      var ka = rowSortKey(a, field), kb = rowSortKey(b, field);
      return dir === "asc" ? ka - kb : kb - ka;
    });
    rows.forEach(function (r) { list.appendChild(r); });   // reorder in DOM
    // Paginate — but ONLY hide rows the filter hasn't already hidden.
    // applyFilter() sets row.style.display = "none" for filtered-out
    // rows; we don't want to override that here.  Count visible-by-
    // filter rows, then hide the ones outside our current page among
    // those visible rows.
    var visibleByFilter = rows.filter(function (r) {
      return r.style.display !== "none";
    });
    var total = visibleByFilter.length;
    var size = pageSize === "all" ? total : parseInt(pageSize, 10);
    if (size <= 0) size = 25;
    var maxPage = Math.max(1, Math.ceil(total / size));
    if (page > maxPage) { page = maxPage; setPage(page); }
    var start = (page - 1) * size;
    var end   = pageSize === "all" ? total : (start + size);
    visibleByFilter.forEach(function (r, idx) {
      if (idx >= start && idx < end) {
        // Already visible-by-filter; leave alone.
      } else {
        r.style.display = "none";
      }
    });
    _syncChips(field, dir, pageSize);
    _renderPageInfo(total, start + 1, Math.min(end, total), page, maxPage);
  }

  function _syncChips(field, dir, size) {
    document.querySelectorAll("[data-eng-sort]").forEach(function (c) {
      var on = c.getAttribute("data-eng-sort") === field;
      c.classList.toggle("active", on);
      c.setAttribute("aria-pressed", on ? "true" : "false");
    });
    document.querySelectorAll("[data-eng-page-size]").forEach(function (c) {
      var on = c.getAttribute("data-eng-page-size") === size;
      c.classList.toggle("active", on);
      c.setAttribute("aria-pressed", on ? "true" : "false");
    });
    var t = document.querySelector("[data-eng-sort-dir-toggle]");
    if (t) {
      t.textContent = dir === "asc" ? "↑" : "↓";
      t.setAttribute("aria-label",
        dir === "asc" ? "Sorted ascending — click for descending"
                      : "Sorted descending — click for ascending");
    }
  }
  function _renderPageInfo(total, first, last, page, maxPage) {
    var info = document.querySelector("[data-eng-page-info]");
    var pageSize = getPageSize();
    if (info) {
      if (total === 0) {
        info.textContent = "No engagements";
      } else if (pageSize === "all") {
        info.textContent = "Showing all " + total;
      } else {
        info.textContent = "Showing " + first + "–" + last + " of " + total;
      }
    }
    var pn = document.querySelector("[data-eng-page-num]");
    if (pn) pn.textContent = "page " + page + " of " + maxPage;
    var prev = document.querySelector("[data-eng-page-prev]");
    var next = document.querySelector("[data-eng-page-next]");
    if (prev) {
      if (page <= 1) prev.setAttribute("disabled", "");
      else prev.removeAttribute("disabled");
    }
    if (next) {
      if (page >= maxPage) next.setAttribute("disabled", "");
      else next.removeAttribute("disabled");
    }
  }

  // Sort chip click
  document.addEventListener("click", function (ev) {
    var chip = ev.target.closest("[data-eng-sort]");
    if (!chip) return;
    ev.stopPropagation();
    var field = chip.getAttribute("data-eng-sort");
    if (getField() === field) {
      // Toggle direction when clicking the active field
      setDir(getDir() === "asc" ? "desc" : "asc");
    } else {
      setField(field);
      // Reset to a sensible default direction per field:
      // numeric fields default to descending (highest first),
      // first_seen defaults to ascending (earliest first).
      setDir(field === "first_seen" ? "asc" : "desc");
    }
    setPage(1);
    applyEngSortAndPage();
  });
  // Sort direction toggle
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-eng-sort-dir-toggle]");
    if (!btn) return;
    ev.stopPropagation();
    setDir(getDir() === "asc" ? "desc" : "asc");
    applyEngSortAndPage();
  });
  // Page-size chip click
  document.addEventListener("click", function (ev) {
    var chip = ev.target.closest("[data-eng-page-size]");
    if (!chip) return;
    ev.stopPropagation();
    setPageSize(chip.getAttribute("data-eng-page-size"));
    setPage(1);
    applyEngSortAndPage();
  });
  // Pagination buttons
  document.addEventListener("click", function (ev) {
    var prev = ev.target.closest("[data-eng-page-prev]");
    var next = ev.target.closest("[data-eng-page-next]");
    if (!prev && !next) return;
    if ((prev && prev.hasAttribute("disabled")) ||
        (next && next.hasAttribute("disabled"))) return;
    ev.stopPropagation();
    setPage(getPage() + (prev ? -1 : 1));
    applyEngSortAndPage();
  });
  // Cross-tab sync
  window.addEventListener("storage", function (ev) {
    if (ev.key === STORE_SORT_FIELD || ev.key === STORE_SORT_DIR ||
        ev.key === STORE_PAGE_SIZE  || ev.key === STORE_PAGE) {
      applyEngSortAndPage();
    }
  });

  window.plenithApplyEngSortAndPage = applyEngSortAndPage;
  // Chain into the shared post-SSE-swap hook so sort + page survive
  // every render.  Order matters: applyFilter (which sets row.display
  // for filtered-out rows) must run FIRST; we sort + paginate the
  // remaining visible rows.
  var _origReapply = window.plenithReapplyClientState;
  window.plenithReapplyClientState = function () {
    if (typeof _origReapply === "function") _origReapply();
    applyEngSortAndPage();
  };
  // Initial run on page load
  applyEngSortAndPage();
})();

// ===========================================================================
// ROW-PULSE ON ACTIVITY
// Detects when an engagement row's command count or alert count
// climbs between SSE swaps and briefly flashes the row brand-color.
// Solves the "looks like nothing happened" problem when concurrent
// attackers reuse the same (ip, user) engagement_id and only the
// last_seen_at moves.  Also gets called out of plenithReapplyClientState
// so the diff is computed after every SSE tick.
// ===========================================================================
(function () {
  // Per-row last-known counts.  Keyed by engagement_id so the diff
  // survives DOM re-renders (the row gets a new node every SSE tick).
  var prevCounts = {};
  var ALERT_PULSE_MS = 1400;
  var CMD_PULSE_MS   = 900;

  function pulse(row, kind) {
    if (!row) return;
    var cls = (kind === "alert") ? "eng-pulse-alert" : "eng-pulse-cmd";
    row.classList.remove(cls);
    // Force reflow so re-adding the class restarts the animation.
    void row.offsetWidth;
    row.classList.add(cls);
    setTimeout(function () { row.classList.remove(cls); },
                kind === "alert" ? ALERT_PULSE_MS : CMD_PULSE_MS);
  }

  // Initialize from current DOM so the FIRST applyPulses after a
  // hard-refresh doesn't pulse every row (every row would look "new").
  function _initIfEmpty() {
    if (Object.keys(prevCounts).length > 0) return;
    document.querySelectorAll("[data-eng-row]").forEach(function (row) {
      var eid = row.getAttribute("data-eng-id");
      if (!eid) return;
      prevCounts[eid] = {
        cmds:   parseInt(row.getAttribute("data-eng-cmds")   || "0", 10),
        alerts: parseInt(row.getAttribute("data-eng-alerts") || "0", 10),
      };
    });
  }
  _initIfEmpty();

  function _rowSeverity(row) {
    // Each .eng row carries one of these severity classes from the
    // server-side renderer: critical / high / medium / proven / low / info.
    var cl = row.classList;
    if (cl.contains("critical") || cl.contains("proven")) return "critical";
    if (cl.contains("high")) return "high";
    if (cl.contains("medium")) return "medium";
    return "info";
  }
  function applyPulses() {
    document.querySelectorAll("[data-eng-row]").forEach(function (row) {
      var eid    = row.getAttribute("data-eng-id");
      if (!eid) return;
      var cmds   = parseInt(row.getAttribute("data-eng-cmds")   || "0", 10);
      var alerts = parseInt(row.getAttribute("data-eng-alerts") || "0", 10);
      var prev   = prevCounts[eid];
      if (prev !== undefined) {
        if (alerts > prev.alerts) {
          pulse(row, "alert");
          // Fire the chime here (DOM-diff path) so it works even when
          // the SSE new_alerts payload missed an alert (reconnect race
          // or audio context suspended at the time).  We pull severity
          // from the row's class so the pitch matches.
          if (window.plenithPlayAlertChime) {
            window.plenithPlayAlertChime(_rowSeverity(row));
          }
        } else if (cmds > prev.cmds) {
          pulse(row, "cmd");
        }
      }
      prevCounts[eid] = { cmds: cmds, alerts: alerts };
    });
  }

  window.plenithApplyRowPulse = applyPulses;
  // Chain into the existing reapply hook so we fire after every SSE swap.
  var _origReapply = window.plenithReapplyClientState;
  window.plenithReapplyClientState = function () {
    if (typeof _origReapply === "function") _origReapply();
    applyPulses();
  };
})();

// ===========================================================================
// LIVE EVENT TICKER
// Small strip above the engagement list showing the last N events as
// they stream in.  Drives off the same SSE new_alerts payload that the
// toast stack consumes.  Persists last events in memory so reconnects
// don't blank the ticker.
// ===========================================================================
(function () {
  var TICKER_MAX_ROWS = 8;
  // "LIVE" means recent. Events older than this age out, so an ended
  // (or gone-quiet) session's events stop residing in the ticker until
  // a manual refresh. Tunable: lower = clears sooner but flickers for
  // sporadically-active attackers; higher = tolerates pauses but keeps
  // ended-session rows around longer.
  var EVENT_TTL_S = 180;
  var events = [];   // most-recent-first

  function ensureTicker() {
    if (document.querySelector("[data-event-ticker]")) return;
    var enList = document.querySelector("[data-panel-id='engagements'] .engagements");
    if (!enList) return;
    var bar = document.createElement("div");
    bar.setAttribute("data-event-ticker", "");
    bar.className = "event-ticker";
    bar.innerHTML =
      '<div class="event-ticker-head">'
        + '<span class="event-ticker-title">LIVE EVENTS</span>'
        + '<span class="event-ticker-dot"></span>'
      + '</div>'
      + '<div class="event-ticker-list" data-event-ticker-list></div>';
    enList.parentNode.insertBefore(bar, enList);
    render();
  }

  function fmt(t) {
    var d = new Date((t || Date.now() / 1000) * 1000);
    return d.toTimeString().slice(0, 8);   // HH:MM:SS
  }
  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function severityClass(sev) {
    return ({"critical": "crit", "high": "high",
              "medium": "med", "info": "info"})[sev] || "info";
  }

  // Drop events past the TTL. events is strictly most-recent-first
  // (unshift + monotonic ts), so find the first stale one and truncate.
  // Returns true if anything was removed.
  function prune() {
    var cutoff = Date.now() / 1000 - EVENT_TTL_S;
    var keep = 0;
    while (keep < events.length && events[keep].ts >= cutoff) keep++;
    if (keep < events.length) { events.length = keep; return true; }
    return false;
  }

  function render(flash) {
    prune();
    var list = document.querySelector("[data-event-ticker-list]");
    if (!list) return;
    if (!events.length) {
      list.innerHTML = '<div class="event-ticker-empty dim">Waiting for events…</div>';
      return;
    }
    var rows = events.slice(0, TICKER_MAX_ROWS).map(function (e) {
      return (
        '<div class="event-ticker-row">'
          + '<span class="event-ticker-ts mono">' + fmt(e.ts) + '</span>'
          + '<span class="event-ticker-sev pill ' + severityClass(e.severity) + '">'
          + escapeHtml((e.severity || "info").slice(0, 4).toUpperCase())
          + '</span>'
          + '<span class="event-ticker-who mono">'
          + escapeHtml(e.user) + '@' + escapeHtml(e.ip)
          + '</span>'
          + '<span class="event-ticker-action mono">'
          + escapeHtml(e.action) + '</span>'
        + '</div>'
      );
    }).join("");
    list.innerHTML = rows;
    // Flash the top row only when a genuinely new event arrived — not
    // on prune/SSE-swap redraws (those would re-flash with nothing new).
    if (flash) {
      var first = list.querySelector(".event-ticker-row");
      if (first) {
        first.classList.add("event-ticker-fresh");
        setTimeout(function () { first.classList.remove("event-ticker-fresh"); }, 800);
      }
    }
  }

  window.plenithPushTickerEvent = function (alertObj) {
    if (!alertObj) return;
    ensureTicker();
    events.unshift({
      ts:       Date.now() / 1000,
      severity: alertObj.severity || "info",
      action:   alertObj.action || "?",
      user:     alertObj.claimed_user || "?",
      ip:       alertObj.source_ip || "?",
    });
    if (events.length > 50) events.length = 50;
    render(true);
  };

  // Hook into the alert-toast path so every toast also pushes to the ticker.
  var _origToast = window.plenithPushAlertToast;
  window.plenithPushAlertToast = function (alertObj) {
    if (typeof _origToast === "function") _origToast(alertObj);
    if (window.plenithPushTickerEvent) window.plenithPushTickerEvent(alertObj);
  };

  // Re-attach the ticker after every SSE swap (the engagements panel
  // gets a fresh DOM each tick — without re-attaching, the ticker
  // would disappear after the first render).
  var _origReapply = window.plenithReapplyClientState;
  window.plenithReapplyClientState = function () {
    if (typeof _origReapply === "function") _origReapply();
    ensureTicker();
    render(false);
  };

  // Self-clear: even with no SSE traffic (session ended / went quiet),
  // prune aged-out events so stale rows don't persist until a manual
  // window refresh — the original complaint.
  setInterval(function () { if (prune()) render(false); }, 5000);
})();

// ===========================================================================
// ALERT-RATE POPOUT CONTROLS
// Time-range tabs, severity filter chips, and stacked/line mode toggle.
// State is held in sessionStorage so the operator's choices persist
// across SSE re-renders of the popout's #panels container.
//
// Every control change does ONE fetch each to:
//   /api/alerts/chart.html?since=…&until=…&bucket_seconds=…&mode=…&severities=…
//   /api/alerts/top.html?since=…&until=…&limit=8
// and swaps the returned HTML into [data-alert-chart] and [data-alert-top].
// The /api/alerts/rate JSON endpoint is left untouched for SOAR consumers.
// ===========================================================================
(function () {
  // Only wire when this popout's toolbar is on the page.  The same JS
  // bundle ships everywhere; the toolbar selector keeps us a no-op on
  // pages that don't have the alert-rate panel.
  function findToolbar() {
    return document.querySelector("[data-alert-rate-toolbar]");
  }
  if (!findToolbar()) return;

  var STORE_RANGE = "plenith-ar-range";
  var STORE_MODE  = "plenith-ar-mode";
  var STORE_SEV   = "plenith-ar-sev";   // comma-joined list

  // Map each range key to (seconds_back, bucket_seconds, label, top_window_seconds).
  // top_window_seconds is what we ask /alerts/top for — usually matches
  // the chart range, but we floor it at 1h so very-short ranges still
  // show something useful in the side list.
  var RANGES = {
    "15m": { width: 900,     bucket: 30,    topWidth: 3600    },
    "1h":  { width: 3600,    bucket: 120,   topWidth: 3600    },
    "6h":  { width: 21600,   bucket: 300,   topWidth: 21600   },
    "24h": { width: 86400,   bucket: 900,   topWidth: 86400   },
    "7d":  { width: 604800,  bucket: 7200,  topWidth: 604800  },
    "30d": { width: 2592000, bucket: 43200, topWidth: 2592000 },
  };
  var ALL_SEV = ["critical", "high", "medium", "info"];

  // localStorage (not sessionStorage) so the choice survives both
  // page reloads AND a separate popout window writing to the same
  // keys (sessionStorage is per-tab; localStorage is per-origin and
  // fires a `storage` event in OTHER tabs).
  function getRange() {
    var r = localStorage.getItem(STORE_RANGE);
    return RANGES[r] ? r : "6h";
  }
  function setRange(r) { localStorage.setItem(STORE_RANGE, r); }
  function getMode() {
    var m = localStorage.getItem(STORE_MODE);
    return (m === "line" || m === "stacked") ? m : "stacked";
  }
  function setMode(m) { localStorage.setItem(STORE_MODE, m); }
  function getSeverities() {
    var raw = localStorage.getItem(STORE_SEV);
    if (raw === null) return ALL_SEV.slice();
    var s = raw.split(",").filter(function (x) { return ALL_SEV.indexOf(x) >= 0; });
    return s.length ? s : ALL_SEV.slice();
  }
  function setSeverities(s) { localStorage.setItem(STORE_SEV, s.join(",")); }

  var inFlight = 0;

  async function refresh() {
    var range = getRange();
    var mode  = getMode();
    var sev   = getSeverities();
    var conf  = RANGES[range];
    var now   = Math.floor(Date.now() / 1000);
    var since = now - conf.width;

    // Reflect the active controls in the DOM (chip classes + aria-pressed).
    document.querySelectorAll("[data-ar-range]").forEach(function (b) {
      var on = b.getAttribute("data-ar-range") === range;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    document.querySelectorAll("[data-ar-mode]").forEach(function (b) {
      var on = b.getAttribute("data-ar-mode") === mode;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    document.querySelectorAll("[data-ar-sev]").forEach(function (b) {
      var on = sev.indexOf(b.getAttribute("data-ar-sev")) >= 0;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });

    var seq = ++inFlight;
    var chartQS = new URLSearchParams({
      since: String(since),
      until: String(now),
      bucket_seconds: String(conf.bucket),
      mode: mode,
      severities: sev.join(","),
      range: range,
    }).toString();
    var topSince = now - conf.topWidth;
    var topQS = new URLSearchParams({
      since: String(topSince),
      until: String(now),
      limit: "8",
    }).toString();

    try {
      var [chartResp, topResp] = await Promise.all([
        fetch("/api/alerts/chart.html?" + chartQS,
              { headers: { "Accept": "text/html" } }),
        fetch("/api/alerts/top.html?" + topQS,
              { headers: { "Accept": "text/html" } }),
      ]);
      if (seq !== inFlight) return;   // newer request superseded this one
      var chartHtml = await chartResp.text();
      var topHtml   = await topResp.text();

      // The chart fragment ships two siblings: a [data-ar-stats] block
      // and either an <svg> or a <div class="dim"> when empty.  Parse
      // once, extract each piece, replace in place.
      var tmp = document.createElement("div");
      tmp.innerHTML = chartHtml;
      var newStats = tmp.querySelector("[data-ar-stats]");
      var newChart = tmp.querySelector("svg.sparkline-large, .dim");

      var statsHost = document.querySelector("[data-ar-stats]");
      if (newStats && statsHost && statsHost.parentNode) {
        statsHost.parentNode.replaceChild(newStats, statsHost);
      }
      var chartHost = document.querySelector("[data-alert-chart]");
      if (chartHost && newChart) {
        chartHost.innerHTML = "";
        chartHost.appendChild(newChart);
      }
      var topEl = document.querySelector("[data-alert-top]");
      if (topEl) topEl.innerHTML = topHtml;
    } catch (e) {
      console.warn("alert-rate refresh failed:", e);
    }
  }

  // Range tabs — single-select
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-ar-range]");
    if (!btn) return;
    ev.stopPropagation();
    setRange(btn.getAttribute("data-ar-range"));
    refresh();
  });
  // Mode toggle — single-select
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-ar-mode]");
    if (!btn) return;
    ev.stopPropagation();
    setMode(btn.getAttribute("data-ar-mode"));
    refresh();
  });
  // Severity chips — multi-select; refuses to leave the set empty.
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-ar-sev]");
    if (!btn) return;
    ev.stopPropagation();
    var sev = getSeverities();
    var name = btn.getAttribute("data-ar-sev");
    var i = sev.indexOf(name);
    if (i >= 0) {
      if (sev.length === 1) return;       // keep at least one severity on
      sev.splice(i, 1);
    } else {
      sev.push(name);
    }
    setSeverities(sev);
    refresh();
  });

  // Cross-tab sync: localStorage writes from a SIBLING tab (e.g. the
  // popout when this window is the main dashboard, or vice versa) fire
  // a `storage` event here.  Refresh whenever one of our keys changes.
  window.addEventListener("storage", function (ev) {
    if (ev.key === STORE_RANGE || ev.key === STORE_MODE || ev.key === STORE_SEV) {
      refresh();
    }
  });

  // Initial sync — reflect persisted state on first load, then refresh
  // so the server-rendered defaults are replaced by what the operator
  // last picked.  Also re-run after each SSE swap of the panel.
  function init() {
    if (!findToolbar()) return;
    refresh();
  }
  init();
  // Hook into the shared post-SSE-swap callback that every other
  // client-state module uses — much more reliable than a per-IIFE
  // MutationObserver, which races with the first SSE tick.  The
  // selector check inside refresh() means this is a no-op on pages
  // that don't have the alert-rate toolbar.
  // Throttle the post-SSE reapply: we don't need to refetch on every
  // 3s SSE tick if we just refreshed for some other reason (e.g. the
  // operator just clicked a chip — refresh() already fired and updates
  // _lastFetchMs).  The reapply path always syncs the chip-active state
  // synchronously, so the controls don't visually lag.
  var _lastFetchMs = 0;
  var FETCH_MIN_INTERVAL_MS = 2500;
  var _origRefresh = refresh;
  refresh = async function () {
    _lastFetchMs = Date.now();
    return await _origRefresh.apply(this, arguments);
  };
  window.plenithApplyAlertRate = function () {
    if (!findToolbar()) return;
    // Cheap synchronous sync of the chip-active state (the SSE swap
    // wiped them back to the server-rendered default).
    var range = getRange();
    var mode  = getMode();
    var sev   = getSeverities();
    document.querySelectorAll("[data-ar-range]").forEach(function (b) {
      var on = b.getAttribute("data-ar-range") === range;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    document.querySelectorAll("[data-ar-mode]").forEach(function (b) {
      var on = b.getAttribute("data-ar-mode") === mode;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    document.querySelectorAll("[data-ar-sev]").forEach(function (b) {
      var on = sev.indexOf(b.getAttribute("data-ar-sev")) >= 0;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    if (Date.now() - _lastFetchMs >= FETCH_MIN_INTERVAL_MS) {
      refresh();
    }
  };
  var _orig = window.plenithReapplyClientState;
  window.plenithReapplyClientState = function () {
    if (typeof _orig === "function") _orig();
    if (window.plenithApplyAlertRate) window.plenithApplyAlertRate();
  };
})();

// ===========================================================================
// DNS POPOUT / MAIN-PANEL CONTROLS
// Result-type filter chips (all / resolved / blocked / nxdomain).  The
// popout adds KPI tiles + top blocked / top NXDOMAIN side lists which
// also refresh on filter change.  State is cross-tab via localStorage
// (same pattern as alert-rate).
// ===========================================================================
(function () {
  function findToolbar() {
    return document.querySelector("[data-dns-toolbar]");
  }
  if (!findToolbar()) return;

  var STORE_FILTER = "plenith-dns-filter";
  var VALID = ["all", "resolved", "blocked", "nxdomain"];

  function getFilter() {
    var v = localStorage.getItem(STORE_FILTER);
    return VALID.indexOf(v) >= 0 ? v : "all";
  }
  function setFilter(v) { localStorage.setItem(STORE_FILTER, v); }

  var inFlight = 0;

  async function refresh() {
    var filter = getFilter();

    // Reflect chip state — every toolbar on the page (main + popout
    // could co-exist in different windows of the same origin).
    document.querySelectorAll("[data-dns-filter]").forEach(function (b) {
      var on = b.getAttribute("data-dns-filter") === filter;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });

    var seq = ++inFlight;
    var feedQS = new URLSearchParams({
      result: filter,
      limit: "80",
    }).toString();

    var fetches = [
      fetch("/api/dns/feed.html?" + feedQS,
            { headers: { "Accept": "text/html" } }).then(r => r.text()),
    ];
    // The popout has the side lists; the main panel does not.  Only
    // fetch them when their hosts exist on the page.
    var blockedHost  = document.querySelector("[data-dns-top-blocked]");
    var nxdomainHost = document.querySelector("[data-dns-top-nxdomain]");
    if (blockedHost) {
      fetches.push(
        fetch("/api/dns/top.html?type=blocked&limit=10",
              { headers: { "Accept": "text/html" } }).then(r => r.text())
      );
    } else { fetches.push(Promise.resolve(null)); }
    if (nxdomainHost) {
      fetches.push(
        fetch("/api/dns/top.html?type=nxdomain&limit=10",
              { headers: { "Accept": "text/html" } }).then(r => r.text())
      );
    } else { fetches.push(Promise.resolve(null)); }

    try {
      var [feedHtml, blockedHtml, nxdomainHtml] = await Promise.all(fetches);
      if (seq !== inFlight) return;   // newer request superseded

      // Parse and swap the feed fragment.  The fragment ships a hidden
      // <span data-dns-feed-count-fragment> with the new count.
      var tmp = document.createElement("div");
      tmp.innerHTML = feedHtml;
      var countSpan = tmp.querySelector("[data-dns-feed-count-fragment]");
      if (countSpan) {
        var n = parseInt(countSpan.textContent, 10);
        document.querySelectorAll("[data-dns-feed-count]").forEach(function (c) {
          c.textContent = isNaN(n) ? "0" : String(n);
        });
        countSpan.remove();
      }
      var feedHost = document.querySelector("[data-dns-feed-host]");
      if (feedHost) {
        feedHost.innerHTML = "";
        while (tmp.firstChild) feedHost.appendChild(tmp.firstChild);
      }
      if (blockedHost && blockedHtml != null) blockedHost.innerHTML = blockedHtml;
      if (nxdomainHost && nxdomainHtml != null) nxdomainHost.innerHTML = nxdomainHtml;
    } catch (e) {
      console.warn("dns refresh failed:", e);
    }
  }

  // Filter chips — single-select; clicking the active chip resets to "all".
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-dns-filter]");
    if (!btn) return;
    ev.stopPropagation();
    var name = btn.getAttribute("data-dns-filter") || "all";
    if (getFilter() === name && name !== "all") name = "all";
    setFilter(name);
    refresh();
  });

  // Cross-tab sync
  window.addEventListener("storage", function (ev) {
    if (ev.key === STORE_FILTER) refresh();
  });

  function init() {
    if (!findToolbar()) return;
    refresh();
  }
  init();
  // Throttle the DNS module's reapply for the same reason as alert-rate:
  // server already paints fresh data via the SSE swap; this fetch is only
  // needed to restore the operator's non-default filter selection.
  var _dnsLastFetchMs = 0;
  var DNS_FETCH_MIN_INTERVAL_MS = 6000;
  var _dnsOrigRefresh = refresh;
  refresh = async function () {
    _dnsLastFetchMs = Date.now();
    return await _dnsOrigRefresh.apply(this, arguments);
  };
  window.plenithApplyDns = function () {
    if (!findToolbar()) return;
    // Cheap chip-active sync first (no fetch).
    var filter = getFilter();
    document.querySelectorAll("[data-dns-filter]").forEach(function (b) {
      var on = b.getAttribute("data-dns-filter") === filter;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    if (Date.now() - _dnsLastFetchMs >= DNS_FETCH_MIN_INTERVAL_MS) {
      refresh();
    }
  };
  var _dnsOrig = window.plenithReapplyClientState;
  window.plenithReapplyClientState = function () {
    if (typeof _dnsOrig === "function") _dnsOrig();
    if (window.plenithApplyDns) window.plenithApplyDns();
  };
})();

// ===========================================================================
// ACTIVITY HEATMAP POPOUT — time-range tabs, kind chips, cell-click drill.
// Mirrors the alert-rate / DNS patterns: localStorage state, cross-tab
// sync via the `storage` event, hook into plenithReapplyClientState.
// ===========================================================================
(function () {
  function findToolbar() {
    return document.querySelector("[data-activity-toolbar]");
  }
  if (!findToolbar()) return;

  var STORE_RANGE = "plenith-act-range";
  var STORE_KIND  = "plenith-act-kind";
  var RANGES = {
    "24h": 86400,
    "7d":  604800,
    "30d": 2592000,
    "90d": 7776000,
  };
  var KINDS = ["all", "alerts", "commands"];

  function getRange() {
    var v = localStorage.getItem(STORE_RANGE);
    return RANGES[v] ? v : "24h";
  }
  function setRange(v) { localStorage.setItem(STORE_RANGE, v); }
  function getKind() {
    var v = localStorage.getItem(STORE_KIND);
    return KINDS.indexOf(v) >= 0 ? v : "all";
  }
  function setKind(v) { localStorage.setItem(STORE_KIND, v); }

  var inFlight = 0;

  async function refresh() {
    var range = getRange();
    var kind  = getKind();
    var now   = Math.floor(Date.now() / 1000);
    var since = now - RANGES[range];

    document.querySelectorAll("[data-act-range]").forEach(function (b) {
      var on = b.getAttribute("data-act-range") === range;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    document.querySelectorAll("[data-act-kind]").forEach(function (b) {
      var on = b.getAttribute("data-act-kind") === kind;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });

    var seq = ++inFlight;
    var qs = new URLSearchParams({
      since: String(since),
      until: String(now),
      kind: kind,
    }).toString();

    try {
      var resp = await fetch("/api/activity/heatmap.html?" + qs,
                              { headers: { "Accept": "text/html" } });
      if (seq !== inFlight) return;
      var html = await resp.text();
      var tmp = document.createElement("div");
      tmp.innerHTML = html;
      var newSummary = tmp.querySelector("[data-activity-summary]");
      var newGrid    = tmp.querySelector(".heatmap, .dim");
      var summaryHost = document.querySelector("[data-activity-summary-host]");
      var heatmapHost = document.querySelector("[data-activity-heatmap-host]");
      if (newSummary && summaryHost) summaryHost.innerHTML = newSummary.outerHTML;
      if (newGrid && heatmapHost) {
        heatmapHost.innerHTML = "";
        heatmapHost.appendChild(newGrid);
      }
    } catch (e) {
      console.warn("activity refresh failed:", e);
    }
  }

  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-act-range]");
    if (!btn) return;
    ev.stopPropagation();
    setRange(btn.getAttribute("data-act-range"));
    refresh();
  });
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-act-kind]");
    if (!btn) return;
    ev.stopPropagation();
    setKind(btn.getAttribute("data-act-kind"));
    refresh();
  });

  // Cell-click drill-in — reuses the export-modal CSS chrome.
  function ensureCellModal() {
    var m = document.getElementById("activity-cell-modal");
    if (m) return m;
    m = document.createElement("div");
    m.id = "activity-cell-modal";
    m.className = "export-modal";
    m.setAttribute("hidden", "");
    m.innerHTML =
      '<div class="export-modal-backdrop" data-modal-close></div>' +
      '<div class="export-modal-card" role="dialog" aria-modal="true">' +
        '<div class="export-modal-head">' +
          '<span class="export-modal-title">Cell drill-in</span>' +
          '<span class="export-modal-meta dim mono"></span>' +
          '<div class="export-modal-actions">' +
            '<span class="filter" data-modal-close>Close (Esc)</span>' +
          '</div>' +
        '</div>' +
        '<div class="export-modal-body activity-cell-body" tabindex="0"></div>' +
      '</div>';
    document.body.appendChild(m);
    m.addEventListener("click", function (ev) {
      if (ev.target.closest("[data-modal-close]")) m.setAttribute("hidden", "");
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && !m.hasAttribute("hidden")) m.setAttribute("hidden", "");
    });
    return m;
  }
  async function openCellModal(host, hour) {
    var m = ensureCellModal();
    var range = getRange();
    var kind  = getKind();
    var now   = Math.floor(Date.now() / 1000);
    var since = now - RANGES[range];
    m.querySelector(".export-modal-title").textContent =
      host + " · " + String(hour).padStart(2, "0") + ":00";
    m.querySelector(".export-modal-meta").textContent =
      "range: " + range + " · kind: " + kind;
    var body = m.querySelector(".activity-cell-body");
    body.innerHTML = '<div class="dim" style="padding: 12px;">Loading…</div>';
    m.removeAttribute("hidden");
    var qs = new URLSearchParams({
      host: host, hour: String(hour),
      since: String(since), until: String(now), kind: kind,
    }).toString();
    try {
      var resp = await fetch("/api/activity/cell.html?" + qs,
                              { headers: { "Accept": "text/html" } });
      body.innerHTML = await resp.text();
    } catch (e) {
      body.innerHTML = '<div class="dim" style="padding: 12px;">' +
                       'Failed to load: ' + e.message + '</div>';
    }
  }
  document.addEventListener("click", function (ev) {
    var cell = ev.target.closest("[data-heatmap-cell]");
    if (!cell) return;
    ev.stopPropagation();
    var host = cell.getAttribute("data-host");
    var hour = parseInt(cell.getAttribute("data-hour"), 10);
    if (!host || isNaN(hour)) return;
    openCellModal(host, hour);
  });

  window.addEventListener("storage", function (ev) {
    if (ev.key === STORE_RANGE || ev.key === STORE_KIND) refresh();
  });

  function init() {
    if (!findToolbar()) return;
    refresh();
  }
  init();
  var _actLastFetchMs = 0;
  var ACT_FETCH_MIN_INTERVAL_MS = 6000;
  var _actOrigRefresh = refresh;
  refresh = async function () {
    _actLastFetchMs = Date.now();
    return await _actOrigRefresh.apply(this, arguments);
  };
  window.plenithApplyActivity = function () {
    if (!findToolbar()) return;
    var range = getRange();
    var kind  = getKind();
    document.querySelectorAll("[data-act-range]").forEach(function (b) {
      var on = b.getAttribute("data-act-range") === range;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    document.querySelectorAll("[data-act-kind]").forEach(function (b) {
      var on = b.getAttribute("data-act-kind") === kind;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
    if (Date.now() - _actLastFetchMs >= ACT_FETCH_MIN_INTERVAL_MS) {
      refresh();
    }
  };
  var _actOrig = window.plenithReapplyClientState;
  window.plenithReapplyClientState = function () {
    if (typeof _actOrig === "function") _actOrig();
    if (window.plenithApplyActivity) window.plenithApplyActivity();
  };
})();
"""
