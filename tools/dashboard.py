"""Live SOC dashboard — tail the deception fabric in real time.

Plain stdlib http.server. Reads state-docker/{persistence,logs}/ plus the
plenith-dns container log, renders everything into one auto-refreshing
HTML page. No JS framework, no external deps, no build step.

Usage:
    python tools/dashboard.py                # serve on http://127.0.0.1:8765
    python tools/dashboard.py --port 9000
    python tools/dashboard.py --refresh 5    # seconds between auto-reloads

Open in any browser. Drive an attack against the proxy on :22000 in a
second terminal; the page reflects new state on the next refresh tick.
"""
import argparse
import html
import importlib.util
import io
import json
import socket
import subprocess
import sys
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_STATE_DIR = _ROOT / "state-docker" / "persistence"
_LOGS_BASE = _ROOT / "state-docker" / "logs"
_PERSONAS  = _ROOT / "personas"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError, OSError):
    pass


def _load_audit():
    spec = importlib.util.spec_from_file_location("audit", _ROOT / "tools" / "audit.py")
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    return audit


_SEV_COLOR = {
    "critical": "#d63b3b",
    "high":     "#e8851e",
    "medium":   "#d8b91a",
    "info":     "#3aa6c2",
}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def _gather() -> dict:
    """Walk the state + logs dirs once and return a render-ready dict."""
    sys.path.insert(0, str(_ROOT))
    audit = _load_audit()

    # Multi-host logs layout: state-docker/logs/<hostname>/*.json
    logs_dirs = [d for d in _LOGS_BASE.iterdir() if d.is_dir()] if _LOGS_BASE.exists() else []
    engagements = []
    for d in logs_dirs:
        for e in audit.load_engagements(_STATE_DIR, d, _PERSONAS):
            e["_host"] = d.name
            engagements.append(e)
    engagements.sort(key=lambda e: e.get("last_seen_at", 0), reverse=True)

    # Aggregate alert counts globally for the top counter
    sev_totals = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    actions_by_eng = {}
    for d in logs_dirs:
        for log_file in sorted(d.glob("*.json")):
            try:
                data = json.loads(log_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for a in data.get("actions_taken", []):
                sev_totals[a.get("severity", "info")] = sev_totals.get(a.get("severity", "info"), 0) + 1

    # Per-engagement action lists keyed by eng_id
    for d in logs_dirs:
        for log_file in sorted(d.glob("*.json")):
            try:
                data = json.loads(log_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            eng_id = data.get("engagement_id")
            actions_by_eng.setdefault(eng_id, []).extend(data.get("actions_taken", []))

    # Container roster
    ps = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}|{{.Status}}"],
        capture_output=True, text=True, timeout=4,
    )
    containers = []
    for line in ps.stdout.strip().split("\n"):
        if "|" in line:
            name, status = line.split("|", 1)
            containers.append({"name": name, "status": status})

    # CoreDNS log slice — exfil-flavored queries
    dlog = subprocess.run(
        ["docker", "logs", "--tail", "120", "plenith-dns"],
        capture_output=True, text=True, timeout=4,
    )
    dns_lines = [
        l for l in (dlog.stdout + dlog.stderr).splitlines()
        if "172.30.0." in l and ("NOERROR" in l or "->" in l)
    ][-30:]

    # Content rotator signature
    from plenith.rotation import ContentRotator, DeploymentSeed
    rot = ContentRotator.from_seed(DeploymentSeed("mc-demo-installation-001", "2026Q2"))

    return {
        "engagements":   engagements,
        "actions_by_eng": actions_by_eng,
        "sev_totals":    sev_totals,
        "containers":    containers,
        "dns_lines":     dns_lines,
        "rotation":      {
            "corp_name":   rot.corp.corp_name,
            "corp_domain": rot.corp.corp_domain,
            "industry":    rot.corp.industry_long,
            "subnet":      rot.corp.prod_subnet,
            "signature":   rot.signature(),
        },
        "now":            datetime.now().strftime("%H:%M:%S"),
    }


def _render_main_panels(state: dict) -> str:
    """Just the dynamic panel HTML (engagements + containers + DNS).
    Returned without the topbar / style block so we can swap it into
    the page via SSE without re-painting the whole DOM."""
    # Render engagements
    eng_html = []
    if not state["engagements"]:
        eng_html.append('<div class="card" style="color:#7a8590;">'
                        'No engagements yet — connect with <code>ssh -p 22000 jdoe@127.0.0.1</code></div>')

    for e in state["engagements"]:
        eng_id = e["engagement_id"]
        actions = state["actions_by_eng"].get(eng_id, [])
        sevs = {a.get("severity") for a in actions}
        sev_cls = "crit" if "critical" in sevs else (
                  "high" if "high" in sevs else (
                  "med"  if "medium" in sevs else ""))
        try:
            narr = e.get("narrative") or ""
            if not narr:
                audit = _load_audit()
                narr = audit.build_narrative(e)
            import re as _re
            narr = _re.sub(r"\x1b\[[0-9;]*m", "", narr)
        except Exception:
            narr = "?"
        seen = {}
        for a in actions:
            seen.setdefault(a["action"], a.get("severity", "info"))
        action_pills = []
        for act_name, sev in sorted(seen.items(),
                                      key=lambda kv: (_SEV_RANK.get(kv[1], 9), kv[0])):
            color = _SEV_COLOR.get(sev, "#666")
            action_pills.append(
                f'<span class="pill" style="background:{color};">{html.escape(act_name)}</span>'
            )
        ip = e.get("source_ip", "?")
        user = e.get("claimed_user", "?")
        conns = e.get("connection_count", "?")
        host = e.get("_host", "?")
        dwell = e.get("dwell_seconds", 0)
        eng_html.append(f"""
        <div class="eng {sev_cls}">
            <h3>{html.escape(eng_id[:8])} &nbsp;
                <span style="color:#8a9ba8;font-size:12px;">
                  {html.escape(user)}@{html.escape(ip)}
                  on {html.escape(host)}
                  · {dwell}s dwell · conn#{conns}
                </span>
            </h3>
            <div class="narr">{html.escape(narr)}</div>
            <div class="actions">{' '.join(action_pills) or '<em style="color:#5d6878;">(no alerts fired)</em>'}</div>
        </div>
        """)

    sev_strip = " ".join(
        f'<span class="pill" style="background:{_SEV_COLOR[s]};">'
        f'{state["sev_totals"][s]} {s}</span>'
        for s in ("critical", "high", "medium", "info")
        if state["sev_totals"][s] > 0
    ) or '<em style="color:#5d6878;">no alerts yet</em>'

    rows = []
    for c in state["containers"]:
        cls = "ok" if c["status"].startswith("Up") else "bad"
        rows.append(
            f'<tr><td>{html.escape(c["name"])}</td>'
            f'<td class="{cls}">{html.escape(c["status"])}</td></tr>'
        )
    container_table = "<table class='containers'>" + "".join(rows) + "</table>"

    dns_html = []
    for l in state["dns_lines"]:
        cls = "exfil" if any(s in l for s in ("oast", "burpcoll", "interactsh")) else ""
        dns_html.append(f'<span class="{cls}">{html.escape(l)}</span>')
    dns_block = "<pre class='dns'>" + "\n".join(dns_html) + "</pre>" if dns_html else (
        "<pre class='dns'>(empty)</pre>"
    )

    return f"""
<div id="sev-strip" style="margin:14px 0;">{sev_strip}</div>
<div class="grid">
    <div>
        <h2>Engagements ({len(state['engagements'])})</h2>
        {''.join(eng_html)}
    </div>
    <div>
        <h2>Bubble containers</h2>
        <div class="card">{container_table}</div>
        <h2>CoreDNS query log (last 30)</h2>
        {dns_block}
    </div>
</div>
"""


def _render(state: dict, refresh: int, sse: bool = True) -> str:
    """Build the full HTML page. The dynamic panels live under
    <div id="panels"> so the SSE handler can swap that subtree on every
    push without re-painting the topbar or the <style> block."""
    css = """
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace, sans-serif;
               background: #0f1116; color: #e6e6e6; margin: 0; padding: 18px; }
        h1 { margin: 0 0 6px 0; font-size: 18px; letter-spacing: 0.5px; }
        h2 { margin: 18px 0 8px 0; font-size: 13px; text-transform: uppercase;
             letter-spacing: 1.2px; color: #8a9ba8; }
        .topbar { display: flex; gap: 24px; align-items: baseline;
                  border-bottom: 1px solid #2a3140; padding-bottom: 10px; }
        .topbar .meta { color: #8a9ba8; font-size: 12px; }
        .pill { display: inline-block; padding: 1px 8px; border-radius: 10px;
                font-size: 11px; font-weight: 600; margin-right: 6px;
                color: #fff; }
        .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 18px; }
        .card { background: #161924; border: 1px solid #2a3140; border-radius: 6px;
                padding: 14px 16px; margin-bottom: 14px; }
        .eng { border-left: 4px solid #3aa6c2; padding-left: 12px; margin: 12px 0; }
        .eng.crit { border-left-color: #d63b3b; }
        .eng.high { border-left-color: #e8851e; }
        .eng.med  { border-left-color: #d8b91a; }
        .eng h3 { margin: 0; font-size: 14px; }
        .eng .narr { color: #b6c3cd; margin-top: 4px; font-size: 13px; }
        .actions { margin-top: 8px; }
        table.containers { width: 100%; font-size: 12px; border-collapse: collapse; }
        table.containers td { padding: 3px 6px; border-bottom: 1px solid #1d212c; }
        table.containers td.ok { color: #3ddc97; }
        table.containers td.bad { color: #d63b3b; }
        pre.dns { background: #0a0c11; border: 1px solid #2a3140; border-radius: 4px;
                  padding: 8px; font-size: 11px; max-height: 320px; overflow-y: auto;
                  white-space: pre-wrap; }
        .dns .exfil { color: #e8851e; font-weight: 600; }
        .footer { color: #4d5868; font-size: 11px; margin-top: 20px;
                  text-align: center; }
        a { color: #6cb6ff; }
    """

    rot = state["rotation"]

    # SSE-mode page: no meta-refresh, EventSource subscribes to /api/stream
    # and swaps the #panels container. Legacy mode keeps the meta-refresh
    # for old browsers / curl tests.
    if sse:
        refresh_meta = ""
        refresh_label = "live (SSE)"
        sse_script = """
<script>
  const es = new EventSource("/api/stream");
  const panels = document.getElementById("panels");
  const ts = document.getElementById("ts");
  let dropouts = 0;
  es.onmessage = function(e) {
    try {
      const data = JSON.parse(e.data);
      if (data.html) panels.innerHTML = data.html;
      if (data.ts)   ts.textContent  = data.ts;
      dropouts = 0;
    } catch (err) { /* swallow */ }
  };
  es.onerror = function() {
    dropouts += 1;
    ts.textContent = "reconnecting ... (" + dropouts + ")";
    // EventSource auto-reconnects after a server-side close; we just
    // surface that the connection is unstable.
  };
</script>
"""
    else:
        refresh_meta = f'<meta http-equiv="refresh" content="{refresh}">'
        refresh_label = f"auto-refresh {refresh}s"
        sse_script = ""

    # The dynamic panel HTML — same content; on SSE-mode the JS will
    # replace this on every push.
    panel_html = _render_main_panels(state)

    return f"""<!doctype html>
<html><head>
<meta charset="utf-8">
{refresh_meta}
<title>Plenith SOC</title>
<style>{css}</style>
</head><body>

<div class="topbar">
    <h1>Plenith SOC</h1>
    <span class="meta">
        deployment <b>{html.escape(rot['corp_name'])}</b>
        ({html.escape(rot['corp_domain'])}) · sig {html.escape(rot['signature'])} ·
        prod {html.escape(rot['subnet'])} ·
        last refresh <span id="ts">{state['now']}</span> ·
        {refresh_label}
    </span>
</div>

<div id="panels">{panel_html}</div>

<div class="footer">
    Live view. Drive an attack with
    <code>ssh -p 22000 jdoe@127.0.0.1</code> in another terminal.
</div>

{sse_script}
</body></html>"""


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that doesn't print a stack trace when a client
    disconnects mid-request. Browser tabs holding /api/stream long-polls
    drop the socket on close/refresh — on Windows that surfaces as
    ConnectionAbortedError (WinError 10053), on Linux as ConnectionResetError
    or BrokenPipeError. All three are benign here; only real bugs deserve
    a traceback."""

    _SILENCED = (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, self._SILENCED):
            return
        super().handle_error(request, client_address)


class Handler(BaseHTTPRequestHandler):
    refresh: int = 3
    sse_enabled: bool = True   # set False to fall back to meta-refresh

    def log_message(self, fmt, *args):  # quiet the default access log
        return

    def handle_one_request(self):
        """First line of defense: catch the disconnect close to the source
        so the keep-alive loop terminates cleanly. The server's
        handle_error override is the backstop for anything that slips past."""
        try:
            super().handle_one_request()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            # When SSE is enabled, the HTML page subscribes to /api/stream
            # and the meta-refresh is omitted; the page updates without
            # full reloads. When disabled (legacy), the old meta-refresh
            # behavior is preserved.
            body = _render(_gather(), Handler.refresh,
                            sse=Handler.sse_enabled).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/state.json":
            body = json.dumps(_gather(), default=str, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/stream":
            # Server-Sent Events — long-lived response, emit one event
            # every `refresh` seconds with the latest state-fragment HTML.
            # The browser's EventSource handles reconnect on its own.
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")   # disable nginx buffering
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                while True:
                    snapshot = _gather()
                    # The HTML fragment the client will swap in. Wrap with
                    # JSON so newlines survive SSE framing.
                    payload = {
                        "html": _render_main_panels(snapshot),
                        "ts":   snapshot["now"],
                    }
                    line = "data: " + json.dumps(payload) + "\n\n"
                    try:
                        self.wfile.write(line.encode("utf-8"))
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                        return    # client disconnected
                    time.sleep(Handler.refresh)
            except Exception:
                return
        else:
            self.send_error(404)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--refresh", type=int, default=3,
                   help="seconds between auto-reloads (default 3)")
    p.add_argument("--no-open", action="store_true",
                   help="don't open a browser window automatically")
    args = p.parse_args()

    Handler.refresh = args.refresh
    # ThreadingHTTPServer so /api/stream's long-poll doesn't block other
    # endpoints (in particular: the same browser tab needs to GET / first
    # to receive the JS, and only then opens an EventSource).
    server = QuietThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True   # don't keep the process alive on Ctrl-C
    url = f"http://{args.host}:{args.port}/"
    print(f"\n  Plenith SOC dashboard listening on {url}")
    print(f"  Refresh interval: {args.refresh}s")
    # H-6 fix: the dashboard has no authentication and exposes every
    # engagement's attacker IoCs, command stream, and DNS-exfil log via
    # /api/state.json. Binding to anything other than loopback makes all
    # of that world-readable to anyone who can reach the port. Print a
    # loud warning so operators reaching for `--host 0.0.0.0` see what
    # they're doing. SECURITY.md flags this as out-of-scope, but a
    # banner on the listen line is much better defense than a
    # paragraph in a doc nobody reads.
    if args.host not in ("127.0.0.1", "::1", "localhost"):
        print(
            f"\n  WARNING: dashboard is bound to {args.host!r} — NOT "
            f"loopback. The dashboard has no authentication and serves "
            f"attacker IoCs, command streams,\n"
            f"  and credential-search terms. Anyone who can reach this "
            f"port can read every engagement. Put it behind a reverse "
            f"proxy with auth, or revert to --host 127.0.0.1.\n",
            file=sys.stderr,
        )
    print(f"  Ctrl-C to stop.\n")
    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  shutting down dashboard")
        server.server_close()


if __name__ == "__main__":
    main()
