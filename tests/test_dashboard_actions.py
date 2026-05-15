"""The dashboard's stdlib POST handlers were the one untested seam:
test_dashboard_sse.py only covers rendering, and test_api.py covers the
*FastAPI* equivalents — not tools/dashboard.py's own _handle_snapshot /
_handle_kill / _handle_escalate / _handle_mfa_decision routing.

These spin the real QuietThreadingHTTPServer on an ephemeral port and
drive it over HTTP exactly as the dashboard's own JS does, asserting
both the response and the on-disk side-effect. Hermetic: state dirs,
the kill/snapshot/acks/notes singletons, and _ROOT are all redirected
into tmp; the real audit module is reused so escalate's _gather()
resolves without depending on the repo's live state-docker/.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from plenith.acks import reset_default_store_for_tests as _reset_acks
from plenith.kill_queue import reset_default_queue_for_tests as _reset_kill
from plenith.notes import reset_default_store_for_tests as _reset_notes
from plenith.snapshots import reset_default_writer_for_tests as _reset_snap

_ROOT = Path(__file__).resolve().parent.parent

EID = "abc12345-0000-0000-0000-000000000001"
IP = "192.0.2.99"


def _load_dashboard():
    sys.path.insert(0, str(_ROOT / "tools"))
    spec = importlib.util.spec_from_file_location(
        "dashboard", _ROOT / "tools" / "dashboard.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_real_audit(orig_root: Path):
    spec = importlib.util.spec_from_file_location(
        "audit", orig_root / "tools" / "audit.py",
    )
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    return audit


def _seed_state(base: Path):
    """Mirror test_api.py's synthetic engagement so audit.load_engagements
    resolves it for the escalate path."""
    state_dir = base / "persistence"
    logs_dir = base / "logs" / "bastion-prod"
    personas = base / "personas"
    state_dir.mkdir(parents=True)
    logs_dir.mkdir(parents=True)
    personas.mkdir(parents=True)

    (personas / "jdoe.yaml").write_text(
        "username: jdoe\nhostname: bastion-prod\nfull_name: J. Doe\n"
        "home: /home/jdoe\nshell: /bin/bash\nuid: 1001\ngroups: [jdoe]\n",
        encoding="utf-8",
    )
    now = time.time()
    eng = {
        "engagement_id": EID,
        "claimed_user": "jdoe",
        "source_ip": IP,
        "persona": "jdoe",
        "first_seen_at": now - 60,
        "last_seen_at": now,
        "connection_count": 2,
        "cwd": "/home/jdoe",
        "observed": {"ran_sudo": True, "attacker_likely_llm": True,
                     "attacker_llm_confidence": 0.78},
    }
    (state_dir / f"{IP}__jdoe.json").write_text(json.dumps(eng),
                                                encoding="utf-8")
    log = {
        "engagement_id": EID, "claimed_user": "jdoe", "source_ip": IP,
        "actions_taken": [
            {"action": "alert_attacker_llm_detected", "severity": "critical",
             "rationale": "counter-AI 0.78", "ts_offset_s": 30.0,
             "triggered_by": "counter-AI heuristic"},
        ],
        "commands": [{"cmd": "whoami"}, {"cmd": "sudo -l"}],
    }
    (logs_dir / f"{int(now)}.json").write_text(json.dumps(log),
                                               encoding="utf-8")
    return state_dir, logs_dir.parent, personas


@pytest.fixture
def dash(tmp_path, monkeypatch):
    mod = _load_dashboard()
    orig_root = mod._ROOT          # real repo root — before we patch it
    real_audit = _load_real_audit(orig_root)

    base = tmp_path / "state"
    state_dir, logs_base, personas = _seed_state(base)

    # Redirect every path the handlers touch into tmp.
    monkeypatch.setattr(mod, "_ROOT", tmp_path)
    monkeypatch.setattr(mod, "_STATE_DIR", state_dir)
    monkeypatch.setattr(mod, "_LOGS_BASE", logs_base)
    monkeypatch.setattr(mod, "_PERSONAS", personas)
    # _gather() side-loads tools/audit.py from _ROOT; _ROOT is now tmp,
    # so hand it the real audit module instead.
    monkeypatch.setattr(mod, "_load_audit", lambda: real_audit)

    # Stores the handlers mutate — all into tmp.
    _reset_kill(tmp_path / "kill_requests.json")
    _reset_snap(base)                       # snapshots co-located w/ state
    _reset_acks(tmp_path / "acks.json")
    _reset_notes(tmp_path / "notes.json")

    server = mod.QuietThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    port = server.server_address[1]
    try:
        yield {"url": f"http://127.0.0.1:{port}", "mod": mod,
               "tmp": tmp_path, "base": base}
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=5)


def _req(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else b""
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(r, timeout=10)
        return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except json.JSONDecodeError:
            return e.code, {}


def test_snapshot_handler_writes_tarball(dash):
    status, body = _req("POST", f"{dash['url']}/api/engagements/{EID}/snapshot",
                         {"op_id": "mwilson"})
    assert status == 200
    assert body["engagement_id"] == EID
    assert body["name"].endswith(".tar.gz")
    assert body["size"] > 0 and "sha256" in body
    tarball = dash["base"] / "snapshots" / body["name"]
    assert tarball.exists() and tarball.stat().st_size == body["size"]


def test_kill_handler_queues_then_cancel_deletes(dash):
    q = dash["mod"]._kill_queue()
    status, body = _req("POST", f"{dash['url']}/api/engagements/{EID}/kill",
                         {"reason": "confirmed LLM"})
    assert status == 200
    assert body["status"] == "pending"
    assert EID in q.pending()

    status, body = _req("DELETE", f"{dash['url']}/api/engagements/{EID}/kill")
    assert status == 200
    assert body["removed"] is True
    assert EID not in q.pending()


def test_escalate_handler_resolves_engagement(dash):
    status, body = _req("POST",
                        f"{dash['url']}/api/engagements/{EID}/escalate",
                        {"tier": "L2", "message": "page L2"})
    assert status == 200
    assert body["engagement_id"] == EID
    # No state-docker/dashboard.cfg.json under tmp → preview, nothing fired.
    assert body["connectors_fired"] == []
    assert "alert_preview" in body


def test_escalate_unknown_engagement_404(dash):
    status, body = _req("POST",
                        f"{dash['url']}/api/engagements/no-such-eng/escalate",
                        {"tier": "L2"})
    assert status == 404
    assert "error" in body


def test_isolate_handler_writes_mfa_fail_file(dash):
    status, body = _req("POST", f"{dash['url']}/mfa/decisions/{IP}",
                         {"decision": "fail", "reason": "isolate test"})
    assert status == 200
    assert body["written"] is True
    fail_file = dash["tmp"] / "state-docker" / "mfa" / f"{IP}.fail"
    assert fail_file.exists()
    contents = fail_file.read_text(encoding="utf-8")
    assert f"ip={IP}" in contents and "decision=fail" in contents


def test_isolate_handler_rejects_non_ip(dash):
    status, body = _req("POST",
                        f"{dash['url']}/mfa/decisions/not-an-ip-address",
                        {"decision": "fail"})
    assert status == 400
    assert "error" in body
