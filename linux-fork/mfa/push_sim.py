"""Push-notification simulator service.

Stands in for Duo / Okta / Authy push approval. The MFA gateway POSTs
a push request and polls for the decision; out-of-band, the user (or a
script representing the user's phone) approves or denies the request.

In production this entire service is replaced by a SDK call into your
real push provider. The contract — request → token → poll(token) →
{pending|approved|denied|timeout} — is identical.

HTTP API (stdlib http.server, no Flask/FastAPI dep):

  POST   /push/request          {username, ip, ttl_seconds}
                                → {token, expires_at}
  POST   /push/approve/<token>  → 204
  POST   /push/deny/<token>     → 204
  GET    /push/poll/<token>     → {status: pending|approved|denied|expired,
                                   age_seconds, expires_in}
  GET    /push/list             → [{token, username, ip, status, age_seconds, expires_in}]

Configurable via env:
  PUSH_LISTEN_HOST   default 0.0.0.0
  PUSH_LISTEN_PORT   default 8080
  PUSH_DEFAULT_TTL   default 60     (push expires after this many seconds)
  PUSH_AUTO_DENY     default ""     (comma-separated usernames to auto-deny)
  PUSH_AUTO_APPROVE  default ""     (comma-separated usernames to auto-approve)
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional

log = logging.getLogger("push_sim")


LISTEN_HOST     = os.environ.get("PUSH_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT     = int(os.environ.get("PUSH_LISTEN_PORT", "8080"))
DEFAULT_TTL     = float(os.environ.get("PUSH_DEFAULT_TTL", "60"))
AUTO_DENY       = set(filter(None, os.environ.get("PUSH_AUTO_DENY", "").split(",")))
AUTO_APPROVE    = set(filter(None, os.environ.get("PUSH_AUTO_APPROVE", "").split(",")))


# ---------------------------------------------------------------------------
# In-memory state. Single-process; thread-safe via the lock below.
# ---------------------------------------------------------------------------

@dataclass
class PushRequest:
    token: str
    username: str
    ip: str
    status: str = "pending"   # pending | approved | denied | expired
    created_at: float = field(default_factory=time.time)
    ttl_seconds: float = DEFAULT_TTL

    def expires_at(self) -> float:
        return self.created_at + self.ttl_seconds

    def remaining(self) -> float:
        return max(0.0, self.expires_at() - time.time())

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at()

    def to_dict(self) -> dict:
        return {
            "token":      self.token,
            "username":   self.username,
            "ip":         self.ip,
            "status":     self.status if not self.is_expired() else "expired",
            "age_seconds": time.time() - self.created_at,
            "expires_in":  self.remaining(),
        }


_LOCK = threading.RLock()
_PUSHES: Dict[str, PushRequest] = {}


def _new_token() -> str:
    return secrets.token_urlsafe(16)


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def create_push(username: str, ip: str,
                ttl_seconds: Optional[float] = None) -> PushRequest:
    """Create a new push request. Applies auto-deny / auto-approve
    policy at creation time so unit tests don't have to wait."""
    ttl = ttl_seconds if ttl_seconds is not None else DEFAULT_TTL
    with _LOCK:
        token = _new_token()
        req = PushRequest(token=token, username=username, ip=ip, ttl_seconds=ttl)
        # Auto-policy: a deployment that has decided a user is high-risk
        # can pre-load AUTO_DENY; one that whitelists internal users can
        # pre-load AUTO_APPROVE. Useful for tests + canary deployments.
        if username in AUTO_DENY:
            req.status = "denied"
            log.info("auto-deny: user=%s ip=%s token=%s", username, ip, token[:8])
        elif username in AUTO_APPROVE:
            req.status = "approved"
            log.info("auto-approve: user=%s ip=%s token=%s", username, ip, token[:8])
        _PUSHES[token] = req
        return req


def get_push(token: str) -> Optional[PushRequest]:
    with _LOCK:
        return _PUSHES.get(token)


def approve(token: str) -> bool:
    with _LOCK:
        req = _PUSHES.get(token)
        if not req:
            return False
        if req.is_expired() or req.status not in ("pending", "approved"):
            return False
        req.status = "approved"
        log.info("approve: token=%s user=%s ip=%s", token[:8], req.username, req.ip)
        return True


def deny(token: str) -> bool:
    with _LOCK:
        req = _PUSHES.get(token)
        if not req:
            return False
        if req.is_expired() or req.status not in ("pending", "denied"):
            return False
        req.status = "denied"
        log.info("deny: token=%s user=%s ip=%s", token[:8], req.username, req.ip)
        return True


def list_pushes() -> list:
    with _LOCK:
        return [r.to_dict() for r in _PUSHES.values()]


def reset() -> None:
    """Test convenience: clear all pushes."""
    with _LOCK:
        _PUSHES.clear()


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

def _json_response(handler: BaseHTTPRequestHandler, code: int, body: dict) -> None:
    payload = json.dumps(body).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(payload)


def _no_content(handler: BaseHTTPRequestHandler, code: int = 204) -> None:
    handler.send_response(code)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


class _Handler(BaseHTTPRequestHandler):
    server_version = "PlenithPush/1.0"

    def log_message(self, fmt, *args):
        # Quiet the default access log; we use the module's logger instead.
        log.debug(fmt, *args)

    # --- POST /push/request, /push/approve/<token>, /push/deny/<token> ----
    def do_POST(self):
        path = self.path.rstrip("/")
        if path == "/push/request":
            try:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
            except (ValueError, json.JSONDecodeError):
                _json_response(self, 400, {"error": "bad JSON body"})
                return
            username = body.get("username") or "?"
            ip = body.get("ip") or "?"
            ttl = body.get("ttl_seconds")
            req = create_push(username, ip, ttl)
            _json_response(self, 201, {
                "token":      req.token,
                "expires_at": req.expires_at(),
                "status":     req.status,
            })
            return

        if path.startswith("/push/approve/"):
            token = path[len("/push/approve/"):]
            if approve(token):
                _no_content(self)
            else:
                _json_response(self, 404, {"error": "no such token, or already final"})
            return

        if path.startswith("/push/deny/"):
            token = path[len("/push/deny/"):]
            if deny(token):
                _no_content(self)
            else:
                _json_response(self, 404, {"error": "no such token, or already final"})
            return

        self.send_error(404)

    # --- GET /push/poll/<token>, /push/list -----------------------------
    def do_GET(self):
        path = self.path.rstrip("/")
        if path.startswith("/push/poll/"):
            token = path[len("/push/poll/"):]
            req = get_push(token)
            if req is None:
                _json_response(self, 404, {"error": "no such token"})
                return
            _json_response(self, 200, req.to_dict())
            return
        if path == "/push/list":
            _json_response(self, 200, {"pushes": list_pushes()})
            return
        if path in ("/", "/healthz"):
            _json_response(self, 200, {"ok": True})
            return
        self.send_error(404)


# ---------------------------------------------------------------------------
# Top-level server
# ---------------------------------------------------------------------------

def serve_forever():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s push: %(message)s",
    )
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), _Handler)
    log.info("push-sim listening on %s:%d (default TTL=%ss)",
             LISTEN_HOST, LISTEN_PORT, DEFAULT_TTL)
    if AUTO_DENY:
        log.info("AUTO_DENY users: %s", sorted(AUTO_DENY))
    if AUTO_APPROVE:
        log.info("AUTO_APPROVE users: %s", sorted(AUTO_APPROVE))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
        server.server_close()


if __name__ == "__main__":
    serve_forever()
