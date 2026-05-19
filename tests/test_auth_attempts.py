"""Auth-attempt persistence.

The honeypot SSH layer sees every password attempt (validate_password)
but historically only emitted it to the app logger — it never reached
the durable session record, so post-hoc investigation couldn't see
credential-stuffing/spray. These tests pin the fix:

  1. validate_password records each attempt (hash ONLY — never the
     cleartext, per the H-3 rationale in ssh_server).
  2. attempts buffer per connection and the same password hashes
     stably (the "same password from two IPs" signal is preserved).
  3. Session carries auth_attempts and serializes it via to_dict()
     (so it rides the existing session-log + audit-chain path).
"""
from plenith.ssh_server import HoneypotServer


def test_validate_password_records_attempt_hash_only():
    srv = HoneypotServer()
    assert srv.auth_attempts == []
    srv.validate_password("root", "hunter2")
    srv.validate_password("admin", "hunter2")     # same pw, diff user
    srv.validate_password("root", "letmein")

    assert len(srv.auth_attempts) == 3
    a = srv.auth_attempts[0]
    assert a["username"] == "root"
    assert a["method"] == "password"
    assert "ts" in a and a["ts"] > 0
    # cleartext must NEVER be stored anywhere in the record (H-3).
    for rec in srv.auth_attempts:
        assert "password" not in rec
        assert "hunter2" not in rec.values()
        assert "letmein" not in rec.values()
    # same password -> same hash (cross-IP correlation signal kept);
    # different password -> different hash.
    assert srv.auth_attempts[0]["password_hash"] == \
        srv.auth_attempts[1]["password_hash"]
    assert srv.auth_attempts[0]["password_hash"] != \
        srv.auth_attempts[2]["password_hash"]


def test_session_serializes_auth_attempts(session):
    assert session.auth_attempts == []
    assert "auth_attempts" in session.to_dict()

    # Mirror what HoneypotSession.connection_made does: snapshot the
    # connection's buffered attempts onto the Session.
    srv = HoneypotServer()
    srv.validate_password("oracle", "oracle")
    session.auth_attempts = list(srv.auth_attempts)

    d = session.to_dict()
    assert len(d["auth_attempts"]) == 1
    assert d["auth_attempts"][0]["username"] == "oracle"
    assert d["auth_attempts"][0]["password_hash"]
    assert "oracle" != d["auth_attempts"][0]["password_hash"]
