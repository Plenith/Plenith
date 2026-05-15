import json
from pathlib import Path

from .audit_chain import stamp_session_chain

def write_session_log(logs_dir, session):
    """Serialize and write the engagement log.

    Before writing, we run the session dict through
    `audit_chain.stamp_session_chain` so every `actions_taken` entry
    carries `prev_hash` + `entry_hash` and the session record carries
    `chain_tip` + `chain_length` + `chain_version`. This is the
    on-disk tamper-evidence layer documented in
    `plenith/audit_chain.py`.
    """
    Path(logs_dir).mkdir(parents=True, exist_ok=True)
    path = Path(logs_dir) / f"{int(session.started_at)}_{session.id}.json"
    stamped = stamp_session_chain(session.to_dict())
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stamped, f, indent=2, default=str)
    return path
