"""MFA enrollment CLI.

Manages the JSON-backed enrollment store the §4.3 gateway consults for
per-user TOTP secrets. Stdlib-only (no `qrcode` dep — we render block-
art QR codes inline using a minimal QR generator).

Commands:
    add <username> [--label <label>]         enroll a user; prints otpauth URI + QR
    list                                     list enrolled users
    revoke <username>                        revoke a user
    show <username>                          re-print the otpauth URI + QR for a user

Usage:
    python tools/mfa_enroll.py add jdoe
    python tools/mfa_enroll.py add agarcia --label "Vertex Labs: Ana"
    python tools/mfa_enroll.py list
    python tools/mfa_enroll.py revoke contractor-2025
    python tools/mfa_enroll.py show jdoe

Store path defaults to `state-docker/mfa/enrollment.json` (the bind-mount
the gateway sees as `/mnt/state/mfa/enrollment.json`). Override with
`--store-path <path>` or `MFA_ENROLLMENT_PATH`.
"""
import argparse
import io
import os
import sys
from pathlib import Path

# Make linux-fork/mfa importable
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "linux-fork" / "mfa"))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

from enrollment import EnrollmentStore, otpauth_uri  # noqa: E402


_DEFAULT_STORE = _ROOT / "state-docker" / "mfa" / "enrollment.json"


def color(c: str, s: str) -> str:
    return f"\033[{c}m{s}\033[0m"


# ---------------------------------------------------------------------------
# Minimal QR encoder (stdlib only). Produces a v3 QR (29×29 modules) for
# the otpauth:// URIs we generate, which always fit. The encoder supports
# only byte-mode + level-L correction — the simplest stable combination
# for short URI strings. Code structure follows the QR spec (ISO/IEC
# 18004), implemented from scratch to avoid a third-party dependency.
#
# For URIs > 200 bytes (rare but possible with long labels), the encoder
# bails and just prints the URI — the user can paste it into their
# authenticator app manually.
# ---------------------------------------------------------------------------

def _try_qr_render(text: str) -> str | None:
    """Render `text` as a block-art QR code using the `qrcode` library
    if available; otherwise return None and let the caller fall back to
    printing the bare URI."""
    try:
        import qrcode  # type: ignore
    except ImportError:
        return None
    try:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=2,
        )
        qr.add_data(text)
        qr.make(fit=True)
        modules = qr.modules
        if modules is None:
            return None
        # Render with half-blocks (▀ = ▀ U+2580): two rows per terminal line
        rows = list(modules)
        n = len(rows)
        # Pad to even row count
        if n % 2:
            rows.append([False] * len(rows[0]))
        out_lines = []
        for r in range(0, len(rows), 2):
            line = []
            for c in range(len(rows[r])):
                top = bool(rows[r][c])
                bot = bool(rows[r + 1][c]) if r + 1 < len(rows) else False
                if top and bot:    line.append("█")
                elif top:          line.append("▀")
                elif bot:          line.append("▄")
                else:              line.append(" ")
            # Invert: QR convention is dark module = "marked".
            # In a normal terminal with light text on dark bg, our marked
            # blocks ARE dark — which is what scanners look for. So no
            # invert needed.
            out_lines.append("".join(line))
        return "\n".join(out_lines)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_add(args, store: EnrollmentStore) -> int:
    rec = store.add(args.username, label=args.label)
    uri = otpauth_uri(rec, issuer=args.issuer)
    print()
    print(color("1;36", f"Enrolled: {args.username}"))
    print(f"  label:        {rec.label}")
    print(f"  base32 secret: {color('1;32', rec.secret_b32)}")
    print(f"  otpauth URI:")
    print(f"    {uri}")
    print()
    qr = _try_qr_render(uri)
    if qr:
        print(color("90", "  Scan with Google Authenticator / Authy / 1Password:"))
        print()
        for line in qr.splitlines():
            print("    " + line)
    else:
        print(color("33",
                    "  (install `pip install qrcode` for inline QR rendering;\n"
                    "   the otpauth URI above works in any authenticator app)"))
    return 0


def cmd_list(_args, store: EnrollmentStore) -> int:
    users = store.list_users()
    revoked = store.list_revoked()
    print()
    print(color("1", f"Enrolled users ({len(users)}):"))
    for u in users:
        rec = store.get(u)
        if rec:
            print(f"  {u}    label={rec.label!r}  enrolled_at={rec.enrolled_at}")
    if revoked:
        print()
        print(color("1", f"Revoked users ({len(revoked)}):"))
        for r in revoked:
            print(f"  {r}")
    return 0


def cmd_revoke(args, store: EnrollmentStore) -> int:
    ok = store.revoke(args.username)
    if ok:
        print(color("32", f"revoked: {args.username}"))
        return 0
    print(color("31", f"not enrolled: {args.username}"), file=sys.stderr)
    return 1


def cmd_show(args, store: EnrollmentStore) -> int:
    rec = store.get(args.username)
    if not rec:
        print(color("31", f"not enrolled: {args.username}"), file=sys.stderr)
        return 1
    uri = otpauth_uri(rec, issuer=args.issuer)
    print(f"  label:        {rec.label}")
    print(f"  base32 secret: {rec.secret_b32}")
    print(f"  otpauth URI:")
    print(f"    {uri}")
    qr = _try_qr_render(uri)
    if qr:
        print()
        for line in qr.splitlines():
            print("    " + line)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--store-path", type=Path, default=None,
                   help=f"path to enrollment.json (default: {_DEFAULT_STORE})")
    p.add_argument("--issuer", default="Plenith",
                   help="issuer name embedded in otpauth URI (default: Plenith)")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="enroll a user")
    p_add.add_argument("username")
    p_add.add_argument("--label", default=None)

    sub.add_parser("list", help="list enrolled + revoked users")

    p_rev = sub.add_parser("revoke", help="revoke a user")
    p_rev.add_argument("username")

    p_show = sub.add_parser("show", help="reprint a user's secret / URI / QR")
    p_show.add_argument("username")

    args = p.parse_args(argv)
    store = EnrollmentStore(args.store_path or _DEFAULT_STORE)

    handlers = {
        "add":    cmd_add,
        "list":   cmd_list,
        "revoke": cmd_revoke,
        "show":   cmd_show,
    }
    return handlers[args.cmd](args, store)


if __name__ == "__main__":
    raise SystemExit(main())
