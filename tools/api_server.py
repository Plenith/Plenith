"""CLI: run the Plenith REST API server.

Usage:
    python tools/api_server.py                       # 127.0.0.1:8080, no auth
    python tools/api_server.py --host 0.0.0.0 --port 8080
    PLENITH_API_TOKENS=secret123 python tools/api_server.py    # auth on
    python tools/api_server.py --workers 4 --reload

Schema:
    GET http://<host>:<port>/openapi.json    OpenAPI 3 spec
    GET http://<host>:<port>/docs            Swagger UI (try-it interactive)
    GET http://<host>:<port>/redoc           ReDoc (read-only doc browser)
"""
import argparse
import io
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

import yaml  # noqa: E402

from plenith.api import build_app  # noqa: E402
from plenith.secrets import SecretResolutionError, resolve as resolve_secrets  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--reload", action="store_true",
                   help="reload on code change (dev)")
    p.add_argument("--config", type=Path, default=_ROOT / "config.yaml")
    p.add_argument("--state-dir", type=Path,
                   default=_ROOT / "state-docker" / "persistence")
    p.add_argument("--logs-dir", type=Path,
                   default=_ROOT / "state-docker" / "logs")
    args = p.parse_args(argv)

    cfg = {}
    if args.config.exists():
        try:
            raw = yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            print(f"warning: bad config.yaml: {e}", file=sys.stderr)
            raw = {}
        # Resolve `<scheme>://...` references via plenith.secrets.
        # Plaintext values pass through; failure to resolve is fatal so
        # the service doesn't start with broken auth.
        try:
            cfg = resolve_secrets(raw)
        except SecretResolutionError as e:
            print(f"FATAL: secret resolution failed: {e}", file=sys.stderr)
            print("  See docs/SECRETS.md for reference syntax.",
                  file=sys.stderr)
            return 2

    app = build_app(
        cfg=cfg,
        state_dir=args.state_dir,
        logs_dir=args.logs_dir,
    )

    import uvicorn
    print(f"  Plenith API listening on http://{args.host}:{args.port}/", file=sys.stderr)
    print(f"  OpenAPI:  http://{args.host}:{args.port}/openapi.json", file=sys.stderr)
    print(f"  Swagger:  http://{args.host}:{args.port}/docs", file=sys.stderr)
    print(f"  ReDoc:    http://{args.host}:{args.port}/redoc", file=sys.stderr)

    # `--reload` requires an import path string, not an app object
    if args.reload:
        # In reload mode we re-import via the path
        uvicorn.run(
            "plenith.api.server:build_app",
            host=args.host, port=args.port, reload=True,
            factory=False,   # build_app is a factory taking cfg; we wrap differently
        )
    else:
        uvicorn.run(app, host=args.host, port=args.port, workers=args.workers,
                    log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
