import asyncio
import os
import sys
from pathlib import Path

import yaml

from plenith.llm_client import LMStudioClient
from plenith.orchestrator import Orchestrator
from plenith.persona import Persona
from plenith.plugins import discover_all, get_registry
from plenith.response_cache import ResponseCache
from plenith.rotation import ContentRotator
from plenith.secrets import SecretResolutionError, resolve as resolve_secrets
from plenith.sim_bot import SimulationBot
from plenith.ssh_server import serve, setup_logging
from plenith.state_store import StateStore

def main():
    setup_logging()
    cfg_path = Path(__file__).parent / "config.yaml"
    with open(cfg_path, encoding="utf-8") as f:
        raw_cfg = yaml.safe_load(f)
    # Resolve `<scheme>://...` references against the secrets backends
    # (env / file / vault / aws-sm). Plaintext values pass through.
    # See `docs/SECRETS.md` for the supported syntax.
    try:
        cfg = resolve_secrets(raw_cfg)
    except SecretResolutionError as e:
        print(f"FATAL: secret resolution failed: {e}", file=sys.stderr)
        print("  See docs/SECRETS.md for reference syntax + troubleshooting.",
              file=sys.stderr)
        raise SystemExit(2)

    llm = LMStudioClient(
        base_url=cfg["llm"]["base_url"],
        model=cfg["llm"]["model"],
        api_key=cfg["llm"]["api_key"],
        temperature=cfg["llm"]["temperature"],
        max_tokens=cfg["llm"]["max_tokens"],
        timeout_seconds=cfg["llm"]["timeout_seconds"],
    )
    cache = ResponseCache(cfg["paths"]["cache_file"])

    # Auto-discover every persona under personas/ so the sim bot's
    # `who`/`w`/`last` reflect the full fleet, not just whoever happens
    # to be authenticated as the attacker.
    personas_dir = Path(cfg["paths"]["personas_dir"])
    personas = [Persona.from_yaml(p) for p in sorted(personas_dir.glob("*.yaml"))]

    # Per-host hostname override — for the Linux fork, each agent container
    # sets PLENITH_HOSTNAME and we want every persona on this agent to
    # claim that hostname (so bash prompts, /etc/hostname, and auth.log
    # all reflect e.g. db-prod-01 vs api-prod-03 instead of the YAML default).
    hostname_override = os.environ.get("PLENITH_HOSTNAME")
    if hostname_override:
        for p in personas:
            p.hostname = hostname_override
        print(f"Hostname override applied: all personas now claim "
              f"hostname={hostname_override!r}", file=sys.stderr)

    sim_bot = SimulationBot(personas)
    print(f"Loaded {len(personas)} persona(s) for sim bot: "
          f"{[p.username for p in personas]}", file=sys.stderr)

    # Content rotation — defeats §8 risk row "synthetic data fingerprinting".
    # Reads `content.deployment_id` + `content.epoch` from config; if either
    # is missing, ContentRotator.disabled() is returned and executors fall
    # back to their static decoy bodies (zero behavior change).
    rotator = ContentRotator.from_config(cfg)
    if rotator.is_enabled:
        print(
            f"Content rotation: deployment={rotator.seed.deployment_id} "
            f"epoch={rotator.seed.epoch} signature={rotator.signature()} "
            f"corp={rotator.corp.corp_name!r}",
            file=sys.stderr,
        )
    else:
        print("Content rotation: disabled (no content.deployment_id in config)",
              file=sys.stderr)

    orchestrator = Orchestrator(llm, cache, sim_bot=sim_bot, rotator=rotator)
    state_store = StateStore(cfg["paths"]["state_dir"])
    print(f"Engagement state dir: {cfg['paths']['state_dir']}", file=sys.stderr)

    # Plugin discovery — pip-installed plugins via the
    # `plenith.plugins` entry-point group, plus drop-in *.py files
    # under ./plugins/ next to run.py. See docs/PLUGINS.md.
    plugin_dir = Path(__file__).parent / "plugins"
    counts = discover_all(plugin_dir=plugin_dir if plugin_dir.exists() else None)
    summary = get_registry().summary()
    if counts["entry_points"] or counts["path"]:
        print(
            f"Plugins loaded: {counts['entry_points']} via entry-points, "
            f"{counts['path']} via {plugin_dir.name}/ — {summary}",
            file=sys.stderr,
        )
    else:
        print("Plugins: none discovered (see docs/PLUGINS.md to add one)",
              file=sys.stderr)

    try:
        asyncio.run(serve(cfg, orchestrator, state_store=state_store))
    except KeyboardInterrupt:
        print("\nshutting down", file=sys.stderr)

if __name__ == "__main__":
    main()
