"""Retention enforcement — actually deletes data per the documented policy.

Documented in `docs/DATA_HANDLING.md`; enforced here. Without this
module, the retention guarantees in the DPIA (`docs/DPIA.md` §6 and §7)
are wishful thinking.

Operational shape:

  - `RetentionPolicy` — pure config; loaded from `config.yaml` or
    explicit kwargs. Default values match the DPIA.
  - `RetentionPlan` — what the executor WOULD do (paths, ages, sizes)
    given the current filesystem state. Computing the plan is read-only.
  - `apply_plan(plan, dry_run=False)` — does the deletion (or just
    reports the plan in dry-run).

The `tools/retention_purge.py` CLI wires these together with cron-
friendly exit codes + JSON output.

Three core principles:

1. **Read-only by default.** The plan is computed without side effects.
   Operators (or cron) explicitly opt in to deletion. A bug in the age
   math can never delete more than dry-run shows.
2. **Categorized.** Engagement logs, IoCs, API audit, heartbeats, and
   caches each have their own window. Lengthening one doesn't lengthen
   another.
3. **Hash chain preservation.** When we delete an engagement file we
   do NOT delete the entire history — we delete the FILE. The hash
   chain inside the file is intact. Cross-engagement chain (a future
   feature) would need different handling; out of scope here.

Failure isolation: a single file we can't delete (permissions, in-use
lock) is logged but doesn't abort the run. The CLI exit code reflects
"how many deletions succeeded / failed."
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar
from collections.abc import Callable, Iterable

logger = logging.getLogger("plenith.retention")

# Default retention windows (days). These match the DPIA. Tighten freely;
# loosen only after re-running the DPIA.
DEFAULT_WINDOWS: dict[str, int] = {
    "engagements":  90,    # state-docker/logs/<host>/*.json
    "persistence":  120,   # state-docker/persistence/*.json (engagement state)
    "ioc_archive":  365,   # state/ioc-archive/**/*.jsonl
    "api_audit":    730,   # state/audit/api_*.jsonl
    "heartbeats":   7,     # state-docker/persistence/heartbeats/*.json
    "cache":        180,   # caches/*.yaml / caches/*.json
}

# A category's filesystem layout. We resolve roots from config to keep
# this module unbound from any one deployment layout.
@dataclass(frozen=True)
class CategorySpec:
    name: str                   # used as the config key
    roots: list[Path]           # one or more directories to scan
    glob: str = "*.json"        # files within the roots to consider
    recursive: bool = True
    default_days: int = 90      # fallback if not set in config
    description: str = ""

def _build_default_specs(root: Path) -> list[CategorySpec]:
    """The canonical category list — keep in sync with DEFAULT_WINDOWS
    and docs/DATA_HANDLING.md."""
    return [
        CategorySpec(
            name="engagements",
            roots=[root / "state-docker" / "logs"],
            glob="*.json",
            recursive=True,
            default_days=90,
            description="Engagement logs (D1–D6 in DATA_HANDLING.md)",
        ),
        CategorySpec(
            name="persistence",
            roots=[root / "state-docker" / "persistence"],
            glob="*.json",
            # NOT recursive — recursive=True would catch heartbeats/
            # which has its own (shorter) policy
            recursive=False,
            default_days=120,
            description="Engagement state, keyed by (ip, user)",
        ),
        CategorySpec(
            name="ioc_archive",
            roots=[root / "state" / "ioc-archive"],
            glob="*.jsonl",
            recursive=True,
            default_days=365,
            description="STIX/TAXII IoC archive (D7)",
        ),
        CategorySpec(
            name="api_audit",
            roots=[root / "state" / "audit"],
            glob="api_*.jsonl",
            recursive=False,
            default_days=730,
            description="Operator audit log (D8)",
        ),
        CategorySpec(
            name="heartbeats",
            roots=[root / "state-docker" / "persistence" / "heartbeats"],
            glob="*.json",
            recursive=False,
            default_days=7,
            description="Agent heartbeats — short-lived",
        ),
        CategorySpec(
            name="cache",
            roots=[root / "caches"],
            glob="*",
            recursive=False,
            default_days=180,
            description="Response cache + sim-bot cache",
        ),
    ]

# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RetentionPolicy:
    """How long each category lives. All values in days."""
    windows: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_WINDOWS))

    # Short-form aliases the docs use (and that operators reach for).
    # Map alias → canonical category name. ClassVar marks this as a
    # class-level constant, not a dataclass field.
    _ALIASES: ClassVar[dict[str, str]] = {
        "ioc":           "ioc_archive",
        "ioc_days":      "ioc_archive",
    }

    @classmethod
    def from_config(cls, cfg: dict | None = None) -> RetentionPolicy:
        """Construct from a `retention:` block in `config.yaml`.

        Example block:
            retention:
              engagements_days: 60
              ioc_days:        180         # alias for ioc_archive_days
              api_audit_days:  365
              heartbeats_days: 3
              cache_days:      90
        """
        cfg = cfg or {}
        windows = dict(DEFAULT_WINDOWS)
        # Build the lookup map: every canonical name and its aliases.
        lookup_keys: dict[str, str] = {}    # config_key -> canonical name
        for canonical in windows:
            lookup_keys[canonical] = canonical
            lookup_keys[f"{canonical}_days"] = canonical
        for alias, canonical in cls._ALIASES.items():
            lookup_keys[alias] = canonical
        # Apply overrides
        for config_key, v in cfg.items():
            canonical = lookup_keys.get(config_key)
            if canonical is None:
                # Unknown key — ignore quietly (forwards-compat for new categories)
                continue
            if not isinstance(v, int) or v < 0:
                raise ValueError(
                    f"retention.{config_key} must be a non-negative int, "
                    f"got {v!r}"
                )
            windows[canonical] = v
        return cls(windows=windows)

    def days_for(self, category: str) -> int:
        if category not in self.windows:
            raise KeyError(f"unknown retention category: {category!r}")
        return self.windows[category]

    def seconds_for(self, category: str) -> float:
        return self.days_for(category) * 86400.0

# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

@dataclass
class FileEntry:
    """One file that has been considered for deletion."""
    path: Path
    age_seconds: float
    size_bytes: int

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "age_days": round(self.age_seconds / 86400.0, 2),
            "size_bytes": self.size_bytes,
        }

@dataclass
class CategoryPlan:
    name: str
    window_days: int
    to_delete: list[FileEntry] = field(default_factory=list)
    kept: int = 0
    missing_root: bool = False

    @property
    def total_bytes(self) -> int:
        return sum(e.size_bytes for e in self.to_delete)

    def to_dict(self) -> dict:
        return {
            "name":         self.name,
            "window_days":  self.window_days,
            "delete_count": len(self.to_delete),
            "delete_bytes": self.total_bytes,
            "kept_count":   self.kept,
            "missing_root": self.missing_root,
            "files":        [e.to_dict() for e in self.to_delete],
        }

@dataclass
class RetentionPlan:
    """All categories' plans rolled up."""
    by_category: dict[str, CategoryPlan] = field(default_factory=dict)
    computed_at: float = 0.0

    @property
    def total_files(self) -> int:
        return sum(len(c.to_delete) for c in self.by_category.values())

    @property
    def total_bytes(self) -> int:
        return sum(c.total_bytes for c in self.by_category.values())

    def to_dict(self) -> dict:
        return {
            "computed_at":  self.computed_at,
            "total_files":  self.total_files,
            "total_bytes":  self.total_bytes,
            "categories":   {k: c.to_dict() for k, c in self.by_category.items()},
        }

# ---------------------------------------------------------------------------
# Building the plan
# ---------------------------------------------------------------------------

def _iter_files(spec: CategorySpec) -> Iterable[Path]:
    for root in spec.roots:
        if not root.exists() or not root.is_dir():
            continue
        if spec.recursive:
            yield from (p for p in root.rglob(spec.glob) if p.is_file())
        else:
            yield from (p for p in root.glob(spec.glob) if p.is_file())

def build_plan(
    *,
    root: Path,
    policy: RetentionPolicy,
    specs: list[CategorySpec] | None = None,
    now: float | None = None,
    filter_predicate: Callable[[Path, dict], bool] | None = None,
) -> RetentionPlan:
    """Compute what `apply_plan` WOULD delete. Pure / read-only.

    `filter_predicate(path, parsed_json_or_empty_dict)` lets a caller
    add custom filtering (e.g. "delete only entries where source_ip
    matches X"). For non-JSON files (e.g. .yaml cache files), the dict
    is empty.
    """
    now = now if now is not None else time.time()
    specs = specs or _build_default_specs(root)
    plan = RetentionPlan(computed_at=now)

    for spec in specs:
        days = policy.days_for(spec.name)
        cp = CategoryPlan(name=spec.name, window_days=days)
        # Track whether any root is reachable.
        cp.missing_root = not any(r.exists() for r in spec.roots)
        cutoff_age = days * 86400.0
        for path in _iter_files(spec):
            try:
                st = path.stat()
            except OSError:
                continue
            age = now - st.st_mtime
            if age <= cutoff_age:
                cp.kept += 1
                continue
            # Optional content filter
            if filter_predicate is not None:
                parsed: dict = {}
                if path.suffix in {".json", ".jsonl"}:
                    try:
                        with path.open("r", encoding="utf-8") as f:
                            parsed = json.load(f) if path.suffix == ".json" else {}
                    except (OSError, json.JSONDecodeError):
                        parsed = {}
                if not filter_predicate(path, parsed):
                    cp.kept += 1
                    continue
            cp.to_delete.append(FileEntry(
                path=path, age_seconds=age, size_bytes=st.st_size,
            ))
        plan.by_category[spec.name] = cp

    return plan

# ---------------------------------------------------------------------------
# Applying the plan
# ---------------------------------------------------------------------------

@dataclass
class ApplyResult:
    deleted: int = 0
    failed: int = 0
    bytes_freed: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "deleted":     self.deleted,
            "failed":      self.failed,
            "bytes_freed": self.bytes_freed,
            "errors":      self.errors[:20],   # cap to keep output reasonable
            "error_count": len(self.errors),
        }

def apply_plan(plan: RetentionPlan, *, dry_run: bool = True) -> ApplyResult:
    """Delete the files in `plan.to_delete`. Returns an ApplyResult.

    In dry_run mode (default), NO files are deleted and the returned
    result reflects what *would* have happened.
    """
    result = ApplyResult()
    for cp in plan.by_category.values():
        for entry in cp.to_delete:
            if dry_run:
                # Account for it as if we'd deleted it so the CLI's
                # `--dry-run` output matches the real run's output.
                result.deleted += 1
                result.bytes_freed += entry.size_bytes
                continue
            try:
                os.remove(entry.path)
                result.deleted += 1
                result.bytes_freed += entry.size_bytes
            except OSError as e:
                result.failed += 1
                result.errors.append(f"{entry.path}: {e}")
                logger.exception("retention purge failed for %s", entry.path)
    return result

# ---------------------------------------------------------------------------
# Convenience: one-call interface
# ---------------------------------------------------------------------------

def purge(
    *,
    root: Path,
    policy: RetentionPolicy | None = None,
    specs: list[CategorySpec] | None = None,
    dry_run: bool = True,
    filter_predicate: Callable[[Path, dict], bool] | None = None,
) -> dict:
    """Build a plan, apply it, and return a serializable summary.

    The CLI wraps this; production code uses it via cron.
    """
    policy = policy or RetentionPolicy()
    plan = build_plan(
        root=root, policy=policy, specs=specs,
        filter_predicate=filter_predicate,
    )
    result = apply_plan(plan, dry_run=dry_run)
    return {
        "dry_run":    dry_run,
        "policy":     dict(policy.windows),
        "plan":       plan.to_dict(),
        "result":     result.to_dict(),
    }
