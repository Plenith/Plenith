"""Concurrency + latency benchmark for the Plenith SSH honeypot.

Spawns N concurrent asyncssh clients, each running a fixed command sequence
against the running honeypot. Measures:
  - Per-command latency (p50, p95, p99, max) bucketed by source tag
  - Total commands per second across all sessions
  - Server-side errors (channel closed, timeouts, etc.)

Emits a JSON result file you can commit as a baseline. Re-run to detect
performance regressions when tuning the orchestrator or the LLM.

Usage:
    python tools/bench.py                       # 5 sessions x 20 cmds
    python tools/bench.py --sessions 20         # 20 concurrent attackers
    python tools/bench.py --commands 50         # 50 cmds per session
    python tools/bench.py --out bench-001.json  # save to file

Requires:
    - The Plenith server running on 127.0.0.1:2222
    - LM Studio running (some commands hit the LLM)
"""
import argparse
import asyncio
import io
import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

import asyncssh

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass


# A mixed workload covering cache-fast and LLM-slow paths in a roughly
# realistic ratio. Tweak this to model your real-attacker corpus.
_DEFAULT_COMMANDS = [
    ("whoami", "cache"),
    ("pwd", "cache"),
    ("id", "cache"),
    ("uname -a", "cache"),
    ("ls -la", "cache"),
    ("cat /etc/passwd", "vfs-read"),
    ("cat ~/.aws/credentials", "vfs-read"),
    ("cat ~/.bash_history", "vfs-read"),
    ("who", "sim-bot"),
    ("w", "sim-bot"),
    ("uptime", "sim-bot"),
    ("ps aux", "sim-bot"),
    ("netstat -tlnp", "sim-bot"),
    ("find /home/jdoe -name id_rsa", "find"),
    ("grep -r AKIA /home/jdoe", "grep"),
    ("echo data > /tmp/probe.txt", "vfs-write"),
    ("cat /tmp/probe.txt", "vfs-read"),
    ("ls /tmp", "ls"),
    ("rm /tmp/probe.txt", "vfs-rm"),
    ("exit", "exit"),
]


class SessionStats:
    def __init__(self, session_id):
        self.session_id = session_id
        self.timings = []           # list of (cmd, expected_src, latency_seconds)
        self.errors = []
        self.connect_ms = 0.0
        self.duration_s = 0.0


async def _read_until_prompt(proc, timeout=15.0, tail="$"):
    """Read until output ends with the prompt-tail char (or timeout)."""
    deadline = asyncio.get_event_loop().time() + timeout
    buf = []
    while asyncio.get_event_loop().time() < deadline:
        try:
            chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=0.5)
        except asyncio.TimeoutError:
            if buf and "".join(buf).rstrip(" ").endswith(tail):
                return True
            continue
        if not chunk:
            return False
        buf.append(chunk)
        if "".join(buf).rstrip(" ").endswith(tail):
            return True
    return False


async def run_one_session(idx, host, port, user, commands, ssh_timeout):
    stats = SessionStats(session_id=idx)
    t_start = time.time()
    try:
        t0 = time.time()
        async with asyncssh.connect(
            host, port=port, username=user, password=f"pw{idx}",
            known_hosts=None, client_keys=None, login_timeout=ssh_timeout,
        ) as conn:
            stats.connect_ms = (time.time() - t0) * 1000
            proc = await conn.create_process(term_type="xterm", term_size=(80, 24))
            await _read_until_prompt(proc, timeout=3.0)
            for cmd, expected_src in commands:
                tc = time.time()
                proc.stdin.write(cmd + "\n")
                got = await _read_until_prompt(proc, timeout=ssh_timeout)
                latency = time.time() - tc
                stats.timings.append((cmd, expected_src, latency))
                if not got and cmd != "exit":
                    stats.errors.append(f"timeout on {cmd!r}")
                if cmd == "exit":
                    break
            proc.close()
    except (asyncssh.Error, OSError) as exc:
        stats.errors.append(f"connection error: {exc}")
    finally:
        stats.duration_s = time.time() - t_start
    return stats


def _percentiles(values, ps=(50, 95, 99)):
    if not values:
        return {p: None for p in ps}
    s = sorted(values)
    out = {}
    for p in ps:
        # Type 7 percentile, simple
        if len(s) == 1:
            out[p] = s[0]
            continue
        k = (len(s) - 1) * (p / 100)
        f = int(k)
        c = min(f + 1, len(s) - 1)
        out[p] = s[f] + (s[c] - s[f]) * (k - f)
    return out


def summarize(all_stats, commands):
    total_commands = sum(len(s.timings) for s in all_stats)
    total_duration = max((s.duration_s for s in all_stats), default=0)
    by_src = defaultdict(list)
    for s in all_stats:
        for cmd, src, lat in s.timings:
            by_src[src].append(lat)
    by_src_summary = {}
    for src, lats in by_src.items():
        by_src_summary[src] = {
            "count": len(lats),
            "mean_ms": round(statistics.mean(lats) * 1000, 2),
            "p50_ms": round(_percentiles(lats, (50,))[50] * 1000, 2),
            "p95_ms": round(_percentiles(lats, (95,))[95] * 1000, 2),
            "p99_ms": round(_percentiles(lats, (99,))[99] * 1000, 2),
            "max_ms": round(max(lats) * 1000, 2),
        }
    return {
        "sessions": len(all_stats),
        "commands_per_session": len(commands),
        "total_commands": total_commands,
        "wall_clock_s": round(total_duration, 2),
        "throughput_cmds_per_sec": round(total_commands / total_duration, 2) if total_duration else 0,
        "errors": [e for s in all_stats for e in s.errors],
        "connect_latency_ms": {
            "mean": round(statistics.mean([s.connect_ms for s in all_stats]), 2),
            "max": round(max(s.connect_ms for s in all_stats), 2),
        },
        "by_source": dict(sorted(by_src_summary.items())),
    }


def render_text(summary):
    out = []
    out.append(f"sessions:    {summary['sessions']}")
    out.append(f"cmds/sess:   {summary['commands_per_session']}")
    out.append(f"total cmds:  {summary['total_commands']}")
    out.append(f"wall clock:  {summary['wall_clock_s']}s")
    out.append(f"throughput:  {summary['throughput_cmds_per_sec']} cmd/s")
    out.append(f"connect:     mean={summary['connect_latency_ms']['mean']}ms max={summary['connect_latency_ms']['max']}ms")
    out.append("")
    out.append(f"{'source':<14} {'count':>6} {'mean':>9} {'p50':>9} {'p95':>9} {'p99':>9} {'max':>9}")
    out.append("-" * 75)
    for src in sorted(summary["by_source"]):
        s = summary["by_source"][src]
        out.append(
            f"{src:<14} {s['count']:>6} "
            f"{s['mean_ms']:>7}ms {s['p50_ms']:>7}ms "
            f"{s['p95_ms']:>7}ms {s['p99_ms']:>7}ms {s['max_ms']:>7}ms"
        )
    if summary["errors"]:
        out.append("")
        out.append(f"errors ({len(summary['errors'])}):")
        for e in summary["errors"][:10]:
            out.append(f"  {e}")
        if len(summary["errors"]) > 10:
            out.append(f"  ... ({len(summary['errors']) - 10} more)")
    return "\n".join(out)


async def amain(args):
    cmds = _DEFAULT_COMMANDS
    if args.commands and args.commands < len(cmds):
        # Always keep the trailing `exit`
        cmds = cmds[: args.commands - 1] + [("exit", "exit")]
    elif args.commands and args.commands > len(cmds):
        # Cycle the workload to reach the requested length
        extra = args.commands - len(cmds) + 1
        cmds = cmds[:-1] + (cmds[:-1] * (extra // (len(cmds) - 1) + 1))[:extra] + [("exit", "exit")]

    print(f"Spinning up {args.sessions} concurrent session(s), {len(cmds)} cmd(s) each...")
    t0 = time.time()
    tasks = [
        run_one_session(i, args.host, args.port, args.user, cmds, args.timeout)
        for i in range(args.sessions)
    ]
    all_stats = await asyncio.gather(*tasks)
    elapsed = time.time() - t0
    # Override the per-session duration_s with the wall-clock of the bench
    # itself for throughput accounting (we want concurrent throughput, not
    # the max session duration).
    summary = summarize(all_stats, cmds)
    summary["wall_clock_s"] = round(elapsed, 2)
    summary["throughput_cmds_per_sec"] = round(summary["total_commands"] / elapsed, 2) if elapsed else 0
    return summary


def compare(current: dict, baseline: dict,
            *, tolerances: dict | None = None) -> dict:
    """Compare a fresh bench summary against a saved baseline.

    Returns a dict with:
        regressions   list of {source, metric, baseline, current, delta_pct}
        improvements  list of same shape (negative deltas)
        passed        bool — True if no regressions exceed tolerances

    Tolerances default to the `_meta.tolerances` block in the baseline
    file, or to reasonable hard-coded defaults if the baseline doesn't
    declare any. This factoring lets unit tests exercise the comparator
    without needing a real SSH server.
    """
    tol = tolerances or (baseline.get("_meta") or {}).get("tolerances") or {
        "p50_regression_pct":   25,
        "p95_regression_pct":   30,
        "p99_regression_pct":   50,
        "throughput_drop_pct":  20,
    }
    regressions: list = []
    improvements: list = []

    def _record(source: str, metric: str, base: float, cur: float,
                tol_pct: float, lower_is_better: bool = True):
        if base in (None, 0):
            return
        delta_pct = (cur - base) / base * 100.0
        # For metrics where lower is better (latency), positive delta is BAD.
        # For metrics where higher is better (throughput), invert the sign.
        regress_pct = delta_pct if lower_is_better else -delta_pct
        entry = {
            "source":   source,
            "metric":   metric,
            "baseline": base,
            "current":  cur,
            "delta_pct": round(delta_pct, 1),
        }
        if regress_pct > tol_pct:
            regressions.append({**entry, "tolerance_pct": tol_pct})
        elif regress_pct < -1.0:    # small improvement noise floor
            improvements.append(entry)

    # Per-source latency comparison
    for src, base_stats in (baseline.get("by_source") or {}).items():
        cur_stats = (current.get("by_source") or {}).get(src)
        if not cur_stats:
            continue
        _record(src, "p50_ms", base_stats.get("p50_ms"),
                cur_stats.get("p50_ms"), tol["p50_regression_pct"])
        _record(src, "p95_ms", base_stats.get("p95_ms"),
                cur_stats.get("p95_ms"), tol["p95_regression_pct"])
        _record(src, "p99_ms", base_stats.get("p99_ms"),
                cur_stats.get("p99_ms"), tol["p99_regression_pct"])

    # Throughput: higher is better
    base_tp = baseline.get("throughput_cmds_per_sec") or 0
    cur_tp  = current.get("throughput_cmds_per_sec") or 0
    _record("(all)", "throughput_cmds_per_sec", base_tp, cur_tp,
            tol["throughput_drop_pct"], lower_is_better=False)

    return {
        "regressions":  regressions,
        "improvements": improvements,
        "passed":       len(regressions) == 0,
        "tolerances":   tol,
    }


def render_comparison(report: dict) -> str:
    """Render a compare() report for human consumption."""
    out = []
    status = "PASS" if report["passed"] else "REGRESSION"
    out.append(f"=== bench comparison: {status} ===")
    out.append("")
    if report["regressions"]:
        out.append(f"Regressions ({len(report['regressions'])}):")
        for r in report["regressions"]:
            out.append(
                f"  {r['source']:<14s} {r['metric']:<20s}  "
                f"baseline={r['baseline']}  current={r['current']}  "
                f"delta={r['delta_pct']:+.1f}%  (tol={r['tolerance_pct']}%)"
            )
        out.append("")
    if report["improvements"]:
        out.append(f"Improvements ({len(report['improvements'])}):")
        for i in report["improvements"]:
            out.append(
                f"  {i['source']:<14s} {i['metric']:<20s}  "
                f"baseline={i['baseline']}  current={i['current']}  "
                f"delta={i['delta_pct']:+.1f}%"
            )
        out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--user", default="jdoe")
    ap.add_argument("--sessions", type=int, default=5)
    ap.add_argument("--commands", type=int, default=20)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--out", type=str, default=None,
                    help="JSON output path; if omitted, prints to stdout")
    ap.add_argument("--compare", type=Path, default=None,
                    metavar="BASELINE_PATH",
                    help="after the run, compare against this baseline JSON. "
                         "Exits 1 if any regression exceeds the tolerances "
                         "in the baseline's _meta.tolerances block (or the "
                         "hard-coded defaults).")
    args = ap.parse_args()
    summary = asyncio.run(amain(args))
    text = render_text(summary)
    print(text)
    if args.out:
        Path(args.out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"\n(JSON written to {args.out})")
    if args.compare:
        try:
            baseline = json.loads(args.compare.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: can't read baseline {args.compare}: {e}", file=sys.stderr)
            return 2
        report = compare(summary, baseline)
        print()
        print(render_comparison(report))
        return 0 if report["passed"] else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
