from __future__ import annotations
import argparse
import json
import sys

from .engine import run, SEV_ORDER
from .models import load_events, event_from_record
from .simulate import generate
from .dsl import load_rule_files, RuleError
from .ingest import IngestStats, stream_events
from .pipeline import Pipeline, load_allowlist, AllowlistError
from .rules import default_rules


def evaluate(seed: int):
    recs, truth = generate(seed)
    events = sorted((event_from_record(r) for r in recs), key=lambda e: e.time)
    alerts = run(events)
    from collections import Counter
    def key(item):
        return (item["rule_id"], item["principal"], item["time"])
    got = Counter(key(a.to_dict()) for a in alerts)
    want = Counter(key(t) for t in truth)
    benign, _ = generate(seed, include_attacks=False)
    benign_alerts = run(sorted((event_from_record(r) for r in benign), key=lambda e: e.time))
    return {"events": len(events), "alerts": len(alerts), "expected_rules": sorted({t[0] for t in want}),
            "fired_rules": sorted({t[0] for t in got}), "benign_alerts": len(benign_alerts),
            "missed": list((want - got).elements()),
            "unexpected": list((got - want).elements()) + [key(a.to_dict()) for a in benign_alerts]}


def _main(argv=None):
    ap = argparse.ArgumentParser(prog="ctdetect")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan CloudTrail files")
    s.add_argument("files", nargs="+")
    s.add_argument("--min-severity", default="LOW", choices=list(SEV_ORDER))
    s.add_argument("--json", action="store_true")
    g = sub.add_parser("simulate", help="write synthetic logs (JSON lines)")
    g.add_argument("--seed", type=int, default=7)
    g.add_argument("--out", default="-")
    e = sub.add_parser("evaluate", help="generate labelled logs, run rules, report misses/false alerts")
    e.add_argument("--seed", type=int, default=7)
    s.add_argument("--rules", nargs="*", default=[], help="JSON rule files (DSL), added to the built-in rules")
    s.add_argument("--no-builtin", action="store_true", help="use only --rules")
    s.add_argument("--allowlist", help="JSON allowlist file (each entry needs a reason)")
    s.add_argument("--cooldown", type=int, default=0, help="suppress repeat alerts for the same rule+principal for N seconds")
    s.add_argument("--skew", type=int, default=300, help="reorder buffer in seconds for out-of-order files")
    s.add_argument("--max-buffer-events", type=int, default=100000, help="reorder buffer event-count cap")
    v = sub.add_parser("validate-rules", help="validate DSL rule files")
    v.add_argument("files", nargs="+")
    b = sub.add_parser("bench", help="throughput/memory benchmark on a synthetic stream")
    b.add_argument("--events", type=int, default=200000)
    b.add_argument("--memory", action="store_true")
    ev2 = sub.add_parser("evaluate-labelled", help="per-rule precision/recall on the labelled set with hard negatives")
    ev2.add_argument("--seed", type=int, default=7)
    a = ap.parse_args(argv)
    if a.cmd == "validate-rules":
        try:
            rules = load_rule_files(a.files)
        except (RuleError, OSError) as e:
            print(f"invalid: {e}", file=sys.stderr)
            return 1
        print(f"ok: {len(rules)} rule(s): " + ", ".join(r.id for r in rules))
        return 0
    if a.cmd == "bench":
        from .bench import run as bench_run
        print(json.dumps(bench_run(a.events, a.memory), indent=2))
        return 0
    if a.cmd == "evaluate-labelled":
        from .labelled import evaluate as ev_l
        rep = ev_l(a.seed)
        print(json.dumps(rep, indent=2))
        return 1 if rep["false_positives"] or rep["missed"] else 0
    if a.cmd == "simulate":
        recs, _ = generate(a.seed)
        f = sys.stdout if a.out == "-" else open(a.out, "w", encoding="utf-8")
        for r in recs:
            f.write(json.dumps(r) + "\n")
        return 0
    if a.cmd == "evaluate":
        rep = evaluate(a.seed)
        print(json.dumps(rep, indent=2))
        return 1 if rep["missed"] or rep["unexpected"] else 0
    try:
        rules = ([] if a.no_builtin else default_rules()) + load_rule_files(a.rules)
        allow = load_allowlist(a.allowlist) if a.allowlist else []
    except (RuleError, AllowlistError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not rules:
        raise ValueError("scan needs at least one rule")
    stats = IngestStats()
    pipe = Pipeline(rules, allow, a.cooldown, a.min_severity)
    alerts = list(pipe.run(stream_events(a.files, stats, a.skew, a.max_buffer_events)))
    dsl_diagnostics = {r.id: {"key_evictions": r.state.evicted, "event_drops": r.dropped_events}
                       for r in rules if hasattr(r, "state")}
    print(json.dumps({"ingest": stats.summary(), "pipeline": pipe.stats, "dsl": dsl_diagnostics}), file=sys.stderr)
    for u in pipe.unused_allowlist():
        print(f"warning: allowlist entry never matched: {u}", file=sys.stderr)
    if a.json:
        print(json.dumps([x.to_dict() for x in alerts], indent=2))
    else:
        for x in alerts:
            print(f"{x.time:%Y-%m-%d %H:%M:%S} [{x.severity:8}] {x.rule_id} {x.title} | {x.principal} | {x.detail} ({x.mitre})")
        print(f"{len(alerts)} alert(s)")
    if not stats.files or stats.unreadable_files or stats.rejected or stats.late or stats.capacity_releases or any(v["key_evictions"] or v["event_drops"] for v in dsl_diagnostics.values()):
        return 1
    return 2 if any(x.severity == "CRITICAL" for x in alerts) else 0


def main(argv=None):
    try:
        return _main(argv)
    except (OSError, ValueError, TypeError, AttributeError, OverflowError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
