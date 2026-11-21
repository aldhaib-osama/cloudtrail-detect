"""Throughput and memory benchmark on a lazily generated synthetic stream (never materialised as a list).
Numbers depend on the machine and on this synthetic traffic shape; they are not a capacity claim."""
from __future__ import annotations
import random
import time
import tracemalloc
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator

from .dsl import load_rule_files
from .labelled import RULES_FILE
from .models import event_from_record
from .pipeline import Pipeline
from .rules import default_rules
from .simulate import _rec

CALLS = [("s3.amazonaws.com", "GetObject"), ("ec2.amazonaws.com", "DescribeInstances"), ("sts.amazonaws.com", "GetCallerIdentity"),
         ("logs.amazonaws.com", "PutLogEvents"), ("dynamodb.amazonaws.com", "Query"), ("secretsmanager.amazonaws.com", "GetSecretValue")]


def records(n: int, seed: int = 1, principals: int = 5000) -> Iterator[dict]:
    rnd = random.Random(seed)
    t = datetime(2026, 4, 1, tzinfo=timezone.utc)
    for i in range(n):
        if i % 40 == 0:
            t += timedelta(seconds=1)
        u = f"user{rnd.randrange(principals)}"
        src, name = rnd.choice(CALLS)
        err = "AccessDenied" if rnd.random() < 0.01 else None
        yield _rec(t, src, name, u, f"10.{rnd.randrange(256)}.{rnd.randrange(256)}.{rnd.randrange(256)}", error=err)


def run(n: int = 200_000, memory: bool = False, principals: int = 5000) -> Dict[str, Any]:
    if n < 1 or principals < 1:
        raise ValueError("events and principals must be positive")
    pipe = Pipeline(default_rules() + load_rule_files([str(RULES_FILE)]))
    if memory:
        tracemalloc.start()
    t0 = time.perf_counter()
    alerts = 0
    for rec in records(n, principals=principals):
        alerts += len(pipe.process(event_from_record(rec)))
    dt = time.perf_counter() - t0
    peak = None
    if memory:
        peak = round(tracemalloc.get_traced_memory()[1] / 1e6, 1)
        tracemalloc.stop()
    evicted = sum(getattr(getattr(r, "state", None), "evicted", 0) for r in pipe.rules)
    return {"events": n, "seconds": round(dt, 2), "events_per_second": int(n / dt), "alerts": alerts,
            "peak_python_heap_mb": peak, "dsl_lru_evictions": evicted, "distinct_principals": principals,
            "note": "synthetic stream; built-in Python rules keep unbounded per-key state, DSL rules are LRU-bounded"}
