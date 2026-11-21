"""Streaming CloudTrail ingestion: directories, .json, .json.gz, .jsonl, .jsonl.gz.

CloudTrail files are not guaranteed to be time-ordered across (or inside) files, and rules need ordered events.
`stream_events` uses a time-skew and event-count-capped reorder buffer: an event is released once the newest event seen is more than
`skew_seconds` ahead of it. Anything arriving older than what has already been released is counted as `late`
and dropped so rules never receive retrograde time. Every rejected record is counted with a reason. JSONL is incremental; each JSON document is loaded whole."""
from __future__ import annotations
import gzip
import heapq
import json
import os
import zlib
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Iterator, List

from .models import Event, event_from_record

EXTS = (".json", ".json.gz", ".jsonl", ".jsonl.gz", ".gz")


@dataclass
class IngestStats:
    files: int = 0
    unreadable_files: int = 0
    records: int = 0
    accepted: int = 0
    late: int = 0
    capacity_releases: int = 0
    rejected: Counter = field(default_factory=Counter)
    examples: List[str] = field(default_factory=list)

    def reject(self, reason: str, example: str = "") -> None:
        self.rejected[reason] += 1
        if len(self.examples) < 10:
            self.examples.append(f"{reason}: {example[:120]}")

    def summary(self) -> Dict[str, Any]:
        return {"files": self.files, "unreadable_files": self.unreadable_files, "records": self.records,
                "accepted": self.accepted, "late": self.late, "capacity_releases": self.capacity_releases, "rejected": dict(self.rejected)}


def expand(paths: Iterable[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                out += [os.path.join(root, n) for n in names if n.endswith(EXTS)]
        else:
            out.append(p)
    return sorted(out)


def _open(path: str):
    return gzip.open(path, "rt", encoding="utf-8") if path.endswith(".gz") else open(path, encoding="utf-8")


def iter_records(paths: Iterable[str], stats: IngestStats) -> Iterator[Any]:
    for path in expand(paths):
        stats.files += 1
        try:
            if path.endswith((".jsonl", ".jsonl.gz")):
                with _open(path) as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            stats.records += 1
                            stats.reject("invalid JSON line", line)
            else:
                with _open(path) as f:
                    doc = json.load(f)
                if isinstance(doc, dict) and isinstance(doc.get("Records"), list):
                    yield from doc["Records"]
                elif isinstance(doc, list):
                    yield from doc
                elif isinstance(doc, dict) and "eventTime" in doc:
                    yield doc
                else:
                    stats.records += 1
                    stats.reject("document without Records (digest or unknown file)", path)
        except (OSError, EOFError, zlib.error, UnicodeDecodeError, json.JSONDecodeError) as e:
            stats.unreadable_files += 1
            stats.reject("unreadable file", f"{path}: {type(e).__name__}")


def stream_events(paths: Iterable[str], stats: IngestStats = None, skew_seconds: int = 300, max_buffer_events: int = 100000) -> Iterator[Event]:
    stats = stats if stats is not None else IngestStats()
    if skew_seconds < 0 or max_buffer_events < 1:
        raise ValueError("skew must be nonnegative and buffer capacity must be positive")
    skew = timedelta(seconds=skew_seconds)
    heap: List = []
    newest = None
    released = None
    n = 0
    for rec in iter_records(paths, stats):
        stats.records += 1
        try:
            ev = event_from_record(rec)
        except (KeyError, ValueError, TypeError) as e:
            stats.reject(str(e)[:60] or type(e).__name__, json.dumps(rec, default=str))
            continue
        stats.accepted += 1
        if released is not None and ev.time < released:
            stats.late += 1
            # Never send retrograde events to window/sequence detectors.
            continue
        n += 1
        heapq.heappush(heap, (ev.time, n, ev))
        newest = ev.time if newest is None or ev.time > newest else newest
        while heap and (newest - heap[0][0] > skew or len(heap) > max_buffer_events):
            if len(heap) > max_buffer_events:
                stats.capacity_releases += 1
            t, _, e = heapq.heappop(heap)
            released = t
            yield e
    while heap:
        t, _, e = heapq.heappop(heap)
        yield e
