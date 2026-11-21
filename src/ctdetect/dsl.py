"""Data-driven detection rules (JSON). Three rule types:

  match      one event satisfies `where`                                        -> alert
  threshold  >= `count` events (or `distinct` values of a field) satisfying     -> alert
             `where`, per `group_by` key, within `window_seconds`
  sequence   `steps` (2+) occur in order for the same key, each within
             `within_seconds` of the previous step                              -> alert

Predicates: {"field": "eventName", "op": "in", "value": [...]} with ops eq, ne, in, contains, startswith, endswith,
exists; combine with {"all": [...]}, {"any": [...]}, {"not": {...}}. Fields are dotted paths into the raw CloudTrail
record (for example userIdentity.type) plus the virtual fields principal, ip, name, source, denied.
There is deliberately no regex operator (avoids catastrophic-backtracking rules from untrusted rule files).

State per rule has an LRU key-count cap and a per-key event-count cap. Eviction/drop diagnostics indicate possible missed detections; these are count bounds, not byte limits."""
from __future__ import annotations
import json
from collections import OrderedDict, deque
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional

from .models import Alert, Event
from .rules import Rule

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
OPS = {"eq", "ne", "in", "contains", "startswith", "endswith", "exists"}
VIRTUAL = {"principal": lambda e: e.principal, "ip": lambda e: e.ip, "name": lambda e: e.name,
           "source": lambda e: e.source, "denied": lambda e: e.denied}


class RuleError(ValueError):
    pass


def get_field(ev: Event, path: str) -> Any:
    if path in VIRTUAL:
        return VIRTUAL[path](ev)
    cur: Any = ev.raw
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _compile_pred(p: Any, where: str) -> Callable[[Event], bool]:
    if not isinstance(p, dict):
        raise RuleError(f"{where}: predicate must be an object")
    if "all" in p or "any" in p:
        key = "all" if "all" in p else "any"
        if len(p) != 1 or not isinstance(p[key], list) or not p[key]:
            raise RuleError(f"{where}: '{key}' needs a non-empty list and no other keys")
        subs = [_compile_pred(x, where) for x in p[key]]
        return (lambda e: all(f(e) for f in subs)) if key == "all" else (lambda e: any(f(e) for f in subs))
    if "not" in p:
        if len(p) != 1:
            raise RuleError(f"{where}: 'not' takes no other keys")
        sub = _compile_pred(p["not"], where)
        return lambda e: not sub(e)
    if set(p) - {"field", "op", "value"} or "field" not in p or "op" not in p:
        raise RuleError(f"{where}: predicate needs field/op/value (got keys {sorted(p)})")
    if p.get("op") != "exists" and "value" not in p:
        raise RuleError(f"{where}: value is required")
    field, op, val = p["field"], p["op"], p.get("value")
    if not isinstance(field, str) or not field:
        raise RuleError(f"{where}: field must be a non-empty string")
    if not isinstance(op, str) or op not in OPS:
        raise RuleError(f"{where}: unknown op {op!r}; allowed: {sorted(OPS)}")
    if op in ("in",) and not isinstance(val, list):
        raise RuleError(f"{where}: op 'in' needs a list value")
    if op in ("contains", "startswith", "endswith") and not isinstance(val, str):
        raise RuleError(f"{where}: op {op!r} needs a string value")
    if op == "exists":
        return lambda e: get_field(e, field) is not None
    def f(e: Event) -> bool:
        v = get_field(e, field)
        if op == "eq": return v == val
        if op == "ne": return v != val
        if op == "in": return v in val
        if not isinstance(v, str):
            return False
        return (val in v) if op == "contains" else v.startswith(val) if op == "startswith" else v.endswith(val)
    return f


class _LRU(OrderedDict):
    def __init__(self, cap: int):
        super().__init__()
        self.cap = cap
        self.evicted = 0

    def touch(self, key, factory):
        if key in self:
            self.move_to_end(key)
            return self[key]
        self[key] = factory()
        if len(self) > self.cap:
            self.popitem(last=False)
            self.evicted += 1
        return self[key]


class DSLRule(Rule):
    def __init__(self, spec: Dict[str, Any]):
        if not isinstance(spec, dict):
            raise RuleError("rule must be an object")
        known = {"id", "title", "severity", "mitre", "type", "group_by", "max_keys", "max_events_per_key", "where", "count", "window_seconds", "distinct", "steps", "within_seconds"}
        if set(spec) - known:
            raise RuleError("unknown rule fields: " + str(sorted(set(spec) - known)))
        rid = spec.get("id")
        if not isinstance(rid, str) or not rid:
            raise RuleError("rule needs a string id")
        self.id = rid
        self.title = self._s(spec, "title")
        self.severity = spec.get("severity", "MEDIUM")
        if self.severity not in SEVERITIES:
            raise RuleError(f"{rid}: severity must be one of {SEVERITIES}")
        self.mitre = spec.get("mitre", "")
        if not isinstance(self.mitre, str):
            raise RuleError(f"{rid}: mitre must be text")
        self.type = spec.get("type")
        self.group_by = spec.get("group_by", "principal")
        if not isinstance(self.group_by, str) or not self.group_by:
            raise RuleError(f"{rid}: group_by must be a field name")
        self.max_keys = spec.get("max_keys", 10000)
        if not isinstance(self.max_keys, int) or isinstance(self.max_keys, bool):
            raise RuleError(f"{rid}: max_keys must be a positive integer")
        self.max_events_per_key = spec.get("max_events_per_key", 10000)
        if not isinstance(self.max_events_per_key, int) or isinstance(self.max_events_per_key, bool) or self.max_events_per_key < 1:
            raise RuleError(f"{rid}: max_events_per_key must be a positive integer")
        self.dropped_events = 0
        self.last_time = None
        if self.max_keys < 1:
            raise RuleError(f"{rid}: max_keys must be >= 1")
        w = f"rule {rid}"
        if self.type in ("match", "threshold"):
            self.where = _compile_pred(spec.get("where"), w + ".where")
        if self.type == "match":
            pass
        elif self.type == "threshold":
            self.count = self._pos(spec, "count")
            if self.count > self.max_events_per_key:
                raise RuleError(f"{rid}: count exceeds max_events_per_key")
            self.window = timedelta(seconds=self._pos(spec, "window_seconds"))
            self.distinct = spec.get("distinct")
            if self.distinct is not None and not isinstance(self.distinct, str):
                raise RuleError(f"{rid}: distinct must be a field name")
            self.state = _LRU(self.max_keys)
        elif self.type == "sequence":
            steps = spec.get("steps")
            if not isinstance(steps, list) or len(steps) < 2:
                raise RuleError(f"{rid}: sequence needs at least 2 steps")
            self.steps = [_compile_pred(s, f"{w}.steps[{i}]") for i, s in enumerate(steps)]
            self.within = timedelta(seconds=self._pos(spec, "within_seconds"))
            self.state = _LRU(self.max_keys)
        else:
            raise RuleError(f"{rid}: type must be match, threshold or sequence (got {self.type!r})")

    @staticmethod
    def _s(spec, k):
        if not isinstance(spec.get(k), str) or not spec[k]:
            raise RuleError(f"rule {spec.get('id')}: {k} must be a non-empty string")
        return spec[k]

    def _pos(self, spec, k):
        v = spec.get(k)
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            raise RuleError(f"{self.id}: {k} must be a positive integer")
        return v

    def process(self, ev: Event) -> List[Alert]:
        if self.last_time is not None and ev.time < self.last_time:
            raise ValueError("DSL rules require nondecreasing event time")
        self.last_time = ev.time
        key = get_field(ev, self.group_by)
        key = "" if key is None else str(key)
        if self.type == "match":
            return [self.alert(ev, "matched")] if self.where(ev) else []
        if self.type == "threshold":
            if not self.where(ev):
                return []
            if self.distinct and get_field(ev, self.distinct) is None:
                return []
            q = self.state.touch(key, deque)
            while q and ev.time - q[0][0] > self.window:
                q.popleft()
            if len(q) >= self.max_events_per_key:
                q.popleft()
                self.dropped_events += 1
            q.append((ev.time, str(get_field(ev, self.distinct)) if self.distinct else None))
            while q and ev.time - q[0][0] > self.window:
                q.popleft()
            n = len({v for _, v in q}) if self.distinct else len(q)
            if n >= self.count:
                q.clear()
                return [self.alert(ev, f"{n} {'distinct ' + self.distinct if self.distinct else 'matching events'} for {self.group_by}={key} in {int(self.window.total_seconds())}s")]
            return []
        # sequence: st = (next_step_index, time_of_last_completed_step)
        st = self.state.touch(key, lambda: [0, None])
        idx, last = st
        if idx and ev.time - last > self.within:
            idx, st[0], st[1] = 0, 0, None
        if idx < len(self.steps) and self.steps[idx](ev):
            st[0], st[1] = idx + 1, ev.time
            if st[0] == len(self.steps):
                st[0], st[1] = 0, None
                return [self.alert(ev, f"{len(self.steps)}-step sequence completed for {self.group_by}={key}")]
        elif idx and self.steps[0](ev):
            st[0], st[1] = 1, ev.time        # restart on a fresh first step
        return []


def load_rules(specs: Any, source: str = "<rules>") -> List[DSLRule]:
    if isinstance(specs, dict):
        if "rules" in specs and set(specs) != {"rules"}:
            raise RuleError(f"{source}: rules wrapper has unknown keys")
        specs = specs.get("rules", [specs])
    if not isinstance(specs, list):
        raise RuleError(f"{source}: expected a rule object or a list of rules")
    rules, seen = [], set()
    for s in specs:
        try:
            r = DSLRule(s)
        except (TypeError, KeyError, AttributeError, OverflowError) as e:
            raise RuleError(f"{source}: invalid rule ({type(e).__name__}: {e})")
        except RuleError as e:
            raise RuleError(f"{source}: {e}")
        if r.id in seen:
            raise RuleError(f"{source}: duplicate rule id {r.id}")
        seen.add(r.id)
        rules.append(r)
    return rules


def load_rule_files(paths: List[str]) -> List[DSLRule]:
    out: List[DSLRule] = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            try:
                out += load_rules(json.load(f), p)
            except json.JSONDecodeError as e:
                raise RuleError(f"{p}: not valid JSON ({e})")
    ids = [r.id for r in out]
    if len(ids) != len(set(ids)):
        raise RuleError("duplicate rule ids across files")
    return out
