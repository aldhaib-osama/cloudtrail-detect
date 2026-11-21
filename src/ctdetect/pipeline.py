"""Alert pipeline: rule evaluation, reviewed allowlist, and cooldown suppression. Never sends anything anywhere."""
from __future__ import annotations
import json
from datetime import timedelta
from fnmatch import fnmatchcase
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from .models import Alert, Event
from .rules import Rule

SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class AllowlistError(ValueError):
    pass


def load_allowlist(path: str) -> List[Dict[str, str]]:
    """Entries: {"rule_id": "CT002" | "*", "principal": glob?, "ip": glob?, "reason": text}. A reason is mandatory so that
    every suppression is explainable in review, and an entry must narrow by principal and/or ip (no blanket mutes)."""
    with open(path, encoding="utf-8") as f:
        entries = json.load(f)
    if not isinstance(entries, list):
        raise AllowlistError("allowlist must be a JSON list")
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not isinstance(e.get("rule_id"), str):
            raise AllowlistError(f"entry {i}: needs rule_id")
        if not isinstance(e.get("reason"), str) or not e["reason"].strip():
            raise AllowlistError(f"entry {i}: a reason is required")
        for k in ("principal", "ip"):
            if k in e and (not isinstance(e[k], str) or not e[k]):
                raise AllowlistError(f"entry {i}: {k} must be nonempty text")
        if not any(e.get(k) and any(c not in "*?[]!" for c in e[k]) for k in ("principal", "ip")):
            raise AllowlistError(f"entry {i}: must narrow by principal and/or ip")
        for k in e:
            if k not in ("rule_id", "principal", "ip", "reason"):
                raise AllowlistError(f"entry {i}: unknown key {k!r}")
    return entries


class Pipeline:
    def __init__(self, rules: List[Rule], allowlist: Optional[List[Dict[str, str]]] = None, cooldown_seconds: int = 0,
                 min_severity: str = "LOW"):
        if cooldown_seconds < 0:
            raise ValueError("cooldown must be nonnegative")
        ids = [r.id for r in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule IDs in pipeline")
        self.rules = rules
        self.allowlist = allowlist or []
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.min_sev = SEV_ORDER[min_severity]
        self.last: Dict[Tuple[str, str], Any] = {}
        self.stats = {"alerts": 0, "allowlisted": 0, "suppressed": 0, "below_severity": 0}
        self.allow_hits: Dict[int, int] = {}

    def _allowed(self, a: Alert) -> bool:
        for i, e in enumerate(self.allowlist):
            if e["rule_id"] not in ("*", a.rule_id):
                continue
            if "principal" in e and not fnmatchcase(a.principal, e["principal"]):
                continue
            if "ip" in e and not fnmatchcase(a.ip, e["ip"]):
                continue
            self.allow_hits[i] = self.allow_hits.get(i, 0) + 1
            return True
        return False

    def process(self, ev: Event) -> List[Alert]:
        out: List[Alert] = []
        for r in self.rules:
            for a in r.process(ev):
                if SEV_ORDER[a.severity] < self.min_sev:
                    self.stats["below_severity"] += 1
                elif self._allowed(a):
                    self.stats["allowlisted"] += 1
                else:
                    key = (a.rule_id, a.principal)
                    prev = self.last.get(key)
                    if prev is not None and self.cooldown and a.time - prev < self.cooldown:
                        self.stats["suppressed"] += 1
                        continue
                    if self.cooldown:
                        self.last[key] = a.time
                    self.stats["alerts"] += 1
                    out.append(a)
        return out

    def run(self, events: Iterable[Event]) -> Iterator[Alert]:
        for ev in events:
            yield from self.process(ev)

    def unused_allowlist(self) -> List[Dict[str, str]]:
        return [e for i, e in enumerate(self.allowlist) if i not in self.allow_hits]
