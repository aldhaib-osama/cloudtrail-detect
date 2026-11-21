from __future__ import annotations
from typing import Iterable, List, Optional, Set

from .models import Alert, Event
from .rules import Rule, default_rules

SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def run(events: Iterable[Event], rules: Optional[List[Rule]] = None, min_severity: str = "LOW") -> List[Alert]:
    """Feed time-ordered events through every rule. Exact duplicate alerts are suppressed."""
    rules = rules if rules is not None else default_rules()
    seen: Set[tuple] = set()
    out: List[Alert] = []
    for ev in events:
        for r in rules:
            for a in r.process(ev):
                key = (a.rule_id, a.principal, a.time, a.detail)
                if key in seen or SEV_ORDER[a.severity] < SEV_ORDER[min_severity]:
                    continue
                seen.add(key)
                out.append(a)
    return out
