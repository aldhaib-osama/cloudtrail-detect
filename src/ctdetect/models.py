"""Event and alert models plus tolerant CloudTrail parsing."""
from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List


def parse_time(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Event:
    time: datetime
    name: str
    source: str
    principal_type: str
    principal: str          # stable id: ARN, else userName, else "unknown"
    ip: str
    error: str
    params: Dict[str, Any]
    response: Dict[str, Any]
    raw: Dict[str, Any] = field(compare=False, repr=False, default_factory=dict)

    @property
    def denied(self) -> bool:
        return self.error in ("AccessDenied", "AccessDeniedException", "Client.UnauthorizedOperation", "UnauthorizedOperation")


def event_from_record(rec: Dict[str, Any]) -> Event:
    if not isinstance(rec, dict):
        raise ValueError("event must be an object")
    ui = rec.get("userIdentity")
    if ui is None:
        ui = {}
    if not isinstance(ui, dict):
        raise ValueError("userIdentity must be an object")
    for field_name in ("requestParameters", "responseElements"):
        if rec.get(field_name) is not None and not isinstance(rec[field_name], dict):
            raise ValueError(field_name + " must be an object")
    for field_name in ("eventTime", "eventName", "eventSource", "sourceIPAddress", "errorCode"):
        if rec.get(field_name) is not None and not isinstance(rec[field_name], str):
            raise ValueError(field_name + " must be text")
    if not isinstance(rec.get("eventTime"), str):
        raise ValueError("eventTime is required")
    if any(ui.get(k) is not None and not isinstance(ui[k], str) for k in ("arn", "userName", "principalId", "type")):
        raise ValueError("identity fields must be text")
    principal = ui.get("arn") or ui.get("userName") or ui.get("principalId") or "unknown"
    return Event(
        time=parse_time(rec["eventTime"]),
        name=rec.get("eventName", ""),
        source=rec.get("eventSource", ""),
        principal_type=ui.get("type", ""),
        principal=principal,
        ip=rec.get("sourceIPAddress", ""),
        error=rec.get("errorCode", "") or "",
        params=rec.get("requestParameters") or {},
        response=rec.get("responseElements") or {},
        raw=rec,
    )


def load_events(paths: Iterable[str]) -> List[Event]:
    """Accepts CloudTrail files ({"Records": [...]}) or JSON-lines of records. Malformed records are skipped."""
    out: List[Event] = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            text = f.read().strip()
        recs = []
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            # JSONL: one damaged line does not discard the other events.
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    recs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        else:
            if isinstance(document, dict) and "Records" in document:
                recs = document["Records"] if isinstance(document["Records"], list) else []
            else:
                recs = [document]
        for r in recs:
            try:
                out.append(event_from_record(r))
            except (KeyError, ValueError, TypeError):
                continue
    out.sort(key=lambda e: e.time)
    return out


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    mitre: str
    time: datetime
    principal: str
    ip: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["time"] = self.time.strftime("%Y-%m-%dT%H:%M:%SZ")
        return d
