"""Stateful detection rules. Each rule sees events in time order and may emit alerts.

Per-key event windows are pruned on activity. Key count and total memory are not bounded.
MITRE ATT&CK technique ids are references for triage, not a coverage claim."""
from __future__ import annotations
import json
from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, List, Set, Tuple, Type

from .models import Alert, Event

REGISTRY: Dict[str, Type["Rule"]] = {}


def register(cls):
    REGISTRY[cls.id] = cls
    return cls


class Rule:
    id = "CT000"
    title = ""
    severity = "LOW"
    mitre = ""

    def process(self, ev: Event) -> List[Alert]:
        raise NotImplementedError

    def alert(self, ev: Event, detail: str) -> Alert:
        return Alert(self.id, self.title, self.severity, self.mitre, ev.time, ev.principal, ev.ip, detail)


@register
class ConsoleBruteForce(Rule):
    """>= N failed console logins from one IP in a window, then a success from that IP."""
    id, title, severity, mitre = "CT001", "Console brute force followed by success", "CRITICAL", "T1110"
    N, WINDOW = 5, timedelta(minutes=10)

    def __init__(self):
        self.fails: Dict[str, Deque] = defaultdict(deque)

    def process(self, ev):
        if ev.name != "ConsoleLogin":
            return []
        q = self.fails[ev.ip]
        while q and ev.time - q[0] > self.WINDOW:
            q.popleft()
        result = (ev.response or {}).get("ConsoleLogin", "")
        if result == "Failure":
            q.append(ev.time)
            return []
        if result == "Success" and len(q) >= self.N:
            n = len(q)
            q.clear()
            return [self.alert(ev, f"{n} failed logins from {ev.ip} within {self.WINDOW}, then success")]
        return []


@register
class RootActivity(Rule):
    id, title, severity, mitre = "CT002", "Root account used for API activity", "HIGH", "T1078.004"

    def process(self, ev):
        if ev.principal_type == "Root" and ev.name not in ("ConsoleLogin", "CheckMfa") and not ev.error:
            return [self.alert(ev, f"root performed {ev.name}")]
        return []


@register
class LoggingTampering(Rule):
    id, title, severity, mitre = "CT003", "Security logging configuration changed", "HIGH", "T1562.008"
    NAMES = {"StopLogging", "DeleteTrail", "PutEventSelectors", "UpdateTrail", "DeleteDetector", "DisableSecurityHub"}

    def process(self, ev):
        if ev.name in self.NAMES and not ev.error:
            return [self.alert(ev, f"{ev.source}:{ev.name} {json.dumps(ev.params, sort_keys=True)[:120]}")]
        return []


@register
class AdminPolicyAttach(Rule):
    id, title, severity, mitre = "CT004", "Admin-level policy attached", "HIGH", "T1098"

    def process(self, ev):
        if ev.error or ev.name not in ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"):
            return []
        if str(ev.params.get("policyArn", "")).endswith("/AdministratorAccess"):
            tgt = ev.params.get("userName") or ev.params.get("roleName") or ev.params.get("groupName")
            return [self.alert(ev, f"AdministratorAccess attached to {tgt}")]
        return []


@register
class PermissionRecon(Rule):
    """Many distinct API calls denied for one principal in a short window (permission enumeration)."""
    id, title, severity, mitre = "CT005", "Permission enumeration (many distinct denied calls)", "MEDIUM", "T1069.003"
    DISTINCT, WINDOW = 8, timedelta(minutes=5)

    def __init__(self):
        self.q: Dict[str, Deque[Tuple]] = defaultdict(deque)
        self.cool: Dict[str, object] = {}

    def process(self, ev):
        if not ev.error:
            return []
        q = self.q[ev.principal]
        q.append((ev.time, ev.name))
        while q and ev.time - q[0][0] > self.WINDOW:
            q.popleft()
        names: Set[str] = {n for _, n in q}
        last = self.cool.get(ev.principal)
        if len(names) >= self.DISTINCT and (last is None or ev.time - last > self.WINDOW):
            self.cool[ev.principal] = ev.time
            return [self.alert(ev, f"{len(names)} distinct denied calls in {self.WINDOW}")]
        return []


@register
class S3Exposure(Rule):
    id, title, severity, mitre = "CT006", "Potential S3 public-access configuration", "HIGH", "T1530"

    def process(self, ev):
        if ev.error:
            return []
        p = ev.params
        if ev.name == "PutBucketPolicy":
            try:
                doc = json.loads(p.get("bucketPolicy") if isinstance(p.get("bucketPolicy"), str) else json.dumps(p.get("bucketPolicy", {})))
            except ValueError:
                return []
            if not isinstance(doc, dict):
                return []
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            if not isinstance(statements, list):
                return []
            for st in statements:
                if not isinstance(st, dict):
                    continue
                pr = st.get("Principal")
                if st.get("Effect") == "Allow" and (pr == "*" or (isinstance(pr, dict) and pr.get("AWS") in ("*", ["*"]))) and "Condition" not in st:
                    return [self.alert(ev, f"public policy on bucket {p.get('bucketName')}")]
        if ev.name == "DeleteBucketPublicAccessBlock":
            return [self.alert(ev, f"public access block removed on {p.get('bucketName')}")]
        if ev.name == "PutBucketAcl" and "AllUsers" in json.dumps(p):
            return [self.alert(ev, f"AllUsers ACL on bucket {p.get('bucketName')}")]
        return []


@register
class NewAccessKeyForOther(Rule):
    """CreateAccessKey where the caller is not the key's owner, a common persistence move."""
    id, title, severity, mitre = "CT007", "Access key created for a different user", "MEDIUM", "T1098.001"

    def process(self, ev):
        if ev.name != "CreateAccessKey" or ev.error:
            return []
        target = ev.params.get("userName")
        if target and not ev.principal.endswith("/" + target):
            return [self.alert(ev, f"{ev.principal} created a key for {target}")]
        return []


def default_rules() -> List[Rule]:
    return [cls() for cls in REGISTRY.values()]
