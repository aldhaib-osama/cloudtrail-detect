"""Labelled evaluation set: baseline attacks + extra attacks for the DSL rules + deliberate hard negatives
(benign behaviour that sits just under, or just outside, each rule's trigger). All data is synthetic.
Per-rule precision and recall are computed at alert level against labelled (rule, principal, time) tuples."""
from __future__ import annotations
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .dsl import load_rule_files
from .models import event_from_record
from .pipeline import Pipeline
from .rules import default_rules
from .simulate import ACCT, _fmt, _rec, generate

RULES_FILE = Path(__file__).resolve().parent / "data" / "example_rules.json"
T0 = datetime(2026, 3, 2, 9, 0, 0, tzinfo=timezone.utc)
ARN = lambda u: f"arn:aws:iam::{ACCT}:user/{u}"
POL_RO = {"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "userName": "bob"}


def _mfa(rec, used):
    rec["additionalEventData"] = {"MFAUsed": used}
    return rec


def attacks() -> Tuple[List[dict], List[Dict]]:
    recs, truth = [], []
    ip = "203.0.113.77"
    # D002: denied Attach then successful Attach by the same principal within 15 min
    recs.append(_rec(T0, "iam.amazonaws.com", "AttachUserPolicy", "erin", ip, error="AccessDenied", params=POL_RO))
    recs.append(_rec(T0 + timedelta(minutes=2), "iam.amazonaws.com", "AttachUserPolicy", "erin", ip, params=POL_RO))
    truth.append({"rule_id": "D002", "principal": ARN("erin"), "time": _fmt(T0 + timedelta(minutes=2))})
    # D003: console login success, no MFA, IAM user
    t = T0 + timedelta(hours=1)
    recs.append(_mfa(_rec(t, "signin.amazonaws.com", "ConsoleLogin", "dave", ip, resp={"ConsoleLogin": "Success"}), "No"))
    truth.append({"rule_id": "D003", "principal": ARN("dave"), "time": _fmt(t)})
    # D004: 25 secret reads in 24 seconds
    t = T0 + timedelta(hours=2)
    for i in range(25):
        recs.append(_rec(t + timedelta(seconds=i), "secretsmanager.amazonaws.com", "GetSecretValue", "deploy-bot", "198.51.100.13"))
    truth.append({"rule_id": "D004", "principal": ARN("deploy-bot"), "time": _fmt(t + timedelta(seconds=24))})
    return recs, truth


def hard_negatives() -> List[dict]:
    recs: List[dict] = []
    ip = "198.51.100.99"
    t = T0 + timedelta(hours=3)
    for i in range(15):                                   # H1 admin burst of successful reads
        recs.append(_rec(t + timedelta(seconds=3 * i), "iam.amazonaws.com", ["ListUsers", "ListRoles", "ListPolicies"][i % 3], "alice", ip))
    t = T0 + timedelta(hours=4)
    for i in range(4):                                    # H2 4 failed logins (< threshold) then success
        recs.append(_rec(t + timedelta(seconds=20 * i), "signin.amazonaws.com", "ConsoleLogin", "bob", "198.51.100.98", resp={"ConsoleLogin": "Failure"}))
    recs.append(_mfa(_rec(t + timedelta(seconds=100), "signin.amazonaws.com", "ConsoleLogin", "bob", "198.51.100.98", resp={"ConsoleLogin": "Success"}), "Yes"))  # H7 MFA used
    t = T0 + timedelta(hours=5)
    names = ["ListUsers", "ListRoles", "ListPolicies", "ListGroups", "ListAccessKeys", "ListBuckets", "DescribeTrails", "ListFunctions"]
    for i, n in enumerate(names):                         # H3 8 distinct denials but spread over 24 minutes
        recs.append(_rec(t + timedelta(minutes=3 * i), "iam.amazonaws.com", n, "dave", ip, error="AccessDenied"))
    recs.append(_rec(T0 + timedelta(hours=6), "signin.amazonaws.com", "ConsoleLogin", "root", ip, utype="Root", resp={"ConsoleLogin": "Success"}))  # H4 root console login
    recs.append(_rec(T0 + timedelta(hours=6, minutes=1), "iam.amazonaws.com", "CreateAccessKey", "carol", ip, params={"userName": "carol"}))        # H5 own key
    pol = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*", "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}]})
    recs.append(_rec(T0 + timedelta(hours=6, minutes=2), "s3.amazonaws.com", "PutBucketPolicy", "alice", ip, params={"bucketName": "b", "bucketPolicy": pol}))  # H6
    t = T0 + timedelta(hours=7)
    for i in range(24):                                   # H8 24 secret reads (< 25)
        recs.append(_rec(t + timedelta(seconds=i * 4), "ssm.amazonaws.com", "GetParameter", "ci-runner", "198.51.100.14"))
    t = T0 + timedelta(hours=8)                           # H9 denied by one principal, success by another
    recs.append(_rec(t, "iam.amazonaws.com", "AttachUserPolicy", "frank", ip, error="AccessDenied", params=POL_RO))
    recs.append(_rec(t + timedelta(minutes=1), "iam.amazonaws.com", "AttachUserPolicy", "grace", ip, params=POL_RO))
    t = T0 + timedelta(hours=9)                           # H10 success first, denial later (wrong order)
    recs.append(_rec(t, "iam.amazonaws.com", "AttachUserPolicy", "heidi", ip, params=POL_RO))
    recs.append(_rec(t + timedelta(minutes=1), "iam.amazonaws.com", "AttachUserPolicy", "heidi", ip, error="AccessDenied", params=POL_RO))
    t = T0 + timedelta(hours=10)                          # H11 sequence too slow (> 15 min apart)
    recs.append(_rec(t, "iam.amazonaws.com", "AttachUserPolicy", "ivan", ip, error="AccessDenied", params=POL_RO))
    recs.append(_rec(t + timedelta(minutes=40), "iam.amazonaws.com", "AttachUserPolicy", "ivan", ip, params=POL_RO))
    return recs


def build(seed: int = 7) -> Tuple[List[dict], List[Dict], List[dict]]:
    base, truth_base = generate(seed)
    extra, truth_extra = attacks()
    hard = hard_negatives()
    truth = list(truth_base) + truth_extra
    # D001 (enumeration) fires on the same event as CT005 in the baseline recon scenario
    truth += [dict(t, rule_id="D001") for t in truth_base if t["rule_id"] == "CT005"]
    return base + extra + hard, truth, hard


def evaluate(seed: int = 7) -> Dict[str, Any]:
    recs, truth, _ = build(seed)
    pipe = Pipeline(default_rules() + load_rule_files([str(RULES_FILE)]))
    events = sorted((event_from_record(r) for r in recs), key=lambda e: e.time)
    alerts = list(pipe.run(events))
    key = lambda rid, p, t: (rid, p, t)
    got = Counter(key(a.rule_id, a.principal, _fmt(a.time)) for a in alerts)
    want = Counter(key(t["rule_id"], t["principal"], t["time"]) for t in truth)
    per_rule: Dict[str, Dict[str, Any]] = {}
    for rid in sorted({k[0] for k in got} | {k[0] for k in want}):
        tp = sum(min(got[k], want[k]) for k in want if k[0] == rid)
        fp = sum(v for k, v in (got - want).items() if k[0] == rid)
        fn = sum(v for k, v in (want - got).items() if k[0] == rid)
        per_rule[rid] = {"tp": tp, "fp": fp, "fn": fn,
                         "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                         "recall": round(tp / (tp + fn), 3) if tp + fn else None}
    return {"events": len(events), "labelled_attacks": sum(want.values()), "alerts": len(alerts), "per_rule": per_rule,
            "false_positives": list((got - want).elements()), "missed": list((want - got).elements()),
            "caveat": "synthetic data authored together with the rules: results show the rules do what their authors intended on these cases, not real-world precision/recall"}
