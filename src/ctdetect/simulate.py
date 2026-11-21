"""Deterministic synthetic CloudTrail generator with labelled attack scenarios.
All data is fake (documentation IP ranges, account 111122223333)."""
from __future__ import annotations
import json
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

ACCT = "111122223333"
BENIGN_CALLS = [("s3.amazonaws.com", "GetObject"), ("ec2.amazonaws.com", "DescribeInstances"),
                ("s3.amazonaws.com", "ListBuckets"), ("logs.amazonaws.com", "PutLogEvents"),
                ("sts.amazonaws.com", "GetCallerIdentity"), ("dynamodb.amazonaws.com", "Query")]


def _fmt(t): return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _rec(t, src, name, user, ip, utype="IAMUser", error=None, params=None, resp=None):
    r = {"eventTime": _fmt(t), "eventSource": src, "eventName": name, "sourceIPAddress": ip,
         "userIdentity": {"type": utype, "arn": f"arn:aws:iam::{ACCT}:{'root' if utype == 'Root' else 'user/' + user}", "userName": user},
         "requestParameters": params or {}, "responseElements": resp}
    if error:
        r["errorCode"] = error
    return r


def generate(seed: int = 7, hours: int = 6, noise_per_hour: int = 120, include_attacks: bool = True) -> Tuple[List[dict], List[Dict]]:
    """Returns (records, ground_truth). ground_truth items: {rule_id, scenario}."""
    rnd = random.Random(seed)
    start = datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc)
    users = ["alice", "bob", "carol", "deploy-bot"]
    recs: List[dict] = []
    for h in range(hours):
        for _ in range(noise_per_hour):
            t = start + timedelta(hours=h, seconds=rnd.randrange(3600))
            src, name = rnd.choice(BENIGN_CALLS)
            u = rnd.choice(users)
            err = "AccessDenied" if rnd.random() < 0.02 else None  # sparse denials never reach the recon threshold
            recs.append(_rec(t, src, name, u, f"198.51.100.{users.index(u) + 10}", error=err))
    if not include_attacks:
        return recs, []
    truth: List[Dict] = []
    t0 = start + timedelta(hours=1, minutes=13)
    atk_ip = "203.0.113.50"
    # CT001 brute force then success
    for i in range(7):
        recs.append(_rec(t0 + timedelta(seconds=20 * i), "signin.amazonaws.com", "ConsoleLogin", "bob", atk_ip, resp={"ConsoleLogin": "Failure"}))
    recs.append(_rec(t0 + timedelta(seconds=170), "signin.amazonaws.com", "ConsoleLogin", "bob", atk_ip, resp={"ConsoleLogin": "Success"}))
    truth.append({"rule_id": "CT001", "scenario": "brute force"})
    # CT005 recon from a dedicated synthetic actor, isolated from noise denials
    t1 = start + timedelta(hours=2, minutes=5)
    for i, n in enumerate(["ListUsers", "ListRoles", "ListPolicies", "GetAccountAuthorizationDetails", "ListGroups",
                           "ListAccessKeys", "ListAttachedUserPolicies", "ListBuckets2", "DescribeTrails", "ListFunctions"]):
        recs.append(_rec(t1 + timedelta(seconds=7 * i), "iam.amazonaws.com", n, "recon-actor", atk_ip, error="AccessDenied"))
    truth.append({"rule_id": "CT005", "scenario": "recon"})
    # CT004 + CT007 persistence by alice (compromised)
    t2 = start + timedelta(hours=3, minutes=30)
    recs.append(_rec(t2, "iam.amazonaws.com", "AttachUserPolicy", "alice", atk_ip,
                     params={"userName": "alice", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    recs.append(_rec(t2 + timedelta(seconds=30), "iam.amazonaws.com", "CreateAccessKey", "alice", atk_ip, params={"userName": "deploy-bot"}))
    truth += [{"rule_id": "CT004", "scenario": "admin attach"}, {"rule_id": "CT007", "scenario": "key for other"}]
    # CT003 defense evasion
    recs.append(_rec(t2 + timedelta(minutes=2), "cloudtrail.amazonaws.com", "StopLogging", "alice", atk_ip, params={"name": "main-trail"}))
    truth.append({"rule_id": "CT003", "scenario": "stop logging"})
    # CT006 exposure
    pol = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data-bkt/*"}]})
    recs.append(_rec(t2 + timedelta(minutes=5), "s3.amazonaws.com", "PutBucketPolicy", "alice", atk_ip, params={"bucketName": "data-bkt", "bucketPolicy": pol}))
    truth.append({"rule_id": "CT006", "scenario": "public bucket"})
    # CT002 root
    recs.append(_rec(start + timedelta(hours=4), "ec2.amazonaws.com", "RunInstances", "root", atk_ip, utype="Root"))
    truth.append({"rule_id": "CT002", "scenario": "root usage"})
    expected_times = {"CT001": t0 + timedelta(seconds=170), "CT005": t1 + timedelta(seconds=49),
                      "CT004": t2, "CT007": t2 + timedelta(seconds=30),
                      "CT003": t2 + timedelta(minutes=2), "CT006": t2 + timedelta(minutes=5),
                      "CT002": start + timedelta(hours=4)}
    for item in truth:
        when = _fmt(expected_times[item["rule_id"]])
        record = next(r for r in recs if r["eventTime"] == when and r["sourceIPAddress"] == atk_ip) if item["rule_id"] != "CT002" else next(r for r in recs if r["eventTime"] == when and r["userIdentity"]["type"] == "Root")
        item.update(time=when, principal=record["userIdentity"]["arn"])
    rnd.shuffle(recs)
    return recs, truth
