"""DSL semantics and validation, streaming ingest, allowlist/cooldown, labelled evaluation (including a check that the
hard negatives actually bite), benchmark smoke test and CLI end-to-end."""
import copy, gzip, json, os, subprocess, sys, tempfile, unittest
from datetime import datetime, timedelta, timezone
HERE = os.path.dirname(__file__)
SRC = os.path.join(HERE, "..", "src")
sys.path.insert(0, SRC)
from ctdetect.dsl import DSLRule, RuleError, load_rules, load_rule_files
from ctdetect.ingest import IngestStats, stream_events
from ctdetect.labelled import evaluate, RULES_FILE
from ctdetect.models import event_from_record
from ctdetect.pipeline import Pipeline, AllowlistError, load_allowlist
from ctdetect.simulate import _rec

T = datetime(2026, 1, 1, tzinfo=timezone.utc)
def E(sec, name="ListUsers", user="u", error=None, src="iam.amazonaws.com", **kw):
    return event_from_record(_rec(T + timedelta(seconds=sec), src, name, user, "1.1.1.1", error=error, **kw))

THRESH = {"id": "X", "title": "t", "type": "threshold", "where": {"field": "name", "op": "eq", "value": "ListUsers"},
          "count": 3, "window_seconds": 10}

class DSL(unittest.TestCase):
    def test_threshold_window_and_group(self):
        r = DSLRule(THRESH)
        self.assertEqual([len(r.process(E(s))) for s in (0, 1, 2)], [0, 0, 1])
        r = DSLRule(THRESH)
        self.assertEqual(sum(len(r.process(E(s * 6))) for s in range(6)), 0)          # too slow
        r = DSLRule(THRESH)
        self.assertEqual(sum(len(r.process(E(s, user=f"u{s}"))) for s in range(6)), 0)  # different actors
    def test_distinct(self):
        r = DSLRule(dict(THRESH, distinct="name", where={"field": "denied", "op": "eq", "value": True}))
        out = [r.process(E(i, name="ListUsers", error="AccessDenied")) for i in range(5)]
        self.assertFalse(any(out))                                                   # same call repeated is not distinct
        out = [r.process(E(i + 5, name=f"Call{i}", error="AccessDenied")) for i in range(3)]
        self.assertTrue(any(out))
    def test_sequence_order_timeout_restart(self):
        spec = {"id": "S", "title": "s", "type": "sequence", "within_seconds": 60, "steps": [
            {"field": "name", "op": "eq", "value": "A"}, {"field": "name", "op": "eq", "value": "B"}]}
        r = DSLRule(spec)
        self.assertEqual(len(r.process(E(0, "A"))) + len(r.process(E(10, "B"))), 1)
        r = DSLRule(spec)
        self.assertEqual(len(r.process(E(0, "B"))) + len(r.process(E(10, "A"))), 0)   # wrong order
        r = DSLRule(spec)
        self.assertEqual(len(r.process(E(0, "A"))) + len(r.process(E(100, "B"))), 0)  # too slow
        r = DSLRule(spec)
        self.assertEqual([len(r.process(E(s, n))) for s, n in ((0, "A"), (50, "A"), (100, "B"))], [0, 0, 1])  # restart on newer A
    def test_nested_fields_and_ops(self):
        r = DSLRule({"id": "M", "title": "m", "type": "match", "where": {"all": [
            {"field": "requestParameters.policyArn", "op": "endswith", "value": "/AdministratorAccess"},
            {"not": {"field": "errorCode", "op": "exists"}}]}})
        ev = E(0, "AttachUserPolicy", params={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
        self.assertEqual(len(r.process(ev)), 1)
        self.assertEqual(r.process(E(0, "AttachUserPolicy", params={"policyArn": "x"})), [])
        self.assertEqual(r.process(E(0, "AttachUserPolicy", error="AccessDenied", params={"policyArn": "a/AdministratorAccess"})), [])
    def test_validation_errors_are_specific(self):
        bad = [({}, "id"), (dict(THRESH, type="nope"), "type"), (dict(THRESH, severity="URGENT"), "severity"),
               (dict(THRESH, count=0), "count"), (dict(THRESH, count=True), "count"),
               (dict(THRESH, where={"field": "x", "op": "regex", "value": ".*"}), "unknown op"),
               (dict(THRESH, where={"field": "x", "op": "in", "value": "a"}), "list"),
               (dict(THRESH, where={"all": []}), "non-empty"), (dict(THRESH, where="x"), "predicate"),
               ({"id": "S", "title": "s", "type": "sequence", "within_seconds": 5, "steps": [{"field": "a", "op": "exists"}]}, "2 steps")]
        for spec, frag in bad:
            with self.assertRaises(RuleError, msg=str(spec)) as cm:
                DSLRule(spec)
            self.assertIn(frag, str(cm.exception))
    def test_duplicate_ids_and_bundled_rules_valid(self):
        with self.assertRaises(RuleError):
            load_rules([THRESH, THRESH])
        self.assertEqual(len(load_rule_files([str(RULES_FILE)])), 4)
    def test_lru_bounds_state_and_evicts(self):
        r = DSLRule(dict(THRESH, max_keys=100))
        for i in range(5000):
            r.process(E(i, user=f"user{i}"))
        self.assertLessEqual(len(r.state), 100)
        self.assertGreater(r.state.evicted, 4000)

class Ingest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.root = self.d.name
        self.recs = [_rec(T + timedelta(seconds=s), "s3.amazonaws.com", "GetObject", "u", "1.1.1.1") for s in range(10)]
    def tearDown(self): self.d.cleanup()
    def w(self, rel, data, gz=False):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with (gzip.open(p, "wt") if gz else open(p, "w")) as f:
            f.write(data)
        return p
    def test_tree_gz_jsonl_and_json_with_diagnostics(self):
        self.w("a/x.json.gz", json.dumps({"Records": self.recs[:4]}), gz=True)
        self.w("a/b/y.jsonl", "\n".join(json.dumps(r) for r in self.recs[4:7]) + "\n{broken\n")
        self.w("z.jsonl.gz", "\n".join(json.dumps(r) for r in self.recs[7:]), gz=True)
        self.w("digest.json", json.dumps({"digestPublicKeyFingerprint": "abc"}))
        self.w("c.json", json.dumps({"Records": [None, {"eventTime": 5}, self.recs[0]]}))
        with open(os.path.join(self.root, "bad.json.gz"), "wb") as f:
            f.write(b"not gzip")
        st = IngestStats()
        evs = list(stream_events([self.root], st))
        self.assertEqual(st.accepted, 11)
        self.assertEqual(len(evs), 11)
        self.assertEqual(st.unreadable_files, 1)
        self.assertGreaterEqual(sum(st.rejected.values()), 5)
        self.assertTrue(any("digest" in k for k in st.rejected))
        self.assertEqual([e.time for e in evs], sorted(e.time for e in evs))
    def test_reorder_buffer_and_late_counter(self):
        shuffled = [self.recs[i] for i in (3, 1, 2, 0, 5, 4)]
        self.w("s.jsonl", "\n".join(json.dumps(r) for r in shuffled))
        st = IngestStats()
        evs = list(stream_events([self.root], st, skew_seconds=10))
        self.assertEqual([e.time for e in evs], sorted(e.time for e in evs))
        self.assertEqual(st.late, 0)
        late_first = [_rec(T + timedelta(hours=1), "s3.amazonaws.com", "GetObject", "u", "1.1.1.1")] + self.recs[:2]
        self.w("t.jsonl", "\n".join(json.dumps(r) for r in late_first))
        st2 = IngestStats()
        list(stream_events([os.path.join(self.root, "t.jsonl")], st2, skew_seconds=10))
        self.assertEqual(st2.accepted, 3)

class PipelineTests(unittest.TestCase):
    def rule(self): return DSLRule({"id": "M", "title": "m", "type": "match", "severity": "HIGH", "where": {"field": "name", "op": "eq", "value": "X"}})
    def test_allowlist_cooldown_and_unused(self):
        evs = [E(0, "X", user="bot"), E(1, "X", user="human"), E(2, "X", user="human"), E(500, "X", user="human")]
        allow = [{"rule_id": "M", "principal": "*user/bot", "reason": "ci"}, {"rule_id": "M", "principal": "*nobody", "reason": "unused"}]
        p = Pipeline([self.rule()], allow, cooldown_seconds=60)
        out = list(p.run(evs))
        self.assertEqual(len(out), 2)
        self.assertEqual(p.stats, {"alerts": 2, "allowlisted": 1, "suppressed": 1, "below_severity": 0})
        self.assertEqual(len(p.unused_allowlist()), 1)
    def test_allowlist_hygiene(self):
        with tempfile.TemporaryDirectory() as d:
            for bad in ([{"rule_id": "M", "principal": "*"}], [{"rule_id": "M", "reason": "r"}], [{"rule_id": "M", "principal": "a", "reason": "r", "x": 1}], {"a": 1}):
                p = os.path.join(d, "a.json")
                with open(p, "w") as f:
                    json.dump(bad, f)
                with self.assertRaises(AllowlistError):
                    load_allowlist(p)

class Labelled(unittest.TestCase):
    def test_clean_on_labelled_set(self):
        for seed in (7, 8, 9):
            r = evaluate(seed)
            self.assertEqual((r["false_positives"], r["missed"]), ([], []), seed)
            self.assertGreaterEqual(len(r["per_rule"]), 11)
    def test_hard_negatives_actually_bite(self):
        """Loosen thresholds in memory and confirm the evaluation then reports false positives."""
        import ctdetect.labelled as L
        with open(RULES_FILE) as f:
            specs = json.load(f)
        specs["rules"][3]["count"] = 20                 # D004 24 reads should now alert
        specs["rules"][0]["window_seconds"] = 3000      # D001 spread-out denials should now alert
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.json")
            with open(p, "w") as f:
                json.dump(specs, f)
            old = L.RULES_FILE
            L.RULES_FILE = p
            try:
                r = L.evaluate(7)
            finally:
                L.RULES_FILE = old
        self.assertTrue(r["false_positives"])

class Bench(unittest.TestCase):
    def test_smoke(self):
        from ctdetect.bench import run
        r = run(5000, memory=True, principals=300)
        self.assertEqual(r["events"], 5000)
        self.assertGreater(r["events_per_second"], 0)
        self.assertIsNotNone(r["peak_python_heap_mb"])

class CLI(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "ctdetect.cli", *args], env=dict(os.environ, PYTHONPATH=SRC), capture_output=True, text=True)
    def test_validate_rules_and_scan(self):
        self.assertEqual(self.run_cli("validate-rules", str(RULES_FILE)).returncode, 0)
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.json")
            with open(bad, "w") as f:
                json.dump({"rules": [{"id": "Z", "type": "nope"}]}, f)
            r = self.run_cli("validate-rules", bad)
            self.assertEqual(r.returncode, 1)
            self.assertIn("Z", r.stderr)
            recs = [_rec(T + timedelta(seconds=s), "iam.amazonaws.com", "AttachUserPolicy", "mal", "9.9.9.9",
                         params={"userName": "mal", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}) for s in (0, 5)]
            with gzip.open(os.path.join(d, "ev.jsonl.gz"), "wt") as f:
                f.write("\n".join(json.dumps(x) for x in recs))
            al = os.path.join(d, "allow.json")
            with open(al, "w") as f:
                json.dump([{"rule_id": "CT004", "principal": "*user/ghost", "reason": "never matches"}], f)
            r = self.run_cli("scan", d, "--cooldown", "60", "--allowlist", al)
            self.assertEqual(r.returncode, 1, r.stderr)  # config JSON in the scanned directory is rejected
            self.assertIn("CT004", r.stdout)
            self.assertIn("1 alert(s)", r.stdout)                      # second alert suppressed by cooldown
            self.assertIn("allowlist entry never matched", r.stderr)
            self.assertIn('"suppressed": 1', r.stderr)

if __name__ == "__main__":
    unittest.main()
