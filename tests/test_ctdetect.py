import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ctdetect.cli import evaluate, main
from ctdetect.engine import run
from ctdetect.models import event_from_record, load_events
from ctdetect.simulate import generate, _rec
from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)

def ev(*a, **k): return event_from_record(_rec(*a, **k))

class T(unittest.TestCase):
    def test_all_scenarios_detected_no_false_rules(self):
        for seed in (1, 7, 42):
            r = evaluate(seed)
            self.assertEqual(r["missed"], [], seed)
            self.assertEqual(r["unexpected"], [], seed)

    def test_bruteforce_needs_success_and_window(self):
        fails = [ev(T0 + timedelta(minutes=2 * i), "signin.amazonaws.com", "ConsoleLogin", "x", "1.1.1.1", resp={"ConsoleLogin": "Failure"}) for i in range(5)]
        ok = ev(T0 + timedelta(minutes=20), "signin.amazonaws.com", "ConsoleLogin", "x", "1.1.1.1", resp={"ConsoleLogin": "Success"})
        self.assertEqual([a for a in run(fails + [ok]) if a.rule_id == "CT001"], [])  # failures aged out of the 10 min window
        ok2 = ev(T0 + timedelta(minutes=9), "signin.amazonaws.com", "ConsoleLogin", "x", "1.1.1.1", resp={"ConsoleLogin": "Success"})
        self.assertEqual(len([a for a in run(fails + [ok2]) if a.rule_id == "CT001"]), 1)

    def test_key_for_self_is_not_flagged(self):
        e = ev(T0, "iam.amazonaws.com", "CreateAccessKey", "alice", "1.1.1.1", params={"userName": "alice"})
        self.assertEqual(run([e]), [])

    def test_public_policy_with_condition_not_flagged(self):
        pol = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*", "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}]})
        e = ev(T0, "s3.amazonaws.com", "PutBucketPolicy", "a", "1.1.1.1", params={"bucketName": "b", "bucketPolicy": pol})
        self.assertEqual(run([e]), [])

    def test_loader_handles_both_formats_and_skips_bad(self):
        recs, _ = generate(3, hours=1, noise_per_hour=5)
        with tempfile.TemporaryDirectory() as d:
            p1, p2 = os.path.join(d, "a.json"), os.path.join(d, "b.jsonl")
            with open(p1, "w") as f:
                json.dump({"Records": recs + [{"bad": 1}]}, f)
            with open(p2, "w") as f:
                f.write("\n".join(json.dumps(r) for r in recs))
            self.assertEqual(len(load_events([p1])), len(recs))
            self.assertEqual(len(load_events([p2])), len(recs))

    def test_cli_evaluate_exit_zero(self):
        self.assertEqual(main(["evaluate"]), 0)

if __name__ == "__main__":
    unittest.main()
