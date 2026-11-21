"""Independent regressions for bounded-state claims, late ordering and malformed controls."""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from ctdetect.dsl import DSLRule, RuleError, load_rules
from ctdetect.ingest import IngestStats, stream_events
from ctdetect.pipeline import load_allowlist, AllowlistError, Pipeline
from ctdetect.models import event_from_record
from ctdetect.cli import main

T = datetime(2026, 1, 1, tzinfo=timezone.utc)
def raw(seconds):
    return {'eventTime': (T + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ'), 'eventName': 'X', 'userIdentity': {'arn': 'arn:user/u'}}
def event(seconds):
    return event_from_record(raw(seconds))
SPEC = {'id': 'R', 'title': 'test', 'type': 'threshold', 'count': 3, 'window_seconds': 10,
        'where': {'field': 'name', 'op': 'eq', 'value': 'X'}}

class IndependentReview(unittest.TestCase):
    def test_one_actor_distinct_queue_is_capped_and_loss_counted(self):
        rule = DSLRule(dict(SPEC, distinct='name', max_events_per_key=4))
        for _ in range(100):
            rule.process(event(0))
        self.assertEqual(len(rule.state['arn:user/u']), 4)
        self.assertEqual(rule.dropped_events, 96)

    def test_missing_distinct_value_not_counted(self):
        rule = DSLRule(dict(SPEC, count=1, distinct='absent'))
        self.assertFalse(rule.process(event(0)))

    def test_rule_validation_shapes_types_and_typos(self):
        for spec in (None, [], dict(SPEC, max_keys='bad'), dict(SPEC, max_keys=True),
                     dict(SPEC, group_by=[]), dict(SPEC, typo=1),
                     dict(SPEC, where={'field': 'name', 'op': 'eq'}),
                     dict(SPEC, where={'field': 'name', 'op': []})):
            with self.assertRaises(RuleError, msg=str(spec)):
                load_rules([spec])

    def test_retrograde_events_rejected_by_stateful_rules(self):
        rule = DSLRule(SPEC)
        rule.process(event(10))
        with self.assertRaises(ValueError):
            rule.process(event(0))

    def test_reorder_count_cap_and_late_drop_preserve_order(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'events.jsonl')
            with open(path, 'w') as f:
                f.write('\n'.join(json.dumps(raw(s)) for s in (5, 6, 7, 0, 8)))
            stats = IngestStats()
            events = list(stream_events([path], stats, skew_seconds=100, max_buffer_events=2))
            self.assertEqual([e.time for e in events], sorted(e.time for e in events))
            self.assertGreater(stats.capacity_releases, 0)
            self.assertEqual(stats.late, 1)
            self.assertEqual(len(events), 4)

    def test_allowlist_cannot_be_global_mute_or_bad_type(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'allow.json')
            for selector in ('*', '**', '?*', 3, ['x']):
                with open(path, 'w') as f:
                    json.dump([{'rule_id': '*', 'principal': selector, 'reason': 'reviewed'}], f)
                with self.assertRaises(AllowlistError):
                    load_allowlist(path)

    def test_no_cooldown_does_not_retain_unneeded_keys(self):
        spec = dict(SPEC, type='match')
        pipeline = Pipeline([DSLRule(spec)])
        list(pipeline.run([event(0), event(1)]))
        self.assertFalse(pipeline.last)
        with self.assertRaises(ValueError):
            Pipeline([DSLRule(spec), DSLRule(spec)])
        with self.assertRaises(ValueError):
            Pipeline([], cooldown_seconds=-1)

    def test_empty_directory_is_not_successful_scan(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(['scan', d]), 1)
            self.assertEqual(main(['scan', d, '--no-builtin']), 1)

class PackagingAndInputReview(unittest.TestCase):
    def test_packaged_rules_match_editable_examples(self):
        from pathlib import Path
        from ctdetect.labelled import RULES_FILE
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(json.loads(Path(RULES_FILE).read_text()), json.loads((root / 'rules/example_rules.json').read_text()))

    def test_nonpositive_benchmark_and_negative_scan_controls_rejected(self):
        self.assertEqual(main(['bench', '--events', '-1']), 1)
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(['scan', d, '--skew', '-1']), 1)
            self.assertEqual(main(['scan', d, '--cooldown', '-1']), 1)

if __name__ == '__main__':
    unittest.main()
