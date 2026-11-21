"""Independent cases for malformed data, failed changes and evaluation attribution."""
import copy
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from ctdetect.models import event_from_record, load_events
from ctdetect.engine import run
from ctdetect.cli import evaluate
from ctdetect.simulate import generate

BASE = {'eventTime': '2026-01-01T00:00:00Z', 'eventSource': 'iam.amazonaws.com',
        'eventName': 'AttachUserPolicy', 'userIdentity': {'arn': 'arn:test:user/alice', 'type': 'IAMUser'},
        'requestParameters': {'userName': 'bob', 'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}}

class Regression(unittest.TestCase):
    def test_loader_skips_invalid_lines_types_and_nested_fields(self):
        rows = [BASE, None, [], dict(BASE, userIdentity=[]), dict(BASE, requestParameters='bad'),
                dict(BASE, responseElements=[1]), dict(BASE, eventTime=42)]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'events.jsonl')
            with open(path, 'w') as f:
                f.write('\n'.join(json.dumps(x) for x in rows) + '\n{damaged\n')
            self.assertEqual(len(load_events([path])), 1)
            with open(path, 'w') as f:
                json.dump({'padding': 'x' * 250, 'Records': [BASE, None]}, f)
            self.assertEqual(len(load_events([path])), 1)

    def test_failed_mutations_not_reported_as_success(self):
        for error in ('AccessDeniedException', 'LimitExceeded', 'NoSuchEntity'):
            self.assertFalse(run([event_from_record(dict(BASE, errorCode=error))]), error)

    def test_s3_single_statement_and_malformed_policy(self):
        event = dict(BASE, eventSource='s3.amazonaws.com', eventName='PutBucketPolicy')
        for doc in (None, [], {'Statement': [None, 1]}, {'Statement': 'bad'}):
            event['requestParameters'] = {'bucketPolicy': json.dumps(doc)}
            self.assertEqual(run([event_from_record(event)]), [])
        event['requestParameters'] = {'bucketPolicy': {'Statement': {'Effect': 'Allow', 'Principal': '*'}}}
        self.assertEqual(run([event_from_record(event)])[0].rule_id, 'CT006')

    def test_same_rule_wrong_actor_alert_is_not_hidden(self):
        from ctdetect.engine import run as real_run
        def extra(events, *args, **kwargs):
            alerts = real_run(events, *args, **kwargs)
            if alerts:
                false_alert = copy.copy(alerts[0])
                false_alert.principal = 'unrelated-benign-actor'
                alerts.append(false_alert)
            return alerts
        with patch('ctdetect.cli.run', side_effect=extra):
            self.assertTrue(evaluate(7)['unexpected'])

    def test_multiple_seeds_and_benign_only(self):
        for seed in range(20):
            report = evaluate(seed)
            self.assertFalse(report['missed'])
            self.assertFalse(report['unexpected'])
            self.assertEqual(report['benign_alerts'], 0)

if __name__ == '__main__':
    unittest.main()
