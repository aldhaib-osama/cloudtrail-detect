# ctdetect: detection-as-code for AWS CloudTrail

Streaming detection pipeline for CloudTrail logs: 7 built-in Python rules, a JSON rule DSL, directory/gzip ingestion with out-of-order handling, an allowlist and cooldown pipeline, a labelled evaluation with hard negatives, and a benchmark. Python 3.9+, standard library only. Offline: it reads files and prints; it sends nothing anywhere.

## Status and attribution
Portfolio prototype, not a production SIEM. Initial code and review were AI-assisted. Dahab has not yet run or reviewed this project.

## What it does
- **Ingest** (`ingest.py`): directories, `.json`, `.json.gz`, `.jsonl`, `.jsonl.gz`. JSONL is incremental; JSON document files are loaded whole. Reorder buffering has time-skew and event-count caps (`--skew`, `--max-buffer-events`) because CloudTrail files are not time-ordered. Late events are counted and dropped, not evaluated out of order. Every rejected record is counted with a reason (invalid JSON line, digest/unknown file, wrong field types, unreadable gzip).
- **Rules**
  - Built-in Python rules CT001-CT007 (brute force then success, root API use, logging tampering, admin policy attach, permission enumeration, S3 public exposure, key created for another user).
  - JSON DSL (`dsl.py`, example in `rules/example_rules.json`): `match`, `threshold` (optionally distinct values of a field) and `sequence` rules over dotted CloudTrail fields. Strict validation with specific errors, no regex operator, per-rule LRU key-count caps (`max_keys`) and per-key queue caps (`max_events_per_key`, default 10000).
- **Pipeline** (`pipeline.py`): minimum severity, allowlist (each entry needs a reason and must narrow by principal and/or IP; unused entries are reported), cooldown suppression per rule+principal, counters for everything suppressed.
- **Evaluation** (`labelled.py`): 11 labelled attacks and 11 deliberate hard negatives (just under thresholds, wrong order, wrong actor, too slow, MFA used, own access key, conditional bucket policy). Reports per-rule true/false positives, misses, precision and recall. A test loosens thresholds and checks the evaluation then reports false positives, so the hard negatives are known to bite.
- **Benchmark** (`bench.py`): lazily generated stream with thousands of distinct principals; reports events/second and peak Python heap.

## Run
```
cd cloudtrail-detect
export PYTHONPATH=src
python3 -m ctdetect.cli validate-rules rules/example_rules.json
python3 -m ctdetect.cli evaluate-labelled
python3 -m ctdetect.cli bench --events 100000 --memory
python3 -m ctdetect.cli simulate --out /tmp/logs.jsonl
python3 -m ctdetect.cli scan /tmp/logs.jsonl --skew 100000 --rules rules/example_rules.json --cooldown 300 --min-severity MEDIUM
python3 -m ctdetect.cli scan /path/to/exported/cloudtrail/dir --allowlist allow.json
python3 -m unittest discover -s tests -v
```
Allowlist file: `[{"rule_id": "CT002", "principal": "arn:aws:iam::*:user/break-glass", "reason": "documented emergency account"}]`.

Benchmark numbers are local, synthetic and machine-dependent, not a capacity or deployment claim. Run the command on your own machine; the benchmark does not exercise disk ingestion or file reordering.

## Limits
- All evaluation data is synthetic and was authored together with the rules. A clean evaluation shows the rules behave as their author intended on these cases. It is not a real-world false-positive rate or recall.
- Thresholds are illustrative and untuned. No enrichment (GeoIP, asset inventory), no alert delivery, no persistence or checkpointing across runs.
- DSL state has explicit count caps; this is not a process-wide byte-memory guarantee. Eviction can cause missed detections. The built-in Python rules (CT001-CT007) keep per-key windows with no cap on the number of keys.
- The reorder buffer holds events for `--skew` seconds of log time. Events older than the last released time are dropped and counted as late. Event-count pressure can force early release before the skew deadline and is counted. Both are data-quality warnings.
- Parsing assumes the common CloudTrail record shape; unusual services or fields can be rejected (and counted). CloudTrail Insights and digest files are not analysed.
- Installed evaluation/benchmark use a packaged copy of the example rules, tested outside the source directory. If modifying example rules, update the packaged copy in `src/ctdetect/data/` too.
- MITRE ATT&CK ids are triage references, not a coverage claim.

## Review and operational semantics
- 36 tests passed on Python 3.10.12 after independent expanded-feature review. The configured Python 3.9/3.12 CI matrix has not been executed. Details and actual output are included in REVIEW_NOTES.md and TEST_RESULTS.txt.
- Exit 0 means scan completed without detected loss/parse warnings and no critical alert. Exit 2 means at least one critical alert in an otherwise clean scan. Exit 1 means invalid arguments/input, empty input, rejected/unreadable content, dropped late events, capacity-driven release, or DSL state eviction/drop. Findings are still printed on a partial scan. Severity is never a statement that the account is safe.
- JSON scan output remains an array of alerts; diagnostics are JSON on stderr. Retain both. Scanning a directory containing config/report JSON can reject those files; use a logs-only input directory.
- Match and threshold rules evaluate exact selected fields. Sequence rules retain one greedy partial sequence per group, restarting on a new first step. They do not enumerate all overlapping sequences. `within_seconds` is per adjacent step, not a total-sequence deadline. Events must be in nondecreasing time; direct DSL calls reject retrograde input.
- Threshold queues reset after a detection, so results are non-overlapping batches, not an alert at every sliding-window crossing. A missing distinct field is not counted. Suppression is per rule/principal, not per IP/resource.
- Built-in rule keys, cooldown keys, whole-file JSON, directory path lists and the CLI's collected alert list can grow. This is not an end-to-end bounded-memory streaming SIEM. JSONL input plus DSL-only rules narrows state but does not establish a total byte bound.
- Built-in S3 alerts indicate risky configuration, not effective public access. Public access block and complete policy/ACL semantics are not evaluated. Conditional bucket policies are skipped, potentially missing exposure. Logging changes can strengthen protection, so they are not proof of tampering. Correlation by shared IP can be misleading. Event-source/service schema validation is incomplete.
- Eleven expected detection instances are not eleven independent attacks: one recon event is expected to trigger both CT005 and D001. Eleven hard-negative groups are authored beside the rules. Perfect synthetic precision/recall does not demonstrate protection against real attackers.
- The allowlist requires nonempty textual reasons and at least one selector containing a literal character. Broad reviewed patterns can still suppress too much; the validation is a hygiene check, not proof that a human reviewed the entry. No network sending occurs.

## Optional installation
```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install .
ctdetect evaluate-labelled
```
The generated demo logs are deliberately shuffled across six hours. The demo scan uses a large skew only to reorder that known small fixture; it is not a production setting.

Keep real CloudTrail logs and outputs private. The repository contains only fictional data.
