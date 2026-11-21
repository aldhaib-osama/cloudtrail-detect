# Expanded-feature independent review, 21 November 2026

AI-assisted educational portfolio project. Dahab has not personally reviewed or run it. Not a production SIEM, real-world protection measurement, or evidence of personal Python proficiency. No accounts or cloud services were accessed and nothing was published.

## Checks actually run
- Submitted candidate: all 26 tests passed, but missed material defects.
- Repaired candidate: 36 tests pass on Python 3.10.12, including 10 independent regression cases. TEST_RESULTS.txt contains actual output. Tests also pass with ResourceWarning escalated.
- Fifty seeds of the small labelled synthetic evaluation produced no unexpected or missing detections. This is not an independent benchmark: data and rules were authored together.
- Package build/install and installed evaluate-labelled/bench work from outside the checkout. Source CLI simulate -> scan with the known fixture's large skew gives eight alerts and critical-finding exit 2 without data-quality warnings.
- A local synthetic benchmark of 10,000 events measured about 23k events/second and 2.6 MB peak traced Python heap on this machine. It excludes disk ingest/reordering and is not a capacity claim. No production or real CloudTrail corpus was used.
- Configured Python 3.9/3.12 hosted CI was NOT executed. No code-coverage percentage, fuzz campaign or formal verification was performed.

## Material expanded defects fixed
- Distinct-threshold queues could grow indefinitely for a single actor despite bounded-state claims. Added a per-key event-count cap, key eviction/event-drop diagnostics and partial-scan exit status when they occur. Missing distinct fields are no longer counted.
- A time-skew buffer is not an event-count bound. Added a reorder event-count cap; capacity-driven releases are counted. Plain JSON still loads whole, and documentation now says so.
- Late records were fed backwards into time-window/sequence state, allowing misleading correlations. Ingestion now drops and counts late events; direct DSL calls reject retrograde timestamps.
- Allowlist validation allowed principal="*" global mutes despite promising narrowed entries, and wrong types could crash matching. Reject pure-wildcard selectors and non-text/empty selectors or reasons. Broad textual patterns remain the operator's responsibility.
- Added rule-object/type validation, missing-predicate-value checks, unknown-field rejection, duplicate pipeline-ID checks and invalid scan/benchmark control checks.
- Installed evaluation/benchmark searched for a source-tree-only rules file. Rules are now included as package data; a regression keeps packaged and editable example copies equal.
- Cooldown-disabled pipelines retained unnecessary state. They now skip that map. Enabled cooldown state is still not globally bounded.
- Empty/rejected/unreadable/late/capacity-degraded input could return success. Such scans now exit 1 with diagnostics, even if some alerts are returned.
- Example rules no longer describe a retry as proof of bypass; secret-read matching now uses service/name pairs and excludes failed calls. An SSM hard-negative fixture now uses the SSM event source instead of Secrets Manager.
- Supplied test fixture writes leaked file handles; fixed context management. A supplied distinct-count test also sent time backwards, which is now corrected.

## Limits that remain
- This is not end-to-end bounded memory: whole JSON documents, directory path lists, built-in rule key maps, enabled cooldown keys and collected CLI alerts can grow. DSL limits count objects/events, not bytes. Large keys or values can still consume memory. Bounds/eviction trade accuracy for finite detector state.
- Reordering cannot guarantee globally correct chronology over arbitrary CloudTrail file arrival. Late data is dropped, not magically recovered. There is no persistence/checkpoint/replay recovery layer.
- Sequence state is one greedy partial match per key, with adjacent-step deadlines. It does not enumerate overlaps or implement a total sequence deadline. Threshold state resets after alerting. Those are documented semantics, not generic CEP behavior.
- Eleven labelled detection instances include one recon event detected by both CT005 and D001. They are not eleven independent attacks. Eleven authored hard-negative groups and many seeds do not estimate field precision/recall.
- The built-in detection rules still have incomplete service validation and AWS semantics. S3 configuration changes do not prove effective exposure; logging changes do not prove weakening; shared-IP login correlation can mislead; conditional bucket policies are skipped.
- The allowlist hygiene check does not prove human review or narrow operational intent. Diagnostics must be retained alongside alerts. Exit 0 never establishes safety.
- Input files and scan outputs may contain private account information; do not commit real logs/reports. Keep honest AI-assistance attribution and update maintainer-review status only after Dahab's own review.
