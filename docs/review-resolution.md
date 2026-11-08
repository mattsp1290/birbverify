# Independent review disposition

The accepted design review is `evidence/design-review.json`, returned by
`claude-opus-5-5`. It reviewed only explicitly supplied design text. Codex owns
these dispositions and their implementation. Runtime test output is author-run
evidence, not an independently executed test.

| Finding | Disposition |
| --- | --- |
| H1. Absent receipt can race delayed original | Agreed absence is not proof. The existing same-ID transaction deduplicates either ordering. Concurrent duplicate test demonstrates one effect. No new effect ID follows absence. A tombstone would change this fixture's semantics without improving that invariant. Other adapters still require reconciliation. |
| H2. Receipt read after revoke and parameter binding | Implemented and tested, including conflicting parameter digest rejection. |
| H3. Cancellation during Docker create/start | Deterministic name exists before create. Creation is shielded and awaited before stop. Reservation is rechecked before start. Forced removal and not-found inspection establish stop. Running-container cancellation is executed. Additional fault windows remain listed below. |
| H4. Stable operation IDs and retry budgets | Operation ID excludes attempt. Request max_attempts controls Temporal RetryPolicy and target's acquired-attempt budget. Busy dispatch is now a non-retryable signal to the test workflow. Unknown termination requires supervision rather than automatic effect retry. |
| H5. Cancellation completion | Uses supported WAIT_CANCELLATION_COMPLETED and a heartbeat task. Test observes requested before acknowledged and rejects early release. |
| H6. Orphaned containers/processes | Unknown termination quarantines. Supervisor must reconcile all owned execution before release. The SIGKILL test stops before candidate launch; running-container cleanup is a separate cancellation test. Automatic orphan reconciliation is outside this bounded adapter. |
| M1/M2. Token and clock authority | Every reservation has a fresh token, same-transaction revocation and target-clock absolute deadline checks. Expiry does not release. Executed expiry test verifies denial and quarantine. No cross-node clock claim. |
| M3. Target-side permissions | Installed allowlist is shared by worker and target admission. Mutation checks request operations in its transaction. Unapproved principal is rejected at the target. |
| M4. Approved procedure bytes | Exact commit files, pinned procedure revision and digest, read-only container, isolated Python and no candidate config discovery. |
| M5. Canonical format and shallow immutability | Documented exact pinned JSON encoding. Nested fields are frozen records and tuples. Added a golden digest test. This is not RFC 8785. |
| M6. Missing/corrupt/inaccessible evidence | Eligibility requires a reader and verifies every size/digest. Missing and corrupt bytes are exercised. I/O denial returns unavailable. Atomic manifest publication is a SQLite commit. |
| M7. Quarantine exit | Executed supervised stop, cleanup and release, followed by a successful second request. |
| L1-L4. Docker limits, host trust, ancestry | Non-root, no capabilities/network, resource limits and pinned image are in use. Same-UID and Docker privilege limits are explicit. Base ancestry is checked. |
| L5. AG-UI acknowledgement | Running, cancel_requested and terminal manifest remain distinct. Observer close has no command effect. |

Two earlier review attempts were rejected. One produced no final result before
termination. Another had no tools but emitted invented textual invocations and
file observations. Neither is cited as design or source approval. The accepted
review used a fresh process with an explicit no-tools system prompt. Review
processes removed ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN and ANTHROPIC_BASE_URL
only for that process. CLI 2.1.309 help and sanitized auth status confirmed safe
mode and existing Claude Max subscription login. No API fallback or persistent
account change was used.

Cursor Task, deslop, Comment Sicko and control APIs were unavailable. The actual
substitutions were explicit design comparison, fresh Claude CLI review of
supplied public source, Ruff and format checks, diff inspection and executable
process tests. No Cursor tool run or independent runtime execution is claimed.

The initial source review and follow-up are recorded below. Additional deployment acceptance must include kills
inside Docker create/start, orphaned-running-container supervision, cancellation
during failed cleanup, native process trees and actual staging mutation paths.
Those deployment cases must not be inferred from this local counter proof.

## Source review fixes

The fresh source review in `evidence/code-review.json` rejected the first
implementation snapshot. Its important findings changed the implementation.

| Finding | Final disposition |
| --- | --- |
| H1/H2. Repeated cancellation can interrupt create/stop reconciliation | A per-execution stop record now starts unknown before create. Repeated cancellation only marks requested while shielded control tasks settle. Unknown create/stop cannot acknowledge cancellation or release. A deterministic test cancels repeatedly after actual Docker create and during delayed cleanup. |
| H3. Release precedes manifest publication | Replaced save plus release with owner-checked `finish`. Canonical manifest publication and target release/quarantine share one SQLite transaction. Reserve checks for an existing terminal result in that transaction. Concurrent duplicate and dropped-finish-reply tests return the same result and one effect. |
| H4. Receipt survives cleanup | Historical receipts intentionally survive. Atomic terminal-result convergence prevents a new reservation for that request after cleanup. A new verification needs a new request. No receipt is voided or silently repeated under a different effect identity. The post-cleanup reserve test returns the canonical result. |
| H5. Stale token can lift quarantine | Quarantine is monotonic under revoke/cancel. Worker stop cannot lift it. Recovery requires a separate random fixture-supervisor capability, stored outside worker configuration but reachable to trusted same-UID host processes. The supervisor tests first confirm real process termination. Same-UID malicious supervisor isolation is still excluded. |
| H6. Token in inspection | Removed from the inspection projection. Tests assert its absence. |
| H7. Expiry and waiting | Inspection/reservation detects expired active ownership and quarantines it without release. Busy is non-retryable at the activity boundary. The test workflow waits for an explicit fixture-supervisor signal, bounded by the deadline. A real second Temporal workflow waits across worker kill and supervisor recovery, then succeeds. This is test coordination, not Birbforge's production queue. |
| M1. Attempt identity | Activity IDs include the Temporal run, activity and SDK attempt digest. The target returns acquired attempt number and actual predecessor. Busy dispatch does not create an attempt. |
| M2. Never-started false pass | Require an exited container with nonzero StartedAt and matching CLI/container exit status. Parse observation JSON and match the approved assertion and pass Boolean. Runtime tests show Docker start -a returns 1 for an assertion failure, so requiring only CLI exit 0 would misclassify real failed assertions. |
| M3. Over-quarantine | Execution stop state distinguishes confirmed cleanup from unknown container termination. Pre-effect errors can stop and finalize inconclusive without quarantine. |
| M4. Local blocking I/O | Retained bounded local Unix-socket and Git calls for this fixture. They can delay heartbeat/cancellation. A delay never releases ownership, and production asynchronous adapters remain a deployment gate. |
| M5. Result consistency | Added timestamp, check uniqueness, retry/predecessor and cancellation/cleanup/release validators and a structured reason. The fixture has no requester authentication API; Birbforge remains the command authority. |
| M6. Repeated check claims | Installation explicitly accepts one approved check only. Its output assertion must match. |
| M7. Artifact publication | Command artifact includes request and attempt identity. Content-addressed files use fsync and atomic replacement. Equal observation bytes can share a content digest; manifests retain attribution. |
| M8. Projection | Stored manifests are parsed by the producer model. RunFinished closes observation; the authoritative snapshot carries passed, failed, inconclusive or cancelled outcome. It is not an assertion-success event. The adapter is a private authenticated-consumer integration input, not a public artifact endpoint. |
| M9/M10. Retry and fault hooks | Identity/target validation errors are non-retryable. The installation requires explicit fixture mode. Target reply-loss hooks only operate in that mode. |
| Low severity and comments | SQLite connections close explicitly. Docker uses pull=never. Invalid examples must have exactly three files. Removed unsupported comment and plan claims. Final trail entries supersede pending rows with actual runtime references. |

No source-review claim is counted as independently executed acceptance. The
follow-up review receives the final source and author-run evidence. Its verdict
and remaining limitations are recorded separately.

## Follow-up blockers and closure

The fresh follow-up review, also `claude-opus-5-5`, found no safety violation
in the revised mutation, finish or cancellation boundaries. It identified two
remaining blockers in `evidence/followup-review.json`.

B1 was warranted. Supervised release now requires an immutable terminal manifest.
The real worker-kill journey attempts supervised release after confirmed stop
and cleanup but before manifest publication and verifies refusal. The worker
also reads observed-before from the actual target after receipt reconciliation;
a receipt/target mismatch becomes infrastructure uncertainty, never an invented
observation. Completed requests cannot reacquire the target after cleanup.

B2 concerned stale acceptance and pending trail entries in the supplied snapshot.
The final verification command regenerates JUnit, acceptance, source hashes and
all nine safe observation digests. The appended final decision row identifies
the JUnit digest and supersedes the pending rows. The exact times of the four
earlier drafted events are unknown; the correction bounds them before
16:27:05 UTC rather than inventing replacement timestamps.

The low-severity expiry gap at worker stop is closed with a target-clock check.
Unexpected procedure JSON types are rejected. The final evidence calls the
create fault window `cancel_after_create_before_reply`. Observer disconnect
cancellation is computed from the observed authoritative state. The redundant
ExecutionState default assertion was removed. The milestone status now points
to fixture evidence while retaining deployment gates.

The fresh closure review is `evidence/closure-review.json`, returned by
`claude-opus-5-5`. It closed B1 and B2 and reported no remaining blocking defect
within the supplied source and fixture scope. It did not run tests, recompute
hashes or inspect the active transcript. Its recommended inexpensive hardening
was applied after that review. Unknown termination clears prior stop/cleanup
flags. The worker-loss before-state is a captured target read. Acceptance
rejects skipped tests and stale observation files and includes the source
manifest digest. The final fourteen-test run passed after those changes.

Remaining non-blocking scope limits are trusted same-UID supervision, bounded
local blocking I/O and unavailable staging/native-Mac/operator identity proof.
Retries cannot reacquire a completed request; reruns require a new request.
