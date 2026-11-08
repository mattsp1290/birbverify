# Contextless closure acceptance

The isolated Linux producer proof passed on 2026-11-08. All 77 tests passed with
zero failures, errors or skips. This accepts the fixture implementation for
consumer integration. It does not establish Birbforge queue, staging or native
isolation acceptance.

## Revision and evidence

The executed source commit is `98ef163155b795ed5f7c00d363df0961eb4cdb00`.
The final PR also contains a later documentation-only acceptance commit.
The runtime source, tests, schemas, fixtures and proof scripts have not changed
since the executed commit.

The public runner was `scripts/setup` with the closure profile, followed by
`scripts/verify-closure`. It ran in an isolated Linux aarch64 container on Docker
Desktop. The [reproduction guide](contextless-closure.md#run-the-isolated-proof)
describes the required PID, cgroup and Docker socket access. The worker image ID
is recorded in the [machine-readable evidence index](evidence/contextless-closure-acceptance.json).
Build-time OS packages are not claimed to be binary reproducible.

The parent agent executed the suite and audited its artifacts. It compared all
52 source hashes with `git show` at the executed commit, checked the unchanged
bytes of all eight original v1 contract files, and hashed 122 retained artifacts.
The audit includes 81 referenced lifecycle evidence files and 34 receipt
occurrences. Each receipt's producer revision and canonical digest matched.
The source manifest excludes documentation. Later documentation edits are not
runtime reruns.

Raw logs, databases, credentials and command evidence remain private. The public
index publishes file digests and safe summary metadata. Digests provide a way to
compare retained evidence; they are not a substitute for rerunning the proof.
No task-labelled driver, worker or candidate containers remained after the run.

## Behaviors exercised

The [F01 through F29 gate map](contextless-closure-gates.md) separates direct target
tests from real runtime journeys. The full suite includes the original fixture
journeys and the new closure tests.

- A real worker delayed before admission or reserve cannot acquire a sealed request.
- Lost reserve replies and deleted worker context do not erase target provenance.
- Whole-worker removal stops the token holder and an escaped-session descendant.
- A real delayed Docker create remains quarantined even after observed absence.
- Acquired and never-acquired closure steps survive crashes and lost replies.
- Independent target connections exercise both orders of reserve, apply and legacy
  recovery against closure. Replay cannot release a successor's environment.
- Missing or corrupt proof cannot satisfy the fixture's queue-release predicate.
- Real Temporal worker loss and a non-retryable `RequestClosed` result are exercised.

The last regression uses a proxy that delays a real Docker start reply beyond
the procedure budget. Both cases record a determinate start. The procedure timeout
case releases after confirmed absence. The expired-lease case remains quarantined
until supervisor closure, which preserves the original manifest. Restoring the
old short start timeout in a private source copy made both cases fail.

## Independent review and fixes

Claude Opus reviewed supplied source and evidence in separate sessions. It did
not execute tests or independently inspect Git. The parent supplied exact source
packets and checked their hashes. The final follow-up reported no blocking source
findings; execution remained a separate gate, closed by the full run above.

| Finding | Resolution |
| --- | --- |
| A lifecycle intent could borrow another attempt's authority | Bind the intent attempt and epoch to the authenticated owner before recording it |
| The extension omitted timeout and observation-shape checks | Restore bounded waits and validate the approved assertion and result shape |
| Unknown read-only wait blocked recovery like an unknown mutation | Require settlement of mutations and a separate attributable final absence observation |
| A short procedure budget could abandon a determinate start reply | Keep the normal control timeout for start and cleanup; apply remaining budget to read-only wait |
| Missing acquired provenance had a synthetic digest | Use an explicit unavailable progress variant that cannot form a release receipt |
| Acquired interruption and legacy arbitration coverage was incomplete | Add committed-step crash cases and independent-connection transaction order tests |

The final source review also confirmed the expired-lease policy after runtime
execution exposed an incorrect test expectation. The fix changed that test to
require supervisor closure; it did not weaken the policy.

## Limits and follow-up

Unknown mutating delivery remains quarantined. Supervisor observation IDs can also
remain blocked after an unknown or non-404 result. Restore reconciliation and
silent database rollback detection are not implemented. The worker and daemon
adapter are trusted installation components with Docker access.

The new timing tests use bounded wall-clock windows. A sufficiently slow host can
fail a timing precondition rather than establish acceptance. Malformed responses
from a misbehaving trusted Docker daemon are not fully normalized. These were
nonblocking review observations, not claims of hostile-worker containment.

Birbforge still needs its own explicit dependency update and integration proof.
It must arbitrate its supervisor paths, preserve original manifests, and require
the exact request's validated receipt plus current free state before its queue
advances. Its AG-UI projection must distinguish historical outcome from current
availability. No consumer pin changed in this work.

Shared k3s staging, native isolation, production identity, artifact access and
retention, and physical client journeys remain separate gates. This proof made
no deployment, production action, live model call or Datadog call. Independent
review used the existing Claude subscription outside the proof runtime.
