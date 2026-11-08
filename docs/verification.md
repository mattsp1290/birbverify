# Contract proof evidence

All nine required fixture journeys are verified by the fourteen-test run.
Independent Claude source review found defects, the warranted findings were
fixed, and the fresh closure review reports no remaining blocking defect
within the supplied source and fixture scope. Recorded
runtime facts and author conclusions are separate below. No fixture evidence
represents deployed staging or native Mac isolation.

## Reproduce the proof

Run `scripts/setup` then `scripts/verify` from a Linux checkout with Docker.
Setup verifies the Temporal 1.10.0 archive against its published checksums.
Temporal reports server 1.32.2 and UI 2.56.1. `uv.lock` pins Python dependencies,
including Temporal SDK 1.35.0, Pydantic 2.12.5 and AG-UI protocol 1.0.0.
The observed host Python is 3.13.12 and Docker Engine is 29.1.3.
The candidate image is pinned in `runner.py` by its repository SHA-256 digest.
The latest full run passed fourteen tests, including all nine required journeys.
`evidence/acceptance.json` records the exact versions, source and artifact hashes.
The run is authored evidence. The independent reviewer did not execute it.

The proof scripts isolate the test environment from ambient credentials and
observability auto-instrumentation. Review calls are separate owner-authorized
Claude subscription processes and are not a fixture dependency.

## Executed journeys

The following are assertions executed by `tests/test_journeys.py`. Their safe
machine-readable observations are in `docs/evidence`.

| Journey | Observation artifact |
| --- | --- |
| 1. Exact candidate, attributable observations and manifest | `candidate-evidence.json` |
| 2. Missing required evidence blocks success, removed artifact blocks eligibility | `candidate-evidence.json` |
| 3. Duplicate converges, conflicting payload rejected | `candidate-evidence.json` |
| 4. Target drops socket reply after commit, receipt reconciles one effect | `lost-reply.json` |
| 5. Temporal worker receives SIGKILL and wait returns -9, assertion remains not run | `temporal-interruption.json` |
| 6. Second request sees busy until supervised stop, cleanup and release | `fencing.json` |
| 7. Still-live subprocess denied at target apply boundary after revocation | `fencing.json` |
| 8. Changed source cannot relabel immutable manifest or satisfy current-candidate gate | `candidate-evidence.json` |
| 9. Requested cancellation blocks release, SDK cancellation stops a running container before acknowledgement | `temporal-interruption.json` |

`expiry.json` verifies deadline expiry denies mutation without releasing the
reservation. `operation-race.json` verifies concurrent duplicate apply calls
produce one receipt and revocation does not hide that receipt. The target rejects
an unapproved principal before admission. Contract tests check published schema
drift, invalid examples, immutability and the golden canonical request digest.

The worker-loss case kills the worker after the committed fixture effect and
before candidate check execution. The supervisor records infrastructure
uncertainty and explicitly terminates the test workflow before reconciling
stop and cleanup. It does not claim automatic recovery of an orphaned native
process or a successful check after worker loss. The cancellation case separately
runs and forcibly removes an actual container. The stale subprocess test proves
the service transaction boundary, not a host security boundary.

## Failures encountered

The first Docker integration run quarantined a stopped container because the
subprocess reader consumed only the first output chunk. The fix reads through
EOF with a byte limit. A later run under `umask 077` exposed an unreadable
candidate mount. The worker now explicitly sets the mount directory and file
permissions while the installation parent stays private. Both were observed
failures and were followed by complete reruns.

Two initial review attempts did not supply usable review. One returned no result
before it was stopped. Another fabricated textual tool observations with an
empty tool list. Those observations were rejected. The accepted independent
design review received only the explicit design and returned model identity
`claude-opus-5-5`. Its raw account/session metadata stays private. The public
review file contains findings and limitations only.

## Independent review and open gates

`design-review.json` is independent prose-design review, not code approval.
`review-resolution.md` records the author's disposition of findings. Source
review cannot verify the runtime observations. The final evidence index binds
safe summaries and contracts to content digests.

The smallest next integration is for Birbforge to pin this schema and fixture
revision, then call the activity from its existing durable environment queue.
Agree the production mutation adapter and quarantine/reconciliation interface
with Birbhomes before any staging run. See `deployment-handoff.md`.

`atomic-finish.json` records a concurrent duplicate and a dropped post-commit
finish reply. Both callers return the same manifest with one effect.
`repeated-cancellation.json` records repeated cancellation after actual Docker
create and during held cleanup. Release waits for confirmed container absence.
The Temporal interruption artifact also includes a second workflow that waits
for the fixture supervisor and then completes with acquired attempt number one.

`unknown-stop.json` records a real running container with intentionally
unavailable stop confirmation. Cancellation stays requested, the environment
stays quarantined and a worker token cannot recover it. The supervisor then
confirms actual removal and uses its separate fixture capability. The immutable
original manifest continues to record the historical uncertainty.
