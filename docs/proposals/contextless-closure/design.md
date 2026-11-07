# Why closure belongs in the target

Status is DOCUMENTATION PROPOSAL. This explanation selects a bounded fixture contract, not a deployed adapter.

## What the source establishes

The producer references below use revision `a70315a276837ffdde32049fdb77670a3468e151`. The consumer references use `6b46dac2931225e0739e9deb047e48b956bff8fc`. Line numbers refer to those revisions.

| Boundary | Source finding |
| --- | --- |
| Admission | [`Target.call`](../../../src/birbverify/target.py), lines 75-95, binds canonical request and idempotency key. `policy.authorize` checks installation authority. There is no closed-request record. |
| Acquisition | `target.py`, lines 96-148, commits the attempt and fresh token with environment ownership. A free target and absent terminal manifest can permit a delayed `reserve`. |
| Lost context | [`Runner.execute`](../../../src/birbverify/runner.py), lines 399-425, calls `reserve` before writing the context. The target retains the request and attempt, but not worker start time, attempt number as a stored field, or exact execution-process provenance. |
| Activity identity | [`Activities.verify`](../../../src/birbverify/temporal_worker.py), lines 72-104, derives attempt identity from request, Temporal run, activity, and retry. A heartbeat identity is not proof of acquisition. |
| Actual target mutation | `target.py`, lines 59-62, 162-207, and 343-352, serializes the owner/state/deadline check, counter mutation, and operation receipt in one SQLite transaction. This is the boundary a request seal can strengthen. |
| Other lifecycle writes | `target.py`, lines 208-315, has owner-authorized revoke, uncertain, cancel, stop, cleanup, and finish paths. `cleanup` and `finish` cannot be left as stale-token bypasses after closure. |
| External execution | `runner.py`, lines 202-283, creates Docker before `assert_active` and starts Docker after that check. The SQL fence is not atomic with Docker. Container absence at one instant does not rule out a delayed create. |
| Known-context recovery | Consumer `verification/supervisor.py`, lines 58-172, reads the context first, checks Linux boot/PID/start identity and a worker lock, confirms container absence, preserves an inconclusive manifest, and reconciles recover/cleanup/release. It cannot start without the context. |
| Queue uncertainty | Consumer `verification/workflow.py`, lines 173-219 and 232-305, retains unknown dispatch at the FIFO head. `verification/producer.py`, lines 31-58, observes manifests and acquired attempts separately. |

The requested [README](../../../README.md), [milestone](../../first-milestone.md), [contract](../../contract.md), [architecture](../../architecture.md), and [deployment handoff](../../deployment-handoff.md) distinguish fixture guarantees from staging requirements.

Existing producer tests cover stale `apply`, known-token quarantine, delayed duplicate effects, lost finish replies, and repeated cancellation during Docker creation. See [`test_target.py`](../../../tests/test_target.py) and [`test_journeys.py`](../../../tests/test_journeys.py), especially `test_stale_process_and_quarantine`, `test_delayed_original_effect_and_policy_boundary`, and `test_repeated_cancellation_during_create_and_cleanup`.

Consumer `tests/verification_python/test_temporal.py` contains known-context recovery and `test_timeout_without_attempt_stays_blocked_and_expires_all_queued`. Its `test_queue.py` distinguishes unknown activity outcomes from confirmed rejection. These are source observations of tests and previously recorded evidence, not fresh executions here. Missing-context safe closure has no executed proof in this assignment.

## Mechanisms considered

| Mechanism | Cost and safety consequence |
| --- | --- |
| Confirm Temporal cancellation, elapsed deadline, or current free target | Requires little producer work, but creates no durable denial of a delayed acquisition. Rejected. |
| Revoke only an acquired token and reconstruct a local context | Extends the known path but cannot seal a request before acquisition. Reconstructing missing fields from guesses invents evidence. Rejected. |
| Advance one environment epoch for every closure | Can reject old epoch-bearing workers, but requires pre-dispatch epoch grants and changes every worker request. An old no-epoch `reserve` is still a bypass unless separately blocked. More machinery than this one-attempt fixture needs. |
| Seal the request in the target and bind its execution epoch durably | Uses the same SQLite transaction as acquisition and `apply`. It denies every later acquisition of the original request and invalidates a matching acquired token. Selected. |

The selected request seal is permanent for the installation incarnation. An execution epoch identifies one request's execution authorization, not a lease or retry counter. The target assigns that epoch when the request first reaches it through admission or closure. Closure never reopens it or allocates another attempt. The caller can close a request whose epoch it has never observed because the target resolves it exactly once.

This avoids a new pre-dispatch scheduler or grant service. Birbforge retains admission order and dispatch. The target adds a journal and fences within its existing service. A new verification requires a new request and idempotency key.

## Why fencing does not establish worker stop

Closing the request denies new `reserve` and SQL mutation commits. A `BEGIN IMMEDIATE` transaction orders `apply` against closure. An effect committed before the seal is retained as evidence and cleaned later. An effect ordered after the seal is rejected.

A worker can still be paused between `assert_active` and Docker start. A create command can still be pending at the daemon after its client dies. The selected contract therefore keeps an acquired environment quarantined until an installation-trusted supervisor confirms the execution process tree stopped, all issued lifecycle commands settled, and the exact container is absent. It never treats the SQL seal as those proofs.

For the fixture, `Target.call("apply")` writes the candidate effect. `cleanup` resets it, while `finish` and `release` change ownership. All these paths need the seal check. Candidate containers have no target socket, network, writable shared mount, or deployment credentials. Docker lifecycle and local artifact writes remain separate effects to reconcile. This distinction follows `runner.py` and [the existing architecture](../../architecture.md). It is not a claim that a staging command behind a one-time `assert_active` is safe.

The implementation must durably record lifecycle intent before each Docker create/start/remove command, with a stable operation identity, argument digest, execution identity, and completion evidence. The supervisor must account for every unresolved intent. An intent or missing container alone cannot prove whether a command was sent. An unresolvable daemon operation keeps closure at `fenced_stop_unknown`. No blind retry, sleep-based proof, or second request is permitted.

This journal does not by itself make Docker commands exactly once. The bounded implementation may first support release only when all commands have recorded settlement, including the reserve-reply-loss case before any command intent. Faults with uncertain daemon delivery remain quarantined. A later adapter that can prove daemon settlement may expand that release path under separate acceptance. This conservative limit is deliberate and testable.

## Preservation of the working recovery path

The normal known-context path still preserves the original inconclusive manifest and uses a separate recovery receipt. Requests that have no contextless closure retain the existing behavior. Closure claims and legacy recovery operations must serialize in the target. Once a closure owns the request, legacy worker or recovery calls cannot release it. Before that claim, a known-context recovery that already released the attempt wins and closure returns `already_released` without rewriting history.

One precise lifecycle change is that the new privileged `release_closure` may commit a closure receipt without a verification manifest. That exception applies only to the claimed sealed request after confirmed stop and cleanup. The old `release` continues to require a terminal manifest. The exception is necessary because contextless recovery cannot truthfully recreate all worker manifest fields from current records. A closure-capable target also records normal finish and supervised release transitions durably. This lets it prove `already_released` without mistaking a different current owner for release evidence. That internal journal addition leaves the existing manifest and consumer recovery receipt unchanged.

## Unproven implementation and deployment assumptions

The current source does not implement request seals, target incarnation identity, durable execution provenance, closure journals, or these receipts. The race matrix defines their future fixture acceptance.

Linux process-tree control and Docker intent settlement are implementation gates. The receiving owner must select an installation-owned execution group with stable identity that includes the token-holding Temporal worker itself and all descendants. A group containing only per-attempt Docker children cannot prove the in-process coroutine stopped. The initial experiment can use a dedicated Linux cgroup and fixture daemon fault controls, if supported by that isolated host. No statement here asserts those controls exist on the current host.

An upgraded target cannot reconstruct missing historical process identity from an old database. Such acquired records stay quarantined as `legacy_provenance_unavailable`. No migration may bless them from file absence. New fixture installations can supply complete provenance before reservation succeeds. An old unacquired request can be sealed only if the target installation identity and complete durable request history are established. Database loss or rollback invalidates that proof.

Birbhomes owns readiness, isolation, and actual deployed lifecycle controls. Its separate readiness proposal must establish a mutation boundary for every staging writer, including manual and CI writers. Until that adapter and lifecycle proof exist, this proposal permits no k3s or native release claim.

The Birbhomes readiness owner independently reported no established k3s mutation adapter in its named handoff. Helm completion does not settle Kubernetes controllers, Jobs, schema changes, or fixture effects. Deployed workers must not hold reusable direct mutation credentials that bypass target authorization. All-writer fencing, continuous interference observation, native isolation, and worker-independent evidence remain separate gates. This is an owner-handoff constraint, not a new infrastructure observation by this producer assignment.

The per-request epoch is an attribution and mismatch-check identity. For this one-attempt profile, the permanent request seal supplies the late-acquisition fence. The epoch alone adds no independent revocation guarantee. Silent database rollback preserving its incarnation is outside the fixture trust model. The proposal adds no external monotonic witness. Operator-declared restore forces a new incarnation and reconciliation of all earlier execution before admission.

Restore reconciliation must also establish absence of every prior-incarnation attempt container after all commands settle. It does not authorize reclassifying an old acquired request as never acquired. The selected extension rejects cross-incarnation closure and preserves the original admission-incarnation binding. Old records with incomplete history remain unresolved; new work uses new identities.
