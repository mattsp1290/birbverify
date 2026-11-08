# Birbforge consumer handoff

Status is DOCUMENTATION PROPOSAL. No consumer file or pin changes are included.
The source baseline is `6b46dac2931225e0739e9deb047e48b956bff8fc`.

## Receiving boundaries

| Consumer location | Current behavior | Proposed later change |
| --- | --- | --- |
| `verification/producer.py`, `observe`, lines 31-58 | Separate inspect/result/current-attempt RPCs and local recovery files | Negotiate `birbverify.closure.v1`. Read target-owned closure and environment in one revisioned snapshot. Keep known recovery observations distinct. |
| `verification/model.py`, `ProducerObservation`, `QueueRow`, `QueueState` | Typed queue and observation shapes | Add separate closure reference, resolved epoch, target incarnation, terminal closure-only condition, and validated release observation. Do not add fields to the v1 Manifest. |
| `verification/workflow.py`, `reconcile`, lines 173-219 | Manifest makes a request terminal. Known rejected/cancelled no-attempt cases can become `not_acquired`. Unknown dispatch stays uncertain. | Validate the exact blocked request's closure evidence before marking `closed_without_verification`. Preserve original manifest and request binding. Generic non-retryable errors are not closure receipts. |
| `verification/workflow.py`, `run`, lines 232-305 | FIFO excludes completed phases and dispatches only when observation says free | Exclude a valid closure-only terminal head, retain current free-state gate, and retain closure identities through Continue-As-New. Never redispatch the closed request. |
| `verification/supervisor.py`, `supervise`, lines 58-172 | Requires local context and worker token | Add a separate contextless command using original request identity, installed authority, and target journal. Check closure state before both existing branches, including the local receipt replay branch. Refuse legacy recovery for a claimed request. Keep ordinary unclaimed known-context receipt semantics unchanged. |
| `verification/producer.py`, `projection` | Computes eligibility and AG-UI-facing view | Show closure progress and separate receipt. Preserve historical manifest, cancellation state, and eligibility. Never infer success from availability. |
| `tests/verification_python/test_queue.py` and `test_temporal.py` | Unknown dispatch quarantine and known-context recovery coverage | Add later integration tests for both unknown-context cases, closure replay, atomic observation, successor ownership, and one-attempt preservation. |

For closure-capable installations, `observe` excludes closure-claimed requests from legacy `recovered_attempts`. The legacy supervisor must check claim status before any `stop_container` or local receipt write, including its early owner-mismatch branch. A local recovery receipt cannot override target closure ownership. For this same-host fixture, both supervisor modes must hold one installation-owned per-request reconciliation lock before checking target claim status and through any local receipt publication. The contextless supervisor holds that same lock across its `begin_closure` call. The target itself does not acquire a consumer-side file lock. An earlier legacy operation therefore completes before the claim, or a later one sees the claim and refuses. This lock serializes trusted supervisors only; it supplies no worker fencing or stop authority. Remote supervisors would require an equivalent target-owned reconciliation claim and separate acceptance. The target remains the final release authority.

The consumer source observations are grounded in the read-only named source reports. The existing target `inspect` returns no token. The existing consumer `observe` is not an atomic snapshot, so assembling the new release proof from its old separate calls is insufficient.

## Exact queue release predicate

For an uncertain request R, the queue can mark R closed only after a supported producer observation establishes every condition below.

1. The target identity and incarnation match the queue's installed binding. The observation has a monotonic target journal revision from one consistent snapshot.
2. The final closure receipt binds R's exact request ID, idempotency key, canonical request digest, expected installed authority, and its resolved epoch and acquired attempt if any. A non-null attempt already known to the queue must match. An unobserved attempt must be adopted from the target evidence, not guessed.
3. The receipt proves a committed permanent request seal. Its stop result is `not_started_target_confirmed` for proven never-acquired execution, or `confirmed` with validated lifecycle evidence for an acquired attempt. Cleanup is complete and release is `release_confirmed`.
4. The receipt and required evidence references pass producer authenticity, integrity, and availability validation through the installed reader. A client copy or raw boolean cannot satisfy this check.
5. Any pre-existing manifest has the identical original digest. If none exists, the terminal type is `closed_without_verification`, with no fabricated `Manifest`, outcome pass/fail, or delivery eligibility.

The queue can dispatch its next eligible queued request only when R has been reconciled as above and the same fresh observation says the current environment is free, with no attempt or closure owner. The snapshot revision must be at least the receipt's release revision. Unknown target status or a different current owner keeps dispatch blocked. Later acquisition still checks target ownership atomically, since observation is not a reservation.

A historical receipt remains valid when a successor owns the target, but it cannot authorize releasing that successor. Older out-of-order observations are discarded by incarnation and target revision. A new incarnation requires installation reconciliation rather than automatic acceptance. The queue retains each request's immutable `admission_target_incarnation`. It cannot carry an old request into a new incarnation to obtain a never-acquired receipt. This extension leaves such old requests unresolved as `legacy_provenance_unavailable`; a restore record gates new installation admission but never relabels old execution. An uncertain head bound to the old incarnation continues to block that FIFO queue by design. A separately reviewed operator action or new queue binding is required; this extension grants no head-skip. Requests admitted under the old incarnation but never dispatched must also be re-admitted with new request and idempotency identities before execution under the new incarnation. Workflow completion, cancellation acknowledgement, deadline expiry, current free state alone, or absence of a local file cannot replace the predicate.

The existing `not_acquired` rule remains unchanged for the pinned legacy producer profile. In a closure-capable profile, post-dispatch generic rejected or cancelled activity outcomes do not skip the head based on an absent attempt alone. They require the target closure predicate above. Pre-dispatch queued cancellation and queued expiry keep their existing behavior. This is an explicit later integration change, not a change to the working acquired-context recovery path. Capability-specific tests must preserve the legacy behavior and exercise the stricter extension behavior.

`dispatch_unknown`, `fenced_stop_unknown`, `fenced_cleanup_unknown`, missing evidence, unsupported version, payload conflict, and legacy missing provenance all keep the queue blocked. An acquired attempt with a lost local context never becomes `never_acquired`.

## Ownership and delivery

Birbverify owns the target transaction, permanent seal, lifecycle evidence adapter, closure journal, and attributable receipt. Birbforge owns admission, trusted authorization, FIFO queue decisions, and delivery eligibility. The host supervisor executes privileged reconciliation. AG-UI remains a client projection and carries no release authority. No new agent runtime or second scheduler is proposed.

Closure is not an application outcome. A prior inconclusive manifest stays inconclusive. A passed historical manifest remains subject to existing artifact checks and current candidate, plan, and policy checks. Closure does not make a failed or missing manifest eligible. Cancellation requested and physical stop remain distinct observations.

The consumer owner must accept the strict schema version and canonical golden fixtures before selecting a later producer pin. This assignment pins neither side differently. Receiving-owner acceptance keeps implementation, integration, and deployment as separate work. `birbforge-s0sc` remains open pending handoff acceptance.

## Bounded producer implementation prompt

Implement the selected contract in an isolated new producer worktree based on the accepted proposal revision. Add request seals, incarnation and epoch identity, atomic reservation provenance, privileged closure journal operations, and immutable receipt publication within the existing target service. Fence every legacy mutator of a claimed request. Preserve `contracts/v1` and known-context manifest/recovery semantics.

Use a fresh Linux fixture. Record exact worker execution registration, including the entire token-holding activity-worker process and descendants. Require positively acknowledged durable intent before sending each Docker lifecycle command. Unknown or failed intent acknowledgement aborts the send. Accept post-seal settlement evidence for existing intents without granting new execution authority. Implement release for proven never-acquired requests and acquired attempts with complete stop/settlement/cleanup evidence. Keep uncertain daemon delivery and legacy missing provenance quarantined. Do not claim automatic recovery for those unsupported cases.

Publish strict proposed-extension schemas and golden digest fixtures only after source review. Execute the failure matrix with actual barriers, lost replies, restart, and independent transaction races. Record exact revisions and attributable evidence. Obtain independent adversarial review of stale-worker release paths and resolve findings.

Return a reviewed producer implementation PR and named private handoff. Do not edit Birbforge, change consumer pins, deploy, merge, reuse the stopped runtime, add a scheduler, or expand retry support. Ask the receiving coordinator to authorize those later milestones separately.
