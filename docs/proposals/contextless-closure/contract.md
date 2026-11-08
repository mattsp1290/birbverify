# Proposed contextless closure contract

Status is DOCUMENTATION PROPOSAL. Names and schemas here are not implemented APIs.
The proposed extension version is `birbverify.closure.v1`. Existing request and manifest objects remain `birbverify.v1`.

## Domain identities

| Identity | Meaning and uniqueness |
| --- | --- |
| `target_id` | Installation-bound logical environment, currently `fixture-local`. The caller cannot redirect a socket or supply a path. |
| `target_incarnation` | Random installation UUID persisted by the target before service begins. Every operator-declared database restore or replacement forces a new incarnation and explicit reconciliation before admission. Silent in-place rollback is outside this fixture guarantee; the database cannot detect rollback of its own incarnation and revision. A request admitted or dispatched under an earlier incarnation cannot resolve `never_acquired` or `not_started_target_confirmed` in a later incarnation. This extension does not support cross-incarnation closure. |
| `request_id`, `idempotency_key`, `request_sha256` | Original immutable request identities and the existing canonical request digest. Both identities retain uniqueness after closure. |
| `execution_epoch` | Target-assigned positive integer from a durable monotonically increasing counter within the incarnation. One epoch binds one request digest. Allocated by first admission or closure, never by retry. A request never receives a second epoch. |
| `attempt_id` | The acquired producer attempt, or null if the target proves none acquired. A Temporal-derived proposed attempt ID is not acquisition evidence. |
| `closure_id` | Trusted-coordinator-chosen UUID, unique across the target incarnation. The first accepted command binds it permanently to one request and canonical payload. One request has at most one closure. |
| `closure_operation_id` | Tuple of incarnation, closure UUID, and step, such as `fence`, `stop`, `cleanup`, or `release`. It is never derived from a caller retry. |
| `record_revision` | Monotonic target journal revision. It orders authoritative observations. It is neither wall time nor a client observation UUID. |
| `worker_execution_id` | Trusted launcher registration identifying host boot, worker PID and start identity, and an owned execution group containing the token-holding process itself and all descendants. At the pinned source this includes the entire Temporal activity-worker process. Private provenance binds issued Docker controls and exact container name to the acquired attempt. |

The target stores request payload, digest, epoch, and seal state in one request record. It stores the acquired attempt's number, predecessor, acquisition time, worker registration, derived container name, and installation policy identity in the acquisition transaction. It can retain the existing token privately, but closure never returns that token or grants a replacement worker token.

New context files are caches. The durable target journal is the source of reservation truth. Existing databases lacking this provenance cannot acquire the property through inference.

## Domain states

Execution history, closure progress, and current availability are separate records.

| State | Meaning | Release consequence |
| --- | --- | --- |
| `dispatch_unknown` | Birbforge scheduled execution but has no authoritative acquired attempt or complete terminal result. This is a consumer knowledge state. | Free-target observation, timeout, and missing context do not authorize progress. |
| `never_acquired` | The target atomically sealed the request and found no attempt in complete durable history. Any future acquisition under that request is denied. | No worker entered target-authorized execution. Closure must still commit its receipt and resolve its availability barrier. |
| `acquired_context_lost` | The target has an acquired attempt but the caller lacks the reservation reply or local context. | Reconstruct attribution from the target journal. Never reconstruct authority from local file absence. |
| `fenced_stop_unknown` | Seal committed and matching worker authority is revoked. Worker or issued lifecycle-command settlement is unknown. | Quarantine remains. |
| `fenced_cleanup_unknown` | Target accepted attributable stop evidence, but cleanup failed, has an unknown result, or has not completed. | Quarantine remains. |
| `release_confirmed` | The target atomically committed immutable closure receipt and released this closure's environment barrier after all required evidence. | Historical permission to finish this request's closure. Current availability still needs a fresh authoritative observation. |

`acquisition` is a frozen discriminated value, either `never_acquired` with null attempt, or `acquired` with attempt and reservation record digest. The caller's initial uncertainty remains in the command reason. It does not overwrite the target's resolved acquisition fact.

A closure record advances from `fenced_stop_unknown` to `fenced_cleanup_unknown` to `release_confirmed`. For `never_acquired`, the fence transaction enters `fenced_cleanup_unknown` and records `stop=not_started_target_confirmed`; cleanup records a target-confirmed no-op. Neither value claims an offline worker process has exited. That worker cannot obtain target execution authority later.

`legacy_provenance_unavailable` is a blocking reason under `fenced_stop_unknown`, not a completed closure. The same progress state can carry `worker_alive`, `intent_unsettled`, or `stop_evidence_unavailable`. `cleanup_failed` and `cleanup_effect_unknown` are blocking reasons under `fenced_cleanup_unknown`. Reasons preserve the uncertainty instead of inventing extra terminal results.

Current environment state remains `active`, `quarantined`, `revoked`, or `free`. A closure barrier holds a previously free target at `quarantined` while a never-acquired closure is completed. A barrier is a tagged owner, either an attempt or a closure, not an invented attempt consuming the attempt budget. `inspect` projections for the new protocol distinguish the two. Legacy callers see a non-free state and cannot acquire through it.

A terminal request record has either its existing immutable manifest or a separate `closed_without_verification` result. The latter contains a closure reference and no application verdict. A manifest can remain inconclusive with historical quarantine while current availability is free.

## Authority and trust boundary

A closure requires the installation's separate supervisor capability and an installation-authorized closure command. The target checks that capability on every mutating closure operation and checks the bound target, incarnation, principal, authorizing workflow, policy, request digest, and operation payload. The supervisor proves authority through its transport capability, not a `trusted=true` field. The command records a bounded reason and actor identity supplied by the installed authority adapter.

Birbforge's trusted coordinator authorizes closure of its admitted request under installation policy. The host supervisor checks that authorization before target calls. The target independently validates the recorded admission binding and allowed closure authority. Normal admission rights, a client cancellation command, an AG-UI state update, and a worker reservation token grant none of this authority.

The trusted coordinator records `admission_target_incarnation` with its original admission before dispatch. The installation authority validates that original binding and cannot issue a replacement grant that relabels an old request for a new incarnation. The target requires it to match the RPC incarnation. A mismatch returns `legacy_provenance_unavailable` before any effect. It creates no request row, seal, epoch, closure, or barrier. The target also persists each request's admission incarnation. Rows carried over by a restore retain their original incarnation and are neither reservable nor closable in the new incarnation. Restored queues retain the original binding.

For a request that never reached `admit`, the supervisor supplies the complete original request and its authorized admission binding. The target validates them and atomically inserts a sealed record. An expired execution deadline may deny execution while still allowing this authorized seal. Closure permission is distinct from permission to run checks. If policy changed, closure must validate an installation-retained original admission policy or explicit installation-authorized historical closure grant. A caller cannot substitute today's payload or invent the old grant. Missing authority leaves quarantine.

The fixture capability is an owner-only secret whose digest is in installation configuration. This retains the current trusted-same-UID boundary. It does not provide hostile same-user isolation or cryptographic attestation. Production actor authentication and signed provenance are separate gates.

## Immutable command

The following field reference is a proposed schema. Unknown fields and unknown versions are rejected at every level.

| `BeginClosure` field | Required content |
| --- | --- |
| `contract_version` | Literal `birbverify.closure.v1` |
| `closure_id` | UUID generated and durably recorded once by the trusted coordinator before the first call; the supervisor receives it |
| `target_id`, `target_incarnation` | Exact installed target binding |
| `request` | Complete original `birbverify.v1` request including its original idempotency key |
| `request_sha256` | Recomputed canonical digest of `request` |
| `expected_attempt_id` | Known attempt or null, meaning resolve once from target history, never assert no attempt |
| `expected_execution_epoch` | Known epoch or null, meaning resolve once from target history |
| `authorization` | Original principal/workflow/policy binding, immutable `admission_target_incarnation`, installation-authorized closure actor, and grant reference. No credentials. |
| `reason` | One of `dispatch_unknown`, `reservation_reply_lost`, or `context_lost` |

Canonical encoding reuses the pinned request convention in [the v1 contract](../../contract.md). The closure model serializes all defaults, explicit nulls, version, and the full authorization record. The digest excludes the transport secret. Ordered arrays stay ordered. The implementation must publish independent golden digests before consumer integration.

Same closure ID and identical canonical command returns the existing operation, including its resolved epoch and attempt. It does not allocate a new epoch or reapply effects. Changing any command field conflicts. A second closure ID for the same request returns `request_already_closing` and the authorized existing reference, with no effects. A closure ID reused for another request conflicts. A later caller that learns the attempt must not fill in a formerly null expected field on replay. It fetches the original command and continues it.

An expected attempt or epoch mismatch fails before any effect. Lost replies do not authorize a new closure identity. The coordinator persists the command before calling. If that coordinator is a Temporal workflow, UUID generation must use a workflow-safe recorded/deterministic mechanism, not ordinary random generation during replay. If the coordinator loses its local copy, an authorized lookup by original request identity retrieves the canonical existing closure.

## Worker transport binding

The request seal handles delayed calls within one incarnation. Preventing old calls from entering a replacement target also requires an explicit transport binding. The proposed closure-capable RPC protocol is `birbverify.target.v2`, separate from the unchanged `birbverify.v1` request and manifest schemas.

Every worker and supervisor RPC envelope names its installed `target_id` and `target_incarnation`. Admission returns the request's stored `execution_epoch`; reservation carries that epoch. Owner mutations carry that epoch together with attempt and token. The target rejects mismatches before mutation. A worker obtains the incarnation from its trusted launcher configuration and never rediscovers a new incarnation to continue an old activity.

A closure-enabled installation rejects legacy envelopes that omit the incarnation or protocol version. There is no downgrade fallback. Inside the v2 target, the permanent request-seal check is still mandatory even for any compatibility reserve route. Such a route cannot omit the incarnation guard. The later producer release must update the worker and supervisor adapters together before advertising closure capability. Ordinary known-context recovery retains its semantics through that updated envelope.

Installations running the pinned producer retain their existing protocol and quarantine behavior. This proposal does not upgrade them. The implementation must prove rejection of delayed v1 messages and old-incarnation v2 messages at a newly initialized target before enabling new admission there.

## Target operations

These signatures describe semantic operations inside the existing target service. They do not select a new network service or runtime.

| Operation | Input and result |
| --- | --- |
| `begin_closure(command, supervisor_capability)` | Returns the immutable fence record and current closure progress. |
| `read_closure(target, request_id or closure_id, read_authority)` | Returns canonical command, frozen resolution, operation journal, and any final receipt. Private process evidence requires supervisor authority. |
| `confirm_closure_stop(closure_id, evidence_ref, expected_revision, supervisor_capability)` | Reconciles the stable stop operation against installed lifecycle evidence. Returns target progress, never accepts a client stop boolean. |
| `cleanup_closure(closure_id, cleanup_payload_sha256, expected_revision, supervisor_capability)` | Reconciles the stable cleanup operation and returns its durable receipt or unknown result. |
| `release_closure(closure_id, expected_revision, supervisor_capability)` | Atomically commits the final closure receipt and free state, or returns the exact existing receipt. |
| `observe_closure_state(request_ids, read_authority)` | Returns selected request terminal records, closures, and environment availability from one target snapshot, with incarnation and journal revision. |

The stable step payload includes the closure binding, pinned procedure/checker policy, and effect arguments. `expected_revision` is a concurrency precondition, not part of that effect payload digest. Stop evidence is an observation of that fixed operation, not a new effect payload. While stop remains unknown, authorized callers may append new evidence references under revision checks. After confirmation, replay returns the committed evidence set and cannot replace it. Revision checks protect new transitions. Replaying an already committed identical step returns its stored receipt even if the supplied expected revision is old. A changed step payload conflicts before revision handling. An uncommitted stale-revision call returns the current authorized record and performs no effect. Observations expose no worker tokens, capability secrets, host paths, raw process data, or artifact bytes.

### Atomic fence

`begin_closure` takes the same SQLite `BEGIN IMMEDIATE` serialization boundary as `reserve` and `apply`. Authentication occurs before disclosure. Under the transaction, the target performs the following work.

1. Validate command identity and immutable payload, or return the already bound closure.
2. Resolve the complete request record and epoch. If no record exists, validate original admission authority and create it already sealed with a fresh epoch.
3. Resolve attempts from durable history. Enforce supplied non-null expectations. Preserve all operation receipts and any terminal manifest.
4. Seal the request permanently. Mark its execution epoch closed. Revoke its acquired token's mutating rights.
5. Claim the matching environment for closure. If it is free and no attempt acquired, create a closure barrier. If an unresolved acquired attempt owns it, retain that ownership as quarantine under the closure. If durable evidence establishes that this request already finished and released, return `already_released` with that evidence and create no new release receipt, even if a successor now owns the target. Otherwise, a different request owner causes `environment_owner_conflict` without changing either request or environment. A non-owner observation alone is not proof of a prior release.
6. Commit closure identity, frozen acquisition resolution, before-state digest, fence revision, and quarantine in the same transaction.

The transaction either commits all these changes or none. No journal entry may claim fencing while acquisition remains possible. A failed transaction or lost target journal never proves closure.

All acquisition paths consult the permanent request seal, including any explicitly supported compatibility `reserve` calls. A missing required epoch in the v2 route is rejected. `admit` replay may return historical identity but cannot remove the seal. `reserve` checks terminal history and the seal before its busy check. For a sealed request it returns the original terminal manifest if one exists, otherwise raises `TargetError("request_closed")`. The updated worker maps that error to a non-retryable terminal infrastructure condition and reads the closure extension. It never indexes a closed-condition dictionary as if it contained a token. Neither returns a new token.

All worker mutators consult both request seal and the token's stored epoch in the same transaction as their mutation. This includes `apply`, `revoke`, `uncertain`, `cancel`, `stop`, `cleanup`, and `finish`. Legacy supervisor `recover` and `release` also reject a request claimed by closure, even with a valid supervisor capability. Only the closure operations may advance that claim. The owner check requires a non-null, non-empty token, a real attempt owner tag, and a matching stored epoch. A null owner/token pair on a free target or closure barrier is never worker authority. A worker must not fabricate successful stop or reset the target with the old token after closure. Exact replay of an already committed immutable manifest is a read-only exception. Receipt reads remain available under their existing identity checks.

An acquisition race has two legal orders. If acquisition commits first, closure captures that exact attempt and enters acquired stop reconciliation. If closure commits first, acquisition fails permanently. An `apply` that committed first remains in history. An `apply` ordered after the fence performs no mutation, even if its worker was offline before closure reached the target.

The explicit request check is necessary in addition to the epoch. A delayed legacy acquisition cannot invent a fresh token merely because no epoch field was supplied. It either uses a deliberately supported incarnation-bound route that checks the seal or is rejected at the envelope boundary. An epoch mismatch, unknown incarnation, known incomplete database history, or missing durable provenance fails closed. This does not imply detection of silent in-place rollback.

### Stop evidence and lifecycle reconciliation

For `never_acquired`, the fence record itself proves target-authorized execution never started. The proof depends on every execution path requiring successful reservation before target effect, candidate preparation, or Docker command. The current runner has that order, but future adapters must preserve it. An offline worker may wake and be rejected without preventing this closure.

For an acquired attempt, the supervisor reads the target's persisted reservation record. It does not read or recreate a token-bearing context to obtain authority. The stop evidence binds the request, epoch, attempt, worker execution group, host boot identity, exact process identity, and deterministic container identity. It includes evidence that the reservation-holding process itself and every descendant are stopped, every issued command has settled, and the exact container is absent after settlement. A group containing only Docker children is insufficient. `Activities.verify` runs in the shared Temporal worker process, so the first implementation must stop that whole process and its descendants. Only an explicitly changed adapter that executes each attempt in a dedicated subprocess can narrow that boundary. The same stop proof covers delayed local checkout, artifact, and diagnostic writes.

The installed lifecycle checker validates those observations and stores their digest with the stop operation. The target verifies their binding and checker authority. A caller-supplied digest without a retrievable authorized evidence record proves nothing. Private records remain owner-only. Public closure evidence carries attributable references and digests, not a claim of independent cryptographic truth.

The first implementation must commit lifecycle intent before Docker create, start, and remove. The target checks the current unsealed request, epoch, attempt, and worker authority in that intent transaction. A command may be sent only after the durable intent commit is positively acknowledged. A failed, rejected, or unknown intent write aborts that command. Reading back an intent after an unknown reply does not authorize another send. Its delivery remains uncertain until reconciled. Intent evidence never grants execution authority after closure. A durable completion binds the result to that exact intent. Only a determinate daemon outcome settles an intent. This means a completed invocation with a daemon-originated response bound to the exact command, or authoritative daemon evidence bound to the intent. A local exit code by itself is insufficient. Client timeout, kill, OSError, bounded-output abort, or missing reply records `delivery_unknown`; a local command exit or a later absent-container observation cannot convert it to settled. Such an intent keeps `fenced_stop_unknown`. Completion evidence for a pre-seal committed intent may still be appended after the seal through an evidence-only endpoint or the supervisor adapter. That endpoint validates identity and cannot create an intent, send a command, resurrect execution, or release ownership. The supervisor adapter records its own lifecycle intents and completions under closure authority, bound to the closure ID, epoch, attempt, exact container, and immutable argument digest. These intents cover closure-time remove operations and the inspection evidence used to confirm absence. They obey the same positive-acknowledgement and determinate-settlement rules and appear in the stop evidence set. They never authorize a worker create/start after sealing. This distinction prevents the seal from discarding settlement evidence. A new supervisor reads the journal before taking further action. Pending delivery without an attributable completion remains unknown unless the installed adapter can reconcile it from authoritative daemon evidence. No absence-only proof or immediate command resend is accepted.

Worker death with an unresolved create is `fenced_stop_unknown`. A live or offline acquired worker whose future execution cannot be excluded is also `fenced_stop_unknown`, even though `apply` is fenced. Missing process registration is `legacy_provenance_unavailable` and cannot become confirmed merely by observing no PID or no context file.

### Cleanup and release

Cleanup is one stable operation bound to the closure, target, epoch, and pinned cleanup procedure digest. For an acquired fixture attempt, it resets counter and candidate under the target transaction after accepted stop evidence. The cleanup result and receipt commit together. It never clears unrelated ownership. For a never-acquired request, the target confirms a no-op without resetting unrelated state. A dirty supposedly free target is a conflict requiring investigation, not proof of no cleanup needed.

A cleanup failure leaves a recorded failed or unknown attempt and quarantine. Reconciliation can retry the same desired cleanup only if the prior operation is proven to have had no effect or the adapter proves the same operation converges safely. This is cleanup reconciliation, not another verification attempt. A different cleanup payload under the same stable operation conflicts. An unresolvable external cleanup effect never permits release.

`release_closure` requires the request seal, complete fence record, current closure ownership, accepted stop, and complete cleanup. It also requires a frozen terminal history reference, either the original manifest digest or explicit absence of a manifest under the seal. A worker cannot publish a new manifest after that seal.

The transaction writes the immutable final receipt, records `closed_without_verification` if no manifest exists, clears only this closure's owner, increments environment revision, and sets free. A crash cannot publish free without the receipt. A lost reply is resolved by reading the closure before any further effect. A repeated release returns the same receipt even when a successor owns the target. It must never free that successor.

Every step has a durable operation record containing identity, canonical payload digest, status, and evidence references. A fresh supervisor first reads that record. It resumes only an uncommitted or safely reconcilable step. Fencing and fixture cleanup are database transactions. Docker settlement is explicitly not granted that property.

## Immutable closure receipt

The proposed receipt is a separate strict object with these fields.

| Field group | Content |
| --- | --- |
| Version and attribution | `contract_version`, producer revision, installed adapter revision, closure actor, authorization grant reference, policy identity, committed time |
| Identity | `closure_id`, canonical command digest, original request ID and idempotency key, request digest, target ID, target incarnation, resolved execution epoch |
| Acquisition | Tagged `never_acquired` with null attempt, or `acquired` with attempt and durable reservation digest |
| Fence | Fence operation ID, commit revision, sealed-request digest, effect-history digest |
| Stop | Tagged `not_started_target_confirmed` or `confirmed`, checker identity and evidence references/digests. Never `true` alone. |
| Cleanup | `complete`, pinned procedure digest, operation ID, result digest, no-op reason when never acquired |
| History | Original manifest digest or null and `manifest_status=unavailable`. No fabricated worker tools, check outcomes, or manifest timestamps. |
| Release | `release_confirmed`, release operation ID, committed environment revision, and final receipt digest |

The field groups above use the following exact proposed discriminator shapes. This is schema notation, not executable code or an acceptance fixture.

```text
acquisition = {kind: "never_acquired", attempt_id: null, reservation_sha256: null}
            | {kind: "acquired", attempt_id: Id, reservation_sha256: Sha256}
stop = {kind: "not_started_target_confirmed", evidence_refs: [FenceEvidence]}
     | {kind: "confirmed", checker_id: Id, evidence_refs: [LifecycleEvidence, ...]}
history = {manifest_status: "present", manifest_sha256: Sha256}
        | {manifest_status: "unavailable", manifest_sha256: null}
release = {status: "release_confirmed", operation_id: OperationId,
           environment_revision: PositiveInteger}
```

`Sha256` is a lowercase 64-character hexadecimal digest. `Id` uses the existing producer identifier restriction. `OperationId` is the tuple defined above, serialized as a strict object. Every evidence reference carries its immutable ID, digest, kind, and issuing checker identity. Its private retrieval location is installation-resolved. The final receipt's own digest field is `receipt_sha256`.

The extension snapshot contains `contract_version`, `target_id`, `target_incarnation`, `record_revision`, request observations, and an environment object. Environment ownership is tagged `none`, `attempt` with request/epoch/attempt, or `closure` with request/epoch/closure. Free requires ownership `none`. Request observations contain the unchanged manifest or null, the closure progress reference, and the immutable receipt or null. Progress alone never has `release_confirmed` without a retrievable receipt.

The final receipt digest hashes the complete canonical receipt with only its own digest field omitted. Receipt bytes are immutable after commit. Intermediate unknown/failed observations are append-only progress records, not replacement final receipts. Same step replay yields the same original evidence, not a fresh completion time.

Retain request seals, identity bindings, closure journals, and receipt digests for the target incarnation's full lifetime. Retention expiry of raw evidence cannot reopen execution. Missing required evidence prevents new release or evidence validation. Rebuilding or restoring a target requires a new incarnation and operator-led reconciliation before admission. The operator must establish that all previous token-holding processes and descendants stopped and all previously issued external commands settled, and every prior-incarnation `birbverify.attempt`-labelled container is absent after settlement. The operator retains a restore-reconciliation record naming the old and new incarnations and the evidence. Without that proof, the replacement remains unavailable. Durable storage with no silent rollback is a trust assumption of this fixture. A revision stored only in SQLite is not an external monotonic witness, and no such witness is proposed here. Existing in-flight commands must never be redirected automatically to that new incarnation. This restore record is an installation gate, not a closure receipt for old requests. Those requests stay unresolved under their original identity as `legacy_provenance_unavailable` if their original target history cannot support closure. They cannot be retried or relabeled as never acquired on the replacement. Reconciled new work requires new request and idempotency identities. A future cross-incarnation recovery contract would require separate review.

## Compatibility and rollout

Existing `contracts/v1` bytes, strict request parsing, manifests, eligible checks, and canonical request hashing remain unchanged. A new extension schema location such as `contracts/closure/v1` is proposed for the implementation milestone, not created here. The target advertises its supported extension versions and installed adapter capability. Unknown versions or absent capabilities keep the consumer on its current quarantine behavior.

`result` for a request with an existing manifest still returns that original manifest. A closure-only terminal record is read through the extension observation, never coerced into `Manifest`. The new producer adapter must recognize a closed request as a terminal infrastructure condition, with no execution retry. Existing consumers must not infer release from that error alone.

The admitted Birbforge path enforces one acquired attempt. Closure does not decrement its count, create a replacement attempt, consume a hidden retry, or let a terminal identity run again. The standalone producer fixture currently configures broader `max_attempts` values in `fixture.request`; that does not authorize additional attempts for this integration. The new closure-capable integration accepts only the existing one-attempt profile.

Known-context recovery remains valid for requests not claimed by this extension. On a closure-capable target, normal `finish` and supervised legacy `release` also record an immutable release transition in their existing transaction. This is internal target evidence, not a replacement for the existing manifest or consumer recovery receipt. `already_released` requires that transition or a normal manifest atomically committed with release. Older records without either return `release_history_unavailable` and do not create a closure receipt. Its original manifest and separate recovery receipt stay unchanged. Claimed closure rejects all legacy lifecycle mutations, including a concurrent known-context supervisor. If legacy recovery has already released, closure reports that fact without manufacturing a second closure history. The implementation must test this arbitration.

Rollout requires producer implementation, isolated fixture acceptance, and an explicit later consumer pin and integration review. No deployed old runtime is upgraded or resumed by this proposal. Legacy acquired records without provenance remain quarantined. The receiving owner must accept this limitation or propose a separately reviewed evidence-backed migration.
