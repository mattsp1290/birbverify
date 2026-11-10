# Candidate A. Admission journal with explicit settlement.

The goal is to fence the exact account/auth Helm, Flux, and controller inventory and prove safe closure without weakening the bare-Pod v1 profile. The accepted source revision was unavailable when this candidate was drafted. It has since been fetched and inventoried in the accompanying README. This is a provisional architecture, not an inventory or acceptance claim.

## Evidence from the current implementation.

`KubernetesTarget._effect` persists pending intent before each gateway API call and records its response afterward. `_load` quarantines any pending intent. The gateway therefore does not infer that a missing object means an unknown write failed. `close` requires the created Pod UID, a retained cleanup finalizer, terminal container state, and baseline ConfigMap restoration before issuing a receipt. `KubernetesInstallation` fixes one Pod, one ConfigMap, one node, and exactly four admission objects. `admission_objects` permits only the target writer and one node status writer. These are coherent bare-Pod constraints. They are not sufficient to admit asynchronous controller effects.

## Whole-shape alternatives.

1. Flatten the Helm render into gateway-created resources and prohibit controllers. This keeps the existing single-writer proof but cannot claim Helm/Flux/controller support. Reject for this task.
2. Admit controller identities, suspend Flux at closure, then list until empty. This is small but unsound. A controller CREATE already allowed by admission can commit after the suspension and empty list. Reject.
3. Journal every admitted mutating request in the same durable ownership epoch as seal. Settle every accepted request with positive completion evidence. Track every resulting object and container. Reject new work after seal while allowing narrowly typed cleanup and terminal-status effects. This is the only candidate here that can describe the required race safely. It needs additional trusted completion plumbing that does not exist in the current API interface.

## Named data shape.

Use a separate versioned controller profile. Keep KubernetesRequest, KubernetesInstallation, and KubernetesTarget v1 semantics intact.

An InstallationEnvelope pins the source commit, rendered inventory digest, Helm release identity and storage representation, Flux source and HelmRelease identities, namespaces, allowed controller/service-account identities, node identities, API resource versions, admission installation identities, and exact supported resource kinds. An owner graph ties each allowed child to its parent UID and request epoch. Labels alone never confer ownership.

A RequestEpoch contains request digest, installation digest, phase, seal sequence, baseline inventory, admission intents, observed object identities, and closure evidence. Its phase is active, sealed, draining, released, or quarantined. A never-admitted sealed request cannot later acquire an epoch.

An AdmissionIntent contains admission correlation identity, epoch, monotonic journal sequence, authenticated writer, GVR/subresource/operation, namespace, object name or generated-name constraints, parent UID, old UID and resource version where present, approved final-object fingerprint, and settlement. Settlement is pending, persisted with UID/resource-version evidence, or definitively rejected with completion evidence. Ambiguous stays pending and blocks release.

An ObservedObject contains GVR, namespace, name, UID, owner UIDs, originating intent, lifecycle evidence, and required closure obligations. Executable objects also carry every regular and init container's terminal evidence. A persistent object carries exact baseline restoration evidence. A receipt names this profile and hashes the complete settled intent set, seal, object graph, restoration proofs, and executable terminal proofs.

## Concrete boundaries and callers.

The controller admission handler is the sole caller of `admit_mutation(review, epoch)`. The gateway is the sole caller of `seal(request)` and `close(request)`. Admission and seal serialize on the same durable authority. The admission handler commits intent before returning allow. Seal records the last permitted candidate-work sequence under that same lock. The existing gateway API response remains sufficient settlement for gateway-owned synchronous operations.

A completion observer calls `settle(intent_id, completion_evidence)` with authoritative proof. This is a trusted boundary, not a controller claim. An inventory observer calls `observe(object)` and validates pinned ownership and fingerprint provenance. `close` derives outstanding obligations from the durable ledger, rather than treating list results as the source of truth.

The lock must not remain held across a gateway API call that reenters the webhook. Otherwise admission deadlocks. Commit intent and release the lock before network I/O. Reacquire it to record completion. A seal racing that call sees pending intent and cannot release.

## Accepted-request race and settlement.

If admission allows CREATE before seal, its durable intent is necessarily in the pre-seal set. The subsequent API persistence can occur after seal. Closure waits for settlement, records the actual UID, and drains that late object. If admission races after seal, admission denies candidate-work CREATE and UPDATE. Controller cleanup DELETE and node status updates require a separate narrowly bounded cleanup capability and their own intents where they can affect closure.

A validating webhook has no post-persistence callback. AdmissionReview.uid is not assumed to equal an API audit identifier. An empty GET/list, timeout, elapsed quiet period, observed controller suspension, or observedGeneration does not establish that an allowed request cannot still persist. An ordinary watch can positively observe a matching persisted effect, but cannot prove an unobserved allowed request definitively failed. An observed fingerprint without unique provenance can also match a different retry.

The implemented `deployment_journal.Journal` uses a unique validating-webhook
`auditAnnotations` key per AdmissionReview UID. The API server prefixes the key
with the webhook name. A private trusted observer supplies the corresponding
RequestResponse ResponseComplete event. The journal checks epoch, writer,
operation, resource, namespace, exact admitted body, and returned UID/resource
version. Generated-name CREATE requests require submitted generateName
provenance because their audit objectRef can omit name. Audit IDs and admission
UIDs are distinct. Conflicting audit reuse or unknown correlated intent
quarantines the epoch. Non-success and timeout responses never prove no effect.

The disposable proof demonstrates native ReplicaSet Pod CREATE across seal and
process restart. The primitive supports core Pod and ConfigMap writes only and
has no release method. It does not implement the whole installation envelope or
controller authorization described above. DELETE settlement explicitly does not
prove container termination. Production use requires an authenticated,
installation-owned audit path and a verified deployed audit policy.

## Closure obligations.

Seal candidate work first. Request suspension and drain known owners, but do not treat suspension as the proof boundary. Settle every pre-seal admitted write and every permitted cleanup effect. Expand the observed owner graph for late children. Prove all executable Pods terminated, including init migration containers and hook Jobs. Block if a Pod vanished before terminal proof, a finalizer was removed without owned evidence, a UID changed, or a node is unavailable. Prove every workload owner cannot create new execution under the retained fence. Restore the pinned baseline storage and configuration only under explicit cleanup rules and verify their identities and content. Validate Helm release storage, Flux objects, Service and EndpointSlice state separately from container termination. Keep the seal active across release and only admit another epoch after the previous ledger is fully settled.

A suspended CronJob still requires proof about accepted Job CREATE requests, existing Jobs, and their Pods. A Deployment with replicas zero still requires settlement of previously admitted ReplicaSet and Pod effects. A hook-delete-policy that removes a Job or Pod before terminal proof is unsupported unless the proof retention design prevents that loss. Unknown kinds, admission mutations, owners, service accounts, external effects, storage state, or containers block admission or quarantine.

## Evidence required before claiming support.

Obtain the accepted source SHA and exact rendered account/auth manifests, hook behavior, init migration behavior, Helm storage mode, Flux versions and service accounts, controller identities, and baseline restoration semantics. Demonstrate a real delayed API persistence crossing seal, including the empty-list interleaving. Demonstrate durable webhook restart after allow but before persistence observation, controller retries, failed admissions after allow, lost watch history, Pod terminal-proof loss, late CronJob children, hook cleanup, and duplicate closure. Prove these retain ownership and never emit released. Existing bare-Pod tests must remain unchanged and pass.

## Feasibility judgment.

An admission-intent ledger plus conservative unknown handling is feasible as a bounded new component. Production controller-backed release remains unjustified until the full owner graph, authorization, and termination/restoration obligations are implemented. The smallest honest implementation can establish the versioned envelope, journal, seal race tests, and fail-closed unsupported outcome. It cannot honestly mark the full account/auth acceptance criterion complete. The Model the Domain principle shaped the explicit epoch and intent settlement union instead of extending the existing Pod-specific close conditionals.
