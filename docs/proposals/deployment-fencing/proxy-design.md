# Candidate B. Credentialed controller proxy

The goal is exact account/auth Helm and Flux execution with closure that cannot release while a controller can still create work. This is a design proposal, not evidence that the accepted source supports the profile.

## Existing boundary

`kubernetes_contract.py` defines a single bare-Pod request, installation, and closure receipt. `kubernetes_target.py` serializes work with a file lock and persists each effect as pending before making its API call. `_load` quarantines pending effects. `close` preserves a Pod finalizer until it sees deletion plus terminal container status. `kubernetes_admission.py` permits only the installed target writer and one node status writer. These files support keeping v1 unchanged and adding an explicit profile instead of widening its allowed inventory.

## Whole-shape alternatives

1. A controller admission webhook checks an open or sealed epoch. This is simpler to install, but its allow response precedes the API server's write. An allow before seal can become a stored object after a post-seal empty list. Without a durable settlement mechanism for those accepted requests, this cannot issue safe closure.
2. A credentialed reverse proxy owns every scoped controller mutation and its response journal. Seal and request acceptance share one durable ordering point. This supplies an explicit set of accepted requests that closure must settle before inventory drain. It is the recommended design only if installation can prove all-writer coverage.
3. The target interprets rendered manifests and creates every object itself. This avoids the controller traffic problem but does not demonstrate actual Helm/Flux/controller behavior. It does not meet this task's intended profile.

## Data shape and caller boundary

Model the Domain changed the proposal to explicit epoch and effect states instead of independent suspension and cleanup flags.

The new installation would pin an immutable profile digest, accepted source SHA, chart digest, exact render digest, cluster and namespace UIDs, controller identities and routing configuration, API discovery versions, admission rules, allowed ownership edges, container inventory, and baseline restore inventory. Source and render inventory are now available. Installed controller routing and settlement evidence remain unresolved, so this profile stays unavailable for admission.

A session holds request digest, epoch, state, accepted-effect sequence, immutable workload UIDs, and closure evidence. Its states are open, sealed, draining, released, and quarantined. Each effect holds sequence, epoch, authenticated caller, method, group/resource/subresource, object key, request body digest, UID/resourceVersion preconditions, and result. Results are pending, definite rejection, or completed response. A transport failure remains pending and blocks release. A completed DELETE response does not mean a Pod has stopped.

Controllers call an HTTP Kubernetes API reverse proxy. They do not receive upstream write credentials. The proxy authenticates each controller and selects a fixed upstream identity from installation configuration. It must not trust caller-supplied impersonation headers. Reads and watches can pass through with explicit scope checks. Each mutation must enter the durable journal before forwarding. Unknown resources, namespace changes, unrecognized subresources, and unapproved ownership edges fail closed.

The target invokes `seal(request_digest)` on the same authority that accepts proxy writes. It then consumes a durable accepted-effect ledger. There must be one active proxy authority, or a shared transactional store plus a fenced leader. An unfenced active-active process is outside the proposal.

## Accepted-request race

The proxy transaction validates the open epoch and commits a pending effect before issuing an upstream write. Seal atomically moves that epoch to sealed and records the last accepted sequence. Requests accepted after that transaction are denied. Requests accepted before it stay pending until the complete upstream response is durably recorded.

Closure waits for all accepted sequences through the seal boundary to settle. It cannot infer settlement from suspension, an empty object list, proxy restart, a timeout, an absent object, or a connection close. A proxy crash after upstream acceptance but before durable response leaves uncertainty. The conservative initial implementation quarantines that session and never releases it automatically. An audit-based reconciliation protocol would be separate future work with its own proof requirements.

Upstream responses need an explicit success contract. A persisted object response establishes an observed write, not completion of asynchronous effects. API status errors must be classified conservatively. Transport errors and server errors whose non-commit semantics have not been proven remain unknown. The proxy must retain response identity and resourceVersion, plus request audit correlation where available. It must not replay an unknown CREATE or PATCH to make progress.

A controller may react to an earlier successful write after seal. Its next mutation is rejected by the proxy. Admission must independently reject direct controller credentials and other bypasses. Existing accepted writes are fully settled before the drain enumerates inventory. This is what closes the late child-create window.

## Drain and release

After settlement, use a separate cleanup capability with a small fixed mutation language. It can suspend pinned Flux objects and CronJobs, stop parent workloads, delete exact observed UIDs, restore the pinned baseline, and remove the target's cleanup finalizers after terminal proof. It cannot create workloads, change images, resume controllers, or forward general controller requests. Deletion retries use UID preconditions. Controller finalizers may prevent cleanup; unresolved controller finalizers quarantine the session unless a separately proven bounded cleanup operation handles them.

Pin a cleanup finalizer on every executable Pod at creation, including controller-generated Pods, hooks, and migration Pods. Verify the actual admitted container and init-container inventory. Terminal proof covers every approved executable container, all restarts, and init containers. The node status writer may remain admitted only under the exact installed node identity and status-only rules. An absent Pod without prior terminal proof blocks release. Restartable sidecars, ephemeral containers, node replacement, or loss of status evidence require explicit support or rejection.

Enumerate all scoped resources only after accepted writes settle. Match stored object UIDs to the approved inventory and owner graph. Preserve tombstone evidence for objects deleted during the run. Remove Service and EndpointSlice state, Helm release storage, hooks, Jobs, Deployment/ReplicaSet children, and other approved inventory. A missing or extra kind is not silently ignored. New executable effects after seal are impossible only under the all-writer premise above.

Release requires a sealed epoch, no unknown accepted effect, terminal proof for every executable UID, verified removal of candidate objects, exact baseline restoration, and unchanged fence configuration. The receipt binds the profile digest, epoch, seal sequence, full settled-effect digest, observed UID graph, terminal proofs, and restoration evidence. An empty final list is one check within this proof and never sufficient by itself.

The session fence must remain closed after release. Reopening an installation for another request requires proving stale controller traffic cannot be accepted under the new epoch. A shared proxy credential with only a namespace lookup does not distinguish old controller queues. Use per-session credentials and controller instances, or an equally proven epoch-bound route. Credential rotation alone does not drain a process's old queue if that process receives the new credentials.

## Feasibility and evidence required

The hard part is routing built-in controllers. Deployment, ReplicaSet, Job, CronJob, Service/EndpointSlice, garbage collection, scheduler binding, and node writes can originate in shared cluster components. Pointing Helm and Flux at the proxy does not put those components behind it. Per-namespace RBAC or admission can deny their direct writes, but cannot redirect them. Allowing native controller identities to write directly reintroduces the race.

This architecture is feasible in a dedicated control plane whose controller clients and permissions can be installed behind the proxy, or with dedicated scoped controllers and a proven isolation arrangement. It is not presently demonstrated feasible as a small change to a shared Kubernetes namespace. For an ordinary shared cluster, reject this profile until the deployment arrangement supplies that evidence.

Required evidence includes the accepted source and fully rendered inventory; chart/hook and Flux controller behavior; every writer identity and bypass denial test; upstream API mutation response semantics; crash tests before and after upstream commit; deliberately delayed controller CREATE across seal; active watches and stale controller queues across session rollover; Pod terminal evidence for init migrations and hooks; suspended CronJob plus already-created Jobs; finalizer and owner-reference deletion behavior; and node-loss quarantine. The decisive test holds a controller CREATE upstream after acceptance, seals, observes an empty inventory, and proves that no receipt is released until that request settles and its resulting Pod is terminal and removed.

No production implementation is justified from the source files alone. The minimal safe deliverable at this stage is an explicit unsupported profile gate plus this architecture and its required evidence. Preserve bare-Pod v1 behavior and its existing receipt schema.
