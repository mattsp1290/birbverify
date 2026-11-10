# Deployment fencing contract v1alpha1

Status is provisional and unsupported by the runtime. This document is the early
Birbforge and Birbhomes handoff for `birbverify-bsmn`. It does not authorize a
controller write, installation, promotion, or target release. The existing
`birbverify.kubernetes.v1` transport and bare-Pod receipts remain unchanged.

## Installation binding

The proposed discriminator is `birbverify.deployment.installation.v1alpha1`.
An installation binds the following immutable inputs before admission.

| Input | Required binding |
| --- | --- |
| Producer | Exact clean source commit, package digest, runtime dependency versions, and policy revision. |
| Application | Accepted source commit, chart and dependency digests, render digest, and complete object inventory. |
| Images | Every regular, init, hook, seed, database, and helper image by registry digest and platform/config identity. Development tags are rejected. |
| Target | Cluster UID, every application/data/control namespace UID, node UID, and protected namespace labels. |
| Writers | Authentication principal, service-account UID where applicable, controller deployment/image/config identity, exact resource/subresource/verb scope, and impersonation restrictions. |
| Admission | Complete mutating configuration inventory, UID and content digests, relevant selectors, protected namespace labels, validating configurations and bindings, and approved final object shapes. |
| Reconciliation | Named Flux source, Kustomization and HelmRelease objects, source/artifact digests, Helm storage mode and release names, owner UID edges, and controller request settlement mechanism. |
| Storage | Every claim and volume identity, node placement, approved mount access, baseline retained-data policy, and accountable restore evidence. |
| Authority | Durable installation incarnation, authenticated closure caller, write acceptance/seal authority, and proof that no scoped writer bypasses it. |

A name or service-account username alone is not a controller incarnation.
Installation pins are rechecked before effects. Admission must enforce the
installed restrictions when the API accepts each write. A preflight read cannot
replace that enforcement. Unknown configuration or mutation drift blocks new
admission and retains any already-owned request.

## Request binding

The proposed discriminator is `birbverify.deployment.request.v1alpha1`.
A request contains request ID, request digest, candidate source commit, authored
work ID and revision, producer revision, policy revision, plan digest,
installation digest/incarnation, target binding, immutable image-role map,
chart/render digests, and a timezone-aware deadline.

Birbforge owns admission, policy, durable FIFO, retry scheduling, and independent
closure after worker loss. Birbverify owns credentialed activities, write fencing,
settlement, and lifecycle evidence. Beans owns authored work. No component adds a
second scheduler or publisher.

A duplicate request with the same content returns its existing state. Reuse of
an ID with different content fails. Closing an unadmitted request permanently
seals that ID without producing release evidence or affecting another owner.

## Accepted writes and closure

The target assigns an epoch. Write acceptance and epoch sealing share one durable
ordering point. Each effect records its sequence, authenticated principal,
resource/subresource, verb, namespace/name, body digest, UID/resource-version
preconditions, owner relationship, and attributable completion evidence.

The proposed states are `active`, `sealed`, `draining`, `released`, and
`quarantined`. An accepted effect is pending until positively settled. Unknown
transport results survive restart and retain ownership. Retrying closure does not
replay an unknown mutation.

Closure first seals candidate writes and records the last accepted sequence.
It settles every accepted effect, including a controller CREATE that persists
after sealing. It then drains the owned UID graph under narrowly scoped cleanup
authority. The fence stays closed after release. A new epoch cannot inherit stale
controller work from an earlier epoch.

A future `birbverify.deployment.closure.v1alpha1` receipt would bind the exact
request and installation, epoch, close reason, seal sequence, settled-effect
digest, complete owned UID graph, regular/init container terminal proofs,
reconciliation-stop evidence, baseline restoration evidence, and receipt digest.
No such receipt is currently produced or accepted by this repository.

A release requires all of the following facts.

- Every pre-seal accepted effect and every cleanup effect has authoritative settlement evidence.
- Every owned executable Pod has terminal evidence for its regular and init containers before deletion loses that evidence.
- Helm hooks, Jobs, ReplicaSets, StatefulSets and other parents cannot recreate execution under the retained seal.
- Services, Endpoints and EndpointSlices have settled routing cleanup.
- Exact approved retained-state obligations are met. Deleting a PVC is not database rollback.
- Installation and admission identities still match, with no unexplained objects or writers.

Suspension, zero replicas, a successful Helm command, a successful activity,
an empty resource list, and an elapsed quiet interval are insufficient release
proofs. Kubernetes admission runs before persistence and supplies no webhook
post-commit callback. See [Dynamic admission control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/).

Application outcome remains separate from lifecycle release. Birbforge-vsrd must
bind passing account/auth assertions to the request, source, images, verifier,
and authored-work identities. A release alone never makes a candidate eligible.

## Mutating admission classification

The initial proposed policy accepts only configurations proven nonmatching for
the entire owned inventory. It rejects matching mutation until an exact approved
transformation and final-object validation have their own fixture proof.
Cert-manager and Datadog names are not evidence of nonmatching behavior.

Classification includes operations, API groups and versions, resources and
subresources, scope, match policy, namespace selectors, object selectors, match
conditions, and reinvocation behavior. Unknown selector/CEL semantics fail closed.
An object-selector exclusion is insufficient when an allowed write can remove
the excluding label. A namespace-selector exclusion requires frozen namespace
labels and identity. Inventory additions require reclassification.

Pin each configuration UID and complete relevant content, including webhook
client configuration. Added, removed, recreated, or changed configurations require
installation reconciliation. MutatingAdmissionPolicy and its bindings are also
in scope where exposed by API discovery. Defaulting and built-in admission effects
must be included in the approved admitted shape.

## Source and workload transitions

The first candidate remains pinned to the accepted source and exact approved
image map. Source, chart, image, controller, namespace, storage, and admission
changes require a new reviewed installation binding. Never silently repin a
journal or durable request history. Unknown effects in an old installation must
be reconciled before target reuse.

No general chart upgrade, rollback, database migration rollback, autoscaling,
unsuspended CronJob, arbitrary Job, new sidecar, ephemeral container, operator,
CRD, or cluster-scoped chart effect is authorized. The seed Job requires a named
one-shot intent derived from the approved suspended template. OpenFGA migration
uses its approved init container; migration Job mode remains prohibited.

## Runtime packaging and activation gates

The existing target package contains Python 3.13 and kubectl with a persistent
SQLite ledger and a private local socket. It implements bare-Pod v1 only. It does
not package a deployment proxy, admission journal, controller completion observer,
or controller-aware closure service.

A deployment package must include its acceptance/seal authority and settlement
transport, durable storage, credential isolation, pinned controller clients and
API compatibility, authenticated closure, and crash recovery. The operator must
prove native controller coverage and bypass denial. Routing Helm and Flux alone
cannot establish that coverage.

Before support is declared, disposable Kubernetes proof must exercise the actual
controller lifecycle, nonmatching webhook coexistence, matching/changed mutator
rejection, outsider writes, cancellation, killed worker, lost accepted responses,
restart, late controller creation across seal, hooks, init termination, retained
storage, and epoch rollover. Receipts must bind exact clean producer/consumer
commits and tool/image digests. Independent review precedes activation.

No shared webhook changes or shared staging deployment are part of this issue.
