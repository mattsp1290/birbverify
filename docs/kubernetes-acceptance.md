# Kubernetes adapter acceptance

The goal of birbverify-r5rh is a real Kubernetes execution adapter with all-writer
fencing and closure evidence for Birbforge. Implementation revision `bc52efc30f7f8ca045cb40daa48fc4e5f1686cbd`
adds a bounded bare-Pod profile without changing the existing fixture contracts.

The real-cluster proof creates and destroys a disposable kind cluster. It
exercises account creation, login, authenticated HTTP reads, exact Pod and image
identity, and ConfigMap restoration. It denies an outsider who has RBAC write
permission, an unlisted target object, namespace mutation, and exec access.

Failure journeys kill a socket-only worker, close after cancellation, hold an
accepted API response while closure waits, and discard an accepted response.
The last case stays quarantined after target restart. A successor is admitted
only after confirmed closure. Runtime container inspection corroborates the
kubelet termination evidence for the released Pod UID.

The target is the only credential owner and journals every effect before API
submission. It checks actual cluster, namespace and node UIDs, installed
admission spec digests, and the absence of mutating webhooks before effects.
The request binds the installed template digest and policy revision. The
namespace policy protects an immutable UID marker because Kubernetes 1.33 CEL
does not expose namespace metadata UID directly.

Birbforge receives the request and closure schemas in contracts/kubernetes/v1.
Its existing durable queue owns activity dispatch, application assertions and
independent closure polling. Activity completion alone is not a passed check.
The producer note on birbforge-yrnb identifies the contract and implementation.

The proof covers direct Pod networking on a trusted pinned kubelet. It does not
establish safe Deployment, Flux, Service or EndpointSlice controller writes.
No shared-staging resources were read or mutated. Forgejo/Ferry publication and
Birbhomes desired-state enrollment remain later work. The local branch contains
implementation and evidence commits; no remote PR or deployment is claimed.

## Executed checks

- `scripts/verify-kubernetes` passed 41 checks on a new kind v1.33.1 cluster.
  Its five live journeys cover the application and four failure cases.
  The script deleted its own cluster after completion.
- The existing contract, target, and closure unit regressions plus new target
  and service checks passed 73 tests.
- Ruff lint, formatting and generated schema comparison passed.
- The pinned target Dockerfile built. Both packaged CLI entrypoints started.
  The local image ID is `sha256:b3bfc9eef3252c6e0d54fd81910b9665f055bd1b23f88b860fc3a522fb84c987`.

The machine-readable report is [kubernetes-acceptance.json](evidence/kubernetes-acceptance.json).
It binds the exact source revision, request, image, namespace UID and receipts.
The exported request and receipt examples are under `contracts/kubernetes/v1`.
Private run output remains under ignored `.proof/kubernetes/`.

## Review and limits

[Review resolution](kubernetes-review.md) records the independent reviews and
Claude Opus follow-up. All reported P2 findings are fixed. Added checks cover
privilege escalation, admission recreation, and unadmitted closure. The final
live proof also denies extra capabilities and host ports and observes a
recreated admission binding block the next effect.

`sealed_unadmitted` has no release receipt. It prevents late execution of that
exact request without retaining unrelated work. Historical pre-publication
journals are not migrated. Trusted bootstrap administration, durable storage,
and the pinned kubelet remain required assumptions.
