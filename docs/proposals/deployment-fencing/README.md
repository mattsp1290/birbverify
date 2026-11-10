# Account/auth deployment fencing

`birbverify-bsmn` requires controller-compatible fencing for the accepted
account/auth charts. This directory records the inventory and design gates.
The runtime still supports only the existing bare-Pod profile.

The [provisional v1alpha1 contract](contract.md) gives Birbforge and Birbhomes a
shared binding and closure vocabulary. It is not an implemented transport.
The [source lock](../../../contracts/deployment/v1alpha1/source-lock.json) comes
from Birbhomes commit `6b3f283b379d4481dc94abe1bec847900a158068`. It pins Birbparty
`503d3bc238e2093eb0e098ecbe87b7e11ed16b4f` and all accepted chart/procedure hashes.

## Exact inventory

The accepted staging render has 24 objects. Both releases use the same explicit target namespace, as required by the accepted deployment procedure. Fourteen
application objects comprise three Deployments, three Services, four
NetworkPolicies, one ServiceAccount, one suspended CronJob, and two Helm test
Pods. Ten data objects comprise two StatefulSets, four Services, three
NetworkPolicies, and one PVC. Generated controller objects are additional effects,
not part of the Helm render count.

| Rendered or generated effect | Required ownership and closure treatment |
| --- | --- |
| API, UI and OpenFGA Deployments | Deployment, ReplicaSet and Pod UIDs, rollout effects and status writes. |
| Two PostgreSQL StatefulSets | StatefulSet, ControllerRevision, Pod and generated PVC identities, retained data and controller recreation. |
| Regular and init containers | Pin every image and admitted specification. Retain terminal proof before Pod deletion. |
| Two Helm test Pods | Pin hook identity and before-hook-creation/hook-succeeded delete behavior. Do not lose terminal proof during automatic deletion. |
| Suspended seed CronJob | Deny scheduled execution. A separately approved one-shot Job needs its own Job and Pod effects. |
| Services | Pin selectors, ports, service identity and allocation behavior. |
| Endpoints and EndpointSlices | Bind Service UID, allowed address/port set, endpoint-controller identities and cleanup. |
| NetworkPolicies | Bind exact specs and prevent outsider or chart drift. |
| ServiceAccounts and Secrets | Pin pre-existing runtime credentials by identity without publishing secret content. Account for any controller token writes or deny them. |
| PVCs and volumes | Separate object cleanup from retained database/authz state. Require explicit restore semantics and identity. |
| Helm and Flux state | Include release Secrets, source artifacts, reconciliation objects, finalizers and accepted API requests. |
| Scheduler, kubelet and garbage collection | Bound binding/status/delete/finalizer writes are part of the all-writer inventory. |

The render still contains development image tags. The accepted source lock has
null API/UI image references. It is an offline inventory, not a deployable plan.
Existing installation evidence does not bind the application controller identities
or mutating webhook configurations. Those remain Birbhomes installation inputs.

## Design gate

[Admission journaling](admission-design.md) now has an implemented settlement
primitive and a disposable native-controller proof. A validating webhook commits
intent before allow and attaches a unique audit annotation. A trusted API-server
RequestResponse ResponseComplete event settles the exact returned object UID.
Missing or ambiguous completion stays pending or quarantined. No release API is
implemented by this primitive.

The proof seals while a real ReplicaSet controller request is held before allow.
An empty Pod list does not clear its intent. The Pod persists after seal, and a
webhook container restart preserves the pending intent. Only the attributable audit
completion settles it. An unreachable nonmatching mutator coexists with the
CREATE; changing its selector is rejected by the inventory classifier.

This establishes a local API settlement boundary. It does not prove termination,
full controller quiescence, or admission enforcement against mutator drift. The
selected shared installation still needs authenticated audit ingestion, complete
controller authorization, immutable installation pins, and the lifecycle closure
obligations below. No shared cluster was changed.

The [decision trail](decisions.tsv) records the choices and evidence. Source
inventory tooling is independent of this runtime design gate and can be rerun
without cluster access.

## Reproduce the inventory

Run from the Birbverify repository root with Python 3.13, uv, Git, curl and tar.
The script reads committed Git objects and never edits the supplied checkout.
The commands below use the accepted Darwin ARM64 Helm binary. The recipe below is specific to Darwin ARM64. Other platforms require their own
reviewed Helm binary digest.

```sh
set -eu
uv sync --locked
mkdir -p .proof/bsmn/tools
curl -fLsS https://get.helm.sh/helm-v3.22.1-darwin-arm64.tar.gz \
  -o .proof/bsmn/tools/helm.tar.gz
printf '%s  %s\n' \
  e73da8a0b0d5193774fdff17ce6319c7436bb22ee229b45fd64f3c40368c753a \
  .proof/bsmn/tools/helm.tar.gz | shasum -a 256 -c -
tar -xzf .proof/bsmn/tools/helm.tar.gz -C .proof/bsmn/tools
curl -fLsS https://github.com/openfga/helm-charts/releases/download/openfga-0.3.12/openfga-0.3.12.tgz \
  -o .proof/bsmn/tools/openfga-0.3.12.tgz
```

Fetch `503d3bc238e2093eb0e098ecbe87b7e11ed16b4f` into an authorized local
`birbparty/birbparty` clone if it is not already present. Replace the source repo
path below. Both Helm releases use `birbparty-staging`, matching the accepted
example target. The script verifies the binary and dependency hashes before
rendering. Its inline environment requires cached PyYAML 6.0.3 and Python 3.13.
`uv sync --locked` prepares the project dependencies, including PyYAML for tests.

```sh
scripts/inspect-account-auth \
  --source-repo /path/to/birbparty \
  --source-revision 503d3bc238e2093eb0e098ecbe87b7e11ed16b4f \
  --namespace birbparty-staging \
  --source-lock contracts/deployment/v1alpha1/source-lock.json \
  --helm .proof/bsmn/tools/darwin-arm64/helm \
  --helm-sha256 b9fa0498b0eef0a2ff912c98fd6bbaba1b9e2c7a6e42063e406f1e4676272db9 \
  --dependency-archive .proof/bsmn/tools/openfga-0.3.12.tgz \
  --dependency-sha256 f4a029a7b65b3e00a603a1b3f1be2b07b8ff1d00eab84639734aa775e3db6e59 \
  > .proof/bsmn/inventory.json
cmp .proof/bsmn/inventory.json contracts/deployment/v1alpha1/inventory.example.json
uv run pytest -q tests/test_account_auth_inventory.py \
  tests/test_kubernetes_target.py tests/test_kubernetes_service.py
```

The [example receipt](../../../contracts/deployment/v1alpha1/inventory.example.json)
records 46 verified files, 24 rendered objects, and no PVC references absent from
the combined same-namespace render. It identifies its inspector by file digest.
Changing the inspector changes the receipt. The receipt does not contain live
cluster identities, published API/UI image digests, or controller closure proof.

## Review and remaining work

The [independent design review](design-review.md) rejects both candidates as
currently deployable. Its proposed next step is to establish the native-controller
completion boundary before selecting a runtime implementation. A separate
artifact review reproduced the inventory, then the parent caught and corrected
an erroneous split-namespace rendering assumption. The regression test now checks
that both releases receive the same target namespace. There is no confirmed
source PVC mismatch.

The journal and mutator classifier are implemented prerequisites. Full Helm/Flux
runtime integration, all-writer authorization, termination and restoration proof,
and shared-cluster activation remain open. This does not complete
`birbverify-bsmn`. The original design review predates the settlement experiment;
a subsequent independent code review passed all 48 journal tests and replayed the
real audit event without finding a false-settlement defect. Review used the same
model family and did not independently rerun the cluster journey.

The [clean-source inventory proof](inventory-proof.json) binds the reproducible
receipt and 45 passing targeted tests to producer commit
`eae60a84251c57cafafb9cc18f289d46acdab6bb`. It is an offline inspector proof,
not a controller lifecycle or shared-staging acceptance receipt.

## Reproduce native-controller settlement

Run `scripts/verify-deployment-settlement` with Docker, kind, kubectl, OpenSSL,
Python 3.13 and uv available. It builds the fixture image from this checkout,
creates a uniquely named disposable kind cluster with an explicit kubeconfig,
and removes only its own cluster and webhook container. It does not use the
current shared kubeconfig context. Evidence remains under `.proof/bsmn/`.

The receipt records source hashes, Git revision and dirty status, fixture image
identity, parent and child UIDs, and the attributable audit ID. The local mailbox
and audit file are trusted proof inputs, not a production ingestion service.
Deployment and ReplicaSet setup is outside the fenced Pod CREATE experiment.
The mutator classifier requires complete discovery and complete execution and
cleanup write inventories from its caller. Snapshot comparison alone cannot
prevent a later admission-configuration race.

The [clean-source settlement receipt](settlement-proof.json) records a passing
live run from commit `c4956d8` and hashes the exact proof inputs. A matching
control request first failed at the unreachable mutator, proving the webhook was
active before the excluded namespace succeeded. The targeted suite passed 132
tests. The broader suite was not validated with its required Linux fixture setup;
direct macOS attempts encountered long socket paths and missing worker/evidence
configuration and Temporal binary. No full-suite pass is claimed.
