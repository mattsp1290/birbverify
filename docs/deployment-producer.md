# Deployment producer installation

The deployment profile serves one approved request per journal. Birbforge owns
the queue and may recover the original epoch and recorded application result.
Birbhomes supplies the trusted installation. A recorded assertion result and a
completed Kubernetes API write are separate from authorization to release the
target. This version always retains deployment ownership after seal.

| Interface | Required installer inputs | Contract |
| --- | --- | --- |
| Journal bootstrap | Exclusive local durable volume, reviewed request and installation digests, cluster UID, target namespace, webhook name, dedicated audit client certificate pin. Store the returned epoch in independent installer configuration. | [Audit installation](deployment-audit.md) |
| API-server completion | RequestResponse audit policy, authenticated audit webhook kubeconfig, server trust and dedicated client key. | [POST /v1/audit](deployment-audit.md) |
| Admission and closure | Immutable namespace and cluster identities, distinct admission and closure certificates, complete approved final object and writer pins, settled parent UIDs. | [Admission, observe, close and result lookup](deployment-ownership.md) |
| Helm release storage | Approved Git revision, release name, writer identity and independently rendered release digest. | [Pin a revision-1 Helm Secret](deployment-helm.md) |
| Admission configuration guard | Reviewed single API server version, protected namespace UID and labels, webhook UIDs/specs, guarded bootstrap and exclusive administrative access to policies and bindings. | [Guard installation](deployment-guard.md) |
| Account activity | Reviewed worker certificate and Temporal authorization, pinned application and dependency images, chart and render digests, observed Pod and owner UIDs, read-only observation and Pod port-forward credentials. | [Activity transport and recovery](deployment-activity.md) |

Build the producer from the reviewed commit with
`docker build -f fixtures/deployment.Dockerfile -t birbverify-deployment .`.
The image runs Python 3.13 and includes kubectl v1.34.1. The Dockerfile pins
the Python base, kubectl and uv image digests and installs runtime dependencies
from `uv.lock`. Pin the resulting platform image by digest at installation.
Its entrypoint is `python -m`. Mount only each process's private inputs and
the installation journal. Limit journal writes to these trusted processes.
The published schemas are under [deployment/v1](../contracts/deployment/v1).

## Disposable Linux proofs

Run these commands from the producer checkout. Use Python 3.13, uv, OpenSSL,
Docker, kind v0.29.0, kubectl v1.34.1, Helm 3 and Flux CLI v2.6.4.
The cluster runners create their own kind nodes and use explicit kubeconfigs.
The Flux proof installs pinned source-controller v1.6.2 and helm-controller
v1.3.0. Its chart writes one ConfigMap. Helm also creates and updates its
release Secret in the same target namespace. Each admitted write has its
own API-server completion receipt.

```sh
scripts/verify-deployment-settlement
scripts/verify-deployment-guard
scripts/verify-deployment-flux
uv run python fixtures/deployment_activity_journey.py --source-repo "$BIRBPARTY_REPOSITORY"
```

The Flux control namespace and controller installation are fixture setup.
The application proof runs the API, OpenFGA and both databases separately.
The full deployment still requires controller status, binding, updates and
cleanup, a passing authenticated end-to-end worker run, and release evidence
for all effects including retained storage. The accepted
source inventory lists development API and UI tags and has no qualified OCI
supply for those two roles. Keep those production bindings open until
`birbparty-i3za` supplies the reviewed artifacts. A new epoch or candidate on
the same physical target requires a separate reviewed transition.

## Executed Linux checks

The [qualification receipts](evidence/deployment-producer.json) bind the
implementation, fixture images, API-server completion, Flux release, workload
observations, application checks and disposable restore. The configured suites
passed 14 legacy checks, 77 closure checks including the legacy cases, and
41 bare-Pod Kubernetes checks. The inventory and deployment unit suite passed
133 checks. The native-controller and guard journeys also passed separately.

Independent review identified two defects before publication. Normal service
startup could provision a missing journal, and the assertion client accepted
ambiguous JSON. The installer now reserves a new path exclusively. All service
starts require its independently saved epoch. The assertion client rejects
duplicate response fields. A second review verified both corrections.

In the PR #6 baseline run on the accepted charts, Helm's first Secret CREATE received an
HTTP 400 from the deployment fence. The receipt records zero accepted writes,
zero persisted Secrets, and zero Pods for that run. The packaged Temporal worker
separately rejected a request with zero settled workloads. Neither run produced
a passing deployed account result. Birbforge must retain the owner.
