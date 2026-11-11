# Deployment admission and closure progress v1

An installation can reserve a reviewed object CREATE for one request. The ownership service records the reservation before returning an allowed AdmissionReview. The audit receiver records the UID returned by the API server. A generated child can use its parent's UID only after the parent has settled. Birbforge can seal the epoch after cancellation, completion or worker loss using a separate client identity.

## Install the two services

Use an exclusive, local, persistent journal owned by the service account. Provision the epoch once using the [journal bootstrap](deployment-audit.md#installation-inputs). Both processes must share the journal, the webhook name and the namespace. Starting the ownership service with an unbound audit source fails. Supply the saved epoch, request ID and SHA-256 digest on every restart. The journal rejects a changed request or installation for its lifetime.

The installer's reviewed ownership document uses the [policy schema](../contracts/deployment/v1/ownership.schema.json). Installers must supply the Kubernetes cluster UID, namespace name and UID, the validating webhook's exact name, and three distinct SHA-256 hashes of DER client certificates. Dedicate one leaf certificate each to the API server's admission client, its audit client and the closure coordinator. Use the digest of the validated policy as the installation digest for the audit receiver and account activity.

```python
from pathlib import Path
from birbverify.contract import digest
from birbverify.deployment_ownership import OwnershipPolicy

policy = OwnershipPolicy.model_validate_json(Path("ownership.json").read_bytes())
installation_sha256 = digest(policy.model_dump(mode="json", exclude_none=True))
```

Start the admission and closure service with an explicit listening address. The default binds to loopback.

```sh
python -m birbverify.deployment_ownership_server \
  --journal /state/deployment.sqlite --policy /install/ownership.json \
  --epoch "$EPOCH" --request-id "$request_id" --request-sha256 "$request_sha256" \
  --client-ca /tls/client-ca.pem --tls-cert /tls/server.pem --tls-key /tls/server.key \
  --host 0.0.0.0 --port 8443
```

Configure the API server's admission client to verify the server certificate and send its pinned client certificate to `/v1/admit`. Configure the validating webhook with `failurePolicy: Fail`, `admissionReviewVersions: [v1]`, and rules for every write and subresource in the owned namespace. Requests outside the reviewed set receive a denial. Include the complete security boundary in the installation review. The namespace UID does not appear in namespaced AdmissionReview requests. An external installation guard must prevent namespace replacement and label drift, admission configuration changes, impersonation of approved writers and controller credential reuse. The policy digest binds the expected namespace UID. It cannot enforce these cluster-wide controls by itself.

## Author CREATE slots

Each slot binds a supported Kubernetes kind, a name or reviewed generated-name prefix, a principal digest and an object digest. Use `digest(userInfo)` on the complete authenticated user information and `object_shape_sha256(obj, generated=..., owned=...)` on the exact final object after Kubernetes defaulting and admission. Installers must obtain and review that shape independently of the incoming request. An incoming request cannot enroll a new principal or object. An unknown default, mutation or principal field causes denial.

The object digest includes the final object, including its spec, labels, annotations and finalizers. It omits the server fields UID, resource version, generation, creation time and managed fields. A generated child binds its reviewed name prefix. Its owner reference must identify exactly one controlling object and match the already settled parent's API version, kind, name and UID. The digest retains the owner reference's remaining fields. Every regular and init container image must include a registry digest. CronJobs must be suspended. The profile denies every Job CREATE, including one-shot seed Jobs.

Each slot admits at most one distinct review. Concurrent requests, client retries with a different review UID and controller recreation cannot consume it again. An identical retry with the original review UID can recover the admission decision while the epoch is active. Authorization, reservation and recording the pending intent share the seal's SQLite transaction boundary. An ambiguous completion retains the slot.

The implementation accepts named CREATEs for ConfigMaps, Deployments, StatefulSets, Services, Endpoints, NetworkPolicies, ServiceAccounts, PVCs, suspended CronJobs and Pods. It supports reviewed owned children on the Deployment/ReplicaSet/Pod, StatefulSet/Pod, StatefulSet/ControllerRevision, StatefulSet/PVC and Service/EndpointSlice edges. This covers the CREATE reservation of a named hook Pod and its init container specification. The optional Helm policy covers the same-namespace revision-1 release Secret CREATE and its status UPDATE. See [Pin a first Helm release](deployment-helm.md). Controller health/status, scheduler binding, source and HelmRelease updates, hook deletion, Jobs, retained-data restoration and the full release write set still need authorization. A generated name with multiple indistinguishable candidate slots receives a denial.

## Seal and recover

The closure client sends the [command](../contracts/deployment/v1/closure-command.schema.json) to `POST /v1/close` as JSON over mutual TLS. Before dispatch, send the [installed request identity](../contracts/deployment/v1/installed-request.schema.json) to `POST /v1/observe` with the closure certificate. The [response](../contracts/deployment/v1/owner.schema.json) identifies the existing epoch, request, installation digest and current state. The installer reserves a single request at bootstrap. The lookup cannot admit another candidate or rebind an epoch. The service compares the request ID, digest and epoch before sealing. It records the first closure reason, so a coordinator retry after worker loss cannot change it. The sealed epoch rejects new writes. Previously accepted requests can still settle through authenticated API completion.

The [progress response](../contracts/deployment/v1/closure-progress.schema.json) reports the owned slots, settlement states, returned object UIDs, attributable audit IDs and event digests, and account activity state. Sealing serializes with admission. The seal commits before progress is read, so an error reading an evidence record cannot reopen the epoch. A late audit completion changes the progress on the next call. The response contains no review payloads, Pod specs, account identities or tokens.

`release_authorized` is always false in this version. Neither successful assertions nor a settled CREATE establishes container termination, stopped reconciliation or restored storage. There is no candidate-transition endpoint. Keep the journal and the fence after seal. Replacing the database while the target exists would discard its ownership history.

Run `uv run pytest -q tests/test_deployment_ownership.py` to exercise reservation, parent UID settlement, TLS role separation, concurrent admission, cancellation, restart and the checked-in schemas.

## Observe a terminal Pod before cleanup

The closure response lists the obligations for each owned object. A pending CREATE requires an API completion. A settled Pod requires observed terminal status and object cleanup. Controllers require stopped reconciliation, routing objects require route cleanup, and StatefulSets and PVCs require storage restoration. Installation-wide writer integrity, reconciliation quiescence and baseline restoration remain outstanding.

For an installed observer, pin the read-only kubeconfig file digest, explicit context, node name and node UID under `terminal_observer` in the policy. Protect this kubeconfig and its referenced trust material as installer inputs. Its role needs GET on the cluster identity namespace, owned namespace, approved Node and scoped Pods. Run the following after seal while the exact Pod UID still exists.

```sh
python -m birbverify.deployment_ownership_observe \
  --journal /state/deployment.sqlite --policy /install/ownership.json \
  --epoch "$epoch" --slot "$pod_slot" --kubeconfig /install/observation-kubeconfig
```

The observer resolves the Pod from a settled owned CREATE. It checks the cluster, namespace and Ready node identities and requires a terminal Pod phase. It compares every declared regular and init container name and image, its terminated runtime container ID, exit code, start and finish times. Empty or missing status, an absent or replaced Pod, and an unavailable node retain the obligation. Only the first successful observation is saved. The next closure call includes its SHA-256 digest, including after restart or later Pod deletion. The status excludes container log text and termination messages. This discharges the per-Pod API status check. The installation still needs an enforced exclusive kubelet/status writer, trustworthy node state, and restored reconciliation and storage to authorize release.

Run `scripts/verify-deployment-flux --terminal-hook` on Linux to exercise the observer. Helm creates one post-install hook Pod with an init container and a regular container. The fixture seals the epoch while terminal evidence is missing, runs the packaged observer with read-only access, and compares its receipt with the next authenticated closure response. The target fence covers the Pod CREATE. Helm storage lives in the control namespace. Scheduling, status writes and cleanup remain outside this proof.

## Recover an account result

Use the same authenticated closure client to send an [invocation](../contracts/deployment/v1/activity.invocation.schema.json) to `POST /v1/account-result`. A mismatched epoch or request receives HTTP 400. For a matching invocation, HTTP 200 returns `{"status":"absent"}` before reservation, `{"status":"pending"}` after reservation and before final result persistence, or `{"status":"recorded","result":...}` with the [immutable result](../contracts/deployment/v1/activity.result.schema.json). The read works while the assertion worker is offline and after sealing. It performs no account operation and grants no lifecycle release.
