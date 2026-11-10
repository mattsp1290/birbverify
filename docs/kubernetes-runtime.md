# Kubernetes target runtime

The Kubernetes adapter executes a digest-pinned bare Pod in a dedicated namespace on one pinned node. Birbforge owns scheduling, workflow retries, and independent closure after worker loss. The adapter registers activities only.

The target service owns the kubeconfig and durable SQLite ledger. The activity worker receives a Unix socket path. The worker does not need Kubernetes credentials. The service process must outlive the worker process and keep its database across restarts.

## Local transport trust

This runtime supports trusted local processes with the same Unix UID. The socket has mode `0600`, and its parent directory must be owned by that UID with no group or other permissions. Every process with socket access can begin, execute, inspect, and close a request. There is no separate closure capability in this local profile.

Use separate container mount namespaces to withhold the kubeconfig and target database from the worker. A shared Unix UID on an unisolated host is not a credential isolation boundary. Neither socket permissions nor the worker Python module prevents another same-UID host process from reading accessible files.

The service refuses to overwrite an existing socket. After a crash, an operator must confirm that the old service has stopped before removing its stale socket. Preserve the database. An ambiguous submitted Kubernetes effect remains quarantined after restart.

## Start the target service

Provision the dedicated namespace, admission policies, restricted service account, revision ConfigMap before starting the service. Supply a `KubernetesInstallation` JSON document with the exact namespace, cluster, and node UIDs, pinned producer revision, and approved Pod template. Use an explicit kubeconfig and context. The service never selects the ambient default context.

```sh
install -d -m 700 /run/birbverify
python -m birbverify.kubernetes_service \
  --socket /run/birbverify/target.sock \
  --database /var/lib/birbverify/target.sqlite \
  --installation /etc/birbverify/installation.json \
  --kubeconfig /etc/birbverify/target.kubeconfig \
  --context birbverify-disposable
```

`fixtures/kubernetes-target.Dockerfile` packages the service and kubectl. Build it from the repository root. It runs as UID `10001`. Mount the installation and kubeconfig read-only, mount the database directory durably, and share only the socket directory with the worker. Building the image does not install cluster resources.

## Start the activity worker

```sh
python -m birbverify.kubernetes_worker \
  --address localhost:7233 \
  --namespace default \
  --queue birbverify-kubernetes \
  --socket /run/birbverify/target.sock
```

`birbverify_kubernetes_execute` accepts a `KubernetesRequest` JSON object. It calls `begin`, then `execute`, and returns the target response unchanged. Successful Pod creation is not an application verification verdict. Birbforge must exercise the deployed workload and inspect the returned provenance before accepting its candidate.

`birbverify_kubernetes_observe` returns the current pinned Pod UID, Pod IP, readiness, and container image status through the target. The bounded profile uses direct Pod networking. Service and EndpointSlice controllers are not authorized by this profile.

`birbverify_kubernetes_close` accepts an object with exactly `request` and `reason`. The reason is `completed`, `cancelled`, or `worker_lost`. The request must be the original request object. Closure returns the target response unchanged. Only the core's durable `released` result authorizes reuse. A successful Temporal activity alone does not authorize reuse.

The execute activity sends heartbeats every second. On activity cancellation, it attempts shielded closure. This is best effort. Birbforge must schedule independent closure after cancellation, heartbeat timeout, or worker death and keep ownership until release evidence exists. It must retry closure while graceful termination is still pending. No activity worker can guarantee its own cleanup after process death.

## Transport reference

Each connection carries one newline-terminated JSON command and one newline-terminated JSON response. The maximum command and response size is one MiB. Command fields are `schema_version`, `method`, `request`, and optional `reason`. The schema version is `birbverify.kubernetes.transport.v1`. Unknown command fields and unsupported versions are rejected before dispatch.

Methods are `begin`, `execute`, `inspect`, and `close`. Only `close` accepts a reason, and it requires one. A successful response is `{"ok":true,"result":{...}}`. The result is the unmodified target response. A failed response is `{"ok":false,"error":"ExceptionClass"}`. Error responses deliberately omit Kubernetes stderr and filesystem paths.

`inspect` reads the recorded state for an exact request and provides a credential-free observation route. A responding socket establishes process reachability only. It does not establish workload readiness, Kubernetes connectivity, admission installation, or safe target reuse.

The client has a 120-second socket timeout. A timeout means the result is unknown. It does not cancel the target's API operation and does not prove that no effect occurred. Query the same durable target with the same request and close it independently.

## Bounded closure claim

The supported workload has no Deployment, ReplicaSet, Job, operator, or autoscaler owner. Closure seals the request, settles submitted effects, and gracefully deletes the exact Pod UID. The gateway finalizer keeps the Pod visible until the pinned kubelet reports terminal container status. Cleanup restores the revision state before durable release. Unknown effects or unavailable termination evidence retain ownership.

The bootstrap administrator, admission configuration, and pinned kubelet are trusted. This contract does not establish safe mutation of a Flux-managed Deployment or shared staging. Disposable fixture evidence must separately confirm application behavior, outsider admission denial, cancellation, worker loss, and runtime termination.

## Installation approval and admission inventory

The installation pins `producer_revision`, `policy_revision`, `pod_template`, and four admission policy and binding spec digests in `admission_specs`. The request's `plan_sha256` must equal the canonical digest of `pod_template`. The target checks all four installed specs before every effect. It rejects clusters with any mutating webhook configuration. This is a conservative profile restriction, including webhooks that would not match this namespace.

Kubernetes 1.33 does not expose namespace UID in the CEL namespace metadata type. Bootstrap records the observed UID in `birbverify.dev/namespace-uid`. The name-matched namespace guard then denies all namespace mutations. Each target effect independently reads the actual namespace UID, cluster identity and node UID. Changing or removing admission policy requires installation-owner reconciliation.

| Identity | Allowed write inventory |
| --- | --- |
| Target service account | Create, update and delete one named Pod. Update one named ConfigMap. |
| Pinned node identity | Update status on that named Pod. |
| Other identities | No namespaced writes, including subresources and CONNECT. |
| Every operational identity | No mutation of the pinned Namespace object. |

The target account additionally reads the named Pod, ConfigMap, node, namespace, kube-system namespace, four admission objects, and the mutating webhook list. It cannot edit policies, bindings, RBAC, namespaces, or credentials. Bootstrap administration and the pinned node remain trusted infrastructure. The account/auth fixture stores disposable data in memory and tests the execution contract only.
