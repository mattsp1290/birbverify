# Account verification activity

Birbforge can dispatch `birbverify_deployment_account_auth_v1` to a dedicated Temporal worker. Verify records an account result before replying. The deployment profile still requires verified controller closure and retained-storage restoration before it can release a target.

## Installation and invocation

The installer supplies the approved [request](../contracts/deployment/v1/activity.request.schema.json), [activity installation](../contracts/deployment/v1/activity.installation.schema.json), and authenticated Kubernetes and Temporal connections. Keep private installation files and certificates outside source control. Use one isolated Linux worker process and network namespace for the activity. Give it the existing installation journal and do not replace the database between restarts.

1. Pin the candidate, authored revision, Beans issue, producer, policy, plan, cluster and namespace. Pin the data and application charts, the OpenFGA dependency and the combined render. Supply all five image roles with immutable references, platform manifest digests and config digests. The five roles cover the accepted render's API, UI, OpenFGA, PostgreSQL and BusyBox containers, including hooks and init containers.
2. Set `installation_sha256` to the ownership policy's canonical digest. The installer must provision the journal with `request_id` and `birbverify.contract.digest(ActivityRequest.model_validate(...))`. Observe and pin one API, one UI, one OpenFGA and two PostgreSQL Pods after their CREATEs settle. Record each Pod name and UID, controlling ReplicaSet or StatefulSet UID, and node name and UID. The activity checks the durable ownership slots before issuing each HTTP request.
3. Install the reviewed worker revision, reviewer identity and `birbverify.deployment_activity.suite_sha256()`. The suite digest covers the bytes of the activity, contract, response decoder and Kubernetes observer modules in the installed package. Provide the SHA-256 of the worker leaf certificate in DER form and of the Temporal root CA bundle in PEM form. Restrict the server-side namespace and task queue so only the approved worker identity can poll and complete these activities. Bind scheduling to the authorized Birbforge coordinator. The installer owns these ACLs. A worker name, queue or result digest cannot authenticate a completion.
4. Give the Kubernetes identity verified HTTPS access to get the two Namespace objects and installed Nodes, list and get Pods in the target namespace and open a port-forward to the approved API Pod. The dedicated kubeconfig must use a trusted CA and explicit context. Pin the reviewed `kubectl` in the worker image. Isolate worker credentials, the journal, the kubeconfig and the loopback tunnel from other processes. The worker reads container images, IDs, ownership, readiness and init status for the complete Pod set.
5. Start the process with the installed configuration. Client private keys stay on disk at operator-selected private paths.

```sh
python -m birbverify.deployment_activity \
  --address "$TEMPORAL_ADDRESS" --server-ca "$TEMPORAL_CA" \
  --client-cert "$WORKER_CERT" --client-key "$WORKER_KEY" \
  --epoch "$EPOCH" --database "$JOURNAL" --installation "$ACTIVITY_INSTALLATION" \
  --kubeconfig "$KUBECONFIG" --context "$EXPLICIT_CONTEXT"
```

Send the [invocation](../contracts/deployment/v1/activity.invocation.schema.json) from the installed workflow ID. Use a heartbeat timeout and handle worker loss through the independent closure activity. The payload contains only `request_id`, `request_sha256` and `epoch`. The worker refuses mismatched or expired requests and requests whose Pods lack settled ownership records. The installed source profile supports exactly five resident Pods after hook cleanup. Unknown replicas, ephemeral containers, additional sidecars and image drift block a pass.

## Results and recovery

The worker connects to the installed API Pod's HTTP port over authenticated Kubernetes port-forwarding. It checks the exact Pod, owner, node, image and container IDs before and after the assertions. It creates a random account with `POST /users`, logs in with `POST /auth/native/login`, verifies that `GET /users/me` identifies that account, checks the invalid-password response and checks the unauthenticated identity response. The five assertion names match the Birbforge consumer vocabulary. The accepted Birbparty revision is `503d3bc238e2093eb0e098ecbe87b7e11ed16b4f`.

The [result](../contracts/deployment/v1/activity.result.schema.json) commits to the request, epoch, activity installation and verifier profile. Compare the exact invocation and profile, require the SHA-256 of the result body, compare the observed workloads with the independently approved installation and require all five assertions and the overall outcome to pass. The operation ID is the canonical digest of a JSON object with `invocation` and `installation`. The installation value in that object is the canonical digest of the complete activity installation. Read results through an authenticated activity completion or by posting the exact invocation to the ownership service's authenticated `/v1/account-result` endpoint. The lookup reports `absent`, `pending` or `recorded` and never starts work. Independently recheck deadline, cancellation and closure before use.

A journal transaction reserves the operation before the first application write. Concurrent calls cannot execute it twice. A completed operation returns the identical stored result even after seal or worker restart. A crash with an outstanding reservation leaves its state running or unknown. An ambiguous transport outcome or changed workload leaves the outcome unknown. Neither condition permits a second registration. The independent closure authority retains the target, and storage restoration must account for the disposable account and its session even on a passing result. The result contains bounded assertion outcomes and workload identities. The worker never records passwords, account names, tokens or HTTP bodies in the result or journal.

## Verification

Run `uv run pytest -q tests/test_deployment_activity.py` for journal and observation cases. To exercise the application protocol against the accepted Birbparty source, run the following on a disposable Linux Docker host with Compose, BuildKit and an authorized local source clone.

```sh
uv run python fixtures/deployment_activity_journey.py --source-repo "$BIRBPARTY_REPOSITORY"
```

The fixture builds the API from the pinned Git tree and starts both PostgreSQL databases and OpenFGA. The disposable baseline contains the initialized databases and authorization configuration before the first registration. Run on an isolated Docker daemon. The proof assumes exclusive control of each randomly named project for its lifetime.

The fixture stops the four services and checks exit evidence for them and the three init containers. It takes private offline archives of the application PostgreSQL, OpenFGA PostgreSQL and authz runtime volumes. It then restarts the original project and runs the five assertions. A database query must find one account and one session.

After a second stop, the fixture extracts each archive into an empty volume in a separate, newly created Compose project. It compares deterministic archive hashes over file contents, paths, modes, ownership, modification times, ACLs and supported extended attributes. It restarts the restored application stack, waits for health and checks that the account and session counts have returned to zero. The fixture removes both projects and their volumes on exit. Its private temporary directory holds the archives during the run.

The receipt contains both volume identities, stopped container IDs, exit evidence, image IDs, archive hashes and aggregate account/session counts. Its authority is limited to the disposable Compose recovery. The Kubernetes tunnel, authenticated Temporal dispatch, controller termination and installation-specific retained-PVC baseline still need a combined deployment proof.

To test the packaged worker's rejection path, run the opt-in dispatch check with
the checksum-verified Temporal CLI from `scripts/setup` and a local Docker engine.

```sh
BIRBVERIFY_DISPATCH_EVIDENCE="$PWD/.proof/dispatch.json" \
  uv run pytest -q tests/test_deployment_activity_dispatch.py
```

The check submits a workflow over mutual TLS with zero settled workloads. It
requires the worker's failure in Temporal history and an empty account-operation
table. The fixture trusts both client certificates. Production namespace and
queue authorization require separate Birbhomes installation evidence.
