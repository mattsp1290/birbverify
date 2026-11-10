# Deployment audit receiver v1

The API server delivers completion evidence to `POST /v1/audit` over mutual TLS.
Each request contains one Kubernetes `audit.k8s.io/v1` JSON `EventList`.
The receiver verifies the client certificate against the configured CA and compares
the leaf certificate's DER SHA-256 digest with the installation pin. A different
certificate from the same CA receives HTTP 403.

## Installation inputs

The receiver and the admission process share a private, durable SQLite journal,
the installation digest, the admission webhook name, and the protected namespace.
The receiver also requires the cluster UID, the API server audit client's leaf
digest, the client CA, and the receiver's server certificate and private key.
Only the API server may hold the dedicated audit client's private key. Reusing
that key across clusters loses cluster attribution. The installer obtains the
cluster UID from its authenticated cluster connection.

On a fresh installation, the installer provisions the private journal once and
retains the returned epoch in its trusted configuration outside the journal
volume. Run the following during exclusive installation bootstrap.

```sh
EPOCH=$(python -m birbverify.deployment_bootstrap \
  --journal "$JOURNAL" --installation-sha256 "$INSTALLATION_SHA256" \
  --webhook-name "$WEBHOOK_NAME" --namespace "$TARGET_NAMESPACE" \
  --cluster-uid "$CLUSTER_UID" --audit-client-sha256 "$AUDIT_CERT_SHA256" \
  --request-id "$REQUEST_ID" --request-sha256 "$REQUEST_SHA256")
```

The command requires a new path and an existing private parent directory. After
an interrupted bootstrap, the installer must account for the partially
provisioned journal before directing services to it. Start the receiver with
the saved configuration.

```sh
python -m birbverify.deployment_audit \
  --host "$BIND_ADDRESS" --port 9443 --journal "$JOURNAL" --epoch "$EPOCH" \
  --installation-sha256 "$INSTALLATION_SHA256" --cluster-uid "$CLUSTER_UID" \
  --webhook-name "$WEBHOOK_NAME" --namespace "$TARGET_NAMESPACE" \
  --client-cert-sha256 "$AUDIT_CERT_SHA256" --client-ca "$AUDIT_CA_FILE" \
  --server-cert "$SERVER_CERT_FILE" --server-key "$SERVER_KEY_FILE"
```

Each service opens the existing journal and requires its original epoch. A
missing volume, an empty database, a missing required table, or a replacement
epoch prevents startup. Only trusted Birbverify processes may write the journal
directory. The installer must exclude a rollback to an earlier snapshot of
the same epoch while API effects can survive.

The API server's audit webhook kubeconfig contains the receiver URL, server CA,
and audit client certificate and key. Its audit policy must select
`RequestResponse` for every protected write and omit nonterminal stages.
This protocol supports one dedicated audit client leaf per journal. Changing
the leaf, installation, or candidate in place is unsupported. The disposable
fixture shows the exact API-server flags and certificate mounts.
[Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
and [disposable fixture](../scripts/verify-deployment-settlement).

## Completion and recovery

The receiver bounds requests at 4 MiB and 128 events. HTTP 200 acknowledges
a committed batch. The response contains no event or object data. A correlated
event can leave the epoch quarantined even when delivery succeeds. HTTP 400
rejects ambiguous JSON or an invalid batch. A failed storage transaction rolls
back the batch and returns HTTP 503. The sender can retry after a lost reply.

The durable delivery cursor is a set of audit ID, stage, event digest, and
admission UID records. Kubernetes supplies neither a contiguous event sequence
nor a durable remote rewind cursor. Restart reopens the SQLite index. Identical
redelivery leaves existing evidence unchanged. A conflicting replay or
impersonated completion quarantines the epoch. Uncorrelated events do not settle
an intent. Delivery failure leaves the accepted intent pending, even after seal
or an empty resource listing. A receiver restart cannot reconstruct an event
the API server has permanently lost.

The annotation identifies the admission UID and epoch. Settlement compares the
stored authenticated writer, operation, resource, name, namespace, object UID,
and persisted object to the admitted request. DELETE settlement does not establish
termination. The receiver stores the event digest and settlement evidence. Raw
incoming audit bodies never enter the replay index. The stored admission requests
can contain private object data. The receiver does not export journal snapshots.

Each journal retains at most 2,048 authenticated admission intents of 2 MiB each
and 4,096 bounded audit identities. At the intent limit, admission denies new
writes. At the audit limit, a new correlated identity quarantines the epoch.
Entries remain until the installation is retired. There is no time-based eviction
or automatic journal replacement.

## Verification

`uv run pytest -q tests/test_deployment_audit.py tests/test_deployment_journal.py`
exercises client certificates, reply replay, wrong-cluster pins, retention limits,
and pending intents across restart. `scripts/verify-deployment-settlement` drives a
real ReplicaSet controller and the API server's audit webhook in a disposable kind
cluster. Its receipt records the source hashes, fixture image ID, cluster UID, TLS
client pin, API audit ID, admission UID, Pod UID, and epoch. The fixture covers
one controller-created Pod. Deployment-wide closure requires separate evidence.
