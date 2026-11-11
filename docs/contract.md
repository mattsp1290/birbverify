# Verification contract v1

Verify owns `birbverify.v1`. The published wire schemas are in
[`contracts/v1`](../contracts/v1). Consumers pin a Verify Git revision and
these files together. This version is a local fixture contract. It does not
change Birbcrew or Birbforge's published contracts.

## Identity and compatibility

The request example is synthetic and does not identify a runnable repository.
The result example comes from the executed synthetic fixture. Compatibility
checks parse both schemas, accept the v1 example, and reject an unknown version,
a credential field, and plan drift. Unknown fields are errors at every level.
Version changes require producer and consumer agreement before integration.

`request_id` and `idempotency_key` are separately unique. Identical canonical
payloads converge on the same request and terminal result. Changed payloads
conflict under either identity. Attempts retain their original request digest.
Operation IDs derive from the request ID and operation name, never a retry.

Canonical hashing uses the complete Pydantic `model_dump(mode="json")` output,
including defaults and version. Python `json.dumps` uses sorted keys, compact
separators and `ensure_ascii=True`, followed by UTF-8 and SHA-256. Arrays retain
order. There are no float fields, sets or mutable nested mappings in the wire
models. Datetime strings use Pydantic 2.12.5 serialization. This is a pinned
encoding, not a claim of RFC 8785 interoperability. Consumers can compare
`canonical.example.sha256` before sending requests. A different candidate or
plan requires a new request, never a replacement label on historical evidence.

## Authority and worker support

The fixture installation independently binds principal, authorizing workflow,
policy revision, environment, capabilities and exact approved plan digest.
Both the worker and target service enforce that binding. Requesting a capability
or operation grants no permission. No credential or credential-bearing URL is
a request field. This fixture needs no credentials or secret references.

The wire format describes head and integration candidates and optional build
artifact digests. The fixture worker accepts head candidates only, no supplied
build artifact, one logical environment and one fixture component. Unsupported
requests fail closed. It validates the exact source commit and base ancestry.
It materializes only `check.py` and `value.json` from that commit with `git show`.
It verifies the procedure against both its pinned source revision and approved
digest. It does not execute a candidate-controlled build configuration or shell.

The test workflow uses the request retry budget with the supported Temporal
RetryPolicy and WAIT_CANCELLATION_COMPLETED. Busy is non-retryable at the activity
boundary. The test workflow waits for an explicit supervisor signal before
redispatch, bounded by the request deadline. Waiting does not consume the
acquired-attempt budget or mutate the fixture target.
Infrastructure uncertainty is a recorded terminal attempt requiring supervised
reconciliation. This proof does not automatically rerun unknown effects or
assertion failures. A completed request always returns its canonical result.
The fixture does not retry effects after a terminal outcome or supervised
cleanup. A new verification needs a new request. Birbforge will own real
queueing and retry policy.

## Results and evidence

A manifest binds request digest, source identity, approved plan and policy,
worker identity and capabilities, attempt number and predecessor, tools,
timestamps, before/after target identity, checks, operation receipt, cancellation,
termination, cleanup and release. Every required check has a record, including
a reason when it did not run. A failed assertion remains in its attempt history.

Artifacts have content-addressed IDs, sizes, SHA-256, capture times,
classification and a local retention policy. Manifests have no public URLs,
credentials, raw files or private storage paths. The fixture's short synthetic
assertion observation is also in the check record. Large/raw files stay private.
Private artifact files use mode 0600 under a 0700 installation root.

`eligible` is an evidence-completeness predicate for consumers. It requires a
current candidate and an artifact-reader callback. It reads every referenced
artifact and verifies size and digest. Missing, inaccessible or corrupt evidence
cannot establish eligibility. Birbforge still owns freshness at decision time,
review requirements and every final delivery decision. Artifact references and
digests establish attributable records, not independent truth or cryptographic
attestation. The local worker name is not a production authenticated identity.

## Progress projection

`observe` emits official AG-UI 1.0.0 RunStarted, StateSnapshot and, for terminal
records, RunFinished events. `threadId` is the stable request ID. `runId` is the
attempt ID. `snapshot.verification` contains those identities, authoritative
attempt state, and its immutable manifest when available. Active snapshots are
point-in-time reads. Reattach for a new snapshot. There is no arbitrary history
cursor or client-state write path. Birbforge can embed this state in its existing
conversation and inbox. This does not introduce a new user-facing protocol.

Cancellation requested appears as `cancel_requested`; acknowledgement appears
only with the persisted cancelled manifest after stop and cleanup. Closing the
observation generator has no command effect. Tests exercise close during work
and reattach to the terminal snapshot.

Structured diagnostic JSONL uses a fixed event-name allowlist and bounded
request, attempt, source and correlation fields. No raw commands, credentials,
artifact bytes or high-cardinality metric labels are emitted. Diagnostics are
private local files for later Datadog adaptation. Durable target state and
Temporal history remain authoritative. The fixture requires no live account.
