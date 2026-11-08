# Contextless fixture closure

Birbverify can permanently close a dispatched request even when its worker's local
context is missing. A closure receipt records execution stop and environment
release. It supplies no application verdict and never makes a candidate eligible.

This extension implements the reviewed [proposal](proposals/contextless-closure/README.md)
for isolated Linux fixtures. The original `contracts/v1` files remain unchanged.
The proposal's historical review is not review or execution evidence for this code.
See the [gate map](contextless-closure-gates.md) for the executable boundaries.

## Who owns each fact

The target's existing SQLite transaction owns admission, one permanent request
seal, the request epoch, reservation provenance, closure progress and final
receipt. Birbforge still owns admission policy, its durable queue and delivery
eligibility. This change neither edits Birbforge nor changes its producer pin.

An installed launcher creates one non-restarting Docker container containing the
entire token-holding Temporal worker. It registers its immutable container ID,
boot identity and process start identity before releasing the worker. The target
uses Linux socket peer credentials, pidfd liveness and the exact peer's cgroup to
check that the reserving process is that registered worker. The target runs
outside the worker's execution group.

A separate supervisor closes the request and resumes from the target journal.
It does not recreate a worker token from a missing file. The ordinary v1 target
and runner remain available for existing installations. An enabled target rejects
unversioned envelopes and a different installed incarnation, without fallback.

## Paths and authority

A closure installation uses `transport/target.sock`. Mounting its containing
directory preserves Unix socket behavior across Docker Desktop and target
restarts. The legacy profile keeps `target.sock` at the fixture root.

The worker's fixture root is a private tmpfs. The launcher mounts only the
transport directory, public installation configuration, installed Git repository,
launch records, checkouts, artifacts, lifecycle evidence and `contexts/` cache.
It does not mount `supervisor.key` or the target database. The v2 context cache is
`contexts/<attempt>.context.json`; the legacy path is unchanged.

The trusted in-worker HTTP adapter has a checker credential that can append
bound completion evidence. It has no closure capability. This is the accepted
trusted fixture boundary, not hostile same-user or production worker isolation.
The worker has Docker access, so a malicious process with that access remains
outside this guarantee. Candidate containers have no network, target socket or
credentials and receive only read-only approved check files.

## Commands and stop evidence

Before every Docker create, start or remove, the adapter commits an intent and
requires a positive acknowledgement. Finding an intent after an unknown reply
never authorizes a resend. The HTTP adapter sends once and saves the bounded
command-bound daemon response. Transport failures, truncated output, 5xx and
ambiguous responses remain unknown. Local exit codes and later container absence
cannot settle an earlier command.

The supervisor first removes the exact worker container and inspects that ID for
404. An exited container alone is insufficient. Every earlier create, start and
remove command must then have determinate completion evidence. Only afterward does it remove
and inspect the candidate. The target revalidates the evidence against its own
journal, including ordering, before accepting stop. After stop confirmation, no
new closure lifecycle command is accepted.

A held create that reaches Docker after the worker dies remains quarantined.
The fixture does not infer command settlement from a later labelled container.
This intentional inability to recover automatically is a safety result.

An unknown read-only wait or log response does not establish an outstanding
mutation. It does not substitute for the final attributable absence observation.
The adapter still enforces the request's check timeout and deadline.
Mutating start uses the normal control timeout, so its reply may arrive after
the procedure budget expires. The remaining budget bounds the read-only wait.
Lease expiry still requires explicit supervisor recovery after cleanup.

A lost reply for a mutating supervisor command also leaves that command unknown.
The supervisor cannot resend it or infer settlement from current container state.
The supervisor's fixed observation IDs also replay an unknown or non-404 result
instead of automatically taking a fresh observation. That path stays blocked.
The target can accept fresh valid stop evidence after rejecting an earlier set;
this does not promise automatic recovery from every supervisor transport failure.

The v2 candidate adapter captures bounded Docker logs with a per-container
`json-file` log limit, then removes the container. The v1 adapter retains its
existing attached-output behavior. Both validate the same approved procedure
and observations. Raw logs and command evidence remain private.

## Supervisor use

The coordinator persists one full `BeginClosure` command before invoking the
supervisor. Its UUID and nullable expected fields must remain identical on replay.
The schemas and independently calculated canonical examples are under
[`contracts/closure/v1`](../contracts/closure/v1) and
[`contracts/target/v2`](../contracts/target/v2).

```python
supervisor = Supervisor(fixture_root, installed_binding)
supervisor.begin(original_command)
view = supervisor.reconcile(original_command["closure_id"])
```

`reconcile` returns durable progress when evidence is uncertain. It neither
retries verification nor silently creates a new closure. A fresh supervisor can
read by request or closure identity and resume already committed steps.

`observe_closure_state` reads selected request histories and current availability
in one revisioned target snapshot. `validate_closure_receipt` separately checks
that the target's historical receipt and required retained evidence are valid
and available. A historical receipt may remain readable when evidence is missing;
validation then returns false. Receipt replay never changes a successor owner.

The existing `projection.observe` helper serves the legacy profile. It uses
unversioned transport and cannot read an enabled v2 target. The later Birbforge
integration must project the extension's atomic observation through AG-UI.
Historical attempt rows are not rewritten into synthetic verification outcomes.

The later consumer must require the exact blocked request's validated receipt
and a fresh matching free snapshot. A terminal error, fence or old receipt alone
must never advance its queue. A new verification requires new request and
idempotency identities.

## Run the isolated proof

Run against a fresh source copy and a Linux Docker engine. The driver needs the
host PID and cgroup views to identify its own worker peers; workers use private
PID namespaces. Do not enable privileged mode or reset a Docker daemon. Record
the built image's immutable ID because build-time OS packages are not a binary
reproducibility claim.

The following commands run on the Docker host. They create a private source copy,
short fixture path and evidence directory. They do not mount account credentials.

```sh
bv_commit=$(git rev-parse HEAD)
bv_root=$(mktemp -d /tmp/bvc.XXXXXX)
bv_root=$(cd "$bv_root" && pwd -P)
mkdir "$bv_root/source" "$bv_root/f" "$bv_root/evidence"
chmod 700 "$bv_root"
git archive "$bv_commit" | tar -x -C "$bv_root/source"
docker build -f fixtures/closure.Dockerfile -t birbverify-closure-proof .
bv_image=$(docker image inspect birbverify-closure-proof --format '{{.Id}}')
docker run --rm --name "bvc-proof-$$" --label proof=contextless-20261108 \
  --pid=host --cgroupns=host --network=host --cap-drop ALL \
  --security-opt no-new-privileges \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$bv_root:$bv_root" \
  -w "$bv_root/source" \
  -e BIRBVERIFY_SETUP_PROFILE=closure \
  -e BIRBVERIFY_WORKER_IMAGE="$bv_image" \
  -e BIRBVERIFY_SOURCE_REVISION="$bv_commit" \
  -e BIRBVERIFY_FIXTURE_ROOT="$bv_root/f" \
  -e BIRBVERIFY_CLOSURE_EVIDENCE="$bv_root/evidence" \
  "$bv_image" sh -c 'scripts/setup && scripts/verify-closure'
```

The test suite owns its exact disposable container IDs and removes them in
teardown. It never uses `docker prune`. If the driver itself crashes, retain the
private evidence and inspect only its labelled resources before owner-approved
cleanup. Do not treat driver exit as proof that every resource stopped.

The default `scripts/verify` continues to run the original fixture suite and now
writes reports into ignored `.proof/evidence`. It does not rewrite the published
v1 manifest example. The extension runner includes the baseline and extension
suites, writes JUnit and observations to the chosen private directory, and does
not publish them automatically. It records source hashes before the run and
rejects source changes afterward. The revision remains caller-supplied until a
reviewer compares those hashes with the named Git commit. The proof summary
includes the actual worker image ID, test counts and artifact digests.
Run `scripts/export-closure` only when intentionally
updating the extension schema fixtures.

## Limits that remain

An operator-declared restore or changed target incarnation is unavailable. This
implementation has no automatic restore-unblock operation. Missing prior history
cannot be reconstructed from current PID or container absence. Old-incarnation
requests cannot obtain never-acquired receipts in a replacement target. Silent
in-place SQLite rollback remains outside the trust assumption.

Legacy acquired records with an epoch but incomplete durable provenance can be
sealed and stay quarantined. Their progress uses
`acquired_provenance_unavailable` with a null reservation digest. That variant
cannot appear in a release receipt. Pre-extension records without an epoch are rejected
before a closure claim. Neither case permits inferred never-acquired release.
Observation of unsupported old-incarnation records fails closed. Policy changes
can also prevent replay authorization; historical authority is not reconstructed.
The real Birbforge queue and its two supervisor paths still need their own
integration, including request-level reconciliation locking. Staging mutation
fencing, native isolation, production identity, artifact retention and physical
client journeys remain separate gates. This proof performs no deployment,
production rollback, model invocation or Datadog call.
