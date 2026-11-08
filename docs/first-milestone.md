# First milestone for Birbverify

Status: owner-launched local fixture implementation and evidence now exist.
The original scope and required journeys below remain the acceptance brief.
Consumer integration and deployed staging proof remain separate gates.

## Outcome

One versioned verification request runs repository-owned checks against an exact
candidate and returns an evidence manifest. Duplicate delivery and worker loss
preserve identity and expose uncertainty. A later request cannot take over a
shared environment while an earlier worker may still mutate it.

## Scope

Implement the request and result types, compatibility fixtures and a minimal
Temporal activity worker. Use the proposal in Birbforge's
`docs/verification-contract.md` as the review input. Publish concrete schemas
here and let consumers pin them. Birbforge owns admission, policy and the durable
environment queue. A test workflow can exercise workers without creating a
second scheduler in this repository.

Begin with an isolated fixture repository and environment. Execute its existing
checks and capture source identity, procedure revision, observations and artifact
digests. Use private local fixture storage for this proof. A storage adapter is
not a claim that deployed retention and access controls are complete.

## Acceptance

| Scenario | Required result |
| --- | --- |
| Exact candidate passes | Every required check has attributable observations and a manifest |
| Required evidence missing | The result cannot satisfy the delivery gate |
| Duplicate request | The same key and payload resolve to one request; changed payload conflicts |
| Interrupted operation reply | Recovery reconciles a stable operation ID before repeating an effect |
| Worker loss | Infrastructure uncertainty is distinct from an application assertion failure |
| Second staging request | It waits until the first request is stopped and cleanup is confirmed |
| Stale worker | A revoked execution cannot mutate the fixture target; uncertain termination quarantines it |
| Candidate changes | Evidence keeps its original revision and cannot be relabeled as current |
| Cancellation | Requested and acknowledged states differ; release follows confirmed stop and cleanup |

The fixture must demonstrate the mutation boundary used for fencing. Temporal
durability alone is not proof of exclusive external ownership. Do not claim
k3s isolation from an in-memory lock or successful fixture-only test.

## Next deployment gate

After the contract proof, integrate the Birbparty repository's existing deployment
and verification procedures through Birbhomes' private staging rules. Confirm
current staging readiness, deployed artifact identity, worker permissions,
native Mac isolation and artifact storage before accepting real candidate code.
The complete pilot must run on k3s. Fixture tests do not satisfy that gate.

## Completion and handoff

Document exercised setup and verification commands, pinned dependencies and all
failure observations. Obtain independent review. Expose progress through
Birbforge's AG-UI projection without inventing another user-facing agent protocol.
This milestone grants no merge, production deployment or rollback authority.
