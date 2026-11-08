# Contextless verification closure proposal

Status is DOCUMENTATION PROPOSAL. Runtime acceptance is NOT VERIFIED.
This is the producer contract handoff for `birbforge-s0sc`. It does not implement recovery or authorize a queue to release today.

The selected contract adds a durable request seal to the existing target transaction. It records reservation provenance before replying and exposes privileged closure operations that do not need a worker token. A separate immutable closure receipt proves release. Historical verification manifests retain their original meaning.

- [Design and source findings](design.md) explain the choice and its limits.
- [Proposed contract](contract.md) defines identities, states, authority, operations, and compatibility.
- [Failure experiments](failure-matrix.md) define the implementation gate. None ran for this proposal.
- [Consumer handoff](consumer-handoff.md) identifies the later Birbforge changes and exact release predicate.
- [Review evidence](review.md) records independent supplied-source review and resolution.

Producer source is pinned at `a70315a276837ffdde32049fdb77670a3468e151`.
Consumer source is pinned at `6b46dac2931225e0739e9deb047e48b956bff8fc`.
The broader shared verification design is a proposal wherever it exceeds these sources.
The source investigations did not start either runtime.

All schemas, method names, and examples in this directory are proposals. `contracts/v1`, runtime modules, and existing acceptance records remain authoritative for implemented behavior. No consumer pin changes belong to this handoff. `birbforge-s0sc` stays open until the receiving owner accepts the handoff, and acceptance does not mean the behavior is implemented.
