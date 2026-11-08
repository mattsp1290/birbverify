# Proposal review evidence

Status is PASS for the documentation handoff after independent supplied-source review and a final clarification check. Runtime acceptance is NOT VERIFIED. Runtime acceptance is NOT VERIFIED.

Producer and consumer investigations used the exact revisions recorded in [source-evidence.json](source-evidence.json). The owner inspected the executable boundaries and wrote all proposal documents. Two Codex source explorers and a separate source synthesizer checked the existing implementation. No recovery code or runtime was executed.

## Independent Claude review

The installed Claude CLI reported version 2.1.312 and Claude subscription authentication. The actual review result identifies `claude-opus-5-5` through the first-party provider. The review used supplied source with tools disabled. It did not read repositories independently, run tests, or establish runtime acceptance.

The reviewer received the concrete proposal and actual pinned target, runner, activity, policy, contract, consumer workflow, observation, supervisor, model, and selected test source. Its question was to find any path that releases the environment while a stale worker can still mutate. The first verdict required revisions for three blocking findings.

| Finding | Resolution in the revised proposal |
| --- | --- |
| B1. A child-only execution group can miss a live in-process activity coroutine | Stop proof covers the token-holding Temporal activity-worker process itself and every descendant. F25 exercises a live parent with an empty child group. |
| B2. Intent logging could be best-effort, and post-seal completion could be impossible | A command requires positive durable intent acknowledgement. Failed or unknown acknowledgement aborts the send. Evidence-only completion remains possible for an existing intent after sealing. F26 exercises both cases. |
| B3. SQLite incarnation and revision cannot detect silent rollback of the same database | The guarantee now explicitly assumes no silent in-place rollback. Every declared restore forces a new incarnation and prior-execution reconciliation. F20 tests the supported path. A separate counterexample experiment documents the unsupported path. No external witness is claimed. |
| N1. Rejected stop evidence could permanently bind a failed payload | Evidence observations append while the fixed stop operation remains unknown. Confirmation freezes the accepted evidence set. F27 exercises later valid evidence. |
| N2. An unrelated owner prevents sealing | Retained as an explicit conservative limitation. The entire begin transaction fails with no claimed fence or release. Birbforge remains blocked. This can delay closure but does not authorize an unsafe successor. Decoupling request seal and ownership would require another progress state and is outside the selected smallest mechanism. |
| N3. The legacy supervisor's early branch could write a second recovery history | The later consumer integration must check target claim status before both branches, serialize privileged reconciliation, and exclude claimed requests from legacy recovered-attempt observations. F28 covers the boundary. |
| N4. Closed reserve could return busy or an unexpected dictionary | The seal precedes busy handling. Closure-only reserve raises `TargetError("request_closed")`; the updated worker handles it explicitly. F29 covers classification. |
| N5. Existing no-attempt rejection behavior was ambiguous | Legacy profile behavior stays unchanged. The closure-capable profile requires closure proof for post-dispatch generic rejection or cancellation. Pre-dispatch cancellation/expiry stay unchanged. |
| N6. Null owner/token could satisfy the existing owner equality check | The new target guard requires non-null token, an attempt owner tag, and matching epoch. F21 includes free and closure-barrier cases. No current runtime was patched. |
| N7. The design described only apply as a mutation | The source description now distinguishes apply, cleanup, and ownership changes. |
| N8. Missing provenance and never-acquired phase were unclear | Missing provenance is a blocking reason under stop-unknown. Never-acquired enters cleanup-unknown with target-confirmed no-start evidence. |
| N9. Closure UUID chooser was ambiguous | The trusted coordinator creates and persists the UUID once. The supervisor receives it. Temporal generation must be replay-safe. |

The owner's separate review added mandatory incarnation-bound worker RPC envelopes through proposed `birbverify.target.v2`. It also added internal target records for existing release transitions so `already_released` never follows from an owner mismatch alone. The final review receives these changes too.

## Closure review and final corrections

The second independent supplied-source review accepted the core design for a bounded implementation handoff. It confirmed the original blocking findings were resolved at the text level. It required one final correction to restore attribution before handoff acceptance.

| Follow-up | Resolution |
| --- | --- |
| R1. Restored history could falsely produce never-acquired evidence | The original admission binds its target incarnation. Cross-incarnation closure is unsupported and returns `legacy_provenance_unavailable`. Restore reconciliation requires prior process stop, command settlement, and absence of every prior-incarnation attempt-labelled container. Its record gates new installation admission only. It cannot relabel an old request. |
| R2. Local client completion could be mistaken for daemon settlement | Only a determinate daemon outcome settles an intent. Timeout, kill, OSError, bounded-output abort, and missing reply remain `delivery_unknown`. F10/F26 require quarantine in those cases. |
| R3. Supervisor lifecycle operations lacked explicit intent rules | Closure-authorized supervisor operations have their own stable intents and completion evidence, with the same acknowledgement and settlement requirements. |
| R4. Lock wording implied a target-side file lock | The contextless supervisor holds the local per-request lock across the target call. The target supplies the durable claim and fence. |

## Final verdict

The third Claude review returned PASS for the documentation handoff and confirmed R1-R4 were resolved. Its remaining clarifications were adopted. Incarnation mismatch now rejects before any effect and restored target rows retain their original admission incarnation. The consumer handoff explicitly keeps old-incarnation queue heads blocked and requires new identities for old undispatched admissions. A determinate daemon outcome is defined positively.

The fourth, narrowly scoped check returned PASS for those final clarifications. It found no new authority, mutation path, or release path. No substantive review finding remains open in this documentation handoff. Implementation, receiving-owner acceptance, and every runtime gate remain outstanding.

[The sanitized review binding](review-evidence.json) hashes the reviewed substantive documents and the private input/output artifacts. The final document bytes match the final clarification-review bundle. This review record and its binding are publication metadata and are excluded from that document hash set to avoid circular claims.

## Evidence and limits

The first review also noted that several referenced source files and source-review artifacts were absent from its bundle. The closure-review bundle supplies them, corrected source ranges, document/source digests, the current decision trail, and captured checkout baseline. A full conversation transcript is not included. Trail review therefore remains an artifact audit, not independent confirmation of every authoring action.

Private artifacts contain raw reviewer output, input bundles, decision trail, protected-checkout hash baselines, and the named final handoff. Only sanitized findings, source hashes, and bounded document validation belong in this directory. The [failure matrix](failure-matrix.md) remains a future implementation gate. Every executable row is NOT EXECUTED for this assignment. Existing acceptance records remain unchanged.

The owner independently recomputed the published source hashes from each exact Git revision and found no mismatches. Local link, privacy-pattern, whitespace, protected-checkout hash, and documentation-scope checks passed. These are document checks, not runtime tests. The unavailable Comment Sicko role and deslop integration were not executed or reported as passing.
