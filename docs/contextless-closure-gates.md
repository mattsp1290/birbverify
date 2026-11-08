# Closure producer gate map

This table maps the accepted F01–F29 proposal to executable producer tests. A
quarantine assertion proves that the fixture stays blocked; it does not prove
automatic recovery. Test names can cover several related assertions, so the gate
count is not a test count. Exact revision-bound execution results belong in a
separate acceptance report, not this map.

`tests/test_closure.py` uses direct target instances and independent SQLite
connections. Its synthetic checker records test validation logic and are not
real daemon or process-stop evidence. `tests/test_closure_journeys.py` drives real
Unix transport, Docker containers, a controlled daemon proxy and a Temporal
activity. It writes private observations through `BIRBVERIFY_CLOSURE_EVIDENCE`.

| Gate | Producer exercise | Remaining boundary |
| --- | --- | --- |
| F01 | Real dispatched worker pauses before admission, closure completes, resumed worker gets `request_closed` | No consumer queue change |
| F02 | Real worker pauses before reserve; original epoch remains sealed | No retry |
| F03 | Real reserve reply is dropped before context publication; target provenance supports closure. A real Temporal worker also pauses after reserve before context | No fabricated manifest |
| F04 | Remove the mounted acquired context cache before supervisor reconstruction | Attribution comes from target |
| F05 | Two independent connections race both controlled reserve/closure transaction orders | SQLite is the sole serialization boundary |
| F06 | Two independent connections race both apply/closure transaction orders; committed effect and receipt survive, while closure-first denies the effect | Shared effect is the fixture counter |
| F07 | Every stale worker mutator and legacy supervisor mutator is denied; immutable manifest replay stays read-only | No arbitrary staging writer claim |
| F08 | Incomplete live-worker proof is rejected; missing provenance stays blocked | Linux registered group only |
| F09 | Worker pauses after positive start-intent acknowledgement, then crosses the seal; release waits for settled controls and whole-worker removal | The SQL seal alone is insufficient |
| F10 | Proxy holds create outside worker, worker dies, target observes absence, then real daemon creates the candidate; a successor stays unacquired | Unknown delivery intentionally remains quarantined |
| F11 | Fixture queue predicate binds target ID/incarnation, retained receipt validation and current free state; missing/corrupt proof and a busy successor block it | Actual Birbforge FIFO integration is deferred |
| F12 | Drop fence reply and recover the original target record; independent process crash boundaries also run | Coordinator retains original command |
| F13 | Drop cleanup reply; replay does not reset twice and changed payload conflicts | Fixture cleanup is transactional |
| F14 | Release replay returns exact receipt while successor ownership remains unchanged | No authority over the successor |
| F15 | Changed reason, expected fields and second closure identity conflict | Closure identity is immutable |
| F16 | Fresh supervisor instances recover each committed step from target after lost replies | No local reconstructed worker token |
| F17 | Inject cleanup failure before commit, verify rollback and quarantine, then reconcile original operation | External unknown cleanup remains unsupported |
| F18 | Original inconclusive manifest survives ordinary known-context recovery; closure and legacy release authority exclude each other | Consumer receipt-file arbitration remains deferred |
| F19 | Closed identity never reserves again; changed request conflicts; new work uses new identities | No attempt-budget reset |
| F20 | Kill target at before/after fence, cleanup and release commit boundaries; restart verifies atomic old-or-new state. Changed incarnation denies admission | Restore remains blocked; automatic reconciliation and silent rollback detection are not implemented |
| F21 | Privileged methods reject missing capability, stale/null worker authority and unavailable/tampered evidence | Trusted same-UID fixture, not production identity |
| F22 | Remove durable acquired provenance and verify persistent quarantine | No inferred migration |
| F23 | Dirty free state and unrelated ownership cannot be reset by never-acquired closure | Operator investigation remains required |
| F24 | Old-incarnation and unversioned envelopes fail before effects | No automatic incarnation rediscovery |
| F25 | Registered worker includes the actual token holder and escaped-session descendant; removal precedes a delayed-write challenge. A real Temporal worker is removed | Native Mac process isolation is not proved |
| F26 | Lost intent ACK produces zero daemon create sends; post-seal completion settles only an existing intent; replay never authorizes send | Unknown delivery remains unknown |
| F27 | First live-worker stop evidence is rejected; later attributable evidence confirms the same closure | Accepted evidence set is immutable |
| F28 | Claimed request rejects legacy recover/release; immutable history is preserved | Actual consumer early-return branches and request lock are deferred |
| F29 | Sealed reserve reports `request_closed` before busy; real delayed worker creates no attempt | A generic error never proves queue release |

Additional regressions reject an old absence observation before a later create,
new lifecycle commands after confirmed stop, wrong registered worker identity,
unknown schema fields, coerced numeric authority and corrupted retained proof.
The canonical examples use an independent SHA-256 calculation. Original v1
schema and example bytes are checked separately.
