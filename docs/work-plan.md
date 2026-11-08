# Contract proof work plan

- [x] Read the Principles section of poteto-mode.
- [x] Phase A: Frame.
- [x] Phase B: Design the workflow.
- [x] Phase C: Run the loop.
- [x] Phase D: Keep the audit trail.
- [x] Phase E: Verify and hand back.

The completion predicate is all nine first-milestone journeys passing against
real disposable processes, a pinned contract with compatibility examples, fresh
Claude review with warranted fixes checked, and a pushed draft PR and scoped
Beans handoff. An unverified journey blocks completion.

The work has four bounded units. First publish request/result models and consumer
examples. Then implement a fixture-only mutation boundary and private artifacts.
Then exercise a minimal Temporal activity worker and interruption journeys.
Finally review, verify, publish safe evidence, and hand off. No staging or Mac
execution is included. Birbforge retains admission and queue policy.

The data shapes are Request, Plan, Candidate, Authority, Manifest attempt fields,
CheckRecord, Artifact, and a fixture reservation state machine. Requests and
manifests are immutable. A SQLite transaction at the fixture target binds fixture effects to
an active reservation token and stable operation ID. A separate service
owns that database. Candidate checks run in a Docker container without network,
credentials, the Docker socket, or access to the mutation service or its files.

Architecture alternatives considered before implementation are direct worker
writes under an advisory lock, and a target-owned mutation service. The first
cannot fence an interrupted worker after lease expiry. The target-owned service
is selected. A fixture reservation rejection demonstrates waiting, while the
test workflow supplies ordering. This is not a production environment queue.

Throughput checkpoint. The critical path is process interruption and fencing,
not schema breadth. Implement the schema first, prove the mutation boundary
next, then integrate Temporal. Run narrow checks after each unit. Use Codex
for authorship and fresh Claude CLI processes for design and code review.
Cursor Task, deslop, Comment Sicko and control APIs are unavailable. Their actual
substitutions are explicit design comparison, Claude read-only review, Ruff,
diff inspection, and scripted CLI/process journeys. No Cursor invocation is claimed.

The principles read and used this session changed concrete choices. Model the
Domain put immutable request/result identities and target reservation transitions
in explicit structures. Foundational Thinking put schemas and target tests
before Temporal integration. Sequence Work into Verifiable Units required a
checked schema and target unit before process journeys. Prove It Works required
real SIGKILL, socket reply loss, Docker cancellation and target writes.
