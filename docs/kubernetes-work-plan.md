# Kubernetes target implementation plan

- [x] Read the Principles section of poteto-mode.
- [x] Phase A: Frame.
- [x] Phase B: Design the workflow.
- [x] Phase C: Run the loop.
- [x] Phase D: Keep the audit trail.
- [ ] Phase E: Verify and hand back.

The completion predicate is a real application journey on disposable kind,
outsider denial by admission, worker-loss and cancellation closure, settled
in-flight writes before release, persistent quarantine for unknown delivery,
versioned receipts, and an implementation commit. Shared staging is excluded.

Architecture steps were Ground, Sketch, Agree, Implement, and Scrap. Agree
proceeded without a human checkpoint. Scrap was unnecessary after the selected
profile passed the live workload journey. Arena steps were Frame, Fan out,
Cross-judge, Pick, Graft, and Verify. Two independent candidates and a separate
judge compared webhook admission against native policy.

The selected design combines native admission with a sole credentialed gateway.
A webhook cannot make admission and API storage atomic. The gateway records
intent before submission and owns serialization through the complete response.
Unknown responses retain ownership. Activity workers receive only a socket.

The workload is one bare Pod on a pinned node. Deployment controllers introduce
untracked writes and remain outside this profile. The fixture uses direct Pod
networking. Service and EndpointSlice routing are not claimed. A gateway
finalizer preserves terminal status before the final API deletion.

Throughput checkpoint. The critical path was the real admission and termination
boundary. Contract and target tests preceded live application and failure
journeys. Independent code review followed those journeys. Final evidence pins
the implementation commit separately from the report commit.

Model the Domain produced a separate Kubernetes contract and durable effect
ledger. Prove It Works required real Kubernetes admission, actual application
HTTP calls, SIGKILL of a credentialless worker, and runtime container inspection.

Configured model families were unavailable through the collaboration tool, so
architecture seats used the inherited model. Cursor-only deslop, control-cli,
and Comment Sicko were unavailable. Ruff, real CLI execution, and independent
comment review supplied explicit substitutes. No unavailable tool execution is
claimed. This issue requests a commit and evidence, not deployment. Forgejo,
Ferry enrollment, Flux desired state, and shared staging remain later gates.

An attempted Claude Opus read-only review failed with an invalid API key before
reviewing files. Independent inherited-model review found and drove fixes for
raw error disclosure, policy/plan approval, and admitted image substitution.
The user then authorized retrying with the API key unset. Claude Opus completed the cross-model review. The decision log explicitly withdraws
estimated timestamp precision in its reconstructed opening rows.

Claude found three hardening gaps. Added capabilities and host ports now fail
profile validation. Admission pins now include object UID and generation.
`sealed_unadmitted` keeps a cancelled request closed without retaining unrelated
work. Mutating admission policies are rejected alongside webhooks. The initial
implementation pin is superseded after these fixes and another live proof.
