# Kubernetes review resolution

Two independent design candidates and a separate judge selected native
admission with a sole credentialed gateway. A later independent code reviewer
found admitted-image substitution and raw error disclosure. The implementation
rejects mutators, checks the admitted container, validates installed policy and
plan approval, and returns only exception classes. Regression tests cover these
boundaries.

Claude Opus reviewed the implementation through the local CLI. The initial call
failed authentication. After the user authorized unsetting `ANTHROPIC_API_KEY`,
the review succeeded. It was read-only and did not execute tests.

| Claude finding | Resolution |
| --- | --- |
| Added capabilities and host ports passed profile admission | Template checks and CEL reject them. The live proof attempts both writes. |
| A removed admission object could return with an unchanged spec | Installation pins spec digest, UID, and generation. A live binding recreation blocks the next effect. |
| Closure before admission retained the target forever | `sealed_unadmitted` permanently seals that request without retaining unrelated work. Tests cover both requests. |
| Mutating admission policies were not inventoried | The target discovers served admission API versions and rejects installed mutating policies. |
| Host kubectl came from PATH despite a pinning claim | Transport wording describes explicit context. The packaged kubectl image is digest-pinned. Host executable lookup remains trusted installation configuration. |
| No final policy check after cleanup | The target rechecks installation identity before committing a release receipt. |
| Legacy AppArmor annotations bypassed template checks | The installed profile rejects the legacy annotation prefix. |
| Historical quarantined journals have no migration | Runtime documentation states the pre-publication journal limitation. This task deployed no persistent staging target. |

Claude's follow-up confirmed all three P2 findings fixed and the earlier P3
items handled. The final policy check, legacy annotation rejection, and related
regressions address the smaller follow-up findings. No later cross-model test
execution is claimed. Local tests and the disposable cluster supply runtime
evidence.

The audit trail records the initial review failure and successful retry. Its
opening rows reconstruct decisions. A later row explicitly withdraws their
estimated timestamp precision. Read those rows in order rather than treating
their timestamps as measured event times.
