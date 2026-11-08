# Next integration and deployment gates

The next bounded change is a Birbforge integration that pins this contract and
its compatibility fixtures, dispatches the activity from Birbforge's existing
durable queue, and projects the returned authoritative state into its AG-UI
conversation and inbox. It must retain request/attempt identities through
reconnect, duplicate submit and cancellation. This repository has not changed
either consumer.

Before accepting an application candidate on shared k3s staging, the deployment
and infrastructure owners must agree an actual target mutation adapter. It must
fence every deploy and fixture mutation, detect other writers, retain ownership
through uncertainty, and supply evidence of stop and cleanup. The local counter
transaction is not that adapter.

The later execution path reuses Birbparty's existing environment deployment
procedure and Birbhomes' existing Linux and Mac worker arrangement. Read-only
inspection for this handoff covered Birbparty's root agent guide, the existing
environment section of its README, deployment/environment runbooks, and the
Birbhomes worker and lifecycle instructions. Exact inspected revisions and
source-file hashes are in `evidence/source-references.json`. No infrastructure
or source files in those repositories changed.

The existing environment procedure requires an explicit target manifest,
verified cluster and namespace identity, digest-pinned API and UI images,
existing Secrets, correct architecture and server-side dry runs. It deploys data
before application. Helm success alone leaves URL verification pending.
Staging uses private application access. No production rollback is authorized.

Birbhomes separates native macOS work from Linux container work in its dedicated
guest. Its controls require protected configuration, recorded workload ownership,
persistent installation/admin/fault latches, actual stop verification and
physical-LAN lifecycle enforcement. Current readiness needs fresh owner-led
inspection. Historical onboarding notes are not current enrollment evidence.
This session did not contact the Mac, reconnect NetBird, recreate the SSH bridge,
or reuse expired fixture credentials. The owner's explicit Large Text and
VoiceOver deferral remains in effect for the existing owner-use scope.

Outstanding gates are staging queue integration, actual deployment fencing and
interference detection, current worker readiness and permissions, native Mac
candidate isolation, authenticated worker submissions, scoped artifact access,
retention, and operator-controlled quarantine recovery. A fixture success
satisfies none of those deployed acceptance gates. No k3s, DigitalOcean, DNS,
NetBird, runner registration or production operation was executed here.
