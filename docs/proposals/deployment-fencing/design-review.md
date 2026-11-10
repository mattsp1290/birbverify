# Independent design review

The goal is deployment-compatible fencing and closure for the exact account/auth Helm and Flux workload, without blanket controller exemptions or weakening bare-Pod v1.

Neither candidate is presently a viable deployable implementation for the existing k3s installation. Candidate A lacks a demonstrated completion authority for allowed admission requests. Candidate B lacks a demonstrated way to route every native controller writer through its proxy. These are correctness prerequisites, not follow-up hardening.

## Rubric scores

Scores are reviewer judgments on a five-point scale. Five means the proposal satisfies the criterion with supplied evidence. Zero means it does not supply the required mechanism or inventory. Totals do not override a failed prerequisite.

| Criterion | A | B | Reason |
| --- | --- | --- | --- |
| Accepted controller request crossing seal | 3 | 4 | Both retain uncertain accepted requests. B directly observes upstream responses in its proposed path. A explicitly lacks completion correlation. Neither has a deployed demonstration. |
| Native controller and Flux bypass denial on existing k3s | 1 | 1 | Neither supplies installed identities, routing, admission selectors, exemption inventory, or a bypass test. B acknowledges native controller routing is unresolved. |
| Preserve v1 | 4 | 4 | Both explicitly separate the new profile and retain existing schemas. No implementation has yet proved regression compatibility. |
| Complete StatefulSet, PVC, init, and hook inventory | 1 | 1 | Both describe general obligations but omit concrete StatefulSet and persistent volume ownership and restore semantics. Both were written before source became available. |
| Smallest viable implementation with verifiable completion | 2 | 2 | Both offer an honest fail-closed partial deliverable. Neither makes the requested workload complete or proves deployment compatibility. |
| Total | 11 | 12 | Neither passes the installation prerequisite. |

## Base selection

Do not select either as the deployable base yet. Use A's durable admission-intent and seal ordering as the requirements model. Preserve B's direct response-capture mechanism as an alternative only if controller routing can be proven in the actual deployment. A proxy restricted to Helm and Flux does not cover their native controller descendants.

A general unsupported-profile gate would be safe, but it would not satisfy birbverify-bsmn. Preserve that distinction in issue status and the eventual report. A speculative production proxy is substantially larger than the evidence warrants.

## Source changes the inventory verdict

The parent supplied the newly fetched accepted revision 503d3bc. I inspected its archive under `.proof/bsmn/accepted-source`. Both candidate documents still call this source unavailable and must correct that statement.

The archive establishes required resource classes before any live inspection. `infra/charts/birbparty-data/templates/_postgresql.tpl` contains StatefulSets, init containers, and volumeClaimTemplates. `redis.yaml` contains the same classes. `authz-runtime-pvc.yaml` contains an independent PersistentVolumeClaim. `infra/charts/birbparty/templates/api.yaml` contains init containers and a persistentVolumeClaim reference. `seed-cronjob.yaml` contains a CronJob and PVC reference. `tests/connectivity.yaml` contains a Helm test Pod with automatic successful-hook deletion.

Templates establish possible inventory, not exact installed values. Render the accepted application chart, data chart, dependency archive, and installed values together. Record whether each hook is invoked. Enumerate StatefulSet ControllerRevisions, dynamically generated PVCs, PV/provisioner effects, attach/detach or mount helpers where applicable, workload children, EndpointSlices, Helm storage, Flux reconciliation objects, and every executable init or hook container. A namespace-only inventory cannot prove cluster-scoped PV and storage cleanup.

Baseline restoration needs an explicit data contract. Restoring PVC metadata or a baseline ConfigMap does not restore PostgreSQL, Redis, or migration changes to persistent data. If baseline database state is in scope, specify an isolated snapshot or another verifiable restoration mechanism. If data restoration is outside scope, the task owner must narrow the claim before acceptance.

## Facts required before implementation choice

Obtain the installed k3s version and native writer identities, Flux deployment and service-account UIDs, exact Helm release values and storage mode, namespace and node UIDs, webhook and admission-policy inventory, mutating-admission behavior, resource discovery, and storage topology. These are absent in the supplied evidence. This review made no cluster access or mutation.

For A, demonstrate a complete correlation path between admitted requests and authoritative API completion. Cover denied requests after this webhook allowed them, timeouts, generated names, retries, dry-run, and writes that are deleted before observation. An absent object or quiet watch never settles an accepted request by itself.

For B, demonstrate that every scoped mutation reaches the proxy and that direct native-controller writes fail closed. Include scheduler binding, StatefulSet and PVC controllers, garbage collection, storage controllers, node status, and Flux. Denial alone does not provide functioning controller behavior. Prove that controllers can perform required work through the admitted route.

Both designs also need exact finalizer retention and mutation rules. An owned Pod may disappear before terminal proof if another actor removes the finalizer. An ownership label or parent UID alone is insufficient authorization for a replacement Pod. Pin allowed spec transformations and reject unrelated workload mutation.

## Decisive completion test

Hold a genuinely accepted controller CREATE before persistence. Seal the epoch and observe an empty list. Closure must remain withheld. Permit persistence, identify the created UID, prove every executable container terminal, and clean up under UID preconditions. Only then may closure release. Repeat across a crash between upstream persistence and durable response recording. An unresolved crash outcome must remain quarantined.

Add stale controller queue traffic after a new epoch opens. Both candidates identify the first epoch race, but admission must also prevent old work from inheriting a new session merely because the namespace is open again.

The Prove It Works principle changed the recommendation from choosing the slightly higher scoring proxy to requiring actual all-writer routing and delayed-persistence evidence. Source inventory and state-machine sketches alone cannot establish the requested deployment guarantee.
