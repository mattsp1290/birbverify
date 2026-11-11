# Verify

Repository: [mattsp1290/verify](https://github.com/mattsp1290/verify)

Versioned verification requests and attributable evidence for Birbforge.
This repository proves a bounded local fixture contract with Python, Temporal
and AG-UI. It does not deploy or verify staging or native Mac isolation.

Run on Linux with Python 3.13, uv, Git, Docker access, curl, ripgrep and Beans
`bn` 0.3.0. Setup downloads a checksum-verified Temporal CLI and a digest-pinned
Python container. The proof needs no live model or observability provider.

```sh
scripts/setup
scripts/verify
```

Verification starts disposable loopback Temporal and Unix-socket fixture
services, creates isolated Git candidates, executes container checks, kills a
worker and a stale mutation probe, and checks cancellation and cleanup. It
writes synthetic summaries to ignored `.proof/evidence`. Checked-in evidence is
historical and is not replaced by a new run. Raw logs, container output,
artifact files and databases stay under ignored `.proof/test-runs`. Re-running
verification replaces only that disposable test directory. Beans command tests
use new disposable hubs under `/tmp`, without remotes or private-hub access.

Read the [contract reference](docs/contract.md),
[fixture boundaries](docs/architecture.md), and
[acceptance evidence](docs/verification.md).
Consumers pin the [v1 schemas and compatibility fixtures](contracts/v1).

The optional [contextless closure extension](docs/contextless-closure.md) uses a
separate one-attempt fixture profile, versioned target transport, and an
installation-owned supervisor. Its [gate map](docs/contextless-closure-gates.md)
distinguishes producer tests from later consumer integration. Existing consumers
remain pinned to v1 until an explicit integration change.

The [closure acceptance report](docs/contextless-closure-acceptance.md) records
the executed source revision, independent review and remaining integration gates.

The [bounded Kubernetes adapter](docs/kubernetes-runtime.md) uses a dedicated
namespace, a pinned bare Pod, native admission policy, and a durable target
process. `scripts/verify-kubernetes` creates and removes its own disposable kind
cluster. It proves an account/auth HTTP fixture, outsider denial, worker loss,
cancellation, and unknown-response quarantine. It does not deploy shared staging
or authorize Deployment, Flux, Service, or EndpointSlice controllers.

The [deployment fencing proposal](docs/proposals/deployment-fencing/README.md)
records the accepted account/auth chart inventory and provisional controller
contract. Its offline inspector does not authorize deployment or controller writes.

The [deployment producer](docs/deployment-producer.md) adds authenticated audit
ingestion, per-request CREATE admission, closure progress, and an account/auth
activity. Its deployment closure retains the owner. Birbforge must keep
deployment promotion disabled.

## Repository rename and compatibility

This repository was renamed from `mattsp1290/birbverify` to
[`mattsp1290/verify`](https://github.com/mattsp1290/verify). Existing checkouts can
update their remote with:

```sh
git remote set-url origin https://github.com/mattsp1290/verify.git
```

The repository rename does not change the published interfaces. The Python
distribution and import namespace remain `birbverify`, as do the versioned
`birbverify.*` contracts, Temporal activity names, `BIRBVERIFY_*` environment
variables, and installation resource identifiers and paths. Existing commands
and consumer integrations therefore remain valid. Changing these identifiers
requires a separate, explicitly versioned migration. Historical evidence and
Beans identifiers retain their original names.
