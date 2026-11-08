# Birbverify

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
