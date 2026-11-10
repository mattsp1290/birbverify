"""Provision a fresh single-request deployment journal and print its epoch."""

import argparse
import os
from pathlib import Path

from birbverify.deployment_journal import Journal


def provision(
    path,
    installation_sha256,
    webhook,
    namespace,
    cluster_uid,
    audit_pin,
    request_id,
    request_sha256,
):
    # An incomplete installation remains occupied. Re-provisioning is an operator decision.
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    journal = Journal(path, installation_sha256, webhook, namespace)
    journal.bind_audit_source(cluster_uid, audit_pin)
    return journal.begin(request_id, request_sha256)["epoch"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, required=True)
    for name in (
        "installation-sha256",
        "webhook-name",
        "namespace",
        "cluster-uid",
        "audit-client-sha256",
        "request-id",
        "request-sha256",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    print(
        provision(
            args.journal,
            args.installation_sha256,
            args.webhook_name,
            args.namespace,
            args.cluster_uid,
            args.audit_client_sha256,
            args.request_id,
            args.request_sha256,
        )
    )


if __name__ == "__main__":
    main()
