"""Serve admission decisions and durable closure progress for one installed epoch."""

import argparse
import re
import sqlite3
from pathlib import Path

from birbverify.deployment_activity import lookup_account_result
from birbverify.deployment_activity_contract import Invocation
from birbverify.deployment_http import HttpError, JSONHandler, MutualTLSServer, server_context
from birbverify.deployment_ownership import (
    CloseCommand,
    InstalledRequest,
    OwnershipJournal,
    OwnershipPolicy,
)

_REVIEW = {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview"}


class OwnershipHandler(JSONHandler):
    def do_POST(self):
        policy = self.server.journal.policy
        peers = {
            "/v1/admit": policy.admission_client_sha256,
            "/v1/close": policy.closure_client_sha256,
            "/v1/observe": policy.closure_client_sha256,
            "/v1/account-result": policy.closure_client_sha256,
        }
        raw, _, query = self.path.partition("?")
        path = "/v1/admit" if raw == "/v1/admit/" else raw
        if query and (
            path != "/v1/admit" or not re.fullmatch(r"timeout=[0-9]{1,5}(?:ms|s)", query)
        ):
            return self.reply(400)
        if path not in peers:
            return self.reply(404)
        if self.client_sha256() != peers[path]:
            return self.reply(403)
        try:
            value = self.body(2 * 1024 * 1024)
            if not isinstance(value, dict):
                raise ValueError("expected a JSON object")
            if path == "/v1/admit":
                if any(value.get(k) != v for k, v in _REVIEW.items()):
                    raise ValueError("expected a v1 AdmissionReview")
                decision = self.server.journal.admit(self.server.epoch, value["request"])
                result = _REVIEW | {"response": decision}
            elif path == "/v1/observe":
                result = self.server.journal.observe_owner(InstalledRequest.model_validate(value))
            elif path == "/v1/close":
                result = self.server.journal.close_owned(CloseCommand.model_validate(value))
            else:
                invocation = Invocation.model_validate(value)
                with self.server.journal._transaction() as db:
                    result = lookup_account_result(db, invocation)
        except HttpError as error:
            return self.reply(error.status)
        except (ValueError, KeyError, TypeError, RecursionError):
            return self.reply(400)
        except sqlite3.Error:
            return self.reply(503)
        self.reply(200, result)


class OwnershipServer(MutualTLSServer):
    def __init__(self, address, tls, journal, request_id, request_sha256):
        self.journal = journal
        request = InstalledRequest(request_id=request_id, request_sha256=request_sha256)
        self.epoch = journal.observe_owner(request)["epoch"]
        super().__init__(address, OwnershipHandler, tls)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    for name in ("request-id", "request-sha256", "tls-cert", "tls-key", "client-ca", "epoch"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    policy = OwnershipPolicy.model_validate_json(args.policy.read_bytes())
    tls = server_context(args.client_ca, args.tls_cert, args.tls_key)
    journal = OwnershipJournal(args.journal, policy, expected_epoch=args.epoch)
    with OwnershipServer(
        (args.host, args.port), tls, journal, args.request_id, args.request_sha256
    ) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
