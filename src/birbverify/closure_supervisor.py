import json
import sys
from pathlib import Path

from birbverify.contract import digest
from birbverify.lifecycle import Engine, GatedDocker, UnknownDelivery, container_path, save_evidence
from birbverify.target import rpc


class Supervisor:
    def __init__(self, root: Path, binding=None):
        self.root = root
        self.binding = (
            binding or json.loads((root / "installation.json").read_text())["closure_binding"]
        )
        self.key = (root / "supervisor.key").read_text()

    def call(self, method, **data):
        return rpc(self.root, method, binding=self.binding, **data)

    def begin(self, command):
        return self.call("begin_closure", command=command, recovery_key=self.key)

    def read(self, closure_id):
        return self.call("read_closure", closure_id=closure_id, recovery_key=self.key)

    def reconcile(self, closure_id):
        view = self.read(closure_id)
        progress = view["progress"]
        if progress["receipt"]:
            return view
        if progress["acquisition"]["kind"] == "acquired" and not progress["stop"]:
            reservation = view["reservation"]
            if reservation is None:
                return view
            commands = GatedDocker(
                self.root,
                self.call,
                reservation["request_id"],
                reservation["execution_epoch"],
                reservation["attempt_id"],
                reservation["registration"],
                closure_id=closure_id,
                recovery_key=self.key,
                engine=Engine(),
            )
            worker = reservation["registration"]["group"]["container_id"]
            candidate = reservation["candidate_container"]
            prefix = "closure-" + closure_id
            try:
                commands.settled_command(
                    prefix + ".worker-remove",
                    "remove",
                    worker,
                    "DELETE",
                    container_path(worker) + "?force=true",
                )
                commands.settled_command(
                    prefix + ".worker-absent",
                    "inspect",
                    worker,
                    "GET",
                    container_path(worker) + "/json",
                )
                records = self.call(
                    "lifecycle_records", request_id=reservation["request_id"], recovery_key=self.key
                )
                if any(
                    record["intent"]["verb"] in {"create", "start", "remove"}
                    and (record["settlement"] == "unknown" or record["completion"] is None)
                    for record in records
                ):
                    return self.read(closure_id)
                commands.settled_command(
                    prefix + ".candidate-remove",
                    "remove",
                    candidate,
                    "DELETE",
                    container_path(candidate) + "?force=true",
                )
                commands.settled_command(
                    prefix + ".candidate-absent",
                    "inspect",
                    candidate,
                    "GET",
                    container_path(candidate) + "/json",
                )
            except UnknownDelivery:
                return self.read(closure_id)
            records = self.call(
                "lifecycle_records", request_id=reservation["request_id"], recovery_key=self.key
            )
            reference = save_evidence(
                self.root,
                "stop",
                {
                    "closure_id": closure_id,
                    "reservation_sha256": digest(reservation),
                    "command_evidence": [
                        record["completion"] for record in records if record["completion"]
                    ],
                },
            )
            view = self.read(closure_id)
            view = self.call(
                "confirm_closure_stop",
                closure_id=closure_id,
                evidence_ref=reference,
                expected_revision=view["record_revision"],
                recovery_key=self.key,
            )
        view = self.read(closure_id)
        if view["progress"]["stop"] and not view["progress"]["cleanup"]:
            self.call(
                "cleanup_closure",
                closure_id=closure_id,
                cleanup_payload_sha256=view["cleanup_payload_sha256"],
                expected_revision=view["record_revision"],
                recovery_key=self.key,
            )
        view = self.read(closure_id)
        if view["progress"]["cleanup"] and not view["progress"]["receipt"]:
            self.call(
                "release_closure",
                closure_id=closure_id,
                expected_revision=view["record_revision"],
                recovery_key=self.key,
            )
        return self.read(closure_id)


if __name__ == "__main__":
    root, closure_id = sys.argv[1:]
    print(json.dumps(Supervisor(Path(root)).reconcile(closure_id)))
