"""Disposable settlement experiment. This is not a production admission policy."""

import json
import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from birbverify.deployment_journal import Journal

ROOT = Path(os.environ["SETTLEMENT_ROOT"])
NAMESPACE = "settlement-proof"
WEBHOOK = "settlement.birbverify.test"
IMAGE = os.environ["SETTLEMENT_PAUSE_IMAGE"]


def journal():
    return Journal(ROOT / "journal.sqlite", "a" * 64, WEBHOOK, NAMESPACE, expected_epoch=epoch)


epoch = os.environ["SETTLEMENT_EPOCH"]
ledger = journal()


def write(name, value):
    temporary = ROOT / (name + ".tmp")
    temporary.write_text(json.dumps(value))
    temporary.replace(ROOT / name)


def authorized(request):
    obj = request.get("object") or {}
    metadata = obj.get("metadata", {})
    spec = obj.get("spec", {})
    owner_path = ROOT / "allowed-owner.json"
    if not owner_path.exists():
        return False
    owner = json.loads(owner_path.read_text())
    owners = metadata.get("ownerReferences", [])
    containers = spec.get("containers", [])
    return (
        request.get("resource", {}).get("resource") == "pods"
        and request.get("operation") == "CREATE"
        and request.get("namespace") == NAMESPACE
        and request.get("userInfo", {}).get("username")
        == "system:serviceaccount:kube-system:replicaset-controller"
        and metadata.get("labels", {}).get("app") == "settlement-proof"
        and len(owners) == 1
        and owners[0].get("kind") == "ReplicaSet"
        and owners[0].get("controller") is True
        and owners[0].get("uid") == owner["uid"]
        and owners[0].get("name") == owner["name"]
        and len(containers) == 1
        and containers[0].get("name") == "pause"
        and containers[0].get("image") == IMAGE
        and not spec.get("hostNetwork")
        and not spec.get("hostPID")
        and not spec.get("hostIPC")
        and not spec.get("volumes")
        and not containers[0].get("securityContext", {}).get("privileged")
    )


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        review = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        request = review["request"]
        if authorized(request):
            response = ledger.admit(epoch, request)
        else:
            response = {
                "uid": request["uid"],
                "allowed": False,
                "status": {"message": "outside disposable proof policy"},
            }
        if response["allowed"] and request["resource"]["resource"] == "pods":
            write("held.json", {"uid": request["uid"], "request": request})
            deadline = time.monotonic() + 25
            while not (ROOT / "unblock").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not (ROOT / "unblock").exists():
                response = {"uid": request["uid"], "allowed": False}
        body = json.dumps(
            {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "response": response}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def control():
    global ledger
    while True:
        for path in ROOT.glob("command-*.json"):
            result = "result-" + path.name.removeprefix("command-")
            if (ROOT / result).exists():
                continue
            try:
                command = json.loads(path.read_text())
                action = command["action"]
                if action == "restart":
                    ledger = journal()
                    value = ledger.snapshot(epoch)
                elif action == "seal":
                    value = ledger.seal(epoch)
                elif action == "snapshot":
                    value = ledger.snapshot(epoch)
                else:
                    raise ValueError("unknown fixture command")
                write(result, {"value": value})
            except Exception as error:
                write(result, {"error": str(error)})
        time.sleep(0.01)


threading.Thread(target=control, daemon=True).start()
server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(ROOT / "tls.crt", ROOT / "tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
write("ready.json", {"epoch": epoch})
server.serve_forever()
