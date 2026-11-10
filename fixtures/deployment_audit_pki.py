"""Create short-lived certificates for the disposable audit transport fixture."""

import argparse
import base64
import hashlib
import json
import os
import ssl
import subprocess
from pathlib import Path


def openssl(root, *args):
    subprocess.run(
        ["openssl", *args],
        cwd=root,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def create(root, server_name):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    openssl(
        root,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=fixture-audit-ca",
        "-keyout",
        "ca.key",
        "-out",
        "ca.crt",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    )
    for name, usage in [
        ("server", "serverAuth"),
        ("apiserver", "clientAuth"),
        ("unassigned", "clientAuth"),
    ]:
        openssl(
            root,
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=" + name,
            "-keyout",
            name + ".key",
            "-out",
            name + ".csr",
        )
        ext = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        ext += "extendedKeyUsage=" + usage + "\n"
        if name == "server":
            ext += "subjectAltName=DNS:" + server_name + "\n"
        (root / "extensions").write_text(ext)
        openssl(
            root,
            "x509",
            "-req",
            "-in",
            name + ".csr",
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            "extensions",
            "-out",
            name + ".crt",
        )
    der = ssl.PEM_cert_to_DER_cert((root / "apiserver.crt").read_text())
    pin = hashlib.sha256(der).hexdigest()
    (root / "pin").write_text(pin)
    return pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("server_name")
    args = parser.parse_args()
    os.umask(0o077)
    create(args.root, args.server_name)

    def pem(name):
        return base64.b64encode((args.root / name).read_bytes()).decode()

    kubeconfig = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": "audit",
                "cluster": {
                    "server": "https://" + args.server_name + ":9443/v1/audit",
                    "certificate-authority-data": pem("ca.crt"),
                },
            }
        ],
        "users": [
            {
                "name": "kube-apiserver",
                "user": {
                    "client-certificate-data": pem("apiserver.crt"),
                    "client-key-data": pem("apiserver.key"),
                },
            }
        ],
        "contexts": [{"name": "audit", "context": {"cluster": "audit", "user": "kube-apiserver"}}],
        "current-context": "audit",
    }
    (args.root / "webhook.kubeconfig").write_text(json.dumps(kubeconfig))


if __name__ == "__main__":
    main()
