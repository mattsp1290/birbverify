import hashlib
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

accounts = {}
tokens = {}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        name, password = data["name"], data["password"]
        if self.path == "/accounts":
            accounts[name] = password
            self.reply(201, {"account": name})
        elif self.path == "/login" and accounts.get(name) == password:
            token = hashlib.sha256((name + password).encode()).hexdigest()
            tokens[token] = name
            self.reply(200, {"token": token})
        else:
            self.reply(403, {"error": "denied"})

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, {"ready": True})
        elif self.path == "/me" and self.headers.get("Authorization") in tokens:
            self.reply(200, {"account": tokens[self.headers["Authorization"]]})
        else:
            self.reply(403, {"error": "denied"})

    def reply(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
