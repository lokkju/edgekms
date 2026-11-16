#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""A stand-in for github.com and api.github.com, for scripts/e2e-hosted.sh.

It serves the two halves of a GitHub login that edgekms touches:

- the device flow the CLI runs (POST /login/device/code, POST /login/oauth/access_token),
  pointed here with EDGEKMS_GITHUB_OAUTH_BASE; it approves every code at once and issues a
  fresh token for the user queued with POST /_stub/next-user (or the default user);
- the token check and revoke the Worker runs (POST and DELETE /applications/{client_id}/token,
  HTTP Basic as client_id:secret), pointed here with the Worker's GITHUB_API_BASE.

A token is valid only for the client id it was issued under, until revoked. GET /_stub/calls
lists every check and revoke as {method, client_id, token, status}; POST /_stub/mint
{"id", "login", "client_id"} issues a token without the device flow, for curl-driven steps.

Usage: STUB_CLIENT_SECRET=<the Worker's GITHUB_CLIENT_SECRET> github-stub.py PORT
"""

import base64
import json
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

DEFAULT_USER = {"id": 1001, "login": "alice"}

lock = threading.Lock()
next_users: list[dict] = []
device_codes: dict[str, tuple[str, dict]] = {}  # device code -> (client id, user)
tokens: dict[str, dict] = {}  # token -> {client_id, user, revoked}
calls: list[dict] = []


def issue(client_id: str, user: dict) -> str:
    token = "gho_" + secrets.token_hex(18)
    tokens[token] = {"client_id": client_id, "user": user, "revoked": False}
    return token


class Handler(BaseHTTPRequestHandler):
    server_version = "github-stub"

    def log_message(self, fmt, *args):  # quiet; the calls log is the record
        pass

    def body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def reply(self, status: int, obj=None):
        data = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(status)
        if obj is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def form(self) -> dict:
        raw = self.body().decode()
        if self.headers.get("Content-Type", "").startswith("application/json"):
            return json.loads(raw or "{}")
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def do_GET(self):
        if self.path == "/_stub/calls":
            with lock:
                return self.reply(200, calls)
        self.reply(404, {"message": "Not Found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/_stub/next-user":
            user = json.loads(self.body() or b"{}")
            with lock:
                next_users.append({"id": int(user["id"]), "login": user["login"]})
            return self.reply(204)
        if path == "/_stub/mint":
            req = json.loads(self.body() or b"{}")
            with lock:
                token = issue(req["client_id"], {"id": int(req["id"]), "login": req["login"]})
            return self.reply(200, {"token": token})
        if path == "/login/device/code":
            f = self.form()
            with lock:
                user = next_users.pop(0) if next_users else DEFAULT_USER
                code = secrets.token_hex(10)
                device_codes[code] = (f.get("client_id", ""), user)
            return self.reply(
                200,
                {
                    "device_code": code,
                    "user_code": "STUB-" + code[:4].upper(),
                    "verification_uri": "http://github.stub/login/device",
                    "expires_in": 900,
                    "interval": 1,
                },
            )
        if path == "/login/oauth/access_token":
            f = self.form()
            with lock:
                entry = device_codes.pop(f.get("device_code", ""), None)
                if entry is None or entry[0] != f.get("client_id"):
                    return self.reply(200, {"error": "incorrect_device_code"})
                token = issue(entry[0], entry[1])
            return self.reply(200, {"access_token": token, "token_type": "bearer", "scope": ""})
        if path.startswith("/applications/") and path.endswith("/token"):
            return self.app_token("POST", path)
        self.reply(404, {"message": "Not Found"})

    def do_DELETE(self):
        path = self.path.split("?")[0]
        if path.startswith("/applications/") and path.endswith("/token"):
            return self.app_token("DELETE", path)
        self.reply(404, {"message": "Not Found"})

    def app_token(self, method: str, path: str):
        client_id = path[len("/applications/") : -len("/token")]
        auth = self.headers.get("Authorization", "")
        try:
            user, _, secret = base64.b64decode(auth.removeprefix("Basic ")).decode().partition(":")
        except ValueError:
            user, secret = "", ""
        token = json.loads(self.body() or b"{}").get("access_token", "")
        with lock:
            entry = tokens.get(token)
            if user != client_id or secret != self.server.client_secret:
                status = 401
            elif entry is None or entry["revoked"] or entry["client_id"] != client_id:
                status = 404
            else:
                status = 204 if method == "DELETE" else 200
                if method == "DELETE":
                    entry["revoked"] = True
            calls.append({"method": method, "client_id": client_id, "token": token, "status": status})
        if status == 200:
            return self.reply(
                200,
                {
                    "id": 1,
                    "token": token,
                    "app": {"client_id": client_id, "name": "edgekms"},
                    "user": {"login": entry["user"]["login"], "id": entry["user"]["id"]},
                },
            )
        self.reply(status, None if status == 204 else {"message": "Not Found"})


def main():
    port, secret = int(sys.argv[1]), os.environ["STUB_CLIENT_SECRET"]
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.client_secret = secret
    print(f"github-stub listening on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
