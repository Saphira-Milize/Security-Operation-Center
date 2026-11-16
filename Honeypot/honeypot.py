#!/usr/bin/env python3
"""Pot de miel à faible interaction pour le SOC.

Expose de faux services qu'aucun utilisateur légitime n'a de raison de
contacter : tout contact est donc un signal d'attaque fiable.

  - HTTP   : faux panneau d'administration avec page de connexion
  - SSH    : fausse bannière OpenSSH (enregistre la bannière du client)
  - Telnet : fausse invite de connexion (enregistre l'identifiant essayé)

Rien n'est exécuté et aucun accès n'est jamais accordé. Chaque événement est
écrit sur la sortie standard en JSON (une ligne), collecté par Vector puis
indexé dans soc-honeypot-*. Les mots de passe essayés ne sont pas conservés :
seule leur longueur l'est.

Bibliothèque standard uniquement.
"""
import json
import os
import socketserver
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

HTTP_PORT = int(os.environ.get("HONEYPOT_HTTP_PORT", "8080"))
SSH_PORT = int(os.environ.get("HONEYPOT_SSH_PORT", "2222"))
TELNET_PORT = int(os.environ.get("HONEYPOT_TELNET_PORT", "2323"))
TIMEOUT = 10          # secondes avant de couper une connexion muette
MAX_BODY = 4096       # octets lus au maximum par requête
MAX_FIELD = 200       # longueur maximale d'un champ journalisé

_lock = threading.Lock()


def clean(value, limit=MAX_FIELD):
    """Rend une valeur fournie par l'attaquant sûre à journaliser."""
    if value is None:
        return None
    text = "".join(c if c.isprintable() else "?" for c in str(value))
    return text[:limit]


def log(service, event, src_ip, port, summary, **fields):
    record = {
        "honeypot": True,
        "service": service,
        "event": event,
        "src_ip": src_ip,
        "port": port,
        "summary": summary,
        "time": datetime.now(timezone.utc).isoformat(),
    }
    record.update({k: clean(v) for k, v in fields.items() if v is not None})
    with _lock:
        sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
        sys.stdout.flush()


LOGIN_PAGE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>Administration - Connexion</title>
<style>body{font-family:sans-serif;background:#f3f4f6;display:flex;justify-content:center;margin-top:12vh}
form{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 8px #0002;width:280px}
input{width:100%;padding:.5rem;margin:.4rem 0 1rem;box-sizing:border-box}
button{width:100%;padding:.6rem;background:#1d4ed8;color:#fff;border:0;border-radius:4px}
.err{color:#b91c1c;font-size:.9rem}</style></head>
<body><form method="post" action="/login"><h2>Administration</h2>%s
<label>Identifiant<input name="username" autocomplete="off"></label>
<label>Mot de passe<input name="password" type="password"></label>
<button>Se connecter</button></form></body></html>"""


class HttpHandler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""
    timeout = TIMEOUT

    def log_message(self, *_):
        pass  # journalisation gérée par log()

    def _page(self, status, error=""):
        body = (LOGIN_PAGE % error).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _contact(self):
        ip = self.client_address[0]
        path = clean(self.path)
        log("http", "http_request", ip, HTTP_PORT,
            f"{self.command} {path} depuis {ip}",
            method=self.command, path=path,
            user_agent=self.headers.get("User-Agent"))

    def do_GET(self):
        self._contact()
        self._page(200)

    do_HEAD = do_GET

    def do_POST(self):
        ip = self.client_address[0]
        try:
            length = min(int(self.headers.get("Content-Length", 0)), MAX_BODY)
        except ValueError:
            length = 0
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace")) if length > 0 else {}
        username = (form.get("username") or [""])[0]
        password = (form.get("password") or [""])[0]
        if username or password:
            user = clean(username) or "(vide)"
            log("http", "login_attempt", ip, HTTP_PORT,
                f"Tentative de connexion « {user} » depuis {ip}",
                method="POST", path=clean(self.path), username=user,
                password_length=len(password),
                user_agent=self.headers.get("User-Agent"))
        else:
            self._contact()
        self._page(401, '<p class="err">Identifiant ou mot de passe incorrect.</p>')

    do_PUT = do_DELETE = do_OPTIONS = do_PATCH = do_GET


class SshHandler(socketserver.BaseRequestHandler):
    """Envoie une bannière OpenSSH, note celle du client, puis raccroche."""

    def handle(self):
        ip = self.client_address[0]
        self.request.settimeout(TIMEOUT)
        client = None
        try:
            self.request.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
            data = self.request.recv(256)
            client = data.split(b"\n")[0].decode("utf-8", "replace").strip() or None
        except OSError:
            pass
        log("ssh", "connection", ip, SSH_PORT,
            f"Connexion SSH depuis {ip}", client_banner=client)


class TelnetHandler(socketserver.BaseRequestHandler):
    """Fausse invite de connexion : enregistre l'identifiant, refuse toujours."""

    def _line(self):
        buf = b""
        while len(buf) < 128:
            chunk = self.request.recv(64)
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf or b"\r" in buf:
                break
        # Retire les négociations Telnet (octets >= 0xF0) et les fins de ligne
        return bytes(b for b in buf if 32 <= b < 127).decode().strip()

    def handle(self):
        ip = self.client_address[0]
        self.request.settimeout(TIMEOUT)
        username = None
        password_length = None
        try:
            self.request.sendall(b"\r\nUbuntu 22.04.4 LTS\r\nsrv-admin login: ")
            username = self._line()
            if username:
                self.request.sendall(b"Password: ")
                password_length = len(self._line())
                self.request.sendall(b"\r\nLogin incorrect\r\n")
        except OSError:
            pass
        if username:
            log("telnet", "login_attempt", ip, TELNET_PORT,
                f"Tentative de connexion Telnet « {clean(username)} » depuis {ip}",
                username=username, password_length=password_length)
        else:
            log("telnet", "connection", ip, TELNET_PORT,
                f"Connexion Telnet depuis {ip}")


class TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    servers = [
        ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), HttpHandler),
        TcpServer(("0.0.0.0", SSH_PORT), SshHandler),
        TcpServer(("0.0.0.0", TELNET_PORT), TelnetHandler),
    ]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(json.dumps({"level": "info", "msg": "pot de miel démarré",
                      "http": HTTP_PORT, "ssh": SSH_PORT, "telnet": TELNET_PORT}),
          flush=True)
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
