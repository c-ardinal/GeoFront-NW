"""Mock notification receivers for the testbed: nothing ever leaves the compose network.

  HTTP :8080  any POST path is recorded (Slack / Discord / LINE / generic webhook all point here).
              A path ending in /fail answers 500, /reject answers 403 (to see failures in tools notify-test).
              GET /captures -> everything recorded (JSON), DELETE /captures -> clear, GET /health.
  SMTP :2525  plain + STARTTLS (self-signed certificate made at start), AUTH PLAIN; a recipient containing
              "reject" is refused with 550; a message with a bare LF (not CRLF) is refused with 554.
  SMTP :4650  implicit TLS (SMTPS), same behaviour.

Run: python notifymock.py
"""
import base64
import datetime
import email
import email.policy
import json
import os
import socketserver
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CAPTURES = []
LOCK = threading.Lock()
MAX_CAPTURES = 2000


def keep(item):
    with LOCK:
        CAPTURES.append({"t": time.time(), **item})
        del CAPTURES[:-MAX_CAPTURES]


def tls_context():
    """Self-signed certificate for the mock SMTP server (cryptography is in the testbed image)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "notifymock")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("notifymock")]), critical=False).sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)
    return ctx


CTX = None


class Http(BaseHTTPRequestHandler):
    def reply(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"ok": True})
        if self.path == "/captures":
            with LOCK:
                return self.reply(200, list(CAPTURES))
        self.reply(404, {"error": "not found"})

    def do_DELETE(self):
        with LOCK:
            CAPTURES.clear()
        self.reply(200, {"cleared": True})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            body = json.loads(raw)
        except ValueError:
            body = raw.decode("utf-8", "replace")
        keep({"kind": "http", "path": self.path, "auth": self.headers.get("Authorization"), "ctype": self.headers.get("Content-Type"), "body": body})
        if self.path.endswith("/fail"):
            return self.reply(500, {"error": "mock failure"})
        if self.path.endswith("/reject"):
            return self.reply(403, {"message": "mock: invalid token"})
        self.send_response(204 if "/discord/" in self.path else 200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class Smtp(socketserver.StreamRequestHandler):
    def handle(self):
        conn, tls = self.request, self.server.implicit_tls
        if tls:
            conn = CTX.wrap_socket(conn, server_side=True)
        state = {"tls": tls, "user": None, "from": None, "rcpt": []}
        rf = conn.makefile("rb")
        send = lambda s: conn.sendall((s + "\r\n").encode())
        send("220 notifymock ESMTP")
        while True:
            line = rf.readline(4096).decode("utf-8", "replace").rstrip("\r\n")
            if not line:
                return
            cmd = line.split(" ", 1)[0].upper()
            arg = line[len(cmd):].strip()
            if cmd in ("EHLO", "HELO"):
                send("250-notifymock" if cmd == "EHLO" else "250 notifymock")
                if cmd == "EHLO":
                    send("250-AUTH PLAIN")
                    send("250-STARTTLS" if not state["tls"] else "250-8BITMIME")
                    send("250 SMTPUTF8")
            elif cmd == "STARTTLS" and not state["tls"]:
                send("220 go ahead")
                conn = CTX.wrap_socket(conn, server_side=True)
                rf, state["tls"] = conn.makefile("rb"), True
            elif cmd == "AUTH" and arg.upper().startswith("PLAIN "):
                parts = base64.b64decode(arg[6:]).split(b"\0")
                state["user"] = parts[1].decode() if len(parts) == 3 else None
                send("235 ok" if parts[-1] != b"wrong" else "535 bad credentials")
            elif cmd == "MAIL":
                state["from"], state["rcpt"] = arg.partition(":")[2].strip(" <>"), []
                send("250 ok")
            elif cmd == "RCPT":
                to = arg.partition(":")[2].strip(" <>")
                if "reject" in to:
                    send("550 mock: no such user")
                else:
                    state["rcpt"].append(to)
                    send("250 ok")
            elif cmd == "DATA":
                send("354 end with .")
                data, bare_lf = [], False
                while (l := rf.readline(1 << 20)) not in (b".\r\n", b".\n", b""):
                    bare_lf |= not l.endswith(b"\r\n")  # strict like many real servers (RFC 5321: CRLF only)
                    data.append(l[1:] if l.startswith(b"..") else l)
                if bare_lf:
                    keep({"kind": "smtp-rejected", "port": self.server.server_address[1], "reason": "bare LF"})
                    send("554 5.6.0 bare LF in message (CRLF required)")
                    continue
                msg = email.message_from_bytes(b"".join(data), policy=email.policy.default)
                part = msg.get_body(("plain",))
                keep({"kind": "smtp", "port": self.server.server_address[1], "tls": state["tls"], "auth_user": state["user"],
                      "mail_from": state["from"], "rcpt": state["rcpt"], "subject": str(msg["subject"]), "to": str(msg["to"]),
                      "body": part.get_content() if part else ""})
                send("250 2.0.0 queued as mock")
            elif cmd in ("RSET", "NOOP"):
                send("250 ok")
            elif cmd == "QUIT":
                send("221 bye")
                return
            else:
                send("502 not implemented")


class SmtpServer(socketserver.ThreadingTCPServer):
    daemon_threads = allow_reuse_address = True

    def __init__(self, port, implicit_tls):
        self.implicit_tls = implicit_tls
        super().__init__(("0.0.0.0", port), Smtp)


if __name__ == "__main__":
    CTX = tls_context()
    for port, tls in ((2525, False), (4650, True)):
        threading.Thread(target=SmtpServer(port, tls).serve_forever, daemon=True).start()
    ThreadingHTTPServer.daemon_threads = True
    print("notifymock: HTTP :8080, SMTP :2525 (STARTTLS) / :4650 (TLS)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Http).serve_forever()
