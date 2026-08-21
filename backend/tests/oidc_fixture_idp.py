"""A real local OIDC identity provider for tests — genuine RSA-signed ID
tokens served over a real local HTTP server (discovery, token, and JWKS
endpoints), not a mocked transport. app/auth/oidc.py's discovery fetch,
code-for-token exchange, and JWKS-signature verification all run for
real against this fixture, exactly as they would against Okta/Azure AD/
Google Workspace/etc. in production.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

_KID = "test-signing-key-1"


class FixtureIdp:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        # The code -> claims this fixture will honor when /token is hit
        # with that code — set by the test before it drives the flow.
        self.valid_codes: dict[str, dict] = {}

        handler = self._make_handler()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def issue_code(self, claims: dict) -> str:
        code = f"code-{len(self.valid_codes)}"
        self.valid_codes[code] = claims
        return code

    def shutdown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)

    def _jwks(self) -> dict:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.public_key))
        jwk.update({"kid": _KID, "alg": "RS256", "use": "sig"})
        return {"keys": [jwk]}

    def _sign_id_token(self, claims: dict) -> str:
        private_pem = self.private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": _KID})

    def _make_handler(self):
        idp = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path == "/.well-known/openid-configuration":
                    body = json.dumps(
                        {
                            "issuer": idp.base_url,
                            "authorization_endpoint": f"{idp.base_url}/authorize",
                            "token_endpoint": f"{idp.base_url}/token",
                            "jwks_uri": f"{idp.base_url}/jwks",
                        }
                    ).encode()
                elif self.path == "/jwks":
                    body = json.dumps(idp._jwks()).encode()
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):  # noqa: N802
                if self.path != "/token":
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", 0))
                body = parse_qs(self.rfile.read(length).decode())
                code = body.get("code", [""])[0]
                claims = idp.valid_codes.get(code)
                if claims is None:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "invalid_grant"}).encode())
                    return
                id_token = idp._sign_id_token(claims)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"id_token": id_token, "token_type": "Bearer"}).encode())

            def log_message(self, format, *args):  # noqa: A002
                pass

        return Handler
