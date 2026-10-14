import base64
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import urlopen

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

import main


class AuthTests(unittest.TestCase):
    def test_cached_token_and_private_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.json"
            main._save_credentials(path, {
                "ext_agent_host_id": "urn:uuid:test",
                "access_token": "cached",
                "scope": main.SCOPES,
                "expires_at": time.time() + 3600,
            })
            with patch.object(main, "_browser_sign_in") as login:
                self.assertEqual(main.auth(auth_dir=Path(directory)), "cached")
                login.assert_not_called()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(Path(directory).stat().st_mode & 0o777, 0o700)

    def test_refresh_saves_rotated_tokens(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.json"
            main._save_credentials(path, {
                "ext_agent_host_id": "urn:uuid:test",
                "client_id": "oaiapp_test",
                "access_token": "expired",
                "refresh_token": "old-refresh",
                "scope": main.SCOPES,
                "expires_at": 0,
            })
            response = httpx.Response(200, json={
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "scope": main.SCOPES,
                "expires_in": 3600,
            })
            with patch.object(main.httpx, "post", return_value=response) as post:
                self.assertEqual(main.auth(auth_dir=Path(directory)), "new-access")
            self.assertEqual(post.call_args.kwargs["data"]["refresh_token"], "old-refresh")
            self.assertEqual(json.loads(path.read_text())["refresh_token"], "new-refresh")

    def test_plan_permission_required(self):
        response = httpx.Response(200, json={
            "access_token": "access", "refresh_token": "refresh", "scope": "openid",
        })
        with patch.object(main.httpx, "post", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "plan usage was not granted"):
                main._exchange_tokens({})

    def test_identity_signature_audience_and_nonce(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        payload = {"sub": "user", "iss": main.ISSUER, "aud": "client", "iat": time.time(),
                   "exp": time.time() + 300, "nonce": "expected"}
        token = jwt.encode(payload, private_key, algorithm="RS256")
        with patch.object(main.jwt, "PyJWKClient") as keys:
            keys.return_value.get_signing_key_from_jwt.return_value.key = private_key.public_key()
            self.assertEqual(main._verify_identity(token, "client", "expected")["sub"], "user")
            with self.assertRaisesRegex(RuntimeError, "nonce"):
                main._verify_identity(token, "client", "wrong")
            with self.assertRaises(jwt.InvalidAudienceError):
                main._verify_identity(token, "different-client", "expected")

    def test_browser_callback_state_and_pkce(self):
        worker = []

        def open_browser(url):
            params = parse_qs(urlsplit(url).query)
            self.assertEqual(params["client_id"], ["dynamic_agent_client"])

            def return_callback():
                # Reject a forged callback, then accept the real state.
                import urllib.error
                try:
                    urlopen(params["redirect_uri"][0] + "?state=wrong&code=forged", timeout=5)
                except urllib.error.HTTPError as error:
                    self.assertEqual(error.code, 400)
                callback = urlencode({"state": params["state"][0], "code": "code",
                                      "client_id": "oaiapp_test"})
                with urlopen(params["redirect_uri"][0] + "?" + callback, timeout=5):
                    pass

            thread = threading.Thread(target=return_callback)
            thread.start()
            worker.append(thread)
            self.authorization = params
            return True

        def exchange(data):
            self.assertEqual(data["client_id"], "oaiapp_test")
            self.assertEqual(data["code"], "code")
            challenge = base64.urlsafe_b64encode(hashlib.sha256(data["code_verifier"].encode()).digest()).rstrip(b"=").decode()
            self.assertEqual(challenge, self.authorization["code_challenge"][0])
            return {"access_token": "access", "id_token": "id"}

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(main.webbrowser, "open", side_effect=open_browser), \
                 patch.object(main, "_exchange_tokens", side_effect=exchange), \
                 patch.object(main, "_verify_identity", return_value={"sub": "user"}) as verify:
                result = main._browser_sign_in({"ext_agent_host_id": "urn:uuid:test"},
                                               Path(directory) / "credentials.json", 5)
            self.assertEqual(result["subject"], "user")
            self.assertEqual(verify.call_args.args[2], self.authorization["nonce"][0])
        for thread in worker:
            thread.join(5)


if __name__ == "__main__":
    unittest.main()
