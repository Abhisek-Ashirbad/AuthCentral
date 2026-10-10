import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from authcentral import AuthCentral, AuthConfig, AuthUser, InMemoryUserStore  # noqa: E402
from authcentral.setup import create_config  # noqa: E402


SECRET = "test-only-secret-key-that-is-long-enough"


class AuthenticationPluginTests(unittest.TestCase):
    def setUp(self):
        self.plugin = AuthCentral(
            AuthConfig(secret_key=SECRET),
            user_store=InMemoryUserStore(),
        )
        self.app = FastAPI()
        self.app.include_router(self.plugin.router)

        @self.app.get("/private")
        async def private_page(user: AuthUser = Depends(self.plugin.get_current_user)):
            return {"username": user.username}

        self.client = TestClient(self.app)

    def tearDown(self):
        self.client.close()

    def test_signup_signin_and_protected_route(self):
        signup = self.client.post(
            "/auth/signup",
            data={"username": "alice", "password": "correct horse battery"},
            follow_redirects=False,
        )
        self.assertEqual(signup.status_code, 303)

        signin = self.client.post(
            "/auth/signin",
            data={"username": "alice", "password": "correct horse battery", "next": "/private"},
            follow_redirects=False,
        )
        self.assertEqual(signin.status_code, 303)
        self.assertEqual(signin.headers["location"], "/private")
        self.assertIn("httponly", signin.headers["set-cookie"].lower())
        self.assertIn("samesite=lax", signin.headers["set-cookie"].lower())

        protected = self.client.get("/private")
        self.assertEqual(protected.status_code, 200)
        self.assertEqual(protected.json(), {"username": "alice"})

    def test_bad_credentials_and_duplicate_user_do_not_authenticate(self):
        form = {"username": "alice", "password": "correct horse battery"}
        self.client.post("/auth/signup", data=form)
        duplicate = self.client.post("/auth/signup", data=form, follow_redirects=False)
        invalid = self.client.post(
            "/auth/signin",
            data={"username": "alice", "password": "incorrect password"},
            follow_redirects=False,
        )

        self.assertIn("User+already+exists", duplicate.headers["location"])
        self.assertNotIn("authcentral_session", invalid.headers.get("set-cookie", ""))

    def test_protected_route_rejects_missing_invalid_expired_and_wrong_audience_tokens(self):
        self.assertEqual(self.client.get("/private").status_code, 401)

        self.client.cookies.set("authcentral_session", "not-a-jwt")
        self.assertEqual(self.client.get("/private").status_code, 401)

        for claims in (
            {
                "sub": "alice",
                "iat": datetime.now(timezone.utc) - timedelta(hours=2),
                "exp": datetime.now(timezone.utc) - timedelta(hours=1),
                "iss": "authcentral",
                "aud": "authcentral-app",
            },
            {
                "sub": "alice",
                "iat": datetime.now(timezone.utc),
                "exp": datetime.now(timezone.utc) + timedelta(hours=1),
                "iss": "authcentral",
                "aud": "other-app",
            },
        ):
            self.client.cookies.set("authcentral_session", jwt.encode(claims, SECRET, algorithm="HS256"))
            self.assertEqual(self.client.get("/private").status_code, 401)

    def test_signin_rejects_external_redirects(self):
        self.client.post("/auth/signup", data={"username": "alice", "password": "correct horse battery"})
        for target in ("//example.com", r"/\\example.com", "https://example.com"):
            response = self.client.post(
                "/auth/signin",
                data={"username": "alice", "password": "correct horse battery", "next": target},
                follow_redirects=False,
            )
            self.assertEqual(response.headers["location"], "/")

    def test_logout_clears_cookie(self):
        response = self.client.post("/auth/logout", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn("authcentral_session", response.headers["set-cookie"].lower())

    def test_setup_uses_defaults_for_blank_answers_and_writes_loadable_toml(self):
        answers = iter(["", "", "", "", "", ""])
        config = create_config(input_fn=lambda _prompt: next(answers), output_fn=lambda _message: None)

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "authcentral.toml"
            config_path.write_text(config.to_toml(), encoding="utf-8")
            loaded = AuthConfig.from_toml(config_path)
        self.assertEqual(config.auth_prefix, "/auth")
        self.assertEqual(config.cookie_name, "authcentral_session")
        self.assertFalse(config.cookie_secure)
        self.assertEqual(config.session_ttl_seconds, 3600)
        self.assertGreaterEqual(len(config.secret_key), 32)
        self.assertEqual(loaded, config)

    def test_config_rejects_short_secrets_and_invalid_prefixes(self):
        with self.assertRaises(ValueError):
            AuthConfig(secret_key="short")
        with self.assertRaises(ValueError):
            AuthConfig(secret_key=SECRET, auth_prefix="//outside")


if __name__ == "__main__":
    unittest.main()
