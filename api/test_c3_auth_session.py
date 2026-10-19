"""C3: authentication and session hardening (compatible by default)."""
import datetime
import os
import uuid
from unittest.mock import patch

from django.test import override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

from api.models import User

STRONG = "x" * 40


class AdminBootstrapTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user("c3", "c3@test.com", "Pass123!")

    def test_hardcoded_token_no_longer_grants_admin_or_lists_users(self):
        with patch.dict(os.environ, {"ADMIN_BOOTSTRAP_TOKEN": ""}):
            r = self.client.post("/api/auth/make-admin/", {"token": "andelef", "username": "c3"}, format="json")
            self.assertEqual(r.status_code, 404)
            self.assertEqual(self.client.get("/api/auth/users/?token=andelef").status_code, 404)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_staff)

    def test_configured_bootstrap_token_still_works(self):
        with patch.dict(os.environ, {"ADMIN_BOOTSTRAP_TOKEN": STRONG}):
            self.assertEqual(self.client.post("/api/auth/make-admin/", {"token": "andelef", "username": "c3"}, format="json").status_code, 404)
            r = self.client.post("/api/auth/make-admin/", {"token": STRONG, "username": "c3"}, format="json")
            self.assertEqual(r.status_code, 200, r.content)
        with patch.dict(os.environ, {"ADMIN_BOOTSTRAP_TOKEN": "short"}):  # < 32 chars = disabled
            self.assertEqual(self.client.post("/api/auth/make-admin/", {"token": "short", "username": "c3"}, format="json").status_code, 404)


class SessionTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user("c3s", "c3s@test.com", "Pass123!")
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token.key}")

    def test_logout_deletes_the_token_on_the_server(self):
        self.assertEqual(self.client.post("/api/auth/logout/").status_code, 204)
        self.assertFalse(Token.objects.filter(key=self.token.key).exists())
        self.assertEqual(self.client.get("/api/auth/me/").status_code, 401)

    def test_password_change_rotates_the_token_and_keeps_this_session(self):
        r = self.client.post("/api/auth/change-password/", {"old_password": "Pass123!", "new_password": "NewPass456!"}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        new_key = r.data["token"]
        self.assertNotEqual(new_key, self.token.key)
        self.assertEqual(self.client.get("/api/auth/me/").status_code, 401)  # old token is gone
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {new_key}")
        self.assertEqual(self.client.get("/api/auth/me/").status_code, 200)

    def test_token_expiry_is_off_by_default_and_works_when_enabled(self):
        Token.objects.filter(pk=self.token.pk).update(created=timezone.now() - datetime.timedelta(days=400))
        self.assertEqual(self.client.get("/api/auth/me/").status_code, 200)  # TOKEN_TTL_HOURS=0
        with override_settings(TOKEN_TTL_HOURS=24):
            r = self.client.get("/api/auth/me/")
        self.assertEqual(r.status_code, 401)
        self.assertIn("expired", str(r.content).lower())


class LoginThrottleTests(APITestCase):
    def test_login_is_rate_limited_per_ip(self):
        from api.throttles import AuthAnonRateThrottle
        with patch.object(AuthAnonRateThrottle, "get_rate", return_value="3/min"):
            ip = f"10.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}"  # fresh bucket, no cache.clear()
            codes = [self.client.post("/api/auth/login/", {"username": "nobody", "password": "wrong"}, format="json",
                                      REMOTE_ADDR=ip).status_code for _ in range(5)]
        self.assertIn(429, codes)
        self.assertNotEqual(codes[0], 429)
