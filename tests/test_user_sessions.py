"""Session lifecycle and permission enforcement without live email or database writes."""
import copy
import os
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlsplit, parse_qs

from bson import ObjectId
from fastapi.testclient import TestClient

with patch.dict(os.environ, {"MONGODB_URL": "mongodb://127.0.0.1:27017"}):
    from main import app
    from api import auth, roles
    from api import session_security as security


class Collection:
    def __init__(self, documents=()):
        self.documents = list(documents)
        self.find_one = AsyncMock(side_effect=self._find)
        self.insert_one = AsyncMock(side_effect=self._insert)
        self.delete_one = AsyncMock(side_effect=self._delete)
        self.find_one_and_update = AsyncMock(side_effect=self._consume)
        self.find = MagicMock(return_value=SimpleNamespace(to_list=AsyncMock(side_effect=lambda **kwargs: copy.deepcopy(self.documents))))

    def matches(self, document, query):
        for key, expected in query.items():
            value = document.get(key)
            if isinstance(expected, dict):
                if "$gt" in expected and (value is None or value <= expected["$gt"]):
                    return False
            elif value != expected:
                return False
        return True

    async def _find(self, query):
        return next((copy.deepcopy(doc) for doc in self.documents if self.matches(doc, query)), None)

    async def _insert(self, document):
        saved = {"_id": ObjectId(), **copy.deepcopy(document)}
        self.documents.append(saved)
        return SimpleNamespace(inserted_id=saved["_id"])

    async def _delete(self, query):
        self.documents[:] = [doc for doc in self.documents if not self.matches(doc, query)]

    async def _consume(self, query, update):
        for doc in self.documents:
            if self.matches(doc, query):
                previous = copy.deepcopy(doc)
                doc.update(update["$set"])
                return previous
        return None


class UserSessionTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"FRONTEND_ORIGINS": "http://127.0.0.1:8081", "FRONTEND_BASE_URL": "http://127.0.0.1:8081", "SESSION_COOKIE_SECURE": "false"})
        env.start()
        self.addCleanup(env.stop)
        self.user_id, self.role_id, self.class_id = ObjectId(), ObjectId(), ObjectId()
        self.user = {"_id": self.user_id, "full_name": "Zain Israr", "email": "zain@example.com", "status": "ACTIVE", "role_ids": [str(self.role_id)], "reader_class_id": str(self.class_id)}
        self.role = {"_id": self.role_id, "role_code": "MANAGER", "role_name": "Manager", "is_active": True, "permissions": ["documents.read", "team.progress.read"], "description": "", "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()}
        self.reader = {"_id": self.class_id, "class_code": "EMPLOYEE", "class_name": "Employee", "is_active": True}
        self.users, self.roles, self.readers = Collection([self.user]), Collection([self.role]), Collection([self.reader])
        self.tokens, self.sessions = Collection(), Collection()
        for module, name, collection in [
            (auth, "users_collection", self.users), (auth, "login_tokens_collection", self.tokens),
            (auth, "sessions_collection", self.sessions), (security, "users_collection", self.users),
            (security, "roles_collection", self.roles), (security, "reader_classes_collection", self.readers),
            (security, "sessions_collection", self.sessions), (roles, "roles_collection", self.roles),
        ]:
            current = patch.object(module, name, collection)
            current.start()
            self.addCleanup(current.stop)
        mail = patch.object(auth, "send_login_email", return_value=True)
        self.mail = mail.start()
        self.addCleanup(mail.stop)
        self.client = TestClient(app)

    def token(self, value="test-secret"):
        self.tokens.documents.append({"token_hash": security.token_hash(value), "user_id": str(self.user_id), "expires_at": datetime.utcnow() + timedelta(minutes=15), "used": False})
        return value

    def login(self):
        response = self.client.post("/api/v1/auth/verify-login-token", json={"token": self.token()})
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def test_request_emails_secret_but_never_returns_or_stores_plaintext_token(self):
        response = self.client.post("/api/v1/auth/request-login-link", json={"email": "zain@example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"message"})
        link = self.mail.call_args.args[1]
        token = parse_qs(urlsplit(link).fragment)["token"][0]
        self.assertNotIn(token, response.text)
        self.assertNotIn("token", self.tokens.documents[0])
        self.assertEqual(self.tokens.documents[0]["token_hash"], security.token_hash(token))
        unknown = self.client.post("/api/v1/auth/request-login-link", json={"email": "unknown@example.com"})
        self.assertEqual(response.json(), unknown.json())
        self.mail.assert_called_once()

    def test_email_failure_revokes_the_link_and_returns_an_error(self):
        self.mail.return_value = False
        response = self.client.post("/api/v1/auth/request-login-link", json={"email": "zain@example.com"})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("token", response.text)
        self.assertEqual(self.tokens.documents, [])

    def test_verification_cookie_me_and_logout(self):
        response = self.login()
        cookie = response.headers["set-cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=lax", cookie)
        self.assertIn("Path=/api", cookie)
        raw = self.client.cookies.get(security.COOKIE_NAME)
        self.assertEqual(self.sessions.documents[0]["token_hash"], security.token_hash(raw))
        self.assertNotIn(raw, str(self.sessions.documents))
        me = self.client.get("/api/v1/auth/me")
        self.assertEqual(me.status_code, 200, me.text)
        self.assertEqual(me.json()["permissions"], ["documents.read", "team.progress.read"])
        self.assertEqual(me.headers["cache-control"], "no-store")
        self.assertEqual(self.client.post("/api/v1/auth/logout").status_code, 200)
        self.assertEqual(self.sessions.documents, [])
        self.assertEqual(self.client.get("/api/v1/auth/me").status_code, 401)

    def test_replayed_expired_and_invalid_tokens_are_rejected(self):
        self.login()
        self.assertEqual(self.client.post("/api/v1/auth/verify-login-token", json={"token": "test-secret"}).status_code, 401)
        token = self.token("expired")
        self.tokens.documents[-1]["expires_at"] = datetime.utcnow() - timedelta(seconds=1)
        for value in [token, "unknown"]:
            self.assertEqual(self.client.post("/api/v1/auth/verify-login-token", json={"token": value}).status_code, 401)
        self.assertEqual(len(self.sessions.documents), 1)

    def test_me_and_api_permissions_refresh_from_database_and_ignore_role_labels(self):
        self.login()
        self.assertEqual(self.client.get("/api/v1/roles").status_code, 403)
        self.role["permissions"] = ["roles.manage"]
        self.assertEqual(self.client.get("/api/v1/auth/me").json()["permissions"], ["roles.manage"])
        self.assertEqual(self.client.get("/api/v1/roles").status_code, 200)
        self.role.update({"role_code": "SYSTEM_ADMIN", "permissions": []})
        self.assertEqual(self.client.get("/api/v1/roles").status_code, 403)
        self.role["is_active"] = False
        self.assertEqual(self.client.get("/api/v1/auth/me").json()["roles"], [])

    def test_disabled_users_reader_classes_and_expired_sessions_lose_access(self):
        self.login()
        self.user["status"] = "INACTIVE"
        self.assertEqual(self.client.get("/api/v1/auth/me").status_code, 403)
        self.user["status"] = "ACTIVE"
        self.reader["is_active"] = False
        self.assertEqual(self.client.get("/api/v1/auth/me").status_code, 403)
        self.reader["is_active"] = True
        self.sessions.documents[0]["expires_at"] = datetime.utcnow() - timedelta(seconds=1)
        self.assertEqual(self.client.get("/api/v1/auth/me").status_code, 401)

    def test_direct_navigation_api_calls_and_spoofed_actor_ids_are_denied(self):
        self.login()
        for path in ["/api/v1/lumen/users", "/api/v1/roles", "/api/v1/lumen/reader-classes", "/api/v1/lumen/document-families", "/api/v1/lumen/access-grants", "/api/v1/lumen/audit/access-logs"]:
            self.assertEqual(self.client.get(path).status_code, 403, path)
        self.assertEqual(self.client.get("/api/v1/lumen/documents", params={"user_id": str(ObjectId())}).status_code, 403)
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/api/v1/lumen/documents", params={"user_id": str(self.user_id)}).status_code, 401)

    def test_cookie_mutations_reject_cross_origin_requests(self):
        self.login()
        response = self.client.post("/api/v1/auth/logout", headers={"Origin": "https://untrusted.example"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(self.sessions.documents), 1)
        self.assertEqual(self.client.post("/api/v1/auth/logout", headers={"Origin": "http://127.0.0.1:8081"}).status_code, 200)

    def test_https_sessions_set_secure_cookies(self):
        self.client = TestClient(app, base_url="https://testserver")
        response = self.login()
        self.assertIn("Secure", response.headers["set-cookie"])
        self.assertEqual(self.client.get("/api/v1/auth/me").status_code, 200)

    def test_user_creation_permission_can_read_options_but_cannot_manage_roles_or_edit_users(self):
        self.role["permissions"] = ["users.create"]
        self.login()
        self.assertEqual(self.client.get("/api/v1/roles").status_code, 200)
        self.assertEqual(self.client.post("/api/v1/roles", json={}).status_code, 403)
        self.assertEqual(self.client.patch("/api/v1/lumen/users/" + str(self.user_id), json={}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
