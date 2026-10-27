"""User management contracts without connecting to MongoDB."""
import os
import unittest
from datetime import datetime
from unittest.mock import AsyncMock, patch

from bson import ObjectId
from fastapi.testclient import TestClient

with patch.dict(os.environ, {"MONGODB_URL": "mongodb://127.0.0.1:27017"}):
    from main import app
    from api import users


class UserManagementTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {
            "DEFAULT_ADMIN_EMAIL": "admin@example.com",
            "DEFAULT_ADMIN_PASSWORD": "test-password",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.client = TestClient(app)
        self.auth = ("admin@example.com", "test-password")
        self.user_id = ObjectId()
        self.role_id = ObjectId()
        self.class_id = ObjectId()
        self.record = {
            "_id": self.user_id, "full_name": "Test User", "email": "user@example.com",
            "role_ids": [self.role_id], "reader_class_id": self.class_id,
            "status": "ACTIVE", "created_by": ObjectId(),
            "created_at": datetime(2026, 10, 25), "updated_at": datetime(2026, 10, 25),
        }

    def test_management_endpoints_require_admin(self):
        for path in ["/api/v1/lumen/users", "/api/v1/roles", "/api/v1/lumen/reader-classes"]:
            for auth in [None, ("admin@example.com", "incorrect")]:
                with self.subTest(path=path, auth=auth):
                    response = self.client.get(path, auth=auth)
                    self.assertEqual(response.status_code, 401)
        for method, path, body in [
            ("POST", "/api/v1/lumen/users", {}),
            ("GET", f"/api/v1/lumen/users/{self.user_id}", None),
            ("PATCH", f"/api/v1/lumen/users/{self.user_id}", {}),
            ("PATCH", f"/api/v1/lumen/users/{self.user_id}/roles", {}),
            ("PATCH", f"/api/v1/lumen/users/{self.user_id}/reader-class", {}),
            ("PATCH", f"/api/v1/lumen/users/{self.user_id}/status", {}),
        ]:
            self.assertEqual(self.client.request(method, path, json=body).status_code, 401)

    def test_login_and_missing_configuration(self):
        response = self.client.post("/api/v1/auth/login", json={
            "email": "ADMIN@example.com", "password": "test-password",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["email"], "admin@example.com")
        with patch.dict(os.environ, {"DEFAULT_ADMIN_PASSWORD": ""}):
            self.assertEqual(self.client.get("/api/v1/lumen/users", auth=self.auth).status_code, 503)

    @patch.object(users, "reader_classes_collection")
    @patch.object(users, "roles_collection")
    @patch.object(users, "users_collection")
    def test_create_user_omits_unset_gaxis_user_id(self, collection, roles, classes):
        collection.find_one = AsyncMock(return_value=None)
        collection.insert_one = AsyncMock(return_value=type("InsertResult", (), {"inserted_id": self.user_id})())
        roles.find_one = AsyncMock(return_value={"is_active": True})
        classes.find_one = AsyncMock(return_value={"is_active": True})

        response = self.client.post("/api/v1/lumen/users", auth=self.auth, json={
            "full_name": "Test User",
            "email": "user@example.com",
            "role_ids": [str(self.role_id)],
            "reader_class_id": str(self.class_id),
        })

        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("gaxis_user_id", collection.insert_one.await_args.args[0])
        self.assertIsNone(response.json()["gaxis_user_id"])

    @patch.object(users, "users_collection")
    def test_list_serializes_database_ids(self, collection):
        collection.find.return_value.to_list = AsyncMock(return_value=[self.record])
        response = self.client.get("/api/v1/lumen/users", auth=self.auth)
        self.assertEqual(response.status_code, 200, response.text)
        user = response.json()[0]
        self.assertEqual(user["_id"], str(self.user_id))
        self.assertEqual(user["role_ids"], [str(self.role_id)])
        self.assertEqual(user["reader_class_id"], str(self.class_id))
        self.assertIsInstance(user["created_by"], str)

    @patch.object(users, "users_collection")
    def test_view_edit_and_status(self, collection):
        collection.find_one = AsyncMock(side_effect=lambda *args, **kwargs: dict(self.record))

        async def apply_update(query, update):
            self.record.update(update["$set"])
        collection.update_one = AsyncMock(side_effect=apply_update)
        path = f"/api/v1/lumen/users/{self.user_id}"
        self.assertEqual(self.client.get(path, auth=self.auth).status_code, 200)
        response = self.client.patch(path, auth=self.auth, json={"full_name": "Updated User"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["full_name"], "Updated User")
        for status in ["INACTIVE", "ACTIVE"]:
            response = self.client.patch(path + "/status", auth=self.auth, json={"status": status})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["status"], status)

    @patch.object(users, "reader_classes_collection")
    @patch.object(users, "roles_collection")
    @patch.object(users, "users_collection")
    def test_assignments_validate_real_active_database_values(self, collection, roles, classes):
        collection.find_one = AsyncMock(side_effect=lambda *args, **kwargs: dict(self.record))
        collection.update_one = AsyncMock()
        roles.find_one = AsyncMock(return_value={"is_active": False, "role_name": "Old role"})
        classes.find_one = AsyncMock(return_value=None)
        path = f"/api/v1/lumen/users/{self.user_id}"
        for suffix, body in [
            ("", {"role_ids": [str(self.role_id)]}),
            ("/roles", {"role_ids": [str(self.role_id)]}),
            ("", {"reader_class_id": str(self.class_id)}),
            ("/reader-class", {"reader_class_id": str(self.class_id)}),
        ]:
            response = self.client.patch(path + suffix, auth=self.auth, json=body)
            self.assertIn(response.status_code, [400, 404], response.text)
        collection.update_one.assert_not_called()


class UserIndexInitializationTests(unittest.IsolatedAsyncioTestCase):
    @patch.object(users, "users_collection")
    async def test_migrates_existing_non_sparse_gaxis_user_id_index(self, collection):
        collection.index_information = AsyncMock(return_value={
            "_id_": {"key": [("_id", 1)]},
            "gaxis_user_id_1": {
                "key": [("gaxis_user_id", 1)],
                "unique": True,
            },
        })
        collection.drop_index = AsyncMock()
        collection.update_many = AsyncMock()
        collection.create_index = AsyncMock()

        await users.initialize_user_indexes()

        collection.drop_index.assert_awaited_once_with("gaxis_user_id_1")
        collection.update_many.assert_awaited_once_with(
            {"gaxis_user_id": None},
            {"$unset": {"gaxis_user_id": ""}},
        )
        collection.create_index.assert_awaited_once_with(
            "gaxis_user_id", unique=True, sparse=True,
        )


if __name__ == "__main__":
    unittest.main()
