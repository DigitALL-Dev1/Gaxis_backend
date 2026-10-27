"""Exercise role management HTTP contracts using an in-memory collection."""
import os
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from bson import ObjectId
from fastapi.testclient import TestClient

with patch.dict(os.environ, {"MONGODB_URL": "mongodb://127.0.0.1:27017"}):
    from main import app
    from api import roles


class RolesTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {
            "DEFAULT_ADMIN_EMAIL": "admin@example.com", "DEFAULT_ADMIN_PASSWORD": "test-password",
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.client = TestClient(app)
        self.auth = ("admin@example.com", "test-password")
        self.role_id = ObjectId()
        self.records = [{
            "_id": self.role_id, "role_name": "Manager", "role_code": "MANAGER",
            "description": "Team oversight", "permissions": ["team.read"], "is_active": True,
            "created_at": datetime(2026, 10, 25), "updated_at": datetime(2026, 10, 25),
        }]
        collection_patch = patch.object(roles, "roles_collection")
        self.collection = collection_patch.start()
        self.addCleanup(collection_patch.stop)
        self.collection.find.return_value.to_list = AsyncMock(side_effect=lambda **kwargs: [dict(record) for record in self.records])

        async def find_one(query):
            for record in self.records:
                if all(record.get(key) != value["$ne"] if isinstance(value, dict)
                       else record.get(key) == value for key, value in query.items()):
                    return dict(record)
            return None

        async def insert_one(record):
            inserted_id = ObjectId()
            self.records.append({**record, "_id": inserted_id})
            return SimpleNamespace(inserted_id=inserted_id)

        async def update_one(query, update):
            for record in self.records:
                if record["_id"] == query["_id"]:
                    record.update(update["$set"])

        self.collection.find_one = AsyncMock(side_effect=find_one)
        self.collection.insert_one = AsyncMock(side_effect=insert_one)
        self.collection.update_one = AsyncMock(side_effect=update_one)
        self.path = "/api/v1/roles"

    def test_list_create_view_edit_and_toggle(self):
        response = self.client.get(self.path, auth=self.auth)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()[0]["_id"], str(self.role_id))
        details = {"role_name": "Document Owner", "role_code": "DOCUMENT_OWNER",
                   "description": "Prepares documents", "permissions": ["documents.prepare"]}
        response = self.client.post(self.path, auth=self.auth, json=details)
        self.assertEqual(response.status_code, 200, response.text)
        role_path = self.path + "/" + response.json()["_id"]
        self.assertTrue(response.json()["is_active"])
        self.assertEqual(self.client.get(role_path, auth=self.auth).json()["permissions"], details["permissions"])
        response = self.client.put(role_path, auth=self.auth, json={"description": "Updated", "permissions": []})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["description"], "Updated")
        self.assertEqual(response.json()["permissions"], [])
        self.assertEqual(response.json()["role_code"], "DOCUMENT_OWNER")
        for status in [False, True]:
            response = self.client.patch(role_path + "/status", auth=self.auth, json={"is_active": status})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(self.client.get(role_path, auth=self.auth).json()["is_active"], status)

    def test_duplicate_codes_and_invalid_ids(self):
        duplicate = {"role_name": "Duplicate", "role_code": "MANAGER", "description": "", "permissions": []}
        response = self.client.post(self.path, auth=self.auth, json=duplicate)
        self.assertEqual(response.status_code, 400)
        self.assertIn("already exists", response.json()["detail"])
        response = self.client.put(self.path + "/" + str(self.role_id), auth=self.auth, json={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get(self.path + "/invalid", auth=self.auth).status_code, 400)
        self.assertEqual(self.client.get(self.path + "/" + str(ObjectId()), auth=self.auth).status_code, 404)
        self.collection.insert_one.assert_not_called()
        self.collection.update_one.assert_not_called()

    def test_all_actions_require_admin(self):
        for method, path, body in [
            ("GET", self.path, None), ("POST", self.path, {}),
            ("GET", self.path + "/" + str(self.role_id), None),
            ("PUT", self.path + "/" + str(self.role_id), {}),
            ("PATCH", self.path + "/" + str(self.role_id) + "/status", {}),
        ]:
            for auth in [None, ("admin@example.com", "incorrect")]:
                self.assertEqual(self.client.request(method, path, auth=auth, json=body).status_code, 401)
        self.collection.find_one.assert_not_called()
        self.collection.insert_one.assert_not_called()


if __name__ == "__main__":
    unittest.main()
