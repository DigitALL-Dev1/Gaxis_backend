"""Family CRUD, role assignment, authorization and active catalog contracts."""
import os
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from bson import ObjectId
from fastapi.testclient import TestClient

with patch.dict(os.environ, {"MONGODB_URL": "mongodb://127.0.0.1:27017"}):
    from main import app
    from api import document_families as families


class DocumentFamiliesTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {"DEFAULT_ADMIN_EMAIL": "admin@example.com", "DEFAULT_ADMIN_PASSWORD": "test-password"})
        environment.start()
        self.addCleanup(environment.stop)
        self.client = TestClient(app)
        self.auth = ("admin@example.com", "test-password")
        self.family_id, self.owner_id, self.releaser_id, self.second_releaser_id = [ObjectId() for _ in range(4)]
        self.owner_role, self.releaser_role = ObjectId(), ObjectId()
        self.record = {
            "_id": self.family_id, "family_name": "HR & Induction", "family_code": "HR", "description": "HR documents",
            "owner_user_id": str(self.owner_id), "releaser_user_ids": [str(self.releaser_id)], "is_active": True,
            "created_by": "admin@example.com", "created_at": datetime(2026, 10, 25), "updated_at": datetime(2026, 10, 25),
        }
        self.users = {
            self.owner_id: {"full_name": "Sarah", "status": "ACTIVE", "role_ids": [str(self.owner_role)]},
            self.releaser_id: {"full_name": "Michael", "status": "ACTIVE", "role_ids": [str(self.releaser_role)]},
            self.second_releaser_id: {"full_name": "Nida", "status": "ACTIVE", "role_ids": [self.releaser_role]},
        }
        self.roles = {
            self.owner_role: {"role_code": "DOCUMENT_OWNER", "is_active": True},
            self.releaser_role: {"role_code": "DOCUMENT_RELEASER", "is_active": True},
        }
        for name in ["document_families_collection", "users_collection", "roles_collection"]:
            current_patch = patch.object(families, name)
            setattr(self, name, current_patch.start())
            self.addCleanup(current_patch.stop)
        self.collection = self.document_families_collection
        self.collection.find.return_value.to_list = AsyncMock(side_effect=lambda **kwargs: [dict(self.record)])

        async def find_one(query):
            return dict(self.record) if query.get("_id") == self.family_id or query.get("family_code") == "HR" else None

        async def update_one(query, update):
            self.record.update(update["$set"])

        self.collection.find_one = AsyncMock(side_effect=find_one)
        self.collection.insert_one = AsyncMock(return_value=SimpleNamespace(inserted_id=ObjectId()))
        self.collection.update_one = AsyncMock(side_effect=update_one)
        self.users_collection.find_one = AsyncMock(side_effect=lambda query: self.users.get(query["_id"]))
        self.roles_collection.find_one = AsyncMock(side_effect=lambda query: self.roles.get(query["_id"]))
        self.path = "/api/v1/lumen/document-families"
        self.detail = self.path + "/" + str(self.family_id)

    def test_create_with_real_owner_multiple_releasers_and_admin_creator(self):
        response = self.client.post(self.path, auth=self.auth, json={
            "family_name": "Safety", "family_code": " hse ", "owner_user_id": str(self.owner_id),
            "releaser_user_ids": [str(self.releaser_id), str(self.second_releaser_id)],
        })
        self.assertEqual(response.status_code, 200, response.text)
        saved = response.json()
        self.assertEqual(saved["family_code"], "HSE")
        self.assertEqual(len(saved["releaser_user_ids"]), 2)
        self.assertEqual(saved["created_by"], "admin@example.com")

    def test_view_edit_assignments_and_status(self):
        self.assertEqual(self.client.get(self.detail, auth=self.auth).status_code, 200)
        response = self.client.patch(self.detail, auth=self.auth, json={"family_name": "Updated HR", "description": ""})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["family_name"], "Updated HR")
        self.assertEqual(response.json()["owner_user_id"], str(self.owner_id))
        for suffix, payload in [
            ("/owner", {"owner_user_id": None}),
            ("/owner", {"owner_user_id": str(self.owner_id)}),
            ("/releasers", {"releaser_user_ids": [str(self.releaser_id), str(self.second_releaser_id)]}),
            ("/status", {"is_active": False}), ("/status", {"is_active": True}),
        ]:
            response = self.client.patch(self.detail + suffix, auth=self.auth, json=payload)
            self.assertEqual(response.status_code, 200, response.text)
            for field, value in payload.items():
                self.assertEqual(response.json()[field], value)

    def test_rejects_wrong_role_inactive_user_and_inactive_role(self):
        response = self.client.patch(self.detail + "/owner", auth=self.auth, json={"owner_user_id": str(self.releaser_id)})
        self.assertEqual(response.status_code, 400)
        for status in ["INACTIVE", "PENDING"]:
            self.users[self.owner_id]["status"] = status
            response = self.client.patch(self.detail + "/owner", auth=self.auth, json={"owner_user_id": str(self.owner_id)})
            self.assertEqual(response.status_code, 400)
        self.users[self.owner_id]["status"] = "ACTIVE"
        self.roles[self.owner_role]["is_active"] = False
        response = self.client.patch(self.detail + "/owner", auth=self.auth, json={"owner_user_id": str(self.owner_id)})
        self.assertEqual(response.status_code, 400)
        response = self.client.patch(self.detail + "/releasers", auth=self.auth, json={"releaser_user_ids": [str(self.owner_id)]})
        self.assertEqual(response.status_code, 400)
        self.collection.update_one.assert_not_called()

    def test_normalizes_codes_before_duplicate_check(self):
        response = self.client.post(self.path, auth=self.auth, json={"family_code": " hr ", "family_name": "Duplicate"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("already exists", response.json()["detail"])
        self.collection.insert_one.assert_not_called()

    def test_management_requires_admin_and_preparation_reads_active_catalog(self):
        for method, path, body in [
            ("GET", self.path, None), ("POST", self.path, {}), ("GET", self.detail, None),
            ("PATCH", self.detail, {}), ("PATCH", self.detail + "/owner", {}),
            ("PATCH", self.detail + "/releasers", {}), ("PATCH", self.detail + "/status", {}),
        ]:
            for auth in [None, ("admin@example.com", "incorrect")]:
                self.assertEqual(self.client.request(method, path, auth=auth, json=body).status_code, 401)
        self.collection.find_one.assert_not_called()
        response = self.client.get(self.path + "?active_only=true")
        self.assertEqual(response.status_code, 200, response.text)
        self.collection.find.assert_called_once_with({"is_active": True})


if __name__ == "__main__":
    unittest.main()
