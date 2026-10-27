"""Reader class API contracts, including expiry transitions."""
import os
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from bson import ObjectId
from fastapi.testclient import TestClient

with patch.dict(os.environ, {"MONGODB_URL": "mongodb://127.0.0.1:27017"}):
    from main import app
    from api import reader_classes


class ReaderClassesTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {
            "DEFAULT_ADMIN_EMAIL": "admin@example.com", "DEFAULT_ADMIN_PASSWORD": "test-password",
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.client = TestClient(app)
        self.auth = ("admin@example.com", "test-password")
        self.class_id = ObjectId()
        self.record = {
            "_id": self.class_id, "class_name": "Contractor", "class_code": "CONTRACTOR_CONSULTANT",
            "description": "External readers", "access_basis": "NAMED_ALLOWLIST",
            "requires_document_allowlist": True, "requires_expiry": True, "max_grant_days": 90,
            "allowed_classifications": ["D2", "D3"], "excluded_families": ["HR"],
            "is_active": True, "created_at": datetime(2026, 10, 25), "updated_at": datetime(2026, 10, 25),
        }
        collection_patch = patch.object(reader_classes, "reader_classes_collection")
        self.collection = collection_patch.start()
        self.addCleanup(collection_patch.stop)
        self.collection.find.return_value.to_list = AsyncMock(side_effect=lambda **kwargs: [dict(self.record)])

        async def find_one(query):
            if query.get("_id") == self.class_id or query.get("class_code") == self.record["class_code"]:
                return dict(self.record)
            return None

        async def update_one(query, update):
            self.record.update(update["$set"])

        self.collection.find_one = AsyncMock(side_effect=find_one)
        self.collection.insert_one = AsyncMock(return_value=SimpleNamespace(inserted_id=ObjectId()))
        self.collection.update_one = AsyncMock(side_effect=update_one)
        self.path = "/api/v1/lumen/reader-classes"
        self.detail_path = self.path + "/" + str(self.class_id)

    def create_details(self):
        return {
            "class_name": "External Reviewer", "class_code": "EXTERNAL_REVIEWER", "description": "Reviewers",
            "access_basis": "NAMED_ALLOWLIST", "requires_document_allowlist": True,
            "requires_expiry": True, "max_grant_days": 90,
        }

    def test_list_create_view_and_status(self):
        response = self.client.get(self.path, auth=self.auth)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()[0]["_id"], str(self.class_id))
        response = self.client.post(self.path, auth=self.auth, json=self.create_details())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["is_active"])
        self.assertEqual(response.json()["max_grant_days"], 90)
        self.assertEqual(self.client.get(self.detail_path, auth=self.auth).status_code, 200)
        for active in [False, True]:
            response = self.client.patch(self.detail_path + "/status", auth=self.auth, json={"is_active": active})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["is_active"], active)

    def test_edit_can_clear_expiry_and_preserve_other_fields(self):
        response = self.client.patch(self.detail_path, auth=self.auth, json={
            "class_name": "Updated Contractor", "requires_expiry": False, "max_grant_days": None,
        })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIsNone(response.json()["max_grant_days"])
        self.assertFalse(response.json()["requires_expiry"])
        self.assertEqual(response.json()["excluded_families"], ["HR"])
        self.assertEqual(response.json()["class_code"], "CONTRACTOR_CONSULTANT")
        response = self.client.patch(self.detail_path, auth=self.auth, json={"description": "Changed"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIsNone(response.json()["max_grant_days"])
        response = self.client.patch(self.detail_path, auth=self.auth, json={"requires_expiry": True, "max_grant_days": 90})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["max_grant_days"], 90)

    def test_rejects_invalid_expiry_combinations_and_duplicate_codes(self):
        for days in [None, 0, -1, 91]:
            response = self.client.post(self.path, auth=self.auth, json={**self.create_details(), "max_grant_days": days})
            self.assertEqual(response.status_code, 400, response.text)
            response = self.client.patch(self.detail_path, auth=self.auth, json={"max_grant_days": days})
            self.assertEqual(response.status_code, 400, response.text)
        response = self.client.patch(self.detail_path, auth=self.auth, json={"requires_expiry": False})
        self.assertEqual(response.status_code, 400)
        response = self.client.post(self.path, auth=self.auth, json={**self.create_details(), "class_code": self.record["class_code"]})
        self.assertEqual(response.status_code, 400)
        self.assertIn("already exists", response.json()["detail"])
        self.collection.update_one.assert_not_called()
        self.collection.insert_one.assert_not_called()

    def test_all_actions_require_admin(self):
        for method, path, body in [
            ("GET", self.path, None), ("POST", self.path, {}), ("GET", self.detail_path, None),
            ("PATCH", self.detail_path, {}), ("PATCH", self.detail_path + "/status", {}),
        ]:
            for auth in [None, ("admin@example.com", "incorrect")]:
                self.assertEqual(self.client.request(method, path, auth=auth, json=body).status_code, 401)
        self.collection.find_one.assert_not_called()
        self.collection.update_one.assert_not_called()


if __name__ == "__main__":
    unittest.main()
