"""Multipart document lifecycle using cookie sessions, temporary files and fake Mongo collections."""
import copy
import tempfile
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from bson import ObjectId
import test_user_sessions as session_tests
from api import documents


class DocumentCollection(session_tests.Collection):
    def __init__(self, records=()):
        super().__init__(records)
        self.create_index = AsyncMock()
        self.update_one = AsyncMock(side_effect=self._update)
        self.find = MagicMock(side_effect=lambda query=None: SimpleNamespace(to_list=AsyncMock(side_effect=lambda **kwargs: [copy.deepcopy(doc) for doc in self.documents if self.matches(doc, query or {})])))

    def matches(self, doc, query):
        for key, expected in query.items():
            if key == "$or":
                if not any(self.matches(doc, option) for option in expected): return False
                continue
            value = doc.get(key)
            if isinstance(expected, dict):
                if "$exists" in expected and (key in doc) != expected["$exists"]: return False
                if "$ne" in expected and value == expected["$ne"]: return False
                if "$in" in expected and not any(item in expected["$in"] for item in (value if isinstance(value, list) else [value])): return False
                if "$gt" in expected and (value is None or value <= expected["$gt"]): return False
                if "$lte" in expected and (value is None or value > expected["$lte"]): return False
            elif value != expected: return False
        return True

    async def _update(self, query, update):
        for doc in self.documents:
            if self.matches(doc, query):
                doc.update(update.get("$set", {}))
                for field in update.get("$unset", {}): doc.pop(field, None)

    async def _consume(self, query, update):
        for doc in self.documents:
            if self.matches(doc, query):
                previous = copy.deepcopy(doc)
                await self._update(query, update)
                return previous
        return None


class DocumentTests(unittest.TestCase):
    token = session_tests.UserSessionTests.token
    login = session_tests.UserSessionTests.login

    def setUp(self):
        session_tests.UserSessionTests.setUp(self)
        self.role["permissions"] = ["documents.prepare", "documents.submit", "documents.read"]
        self.reader.update({"allowed_classifications": ["D2", "D3"], "excluded_families": [], "access_basis": "ROLE_DEFAULT"})
        self.family_id = ObjectId()
        self.family = {"_id": self.family_id, "family_name": "HR & Induction", "family_code": "HR", "owner_user_id": str(self.user_id), "releaser_user_ids": [], "is_active": True}
        self.docs, self.versions, self.grants = DocumentCollection(), DocumentCollection(), DocumentCollection()
        for name, collection in [
            ("documents_collection", self.docs), ("document_versions_collection", self.versions),
            ("document_families_collection", DocumentCollection([self.family])), ("users_collection", self.users),
            ("roles_collection", self.roles), ("reader_classes_collection", self.readers), ("access_grants_collection", self.grants),
        ]:
            current = patch.object(documents, name, collection)
            current.start(); self.addCleanup(current.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        upload = patch.object(documents, "UPLOAD_DIR", self.directory.name)
        upload.start(); self.addCleanup(upload.stop)
        self.login()
        self.path = "/api/v1/lumen/documents"

    def fields(self, **overrides):
        return {"title": "HR Policy", "reference": "HR-POL-001", "family_id": str(self.family_id), "owner_user_id": str(self.user_id), "classification": "D2", "reader_class_ids": str(self.class_id), "version_number": "1.0", "acknowledgement_required": "true", "change_summary": "First issue", **overrides}

    def upload(self, **overrides):
        return self.client.post(self.path + "/prepare", data=self.fields(**overrides), files={"file": ("policy.pdf", b"%PDF-test content", "application/pdf")})

    def approve_initial(self):
        response = self.upload()
        self.assertEqual(response.status_code, 200, response.text)
        self.docs.documents[0]["current_version_id"] = response.json()["version_id"]
        self.versions.documents[0]["status"] = "APPROVED_CURRENT"
        return response.json()

    def revision(self, document_id, number="2.0", summary="Updated procedure"):
        return self.client.post(self.path + f"/{document_id}/versions", data={"owner_user_id": str(self.user_id), "version_number": number, "change_summary": summary}, files={"file": ("policy-v2.pdf", b"%PDF-revised content", "application/pdf")})

    def test_prepare_persists_file_and_pending_version_and_my_prepared_route_is_reachable(self):
        response = self.upload(reference=" hr-pol-001 ")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "UNDER_REVIEW")
        self.assertIsNone(self.docs.documents[0]["current_version_id"])
        self.assertEqual(self.docs.documents[0]["reference"], "HR-POL-001")
        from pathlib import Path
        self.assertEqual(len(list(Path(self.directory.name).iterdir())), 1)
        prepared = self.client.get(self.path + "/my-prepared")
        self.assertEqual(prepared.status_code, 200, prepared.text)
        self.assertEqual(prepared.json()[0]["latest_version"]["status"], "UNDER_REVIEW")
        self.assertIsNone(prepared.json()[0]["current_approved_version"])
        self.assertEqual(self.client.get(self.path).json(), [])
        duplicate = self.upload(reference="hr-pol-001")
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(len(self.docs.documents), 1)

    def test_family_ownership_submit_permission_and_actor_are_enforced(self):
        self.family["owner_user_id"] = str(ObjectId())
        self.assertEqual(self.upload().status_code, 403)
        self.family["owner_user_id"] = str(self.user_id)
        self.role["permissions"] = ["documents.prepare"]
        self.assertEqual(self.upload().status_code, 403)
        self.role["permissions"].append("documents.submit")
        self.assertEqual(self.upload(owner_user_id=str(ObjectId())).status_code, 403)
        self.family["is_active"] = False
        self.assertEqual(self.upload().status_code, 400)
        self.assertEqual(self.docs.documents, [])

    def test_rejects_invalid_metadata_inactive_readers_and_invalid_files_without_orphans(self):
        self.assertEqual(self.upload(classification="D4").status_code, 400)
        self.assertEqual(self.upload(version_number="latest").status_code, 400)
        inactive_id = ObjectId()
        self.readers.documents.append({"_id": inactive_id, "is_active": False})
        self.assertEqual(self.upload(reader_class_ids=str(inactive_id)).status_code, 400)
        for filename, content, mime, expected in [("script.exe", b"unsafe", "application/octet-stream", 400), ("empty.pdf", b"", "application/pdf", 400), ("large.pdf", b"x" * 65, "application/pdf", 413)]:
            with patch.object(documents, "MAX_FILE_SIZE", 64):
                response = self.client.post(self.path + "/prepare", data=self.fields(), files={"file": (filename, content, mime)})
            self.assertEqual(response.status_code, expected, response.text)
            self.assertEqual(self.docs.documents, [])
        from pathlib import Path
        self.assertEqual(list(Path(self.directory.name).iterdir()), [])

    def test_revision_preserves_current_approved_version_and_blocks_duplicate_pending_uploads(self):
        initial = self.approve_initial()
        response = self.revision(initial["document_id"])
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.docs.documents[0]["current_version_id"], initial["version_id"])
        self.versions.documents[1]["prepared_at"] = self.versions.documents[0]["prepared_at"]
        detail = self.client.get(self.path + "/" + initial["document_id"]).json()
        self.assertEqual(detail["current_approved_version"]["version_number"], "1.0")
        self.assertEqual(detail["pending_versions"][0]["version_number"], "2.0")
        self.assertEqual(detail["latest_version"]["version_number"], "2.0")
        self.assertEqual(self.client.get(self.path).json()[0]["pending_versions"], [])
        self.assertEqual(self.revision(initial["document_id"], "3.0").status_code, 409)
        self.assertNotIn("upload_lock", self.docs.documents[0])

    def test_revision_requires_summary_unique_number_and_exclusive_upload_lock(self):
        initial = self.approve_initial()
        self.assertEqual(self.revision(initial["document_id"], summary=" ").status_code, 400)
        self.assertEqual(self.revision(initial["document_id"], number="1.0").status_code, 409)
        self.docs.documents[0]["upload_lock_until"] = datetime.utcnow() + timedelta(minutes=5)
        self.assertEqual(self.revision(initial["document_id"]).status_code, 409)
        self.assertEqual(len(self.versions.documents), 1)

    def test_employee_sees_only_approved_version_and_cannot_read_pending_version_details(self):
        initial = self.approve_initial()
        revised = self.revision(initial["document_id"]).json()
        self.role["permissions"] = ["documents.read"]
        library = self.client.get(self.path)
        self.assertEqual(library.status_code, 200, library.text)
        self.assertEqual(library.json()[0]["latest_version"]["version_number"], "1.0")
        self.assertEqual(library.json()[0]["pending_versions"], [])
        history = self.client.get(self.path + f"/{initial['document_id']}/versions").json()
        self.assertEqual([version["version_number"] for version in history], ["1.0"])
        self.assertEqual(self.client.get("/api/v1/lumen/document-versions/" + revised["version_id"]).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/lumen/document-versions/" + initial["version_id"]).status_code, 200)

    def test_reader_class_exclusions_and_expiring_document_grants_are_enforced(self):
        initial = self.approve_initial()
        self.role["permissions"] = ["documents.read"]
        self.reader["excluded_families"] = ["HR"]
        self.assertEqual(self.client.get(self.path).json(), [])
        self.reader.update({"excluded_families": [], "requires_document_allowlist": True})
        self.assertEqual(self.client.get(self.path).json(), [])
        grant = {"approval_policy_version": 1, "approved_family_ids": [str(self.family_id)], "approval_authority": "DIVISIONAL_MANAGER", "reader_class_id": str(self.class_id), "user_id": str(self.user_id), "document_ids": [initial["document_id"]], "status": "ACTIVE", "approval_status": "APPROVED", "start_date": datetime.utcnow() - timedelta(days=1), "expiry_date": datetime.utcnow() + timedelta(days=1)}
        self.grants.documents.append(grant)
        self.assertEqual(len(self.client.get(self.path).json()), 1)
        grant["expiry_date"] = datetime.utcnow() - timedelta(seconds=1)
        self.assertEqual(self.client.get(self.path).json(), [])

    def test_review_queue_is_database_backed_and_has_no_approval_side_effects(self):
        initial = self.upload().json()
        self.role["permissions"] = ["documents.release"]
        self.assertEqual(self.client.get(self.path + "/review-queue").json(), [])
        self.family["releaser_user_ids"] = [str(self.user_id)]
        queue = self.client.get(self.path + "/review-queue")
        self.assertEqual(queue.status_code, 200, queue.text)
        self.assertEqual(queue.json()[0]["pending_versions"][0]["_id"], initial["version_id"])
        self.assertEqual(self.versions.documents[0]["status"], "UNDER_REVIEW")
        self.assertIsNone(self.docs.documents[0]["current_version_id"])

    def test_failed_version_write_removes_the_file_and_initial_document(self):
        self.versions.insert_one.side_effect = RuntimeError("Database write failed")
        with self.assertRaises(RuntimeError):
            self.upload()
        self.assertEqual(self.docs.documents, [])
        from pathlib import Path
        self.assertEqual(list(Path(self.directory.name).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
