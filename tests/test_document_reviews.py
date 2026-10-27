"""Real multipart uploads and independent review through cookie-authenticated APIs."""
import unittest
import os
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from types import SimpleNamespace

from bson import ObjectId
import test_documents as document_tests
from api import documents


class DocumentReviewTests(unittest.TestCase):
    setUp = document_tests.DocumentTests.setUp
    token = document_tests.DocumentTests.token
    login = document_tests.DocumentTests.login
    fields = document_tests.DocumentTests.fields
    upload = document_tests.DocumentTests.upload
    revision = document_tests.DocumentTests.revision

    def prepare(self):
        response = self.upload()
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def as_reviewer(self, permissions=None):
        self.owner_id = self.user_id
        reviewer_id = ObjectId()
        role_id = ObjectId()
        self.users.documents.append({**self.user, "_id": reviewer_id, "email": "reviewer@example.com", "full_name": "Michael", "role_ids": [str(role_id)]})
        self.roles.documents.append({**self.role, "_id": role_id, "permissions": permissions or ["documents.review", "documents.release", "documents.read"]})
        self.family["releaser_user_ids"] = [str(reviewer_id)]
        self.user_id = reviewer_id
        self.login()
        guard = patch("api.media.validate_media_release", new=AsyncMock())
        self.media_guard = guard.start(); self.addCleanup(guard.stop)

    def decision(self, version_id, action="release", comments="Reviewed and approved", **kwargs):
        return self.client.post(f"/api/v1/lumen/document-versions/{version_id}/{action}", json={"review_comments": comments}, **kwargs)

    def admin_auth(self, email="admin@example.com"):
        env = patch.dict(os.environ, {"DEFAULT_ADMIN_EMAIL": email, "DEFAULT_ADMIN_PASSWORD": "test-admin-password"})
        env.start(); self.addCleanup(env.stop)
        guard = patch("api.media.validate_media_release", new=AsyncMock())
        self.admin_media_guard = guard.start(); self.addCleanup(guard.stop)
        return (email, "test-admin-password")

    def test_bootstrap_admin_can_review_and_release_without_family_assignment_and_is_audited(self):
        prepared = self.prepare()
        auth = self.admin_auth()
        self.assertEqual(self.family["releaser_user_ids"], [])
        details = self.client.get("/api/v1/lumen/release-queue/"+prepared["version_id"], auth=auth)
        self.assertEqual(details.status_code, 200, details.text)
        self.assertTrue(details.json()["can_release"])
        self.assertTrue(details.json()["can_return"])
        response = self.decision(prepared["version_id"], auth=auth)
        self.assertEqual(response.status_code, 200, response.text)
        review = response.json()["review"]
        self.assertEqual(review["reviewer_kind"], "BOOTSTRAP_ADMIN")
        self.assertEqual(review["reviewed_by"], "bootstrap:admin@example.com")
        self.assertEqual(review["reviewer_email"], "admin@example.com")
        self.assertEqual(self.versions.documents[0]["released_by"], "bootstrap:admin@example.com")
        self.assertEqual(self.docs.documents[0]["current_version_id"], prepared["version_id"])
        self.assertEqual(self.decision(prepared["version_id"], auth=auth).status_code, 409)
        self.admin_media_guard.assert_awaited_once()

    def test_admin_can_return_with_comments_but_cannot_review_inactive_families(self):
        prepared = self.prepare(); auth = self.admin_auth()
        self.assertEqual(self.decision(prepared["version_id"], "return", " ", auth=auth).status_code, 400)
        self.family["is_active"] = False
        self.assertEqual(self.decision(prepared["version_id"], auth=auth).status_code, 403)
        self.family["is_active"] = True
        response = self.decision(prepared["version_id"], "return", "Correct metadata", auth=auth)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "RETURNED_FOR_CORRECTION")
        self.assertEqual(response.json()["review"]["reviewer_kind"], "BOOTSTRAP_ADMIN")

    def test_basic_admin_self_review_is_an_explicit_audited_override_and_invalid_credentials_are_denied(self):
        prepared = self.prepare(); auth = self.admin_auth(self.user["email"])
        details = self.client.get("/api/v1/lumen/release-queue/"+prepared["version_id"], auth=auth).json()
        self.assertTrue(details["can_release"])
        self.assertTrue(details["self_review_override"])
        self.assertEqual(self.decision(prepared["version_id"], auth=(auth[0], "wrong-password")).status_code, 401)
        response = self.decision(prepared["version_id"], auth=auth)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["review"]["self_review_override"])

    def test_registered_system_admin_with_release_permission_can_review_other_families(self):
        prepared = self.prepare(); self.as_reviewer()
        self.roles.documents[-1]["role_code"] = "SYSTEM_ADMIN"
        self.family["releaser_user_ids"] = []
        details = self.client.get("/api/v1/lumen/release-queue/"+prepared["version_id"])
        self.assertTrue(details.json()["can_release"])
        file = self.client.get(f"/api/v1/lumen/document-versions/{prepared['version_id']}/file")
        self.assertEqual(file.status_code, 200, file.text)
        response = self.decision(prepared["version_id"])
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["review"]["reviewer_kind"], "SYSTEM_ADMIN")
        self.assertEqual(self.client.get(self.path+f"/{prepared['document_id']}/reviews").status_code, 200)

    def test_registered_system_admin_can_explicitly_override_own_document_review(self):
        prepared = self.prepare()
        self.role["role_code"] = "SYSTEM_ADMIN"
        self.role["permissions"].append("documents.release")
        guard = patch("api.media.validate_media_release", new=AsyncMock())
        guard.start(); self.addCleanup(guard.stop)
        response = self.decision(prepared["version_id"])
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["review"]["self_review_override"])

    def test_admin_media_approval_preserves_processing_checks_and_playback_accepts_its_audit_identity(self):
        from api import media
        from fastapi import HTTPException
        version_id = str(ObjectId()); actor = "bootstrap:admin@example.com"
        profile = {"user_id": actor, "kind": "BOOTSTRAP_ADMIN", "email": "admin@example.com"}
        asset = {"created_by": self.user_id, "licence_status": "LICENSED_WITH_REFERENCE", "licence_reference": "Evidence", "processing_status": "PROCESSING", "media_type": "VIDEO", "renditions": [{"quality": quality} for quality in ("1080p", "720p", "480p", "240p")], "has_audio": False, "captions_required": False}
        saved = {"status": "APPROVED_CURRENT", "released_by": actor, "review": {"reviewed_by": actor, "reviewer_kind": "BOOTSTRAP_ADMIN", "reviewer_email": "admin@example.com"}}
        with patch.object(media, "assets", SimpleNamespace(find_one=AsyncMock(return_value=asset))), patch.object(media, "db", SimpleNamespace(users=SimpleNamespace(find_one=AsyncMock(return_value=self.user)), document_versions=SimpleNamespace(find_one=AsyncMock(return_value=saved)))):
            with self.assertRaises(HTTPException) as failure:
                asyncio.run(media.validate_media_release(version_id, actor, admin_actor=profile))
            self.assertEqual(failure.exception.status_code, 409)
            self.assertIn("processing", failure.exception.detail.lower())
            asset["processing_status"] = "COMPLETED"
            asyncio.run(media.validate_media_release(version_id, actor, admin_actor=profile))
            asyncio.run(media.validate_media_release(version_id, actor))

    def test_release_publishes_once_records_reviewer_and_removes_from_queue(self):
        prepared = self.prepare()
        self.as_reviewer()
        queue = self.client.get("/api/v1/lumen/release-queue")
        self.assertEqual(queue.status_code, 200, queue.text)
        self.assertEqual(queue.json()[0]["version"]["_id"], prepared["version_id"])
        details = self.client.get("/api/v1/lumen/release-queue/" + prepared["version_id"])
        self.assertTrue(details.json()["can_release"])
        self.assertEqual(details.json()["preparer_name"], "Zain Israr")
        response = self.decision(prepared["version_id"])
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "APPROVED_CURRENT")
        self.assertEqual(self.docs.documents[0]["current_version_id"], prepared["version_id"])
        self.assertEqual(self.versions.documents[0]["released_by"], str(self.user_id))
        self.assertIsNotNone(self.versions.documents[0]["released_at"])
        self.assertEqual(self.client.get("/api/v1/lumen/release-queue").json(), [])
        self.assertEqual(self.decision(prepared["version_id"]).status_code, 409)
        self.assertEqual(self.decision(prepared["version_id"], "return").status_code, 409)
        history = self.client.get(self.path + f"/{prepared['document_id']}/reviews").json()
        self.assertEqual(history[0]["reviewer_name"], "Michael")
        self.assertEqual(history[0]["review_comments"], "Reviewed and approved")
        self.media_guard.assert_awaited_once_with(prepared["version_id"], str(self.user_id))

    def test_preparer_cannot_decide_even_with_permissions_and_family_assignment(self):
        prepared = self.prepare()
        self.role["permissions"] += ["documents.review", "documents.release"]
        self.family["releaser_user_ids"] = [str(self.user_id)]
        details = self.client.get("/api/v1/lumen/release-queue/" + prepared["version_id"]).json()
        self.assertFalse(details["can_release"])
        self.assertFalse(details["can_return"])
        for action in ("release", "return"):
            self.assertEqual(self.decision(prepared["version_id"], action).status_code, 403)
        self.assertIsNone(self.docs.documents[0]["current_version_id"])

    def test_review_only_can_return_with_comments_but_cannot_release(self):
        prepared = self.prepare()
        self.as_reviewer(["documents.review"])
        self.assertEqual(self.client.get("/api/v1/lumen/release-queue").status_code, 200)
        self.assertEqual(self.decision(prepared["version_id"]).status_code, 403)
        self.assertEqual(self.decision(prepared["version_id"], "return", "  ").status_code, 400)
        response = self.decision(prepared["version_id"], "return", "Correct classification")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "RETURNED_FOR_CORRECTION")
        self.assertIsNone(self.docs.documents[0]["current_version_id"])
        self.assertEqual(self.client.get("/api/v1/lumen/release-queue").json(), [])
        self.user_id = self.owner_id; self.login()
        owner_document = self.client.get(self.path + "/my-prepared").json()[0]
        self.assertTrue(owner_document["can_prepare_revision"])
        self.assertEqual(owner_document["latest_version"]["review"]["review_comments"], "Correct classification")
        response = self.revision(prepared["document_id"], summary="Classification corrected")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(self.versions.documents), 2)

    def test_unassigned_inactive_and_unauthenticated_reviewers_are_denied(self):
        prepared = self.prepare()
        self.as_reviewer()
        self.family["releaser_user_ids"] = []
        self.assertEqual(self.client.get("/api/v1/lumen/release-queue").json(), [])
        for path in ("/api/v1/lumen/release-queue/", "/api/v1/lumen/document-versions/"):
            self.assertEqual(self.client.get(path + prepared["version_id"]).status_code, 403)
        self.assertEqual(self.decision(prepared["version_id"]).status_code, 403)
        self.family["releaser_user_ids"] = [str(self.user_id)]
        self.family["is_active"] = False
        self.assertEqual(self.decision(prepared["version_id"]).status_code, 403)
        self.family["is_active"] = True
        self.assertEqual(self.decision(prepared["version_id"], headers={"Origin": "https://evil.example"}).status_code, 403)
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/api/v1/lumen/release-queue").status_code, 401)

    def test_version_file_requires_document_access_and_serves_actual_bytes(self):
        prepared = self.prepare()
        path = f"/api/v1/lumen/document-versions/{prepared['version_id']}/file"
        self.as_reviewer()
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.content, b"%PDF-test content")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.roles.documents[-1]["permissions"] = ["documents.read"]
        self.assertEqual(self.client.get(path).status_code, 403)
        self.assertEqual(self.client.get(self.path).json(), [])
        self.versions.documents[0]["storage_key"] = "../private.env"
        self.user_id = self.owner_id; self.login()
        self.assertEqual(self.client.get(path).status_code, 404)

    def test_revised_release_supersedes_previous_and_applies_only_reviewed_metadata(self):
        prepared = self.prepare()
        self.as_reviewer()
        reviewer_id = self.user_id
        self.assertEqual(self.decision(prepared["version_id"]).status_code, 200)
        self.user_id = self.owner_id; self.login()
        revised = self.client.post(self.path + f"/{prepared['document_id']}/versions", data={"owner_user_id": str(self.user_id), "version_number": "2.0", "change_summary": "Corrected classification", "classification": "D3"}, files={"file": ("revision.pdf", b"%PDF-v2", "application/pdf")})
        self.assertEqual(revised.status_code, 200, revised.text)
        self.assertEqual(self.docs.documents[0]["classification"], "D2")
        self.assertEqual(self.client.get(self.path).json()[0]["current_approved_version"]["version_number"], "1.0")
        self.user_id = reviewer_id; self.login()
        version_id = revised.json()["version_id"]
        details = self.client.get("/api/v1/lumen/release-queue/" + version_id).json()
        self.assertEqual(details["document"]["classification"], "D3")
        self.assertEqual(self.decision(version_id).status_code, 200)
        self.assertEqual(self.versions.documents[0]["status"], "SUPERSEDED")
        self.assertIsNotNone(self.versions.documents[0]["superseded_at"])
        self.assertEqual(self.docs.documents[0]["classification"], "D3")
        self.assertEqual(self.client.get(self.path).json()[0]["current_approved_version"]["version_number"], "2.0")

    def test_lock_and_media_validation_prevent_publication_and_failed_pointer_write_rolls_back(self):
        prepared = self.prepare()
        self.as_reviewer()
        self.docs.documents[0]["upload_lock_until"] = datetime.utcnow() + timedelta(minutes=5)
        self.assertEqual(self.decision(prepared["version_id"]).status_code, 409)
        self.docs.documents[0].pop("upload_lock_until")
        from fastapi import HTTPException
        self.media_guard.side_effect = HTTPException(409, "Media processing must complete before release")
        self.assertEqual(self.decision(prepared["version_id"]).status_code, 409)
        self.assertEqual(self.versions.documents[0]["status"], "UNDER_REVIEW")
        self.media_guard.side_effect = None
        async def fail_pointer(query, update):
            if "current_version_id" in update.get("$set", {}):
                raise RuntimeError("Pointer write failed")
            return await self.docs._update(query, update)
        self.docs.update_one.side_effect = fail_pointer
        with self.assertRaises(RuntimeError):
            self.decision(prepared["version_id"])
        self.assertEqual(self.versions.documents[0]["status"], "UNDER_REVIEW")
        self.assertNotIn("review", self.versions.documents[0])
        self.assertIsNone(self.docs.documents[0]["current_version_id"])
        self.assertNotIn("upload_lock", self.docs.documents[0])

    def test_release_revalidates_active_audience_and_uploaded_file(self):
        prepared = self.prepare()
        self.as_reviewer()
        # Use a different audience class so the signed-in reviewer remains active.
        audience_id = ObjectId()
        self.readers.documents.append({"_id": audience_id, "is_active": False})
        self.docs.documents[0]["reader_class_ids"] = [str(audience_id)]
        response = self.decision(prepared["version_id"])
        self.assertEqual(response.status_code, 409, response.text)
        self.docs.documents[0]["reader_class_ids"] = [str(self.class_id)]
        from pathlib import Path
        (Path(self.directory.name) / self.versions.documents[0]["storage_key"]).unlink()
        self.assertEqual(self.decision(prepared["version_id"]).status_code, 409)
        self.assertIsNone(self.docs.documents[0]["current_version_id"])
        self.assertEqual(self.versions.documents[0]["status"], "UNDER_REVIEW")

    def test_failed_revised_publication_restores_the_previous_approved_version(self):
        prepared = self.prepare()
        self.as_reviewer()
        reviewer_id = self.user_id
        self.assertEqual(self.decision(prepared["version_id"]).status_code, 200)
        self.user_id = self.owner_id; self.login()
        revised = self.revision(prepared["document_id"]).json()
        self.user_id = reviewer_id; self.login()
        async def fail_pointer(query, update):
            if "current_version_id" in update.get("$set", {}):
                raise RuntimeError("Pointer write failed")
            return await self.docs._update(query, update)
        self.docs.update_one.side_effect = fail_pointer
        with self.assertRaises(RuntimeError):
            self.decision(revised["version_id"])
        self.assertEqual(self.versions.documents[0]["status"], "APPROVED_CURRENT")
        self.assertEqual(self.versions.documents[1]["status"], "UNDER_REVIEW")
        self.assertEqual(self.docs.documents[0]["current_version_id"], prepared["version_id"])
        self.assertEqual(self.client.get(self.path).json()[0]["current_approved_version"]["version_number"], "1.0")
