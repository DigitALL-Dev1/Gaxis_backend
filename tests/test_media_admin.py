"""Bootstrap administrator media access without live database writes."""
import asyncio
import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from bson import ObjectId
from fastapi import HTTPException

with patch.dict(os.environ, {"MONGODB_URL": "mongodb://127.0.0.1:27017"}):
    from api import media

ADMIN = {"_id": "bootstrap:admin@example.com", "email": "admin@example.com", "status": "ACTIVE", "bootstrap_admin": True}


class MediaAdminTests(unittest.TestCase):
    def setUp(self):
        self.db = MagicMock()
        self.owner = {"_id": ObjectId(), "email": "owner@example.com", "status": "ACTIVE"}
        self.family = {"_id": ObjectId(), "owner_user_id": str(self.owner["_id"]), "is_active": True}
        self.document = {"_id": ObjectId(), "family_id": self.family["_id"]}
        self.db.document_families.find_one = AsyncMock(return_value=self.family)
        self.db.reader_classes.find_one = AsyncMock(return_value={"is_active": True})
        self.db.users.find_one = AsyncMock(return_value=self.owner)
        self.db.documents.find_one = AsyncMock(return_value=self.document)
        self.db.documents.create_index = AsyncMock()
        self.db.documents.insert_one = AsyncMock()
        self.db.document_versions.create_index = AsyncMock()
        self.db.document_versions.insert_one = AsyncMock()
        self.db.audit_logs.insert_one = AsyncMock()
        self.db.roles.find_one = AsyncMock(return_value=None)
        self.assets = MagicMock(insert_one=AsyncMock())
        for patcher in (patch.object(media, "db", self.db), patch.object(media, "assets", self.assets)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def prepare(self, user):
        return asyncio.run(media.prepare_media(
            MagicMock(), title="Induction", family_id=str(self.family["_id"]), classification="D2",
            reader_class_ids=str(ObjectId()), version_number="1.0", media_type="VIDEO",
            licence_status="REFERENCE_ONLY", acknowledgement_required=False, reference="HSE-VID-001",
            description="", licence_reference=None, document_id=None, external_url="https://example.com/video",
            safety_or_induction=False, file=None, user=user))

    def test_bootstrap_login_resolves_without_a_user_record(self):
        request = SimpleNamespace(state=SimpleNamespace(bootstrap_admin=True, actor_email="admin@example.com"))
        self.assertEqual(asyncio.run(media.current_user(request, None)), ADMIN)
        self.db.users.find_one.assert_not_called()

    def test_administrator_can_manage_but_not_play_media(self):
        asset = {"document_id": self.document["_id"], "version_id": ObjectId()}
        self.assertEqual(asyncio.run(media.management_access(asset, ADMIN)), self.document)
        with self.assertRaises(HTTPException) as denied:
            asyncio.run(media.playback_access(asset, ADMIN))
        self.assertEqual(denied.exception.status_code, 403)

    def test_administrator_prepares_for_the_family_owner_and_is_audited(self):
        self.assertEqual(self.prepare(ADMIN)["publication_status"], "UNDER_REVIEW")
        self.assertEqual(self.assets.insert_one.await_args.args[0]["created_by"], self.owner["_id"])
        audit = self.db.audit_logs.insert_one.await_args.args[0]
        self.assertEqual(audit["user_id"], self.owner["_id"])
        self.assertEqual(audit["details"]["acting_administrator"], "admin@example.com")

    def test_administrator_cannot_prepare_for_a_family_without_an_active_owner(self):
        self.owner["status"] = "INACTIVE"
        with self.assertRaises(HTTPException) as denied:
            self.prepare(ADMIN)
        self.assertEqual(denied.exception.status_code, 403)
        self.assets.insert_one.assert_not_called()


if __name__ == "__main__":
    unittest.main()
