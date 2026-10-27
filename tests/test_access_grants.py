"""Disclosure authority, timed access and renewal invariants through real API dependencies."""
import copy
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from bson import ObjectId

import test_documents as document_tests
from api import documents, document_families


class AccessGrantTests(unittest.TestCase):
    token = document_tests.DocumentTests.token
    login = document_tests.DocumentTests.login
    fields = document_tests.DocumentTests.fields
    upload = document_tests.DocumentTests.upload
    approve_initial = document_tests.DocumentTests.approve_initial

    def setUp(self):
        document_tests.DocumentTests.setUp(self)
        self.role["permissions"] += ["access_grants.manage", "users.read", "document_families.manage"]
        self.family.update({"family_code": "HSE", "family_name": "Safety", "grant_approver_user_ids": [str(self.user_id)]})
        self.actor_id = self.user_id
        self.recipient_id, self.recipient_class_id, reader_role_id = ObjectId(), ObjectId(), ObjectId()
        self.recipient_class = {**self.reader, "_id": self.recipient_class_id, "class_name": "Contractor", "class_code": "CONTRACTOR_CONSULTANT", "requires_document_allowlist": True, "requires_expiry": True, "max_grant_days": 90, "access_basis": "NAMED_ALLOWLIST"}
        self.readers.documents.append(self.recipient_class)
        self.roles.documents.append({**self.role, "_id": reader_role_id, "role_code": "DOCUMENT_READER", "permissions": ["documents.read"]})
        self.recipient = {**self.user, "_id": self.recipient_id, "full_name": "David", "email": "david@example.com", "user_type": "CONTRACTOR", "role_ids": [str(reader_role_id)], "reader_class_id": str(self.recipient_class_id)}
        self.users.documents.append(self.recipient)
        self.prepared = self.approve_initial()
        self.doc_id = self.prepared["document_id"]
        self.docs.documents[0]["reader_class_ids"].append(str(self.recipient_class_id))
        self.base = "/api/v1/lumen/access-grants"

    def create(self, **overrides):
        now = datetime.now(timezone.utc)
        return self.client.post(self.base, json={"user_id": str(self.recipient_id), "document_ids": [self.doc_id], "reason": "Safety induction", "start_date": (now-timedelta(minutes=1)).isoformat(), "expiry_date": (now+timedelta(days=30)).isoformat(), **overrides})

    def as_user(self, user_id):
        self.user_id = user_id; self.login()

    def library(self):
        self.as_user(self.recipient_id)
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 200, response.text)
        self.as_user(self.actor_id)
        return response.json()

    def test_pending_then_manager_approval_grants_only_document_specific_access_and_revoke_is_immediate(self):
        response = self.create()
        self.assertEqual(response.status_code, 200, response.text)
        grant = response.json()
        self.assertEqual(grant["approval_status"], "PENDING")
        self.assertEqual(grant["granted_by"], str(self.actor_id))
        self.assertTrue(grant["can_approve"])
        self.assertEqual(self.library(), [])
        approved = self.client.post(self.base+f"/{grant['_id']}/approve")
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["status"], "ACTIVE")
        self.assertEqual([doc["_id"] for doc in self.library()], [self.doc_id])
        self.assertEqual(self.client.post(self.base+f"/{grant['_id']}/approve").status_code, 409)
        revoked = self.client.post(self.base+f"/{grant['_id']}/revoke", json={"revocation_reason": "Contract completed"})
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(revoked.json()["status"], "REVOKED")
        self.assertEqual(self.library(), [])

    def test_only_ceo_can_approve_sensitive_families_system_admin_is_not_ceo(self):
        for family_code in ("X1", "COMMERCIAL", "COSTING", "CLIENT_DATA"):
            self.family["family_code"] = family_code
            grant = self.create().json()
            self.assertTrue(grant["requires_ceo_approval"])
            for role_code in ("MANAGER", "SYSTEM_ADMIN"):
                self.role["role_code"] = role_code
                self.assertEqual(self.client.post(self.base+f"/{grant['_id']}/approve").status_code, 403)
            self.role["role_code"] = "CEO"
            response = self.client.post(self.base+f"/{grant['_id']}/approve")
            self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(self.library()), 1)

    def test_ordinary_disclosures_require_explicit_manager_assignment_for_all_families(self):
        grant = self.create().json()
        self.family["grant_approver_user_ids"] = []
        self.assertEqual(self.client.post(self.base+f"/{grant['_id']}/approve").status_code, 403)
        self.family["grant_approver_user_ids"] = [str(self.actor_id)]
        self.role["role_code"] = "SYSTEM_ADMIN"
        self.assertEqual(self.client.post(self.base+f"/{grant['_id']}/approve").status_code, 403)
        self.role["role_code"] = "MANAGER"
        other_family_id, other_doc_id, version_id = ObjectId(), ObjectId(), ObjectId()
        families = documents.document_families_collection
        families.documents.append({**self.family, "_id": other_family_id, "family_code": "ENGINEERING", "grant_approver_user_ids": []})
        self.docs.documents.append({**self.docs.documents[0], "_id": other_doc_id, "family_id": str(other_family_id), "current_version_id": str(version_id)})
        self.versions.documents.append({**self.versions.documents[0], "_id": version_id, "document_id": str(other_doc_id)})
        grant = self.create(document_ids=[self.doc_id, str(other_doc_id)]).json()
        self.assertEqual(self.client.post(self.base+f"/{grant['_id']}/approve").status_code, 403)

    def test_hr_d4_pending_versions_and_inactive_reader_restrictions_fail_closed(self):
        self.family["family_code"] = "HR"
        self.assertEqual(self.create().status_code, 400)
        options = self.client.get(self.base+"/eligible-documents", params={"user_id": str(self.recipient_id)})
        self.assertEqual(options.json()["documents"], [])
        self.family["family_code"] = "HSE"
        for key, value in [("classification", "D4"), ("is_active", False), ("current_version_id", None)]:
            old = self.docs.documents[0][key]; self.docs.documents[0][key] = value
            self.assertEqual(self.create().status_code, 400)
            self.docs.documents[0][key] = old
        self.versions.documents[0]["status"] = "UNDER_REVIEW"
        self.assertEqual(self.create().status_code, 400)
        self.versions.documents[0]["status"] = "APPROVED_CURRENT"
        self.recipient_class["excluded_families"] = ["HSE"]
        self.assertEqual(self.create().status_code, 400)
        self.recipient_class["excluded_families"] = []
        self.recipient_class["is_active"] = False
        self.assertEqual(self.create().status_code, 400)

    def test_precise_duration_utc_offsets_and_class_specific_limits(self):
        now = datetime.now(timezone.utc)
        self.assertEqual(self.create(start_date=now.isoformat(), expiry_date=(now+timedelta(days=90, seconds=1)).isoformat()).status_code, 400)
        self.recipient_class["max_grant_days"] = 10
        self.assertEqual(self.create().status_code, 400)
        valid = self.create(start_date=now.astimezone(timezone(timedelta(hours=5))).isoformat(), expiry_date=(now+timedelta(days=9)).isoformat())
        self.assertEqual(valid.status_code, 200, valid.text)
        self.assertTrue(valid.json()["start_date"].endswith(("Z", "+00:00")))
        self.assertEqual(self.create(expiry_date=(now-timedelta(days=1)).isoformat()).status_code, 400)
        self.assertEqual(self.create(reason="  ").status_code, 422)

    def test_scheduled_approved_grant_activates_and_expires_without_a_status_job(self):
        now = datetime.now(timezone.utc)
        grant = self.create(start_date=(now+timedelta(days=1)).isoformat(), expiry_date=(now+timedelta(days=2)).isoformat()).json()
        response = self.client.post(self.base+f"/{grant['_id']}/approve")
        self.assertEqual(response.json()["status"], "PENDING")
        self.assertEqual(self.library(), [])
        stored = self.grants.documents[0]
        stored["start_date"] = datetime.utcnow()-timedelta(minutes=1)
        self.assertEqual(stored["status"], "PENDING")
        self.assertEqual(len(self.library()), 1)
        self.assertEqual(self.client.get(self.base+f"/{grant['_id']}").json()["status"], "ACTIVE")
        self.assertEqual(len(self.client.get(self.base+"/expiring?days=7").json()), 1)
        stored["expiry_date"] = datetime.utcnow()-timedelta(seconds=1)
        self.assertEqual(self.library(), [])
        self.assertEqual(self.client.get(self.base+f"/{grant['_id']}").json()["status"], "EXPIRED")
        self.assertEqual(self.client.get(self.base+"/expiring").json(), [])

    def test_rejection_reason_and_renewal_approval_preserve_original_validity(self):
        grant = self.create().json(); path = self.base+f"/{grant['_id']}"
        self.assertEqual(self.client.post(path+"/reject", json={"rejection_reason": " "}).status_code, 400)
        self.assertEqual(self.client.post(path+"/reject", json={"rejection_reason": "No business justification"}).json()["approval_status"], "REJECTED")
        self.assertEqual(self.library(), [])
        grant = self.create().json(); path = self.base+f"/{grant['_id']}"
        self.client.post(path+"/approve")
        old_expiry = self.grants.documents[-1]["expiry_date"]
        renewal = {"new_expiry_date": (datetime.now(timezone.utc)+timedelta(days=60)).isoformat(), "reason": "Extended project"}
        renewed = self.client.post(path+"/renew", json=renewal)
        self.assertEqual(renewed.status_code, 200, renewed.text)
        self.assertEqual(self.grants.documents[-1]["expiry_date"], old_expiry)
        self.assertIn("renewal", renewed.json())
        self.assertEqual(self.client.post(path+"/renew", json=renewal).status_code, 409)
        rejected = self.client.post(path+"/reject", json={"rejection_reason": "Extension declined"})
        self.assertEqual(rejected.json()["approval_status"], "APPROVED")
        self.assertNotIn("renewal", rejected.json())
        self.assertEqual(self.grants.documents[-1]["expiry_date"], old_expiry)
        self.assertEqual(len(self.library()), 1)
        self.assertEqual(self.client.post(path+"/renew", json=renewal).status_code, 200)
        approved = self.client.post(path+"/approve")
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertGreater(self.grants.documents[-1]["expiry_date"], old_expiry)
        self.assertEqual(len(approved.json()["renewal_history"]), 2)

    def test_no_authority_spoofing_access_without_management_or_legacy_grant_bypass(self):
        self.assertEqual(self.create(granted_by=str(ObjectId())).status_code, 403)
        grant = self.create().json()
        self.client.post(self.base+f"/{grant['_id']}/approve")
        self.grants.documents[0].pop("approval_policy_version")
        self.assertEqual(self.library(), [])
        details = self.client.get(self.base+f"/{grant['_id']}").json()
        self.assertTrue(details["needs_reapproval"])
        self.assertEqual(details["status"], "PENDING")
        self.assertEqual(self.client.post(self.base+f"/{grant['_id']}/approve").status_code, 200)
        self.assertEqual(len(self.library()), 1)
        self.as_user(self.recipient_id)
        self.assertEqual(self.client.get(self.base).status_code, 403)
        self.assertEqual(self.client.post(self.base+f"/{grant['_id']}/approve").status_code, 403)
        self.client.cookies.clear()
        self.assertEqual(self.client.get(self.base).status_code, 401)

    def test_user_grants_expiring_static_routes_and_stale_decisions(self):
        grant = self.create().json()
        self.assertEqual(self.client.get(f"/api/v1/lumen/users/{self.recipient_id}/access-grants").json()[0]["_id"], grant["_id"])
        self.assertEqual(self.client.get(self.base+"/expiring").status_code, 200)
        with patch.object(self.grants, "find_one_and_update", return_value=None):
            self.assertEqual(self.client.post(self.base+f"/{grant['_id']}/approve").status_code, 409)
        self.assertEqual(self.library(), [])

    def test_grant_approver_assignment_requires_family_permission_and_active_manager(self):
        collection = documents.document_families_collection
        for name, value in [("document_families_collection", collection), ("users_collection", self.users), ("roles_collection", self.roles)]:
            current = patch.object(document_families, name, value); current.start(); self.addCleanup(current.stop)
        path = f"/api/v1/lumen/document-families/{self.family_id}"
        self.family.update({"created_by": "admin", "created_at": datetime.utcnow(), "updated_at": datetime.utcnow(), "description": None})
        self.assertEqual(self.client.patch(path, json={"grant_approver_user_ids": [str(self.recipient_id)]}).status_code, 400)
        response = self.client.patch(path, json={"grant_approver_user_ids": [str(self.actor_id)]})
        self.assertEqual(response.status_code, 200, response.text)
        self.role["permissions"].remove("document_families.manage")
        self.assertEqual(self.client.patch(path, json={"grant_approver_user_ids": []}).status_code, 403)

    def test_external_users_always_need_grants_and_new_sensitive_family_requires_ceo_approval(self):
        self.recipient_class.update({"requires_document_allowlist": False, "access_basis": "ROLE_DEFAULT"})
        self.assertEqual(self.library(), [])
        grant = self.create().json()
        self.assertEqual(self.client.post(self.base+f"/{grant['_id']}/approve").status_code, 200)
        self.assertEqual(len(self.library()), 1)
        self.family["family_code"] = "COMMERCIAL"
        self.assertEqual(self.library(), [])

    def test_expired_renewal_stays_inaccessible_until_approved_and_can_be_revoked(self):
        grant = self.create().json(); path = self.base+f"/{grant['_id']}"
        self.client.post(path+"/approve")
        self.grants.documents[0]["expiry_date"] = datetime.utcnow()-timedelta(seconds=1)
        response = self.client.post(path+"/renew", json={"new_expiry_date": (datetime.now(timezone.utc)+timedelta(days=30)).isoformat(), "reason": "New project phase"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["can_revoke"])
        self.assertEqual(self.library(), [])

        revoked = self.client.post(path+"/revoke", json={"revocation_reason": "Request withdrawn"})
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(revoked.json()["renewal_history"][-1]["approval_status"], "CANCELLED")
        self.assertEqual(self.client.post(path+"/approve").status_code, 409)
        self.assertEqual(self.library(), [])

    def test_bootstrap_admin_can_request_but_cannot_supply_ceo_approval(self):
        self.family["family_code"] = "COMMERCIAL"
        now = datetime.now(timezone.utc)
        payload = {"user_id": str(self.recipient_id), "document_ids": [self.doc_id], "reason": "Commercial review", "start_date": now.isoformat(), "expiry_date": (now+timedelta(days=10)).isoformat()}
        with patch.dict(os.environ, {"DEFAULT_ADMIN_EMAIL": "test-admin@example.com", "DEFAULT_ADMIN_PASSWORD": "test-only-password"}):
            auth = ("test-admin@example.com", "test-only-password")
            response = self.client.post(self.base, json=payload, auth=auth)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["granted_by"], "bootstrap:test-admin@example.com")
            self.assertFalse(response.json()["can_approve"])
            self.assertEqual(self.client.post(self.base+f"/{response.json()['_id']}/approve", auth=auth).status_code, 403)
