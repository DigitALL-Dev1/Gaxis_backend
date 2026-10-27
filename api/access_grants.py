"""Time-limited document grants with explicit disclosure approval authority."""
import math
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from api import documents as docs

router = APIRouter()
SENSITIVE_FAMILIES = {"X1", "COMMERCIAL", "COSTING", "CLIENT_DATA"}
MANAGER_ROLES = {"MANAGER", "DIVISIONAL_MANAGER"}


class CreateGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: str
    document_ids: list[str] = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=10000)
    start_date: datetime
    expiry_date: datetime

    @field_validator("reason")
    @classmethod
    def reason_required(cls, value):
        if not value.strip():
            raise ValueError("Business reason is required")
        return value.strip()


class Reason(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=10000)

    @field_validator("reason")
    @classmethod
    def required(cls, value):
        if not value.strip():
            raise ValueError("A reason is required")
        return value.strip()


class RenewGrant(Reason):
    new_expiry_date: datetime


class RejectGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rejection_reason: str = Field(min_length=1, max_length=10000)


class RevokeGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revocation_reason: str = Field(min_length=1, max_length=10000)


def utc(value):
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def needs_reapproval(grant):
    return grant.get("approval_status") == "APPROVED" and (grant.get("approval_policy_version") != 1 or grant.get("approval_authority") not in ("CEO", "DIVISIONAL_MANAGER") or not grant.get("approved_family_ids"))


def grant_status(grant):
    if grant.get("status") == "REVOKED":
        return "REVOKED"
    if grant.get("approval_status") == "REJECTED":
        return "REJECTED"
    now = datetime.utcnow()
    if utc(grant["expiry_date"]) <= now:
        return "EXPIRED"
    if grant.get("approval_status") != "APPROVED" or needs_reapproval(grant) or utc(grant["start_date"]) > now:
        return "PENDING"
    return "ACTIVE"


def actor(request):
    if docs.is_admin(request):
        email = request.state.actor_email
        return "bootstrap:" + email, email
    profile = docs.identity(request)
    return profile["user_id"], profile["full_name"]


async def target(user_id):
    user = await docs.users_collection.find_one({"_id": docs.oid(user_id, "user")})
    if not user or user.get("status", "").upper() != "ACTIVE":
        raise HTTPException(400, "Select an active existing user")
    class_id = user.get("reader_class_id")
    reader = await docs.reader_classes_collection.find_one({"_id": docs.oid(str(class_id), "reader class")})
    if not reader or not reader.get("is_active"):
        raise HTTPException(400, "The user needs an active reader class")
    if not (docs.external_reader(user, reader) or reader.get("requires_document_allowlist") or reader.get("access_basis") == "NAMED_ALLOWLIST"):
        raise HTTPException(400, "Select a user who requires document-specific access grants")
    return user, reader


async def validate_documents(ids, user, reader):
    records, families = [], []
    for doc_id in dict.fromkeys(ids):
        document = await docs.documents_collection.find_one({"_id": docs.oid(doc_id)})
        family = await docs.family_for(document) if document else None
        if not document or not await docs.approved_version(document) or not docs.reader_allows_document(document, family, user, reader, explicit=True):
            raise HTTPException(400, "Select only active approved documents eligible for this user's reader class and family restrictions")
        records.append(document); families.append(family)
    return records, families


def sensitive(families):
    return any(family["family_code"].upper() in SENSITIVE_FAMILIES for family in families)


async def approval_authority(request, families):
    if docs.is_admin(request):
        return False
    profile = docs.identity(request)
    codes = {role["code"].upper() for role in profile.get("roles", [])}
    if sensitive(families):
        return "CEO" in codes
    return bool(codes.intersection(MANAGER_ROLES) and all(profile["user_id"] in [str(value) for value in family.get("grant_approver_user_ids", [])] for family in families))


def dates(start, expiry, reader, allow_past=False):
    start, expiry = utc(start), utc(expiry)
    now = datetime.utcnow()
    limit = min(90, reader.get("max_grant_days") or 90)
    if not allow_past and start < now - timedelta(days=1):
        raise HTTPException(400, "Start date cannot be in the past")
    if expiry <= start or expiry <= now:
        raise HTTPException(400, "Expiry must be after the start date and in the future")
    if expiry - start > timedelta(days=limit):
        raise HTTPException(400, f"Grant duration cannot exceed {limit} days")
    return start, expiry


async def get_record(grant_id):
    grant = await docs.access_grants_collection.find_one({"_id": docs.oid(grant_id, "grant")})
    if not grant:
        raise HTTPException(404, "Access grant not found")
    return grant


async def change(grant, updates, unset=None):
    # Every transition compares the revision: approve/reject/revoke cannot overwrite one another.
    query = {"_id": grant["_id"], "revision": grant["revision"] if "revision" in grant else {"$exists": False}}
    updates = {**updates, "revision": grant.get("revision", 0) + 1, "updated_at": datetime.utcnow()}
    result = await docs.access_grants_collection.find_one_and_update(query, {"$set": updates, **({"$unset": unset} if unset else {})})
    if not result:
        raise HTTPException(409, "This grant changed. Refresh and try again.")
    return await get_record(str(grant["_id"]))


def json_dates(value):
    if isinstance(value, datetime): return utc(value).replace(tzinfo=timezone.utc)
    if isinstance(value, dict): return {key: json_dates(item) for key, item in value.items()}
    if isinstance(value, list): return [json_dates(item) for item in value]
    return value


async def present(grant, request):
    result = docs.json_ids(dict(grant))
    result["status"] = grant_status(grant)
    result["days_remaining"] = max(0, math.ceil((utc(grant["expiry_date"]) - datetime.utcnow()).total_seconds() / 86400))
    result["can_approve"] = result["can_reject"] = result["can_renew"] = False
    result["can_revoke"] = result["status"] in ("ACTIVE", "PENDING") or bool(grant.get("renewal"))
    result["documents"] = []
    families = []
    for doc_id in grant["document_ids"]:
        document = await docs.documents_collection.find_one({"_id": docs.oid(str(doc_id))})
        if document:
            result["documents"].append({"_id": str(document["_id"]), "title": document["title"], "reference": document["reference"]})
            family = await docs.family_for(document)
            if family: families.append(family)
        else:
            result["documents"].append({"_id": str(doc_id), "title": "Document unavailable", "reference": ""})
    authority = bool(len(families) == len(grant["document_ids"]) and await approval_authority(request, families))
    result["needs_reapproval"] = needs_reapproval(grant)
    if result["needs_reapproval"]:
        result["eligibility_error"] = "This legacy grant needs fresh disclosure approval before it can provide access."
    awaiting = grant.get("approval_status") == "PENDING" or bool(grant.get("renewal")) or needs_reapproval(grant)
    result["requires_ceo_approval"] = sensitive(families) or grant.get("requires_ceo_approval", False)
    result["approval_required"] = "CEO" if result["requires_ceo_approval"] else "Assigned divisional manager for every selected family"
    result["can_reject"] = authority and awaiting and result["status"] != "REVOKED"
    try:
        user, reader = await target(grant["user_id"])
        await validate_documents(grant["document_ids"], user, reader)
        result["max_grant_days"] = min(90, reader.get("max_grant_days") or 90)
        result["can_approve"] = result["can_reject"] and (grant.get("renewal", {}).get("expiry_date", grant["expiry_date"]) > datetime.utcnow())
        result["can_renew"] = grant.get("approval_status") == "APPROVED" and result["status"] in ("ACTIVE", "EXPIRED") and not grant.get("renewal")
    except HTTPException as error:
        result["eligibility_error"] = error.detail
    return json_dates(result)


@router.get("/access-grants/eligible-documents")
async def eligible_documents(user_id: str, request: Request):
    user, reader = await target(user_id)
    records = await docs.documents_collection.find({"is_active": True}).to_list(length=None)
    result = []
    for document in records:
        family = await docs.family_for(document)
        version = await docs.approved_version(document)
        if version and docs.reader_allows_document(document, family, user, reader, explicit=True):
            result.append({"_id": str(document["_id"]), "title": document["title"], "reference": document["reference"], "classification": document["classification"], "family_name": family["family_name"], "requires_ceo_approval": sensitive([family])})
    return {"reader_class": {"_id": str(reader["_id"]), "class_name": reader["class_name"], "class_code": reader["class_code"]}, "max_grant_days": min(90, reader.get("max_grant_days") or 90), "documents": result}


@router.post("/access-grants")
async def create_access_grant(body: CreateGrant, request: Request):
    user, reader = await target(body.user_id)
    records, families = await validate_documents(body.document_ids, user, reader)
    start, expiry = dates(body.start_date, body.expiry_date, reader)
    by, name = actor(request)
    grant = {"user_id": str(user["_id"]), "user_name": user["full_name"], "reader_class_id": str(reader["_id"]), "reader_class_code": reader["class_code"], "reader_class_name": reader["class_name"], "document_ids": [str(record["_id"]) for record in records], "reason": body.reason, "start_date": start, "expiry_date": expiry, "granted_by": by, "granted_by_name": name, "approval_status": "PENDING", "status": "PENDING", "requires_ceo_approval": sensitive(families), "created_at": datetime.utcnow(), "updated_at": datetime.utcnow(), "revision": 0}
    saved = await docs.access_grants_collection.insert_one(grant)
    return await present(await get_record(str(saved.inserted_id)), request)


@router.get("/access-grants")
async def list_access_grants(request: Request, user_id: Optional[str] = None, status: Optional[str] = None, approval_status: Optional[str] = None, include_expired: bool = True):
    query = {"user_id": str(docs.oid(user_id, "user"))} if user_id else {}
    grants = await docs.access_grants_collection.find(query).to_list(length=None)
    result = []
    for grant in grants:
        effective = grant_status(grant)
        if status and effective != status.upper(): continue
        if approval_status and grant["approval_status"] != approval_status.upper(): continue
        if not include_expired and effective == "EXPIRED": continue
        result.append(await present(grant, request))
    return result


@router.get("/access-grants/expiring")
async def expiring_grants(request: Request, days: int = Query(7, ge=1, le=90)):
    grants = await docs.access_grants_collection.find({"approval_status": "APPROVED"}).to_list(length=None)
    return [await present(grant, request) for grant in grants if grant_status(grant) == "ACTIVE" and utc(grant["expiry_date"]) <= datetime.utcnow() + timedelta(days=days)]


@router.get("/users/{user_id}/access-grants")
async def user_grants(user_id: str, request: Request):
    docs.oid(user_id, "user")
    return await list_access_grants(request, user_id=user_id)


@router.get("/access-grants/{grant_id}")
async def grant_details(grant_id: str, request: Request):
    return await present(await get_record(grant_id), request)


@router.post("/access-grants/{grant_id}/approve")
async def approve_grant(grant_id: str, request: Request):
    grant = await get_record(grant_id)
    if grant["status"] == "REVOKED" or grant["approval_status"] == "REJECTED" or (grant["approval_status"] != "PENDING" and not grant.get("renewal") and not needs_reapproval(grant)):
        raise HTTPException(409, "This grant is not awaiting approval")
    user, reader = await target(grant["user_id"])
    _, families = await validate_documents(grant["document_ids"], user, reader)
    if not await approval_authority(request, families):
        raise HTTPException(403, "CEO approval is required" if sensitive(families) else "Approval requires an assigned divisional manager for every selected family")
    proposal = grant.get("renewal") or grant
    start, expiry = dates(proposal["start_date"], proposal["expiry_date"], reader, allow_past=True)
    by, name = actor(request)
    updates = {"approval_status": "APPROVED", "approval_policy_version": 1, "approval_authority": "CEO" if sensitive(families) else "DIVISIONAL_MANAGER", "approved_family_ids": list({str(family["_id"]) for family in families}), "approved_by": by, "approved_by_name": name, "approved_at": datetime.utcnow(), "status": "ACTIVE" if start <= datetime.utcnow() else "PENDING", "start_date": start, "expiry_date": expiry, "reader_class_id": str(reader["_id"]), "reader_class_code": reader["class_code"], "reader_class_name": reader["class_name"], "requires_ceo_approval": sensitive(families)}
    if grant.get("renewal"):
        updates["renewal_history"] = [*grant.get("renewal_history", []), {**grant["renewal"], "approval_status": "APPROVED", "approval_policy_version": 1, "approval_authority": "CEO" if sensitive(families) else "DIVISIONAL_MANAGER", "approved_family_ids": list({str(family["_id"]) for family in families}), "approved_by": by, "approved_by_name": name, "decided_at": datetime.utcnow()}]
    return await present(await change(grant, updates, {"renewal": "", "rejection_reason": "", "rejected_by": "", "rejected_by_name": ""}), request)


@router.post("/access-grants/{grant_id}/reject")
async def reject_grant(grant_id: str, body: RejectGrant, request: Request):
    grant = await get_record(grant_id)
    reason = body.rejection_reason.strip()
    if not reason: raise HTTPException(400, "A rejection reason is required")
    if grant["status"] == "REVOKED" or (grant["approval_status"] != "PENDING" and not grant.get("renewal") and not needs_reapproval(grant)):
        raise HTTPException(409, "This grant is not awaiting approval")
    families = []
    for doc_id in grant["document_ids"]:
        document = await docs.documents_collection.find_one({"_id": docs.oid(doc_id)})
        family = await docs.family_for(document) if document else None
        if not family: raise HTTPException(400, "The document family is unavailable")
        families.append(family)
    if not await approval_authority(request, families):
        raise HTTPException(403, "The appropriate disclosure approver must reject this request")
    by, name = actor(request)
    updates = {"rejection_reason": reason, "rejected_by": by, "rejected_by_name": name}
    if grant.get("renewal"):
        updates = {}
        updates["renewal_history"] = [*grant.get("renewal_history", []), {**grant["renewal"], "approval_status": "REJECTED", "rejection_reason": reason, "rejected_by": by, "rejected_by_name": name, "decided_at": datetime.utcnow()}]
    else:
        updates.update({"approval_status": "REJECTED", "status": "REJECTED"})
    return await present(await change(grant, updates, {"renewal": ""}), request)


@router.post("/access-grants/{grant_id}/revoke")
async def revoke_grant(grant_id: str, body: RevokeGrant, request: Request):
    grant = await get_record(grant_id)
    if grant_status(grant) not in ("ACTIVE", "PENDING") and not grant.get("renewal"):
        raise HTTPException(409, "Only active or pending grants can be revoked")
    if not body.revocation_reason.strip(): raise HTTPException(400, "A revocation reason is required")
    by, name = actor(request)
    updates = {"status": "REVOKED", "revoked_at": datetime.utcnow(), "revoked_by": by, "revoked_by_name": name, "revocation_reason": body.revocation_reason.strip()}
    if grant.get("renewal"):
        updates["renewal_history"] = [*grant.get("renewal_history", []), {**grant["renewal"], "approval_status": "CANCELLED", "revoked_by": by, "revoked_by_name": name, "decided_at": datetime.utcnow()}]
    return await present(await change(grant, updates, {"renewal": ""}), request)


@router.post("/access-grants/{grant_id}/renew")
async def renew_grant(grant_id: str, body: RenewGrant, request: Request):
    grant = await get_record(grant_id)
    if grant["approval_status"] != "APPROVED" or grant_status(grant) not in ("ACTIVE", "EXPIRED") or grant.get("renewal"):
        raise HTTPException(409, "Only approved active or expired grants without a pending renewal can be renewed")
    user, reader = await target(grant["user_id"])
    await validate_documents(grant["document_ids"], user, reader)
    start, expiry = dates(datetime.utcnow(), body.new_expiry_date, reader)
    if expiry <= utc(grant["expiry_date"]): raise HTTPException(400, "The new expiry must extend the existing expiry")
    by, name = actor(request)
    renewal = {"start_date": start, "expiry_date": expiry, "reason": body.reason, "requested_by": by, "requested_by_name": name, "requested_at": start, "approval_status": "PENDING"}
    return await present(await change(grant, {"renewal": renewal}), request)


@router.get("/access-grants/user/{user_id}/documents")
async def granted_documents(user_id: str, request: Request):
    context = await docs.read_context(user_id)
    documents = await docs.documents_collection.find({"is_active": True}).to_list(length=None)
    permitted = [await docs.document_json(request, document, False) for document in documents if await docs.approved_access(document, context)]
    return {"user_id": user_id, "documents": permitted, "granted_document_count": len(permitted)}


@router.post("/access-grants/check-validity")
async def check_validity(user_id: str, document_id: str):
    context = await docs.read_context(user_id)
    document = await docs.documents_collection.find_one({"_id": docs.oid(document_id)})
    return {"has_access": bool(document and await docs.approved_access(document, context))}


@router.post("/access-grants/batch-check-validity")
async def batch_validity(user_id: str, document_ids: list[str]):
    return {"user_id": user_id, "documents": {document_id: await check_validity(user_id, document_id) for document_id in document_ids}}
