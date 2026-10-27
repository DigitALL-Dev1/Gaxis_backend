"""Document preparation, version metadata and the approved document catalog."""
import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Request
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import DuplicateKeyError
from starlette.concurrency import run_in_threadpool

load_dotenv()
db = AsyncIOMotorClient(os.getenv("MONGODB_URL")).get_database("gaxis_lumen")
documents_collection = db.get_collection("documents")
document_versions_collection = db.get_collection("document_versions")
document_families_collection = db.get_collection("document_families")
users_collection = db.get_collection("users")
roles_collection = db.get_collection("roles")
reader_classes_collection = db.get_collection("reader_classes")
access_grants_collection = db.get_collection("access_grants")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
MAX_FILE_SIZE = 100 * 1024 * 1024
ALLOWED_FILE_TYPES = {"application/pdf": ".pdf", "application/msword": ".doc", "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx"}
router = APIRouter()


def oid(value: str, label="document") -> ObjectId:
    if not ObjectId.is_valid(value):
        raise HTTPException(400, f"Invalid {label} ID format")
    return ObjectId(value)


def is_admin(request: Request) -> bool:
    return bool(getattr(request.state, "bootstrap_admin", False))


def is_document_admin(request: Request) -> bool:
    profile = identity(request)
    return is_admin(request) or ("documents.release" in profile.get("permissions", []) and any(role.get("code") == "SYSTEM_ADMIN" for role in profile.get("roles", [])))


def identity(request: Request) -> dict:
    return getattr(request.state, "authenticated_profile", {})


async def read_context(user_id: str) -> dict:
    user = await users_collection.find_one({"_id": oid(user_id, "user")})
    if not user or user.get("status", "").upper() != "ACTIVE":
        raise HTTPException(403, "An active user account is required")
    permissions = set()
    for role_id in user.get("role_ids", []):
        if ObjectId.is_valid(role_id):
            role = await roles_collection.find_one({"_id": ObjectId(role_id)})
            if role and role.get("is_active", False):
                permissions.update(role.get("permissions", []))
    class_id = user.get("reader_class_id")
    reader = await reader_classes_collection.find_one({"_id": ObjectId(class_id)}) if ObjectId.is_valid(class_id) else None
    if not reader or not reader.get("is_active", False):
        raise HTTPException(403, "An active reader class is required")
    return {"user": user, "reader_class": reader, "permissions": permissions}


async def validate_user_permission(user_id: str, permission: str) -> dict:
    context = await read_context(user_id)
    if permission not in context["permissions"]:
        raise HTTPException(403, f"User does not have required permission: {permission}")
    return context["user"]


async def validate_family_authorization(user_id: str, family_id: str) -> dict:
    family = await document_families_collection.find_one({"_id": oid(family_id, "family")})
    if not family or not family.get("is_active", False):
        raise HTTPException(400, "Select an active document family")
    if str(family.get("owner_user_id")) != user_id:
        raise HTTPException(403, "Only the assigned document owner can prepare documents for this family")
    return family


async def approved_version(document: dict):
    current_id = document.get("current_version_id")
    if not ObjectId.is_valid(current_id):
        return None
    version = await document_versions_collection.find_one({"_id": ObjectId(current_id)})
    if version and str(version.get("document_id")) == str(document["_id"]) and version.get("status") in ("APPROVED_CURRENT", "RELEASED"):
        return version
    return None


EXTERNAL_CODES = {"CONTRACTOR", "CONSULTANT", "CONTRACTOR_CONSULTANT", "SUBCONTRACTOR", "EXTERNAL_REVIEWER"}


def external_reader(user, reader):
    return user.get("user_type", "").upper() in EXTERNAL_CODES or reader.get("class_code", "").upper() in EXTERNAL_CODES


def reader_allows_document(document, family, user, reader, explicit=False):
    if not document.get("is_active") or not family or not family.get("is_active") or not reader.get("is_active"):
        return False
    classification = document.get("classification")
    if classification not in ("D2", "D3") or classification not in reader.get("allowed_classifications", []):
        return False
    code = family.get("family_code", "").upper()
    excluded = {str(value).upper() for value in reader.get("excluded_families", [])}
    if str(family["_id"]).upper() in excluded or code in excluded:
        return False
    contractor = user.get("user_type", "").upper() in {"CONTRACTOR", "CONSULTANT", "SUBCONTRACTOR"} or reader.get("class_code", "").upper() in {"CONTRACTOR", "CONSULTANT", "CONTRACTOR_CONSULTANT", "SUBCONTRACTOR"}
    if contractor and (code == "HR" or code.startswith("HR_") or code.startswith("HR-")):
        return False
    if explicit and str(reader["_id"]) not in [str(value) for value in document.get("reader_class_ids", [])]:
        return False
    return True


async def approved_access(document: dict, context: dict):
    """Apply the current reader-class and grant schema; never grant access on errors."""
    if "documents.read" not in context["permissions"] or not document.get("is_active", False):
        return None
    version = await approved_version(document)
    if not version:
        return None
    reader = context["reader_class"]
    family = await document_families_collection.find_one({"_id": oid(document["family_id"], "family")})
    explicit = bool(external_reader(context["user"], reader) or reader.get("requires_document_allowlist") or reader.get("access_basis") == "NAMED_ALLOWLIST")
    if not reader_allows_document(document, family, context["user"], reader, explicit=explicit):
        return None
    if explicit:
        now = datetime.utcnow()
        grant = await access_grants_collection.find_one({
            "user_id": {"$in": [str(context["user"]["_id"]), context["user"]["_id"]]},
            "document_ids": {"$in": [str(document["_id"]), document["_id"]]},
            "status": {"$in": ["ACTIVE", "PENDING"]}, "approval_status": "APPROVED",
            "reader_class_id": str(reader["_id"]), "approval_policy_version": 1,
            "approved_family_ids": {"$in": [str(family["_id"])]},
            "approval_authority": "CEO" if family["family_code"].upper() in {"X1", "COMMERCIAL", "COSTING", "CLIENT_DATA"} else {"$in": ["CEO", "DIVISIONAL_MANAGER"]},
            "start_date": {"$lte": now}, "expiry_date": {"$gt": now},
        })
        if not grant:
            return None
    elif reader.get("access_basis") != "ADMIN_APPOINTMENT" and str(reader["_id"]) not in [str(value) for value in document.get("reader_class_ids", [])]:
        return None
    return version


async def family_for(document: dict):
    return await document_families_collection.find_one({"_id": oid(document["family_id"], "family")})


async def can_manage(request: Request, document: dict, family: dict) -> bool:
    if is_document_admin(request):
        return True
    profile = identity(request)
    actor = profile.get("user_id")
    permissions = profile.get("permissions", [])
    return bool(family and (("documents.prepare" in permissions and actor in [str(document.get("owner_user_id")), str(family.get("owner_user_id"))]) or ({"documents.review", "documents.release"}.intersection(permissions) and actor in [str(value) for value in family.get("releaser_user_ids", [])])))


async def require_document(request: Request, document_id: str):
    document = await documents_collection.find_one({"_id": oid(document_id)})
    if not document:
        raise HTTPException(404, "Document not found")
    family = await family_for(document)
    manage = await can_manage(request, document, family)
    if not manage:
        context = await read_context(identity(request)["user_id"])
        if not await approved_access(document, context):
            raise HTTPException(403, "You are not authorised to view this document")
    return document, family, manage


def version_json(version: dict):
    result = json_ids({key: value for key, value in version.items() if key != "storage_key"})
    for key in ("_id", "document_id", "prepared_by", "released_by"):
        if result.get(key) is not None:
            result[key] = str(result[key])
    if result.get("status") == "RELEASED":
        result["status"] = "APPROVED_CURRENT"
    return result


def json_ids(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, dict):
        return {key: json_ids(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_ids(item) for item in value]
    return value


async def all_versions(document_id: str):
    versions = await document_versions_collection.find({"document_id": {"$in": [document_id, ObjectId(document_id)]}}).to_list(length=None)
    return sorted(versions, key=lambda version: (version.get("prepared_at") or datetime.min, str(version["_id"])), reverse=True)


async def document_json(request: Request, document: dict, manage: bool, family=None):
    family = family or await family_for(document)
    approved = await approved_version(document)
    versions = await all_versions(str(document["_id"])) if manage else ([approved] if approved else [])
    pending = [version_json(version) for version in versions if version.get("status") == "UNDER_REVIEW"]
    latest = next((version for version in versions if version.get("status") == "UNDER_REVIEW"), versions[0] if versions else None)
    owner = await users_collection.find_one({"_id": oid(str(document["owner_user_id"]), "user")})
    result = json_ids(dict(document))
    result.pop("upload_lock", None)
    result.pop("upload_lock_until", None)
    for key in ("_id", "family_id", "owner_user_id", "current_version_id", "created_by"):
        if result.get(key) is not None:
            result[key] = str(result[key])
    result["reader_class_ids"] = [str(value) for value in document.get("reader_class_ids", [])]
    result["reader_classes"] = []
    for class_id in result["reader_class_ids"]:
        if ObjectId.is_valid(class_id):
            reader = await reader_classes_collection.find_one({"_id": ObjectId(class_id)})
            if reader:
                result["reader_classes"].append({"_id": class_id, "class_name": reader["class_name"]})
    actor = identity(request).get("user_id")
    can_prepare = bool(family and family.get("is_active") and (is_admin(request) or (actor == str(family.get("owner_user_id")) and "documents.prepare" in identity(request).get("permissions", []))))
    result.update({
        "family_name": family.get("family_name", "Unknown") if family else "Unknown",
        "owner_name": owner.get("full_name", "Unknown") if owner else "Unknown",
        "current_approved_version": version_json(approved) if approved else None,
        "pending_versions": pending,
        "latest_version": version_json(latest) if latest else None,
        "status": "UNDER_REVIEW" if pending else "APPROVED_CURRENT" if approved else (versions[0].get("status", "UNDER_REVIEW") if versions else "UNDER_REVIEW"),
        "can_prepare_revision": can_prepare and not pending,
        "can_view_reviews": manage,
    })
    return result


def save_uploaded_file(file: UploadFile):
    filename = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    extension = Path(filename).suffix.lower()
    expected = ALLOWED_FILE_TYPES.get(file.content_type)
    if expected != extension or not expected:
        raise HTTPException(400, "Select a PDF, DOCX or DOC document with a matching file type")
    root = Path(UPLOAD_DIR).resolve()
    root.mkdir(parents=True, exist_ok=True)
    key = secrets.token_urlsafe(24) + extension
    target = root / key
    size, checksum = 0, hashlib.sha256()
    try:
        with target.open("wb") as output:
            while chunk := file.file.read(64 * 1024):
                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    raise HTTPException(413, "Maximum document file size is 100 MB")
                checksum.update(chunk)
                output.write(chunk)
        if not size:
            raise HTTPException(400, "The uploaded document is empty")
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return key, target, size, checksum.hexdigest(), filename


async def preparation_actor(request: Request, candidate: str):
    actor = candidate if is_admin(request) else identity(request).get("user_id")
    if not actor or actor != candidate:
        raise HTTPException(403, "Cannot prepare as another user")
    await validate_user_permission(actor, "documents.prepare")
    await validate_user_permission(actor, "documents.submit")
    return actor


def validate_version_number(value: str):
    if not re.fullmatch(r"\d+(?:\.\d+)*", value.strip()):
        raise HTTPException(400, "Use a numeric version number, such as 1.0 or 2.1")


async def save_version(document_id: str, actor: str, version_number: str, change_summary: str, file: UploadFile, proposed_metadata=None):
    key, target, size, checksum, filename = await run_in_threadpool(save_uploaded_file, file)
    try:
        version = {
            "document_id": document_id, "version_number": version_number.strip(), "status": "UNDER_REVIEW",
            "file_name": filename, "file_type": file.content_type, "file_size": size, "storage_key": key,
            "checksum_sha256": checksum, "change_summary": change_summary.strip() or None,
            "prepared_by": actor, "prepared_at": datetime.utcnow(), "released_by": None,
            "released_at": None, "superseded_at": None,
        }
        if proposed_metadata:
            version["proposed_metadata"] = proposed_metadata
        result = await document_versions_collection.insert_one(version)
        return str(result.inserted_id)
    except Exception:
        target.unlink(missing_ok=True)
        raise


@router.post("/documents/prepare")
async def prepare_document(request: Request, title: str = Form(...), reference: str = Form(...), family_id: str = Form(...), owner_user_id: str = Form(...), classification: str = Form(...), reader_class_ids: str = Form(...), version_number: str = Form(...), acknowledgement_required: bool = Form(...), change_summary: str = Form(""), file: UploadFile = File(...)):
    actor = await preparation_actor(request, owner_user_id)
    await validate_family_authorization(actor, family_id)
    validate_version_number(version_number)
    reference = reference.strip().upper()
    if not title.strip() or len(reference) < 5:
        raise HTTPException(400, "Enter a title and a document reference of at least five characters")
    if classification not in ("D2", "D3"):
        raise HTTPException(400, "Classification must be D2 or D3")
    reader_ids = list(dict.fromkeys(value.strip() for value in reader_class_ids.split(",") if value.strip()))
    if not reader_ids:
        raise HTTPException(400, "At least one active reader class is required")
    for reader_id in reader_ids:
        reader = await reader_classes_collection.find_one({"_id": oid(reader_id, "reader class")})
        if not reader or not reader.get("is_active", False):
            raise HTTPException(400, "Select active reader classes from the database")
    if await documents_collection.find_one({"reference": reference}):
        raise HTTPException(409, "This document reference already exists. Upload a revised version instead.")
    await documents_collection.create_index("reference", unique=True, sparse=True)
    await document_versions_collection.create_index([("document_id", 1), ("version_number", 1)], unique=True)
    document = {
        "title": title.strip(), "reference": reference, "family_id": family_id, "owner_user_id": actor,
        "classification": classification, "reader_class_ids": reader_ids, "current_version_id": None,
        "acknowledgement_required": acknowledgement_required, "is_active": True, "created_by": actor,
        "created_at": datetime.utcnow(), "updated_at": datetime.utcnow(),
    }
    document_id = None
    try:
        result = await documents_collection.insert_one(document)
        document_id = str(result.inserted_id)
        version_id = await save_version(document_id, actor, version_number, change_summary, file)
    except Exception as error:
        if document_id:
            await documents_collection.delete_one({"_id": ObjectId(document_id)})
        if isinstance(error, DuplicateKeyError):
            raise HTTPException(409, "The document reference or version already exists")
        raise
    return {"message": "Document prepared successfully", "document_id": document_id, "version_id": version_id, "status": "UNDER_REVIEW", "title": document["title"], "reference": reference, "version_number": version_number.strip(), "prepared_by": actor}


# Static collection routes must precede /documents/{document_id}.
@router.get("/documents/my-prepared")
async def my_prepared(request: Request, user_id: Optional[str] = None):
    actor = user_id if is_admin(request) else identity(request).get("user_id")
    if is_admin(request) and not actor:
        documents = await documents_collection.find({}).to_list(length=None)
    else:
        oid(actor, "user")
        versions = await document_versions_collection.find({"prepared_by": {"$in": [actor, ObjectId(actor)]}}).to_list(length=None)
        ids = list({ObjectId(version["document_id"]) for version in versions})
        documents = await documents_collection.find({"_id": {"$in": ids}}).to_list(length=None)
    return [await document_json(request, document, True) for document in documents]


@router.get("/documents/review-queue")
async def review_queue(request: Request):
    versions = await document_versions_collection.find({"status": "UNDER_REVIEW"}).to_list(length=None)
    ids = list({ObjectId(version["document_id"]) for version in versions})
    documents = await documents_collection.find({"_id": {"$in": ids}, "is_active": True}).to_list(length=None)
    result = []
    for document in documents:
        family = await family_for(document)
        if await can_manage(request, document, family):
            result.append(await document_json(request, document, True, family))
    return result


@router.get("/documents")
async def list_documents(request: Request, user_id: Optional[str] = None):
    documents = await documents_collection.find({"is_active": True, "current_version_id": {"$ne": None}}).to_list(length=None)
    context = None if is_admin(request) else await read_context(identity(request)["user_id"])
    result = []
    for document in documents:
        approved = await approved_version(document) if is_admin(request) else await approved_access(document, context)
        if approved:
            result.append(await document_json(request, document, False))
    return result


@router.get("/documents/{document_id}")
async def get_document(document_id: str, request: Request, user_id: Optional[str] = None):
    document, family, manage = await require_document(request, document_id)
    return await document_json(request, document, manage, family)


@router.get("/documents/{document_id}/versions")
async def list_document_versions(document_id: str, request: Request):
    document, _, manage = await require_document(request, document_id)
    versions = await all_versions(document_id) if manage else [await approved_version(document)]
    return [version_json(version) for version in versions if version]


@router.get("/document-versions/{version_id}")
async def get_document_version(version_id: str, request: Request):
    version = await document_versions_collection.find_one({"_id": oid(version_id, "version")})
    if not version:
        raise HTTPException(404, "Document version not found")
    document, _, manage = await require_document(request, str(version["document_id"]))
    if not manage and str(document.get("current_version_id")) != version_id:
        raise HTTPException(403, "Only the current approved version is available")
    return version_json(version)


@router.post("/documents/{document_id}/versions")
async def upload_revision(document_id: str, request: Request, owner_user_id: str = Form(...), version_number: str = Form(...), change_summary: str = Form(...), file: UploadFile = File(...), title: Optional[str] = Form(None), classification: Optional[str] = Form(None), reader_class_ids: Optional[str] = Form(None), acknowledgement_required: Optional[bool] = Form(None)):
    actor = await preparation_actor(request, owner_user_id)
    document = await documents_collection.find_one({"_id": oid(document_id)})
    if not document or not document.get("is_active", False):
        raise HTTPException(404, "Active document not found")
    await validate_family_authorization(actor, str(document["family_id"]))
    validate_version_number(version_number)
    if not change_summary.strip():
        raise HTTPException(400, "A change summary is required for a revised version")
    proposed = {}
    if title is not None:
        if not title.strip():
            raise HTTPException(400, "Enter a document title")
        proposed["title"] = title.strip()
    if classification is not None:
        if classification not in ("D2", "D3"):
            raise HTTPException(400, "Classification must be D2 or D3")
        proposed["classification"] = classification
    if acknowledgement_required is not None:
        proposed["acknowledgement_required"] = acknowledgement_required
    if reader_class_ids is not None:
        ids = list(dict.fromkeys(value.strip() for value in reader_class_ids.split(",") if value.strip()))
        if not ids:
            raise HTTPException(400, "At least one active reader class is required")
        for reader_id in ids:
            reader = await reader_classes_collection.find_one({"_id": oid(reader_id, "reader class")})
            if not reader or not reader.get("is_active"):
                raise HTTPException(400, "Select active reader classes from the database")
        proposed["reader_class_ids"] = ids
    lock = secrets.token_urlsafe(16)
    now = datetime.utcnow()
    reserved = await documents_collection.find_one_and_update({"_id": ObjectId(document_id), "$or": [{"upload_lock_until": {"$exists": False}}, {"upload_lock_until": {"$lte": now}}]}, {"$set": {"upload_lock": lock, "upload_lock_until": now + timedelta(minutes=10)}})
    if not reserved:
        raise HTTPException(409, "Another version upload is already in progress")
    try:
        versions = await all_versions(document_id)
        if any(version.get("status") == "UNDER_REVIEW" for version in versions):
            raise HTTPException(409, "A version is already under review. Wait for its review before uploading another.")
        if any(version.get("version_number") == version_number.strip() for version in versions):
            raise HTTPException(409, "This version number already exists")
        await document_versions_collection.create_index([("document_id", 1), ("version_number", 1)], unique=True)
        version_id = await save_version(document_id, actor, version_number, change_summary, file, proposed)
        # The approved pointer and all approved metadata remain unchanged until independent release.
        return {"message": "Revised version prepared successfully", "document_id": document_id, "version_id": version_id, "version_number": version_number.strip(), "status": "UNDER_REVIEW"}
    except DuplicateKeyError:
        raise HTTPException(409, "This version number already exists")
    finally:
        await documents_collection.update_one({"_id": ObjectId(document_id), "upload_lock": lock}, {"$unset": {"upload_lock": "", "upload_lock_until": ""}})
