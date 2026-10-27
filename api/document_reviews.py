"""Independent, family-scoped controlled document review and publication."""
import secrets
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from api import documents as docs

router = APIRouter()


class ReviewDecision(BaseModel):
    review_comments: str = Field(default="", max_length=10000)


def review_identity(request):
    if docs.is_admin(request):
        email = request.state.actor_email
        return {"user_id": "bootstrap:" + email, "full_name": f"Administrator ({email})", "email": email, "kind": "BOOTSTRAP_ADMIN"}
    profile = docs.identity(request)
    return {**profile, "kind": "SYSTEM_ADMIN" if docs.is_document_admin(request) else "USER"}


async def self_review(request, document, version):
    profile = review_identity(request)
    actor = profile.get("user_id")
    people = {str(version["prepared_by"]), str(document["owner_user_id"])}
    if actor in people:
        return True
    if docs.is_admin(request):
        for user_id in people:
            user = await docs.users_collection.find_one({"_id": docs.oid(user_id, "user")})
            if user and user.get("email", "").strip().lower() == profile["email"].strip().lower():
                return True
    return False


async def reviewer(request, document, permission=None):
    family = await docs.family_for(document)
    if not family or not family.get("is_active") or not document.get("is_active"):
        raise HTTPException(403, "An active document and family are required")
    profile = docs.identity(request)
    actor = profile.get("user_id")
    permissions = profile.get("permissions", [])
    if docs.is_document_admin(request):
        return family
    if actor not in [str(value) for value in family.get("releaser_user_ids", [])]:
        raise HTTPException(403, "You are not an assigned releaser for this document family")
    if permission and permission not in permissions:
        raise HTTPException(403, f"Missing required permission: {permission}")
    if not {"documents.review", "documents.release"}.intersection(permissions):
        raise HTTPException(403, "Document review permission is required")
    return family


async def review_record(version_id, request):
    version = await docs.document_versions_collection.find_one({"_id": docs.oid(version_id, "version")})
    if not version:
        raise HTTPException(404, "Document version not found")
    document = await docs.documents_collection.find_one({"_id": docs.oid(str(version["document_id"]))})
    if not document:
        raise HTTPException(404, "Document not found")
    family = await reviewer(request, document)
    return document, version, family


@router.get("/release-queue")
async def release_queue(request: Request):
    result = []
    versions = await docs.document_versions_collection.find({"status": "UNDER_REVIEW"}).to_list(length=None)
    for version in versions:
        try:
            document, _, family = await review_record(str(version["_id"]), request)
        except HTTPException as error:
            if error.status_code in (403, 404):
                continue
            raise
        preparer = await docs.users_collection.find_one({"_id": docs.oid(str(version["prepared_by"]), "user")})
        result.append({"document": await docs.document_json(request, {**document, **version.get("proposed_metadata", {})}, True, family), "version": {**docs.version_json(version), "preparer_name": preparer.get("full_name", "Unknown") if preparer else "Unknown"}})
    return result


@router.get("/release-queue/{version_id}")
async def review_details(version_id: str, request: Request):
    document, version, family = await review_record(version_id, request)
    preparer = await docs.users_collection.find_one({"_id": docs.oid(str(version["prepared_by"]), "user")})
    own_document = await self_review(request, document, version)
    admin = docs.is_document_admin(request)
    independent = bool(review_identity(request).get("user_id") and (admin or not own_document))
    permissions = docs.identity(request).get("permissions", [])
    pending = version.get("status") == "UNDER_REVIEW"
    display_document = {**document, **version.get("proposed_metadata", {})}
    return {
        "document": await docs.document_json(request, display_document, True, family),
        "version": docs.version_json(version), "preparer_name": preparer.get("full_name", "Unknown") if preparer else "Unknown",
        "admin_review": admin, "self_review_override": bool(admin and own_document),
        "can_release": bool(independent and pending and (admin or "documents.release" in permissions)),
        "can_return": bool(independent and pending and (admin or {"documents.review", "documents.release"}.intersection(permissions))),
    }


@router.get("/document-versions/{version_id}/file")
async def version_file(version_id: str, request: Request):
    # Reuse metadata access: ordinary readers can only fetch the current approved file.
    await docs.get_document_version(version_id, request)
    version = await docs.document_versions_collection.find_one({"_id": docs.oid(version_id, "version")})
    root = Path(docs.UPLOAD_DIR).resolve()
    key = version.get("storage_key")
    if not key:
        raise HTTPException(404, "No uploaded document file is available")
    target = (root / key).resolve()
    if target.parent != root or not target.is_file():
        raise HTTPException(404, "Uploaded document file not found")
    return FileResponse(target, media_type=version.get("file_type", "application/octet-stream"), filename=version.get("file_name", "document"), headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.get("/documents/{document_id}/reviews")
async def review_history(document_id: str, request: Request):
    document, _, manage = await docs.require_document(request, document_id)
    if not manage:
        raise HTTPException(403, "Review history is only available to document owners and assigned reviewers")
    result = []
    for version in await docs.all_versions(str(document["_id"])):
        if version.get("review"):
            result.append({"version_id": str(version["_id"]), "version_number": version["version_number"], **docs.json_ids(version["review"])})
    return result


async def decide(version_id, request, body, release):
    document, version, _ = await review_record(version_id, request)
    await reviewer(request, document, "documents.release" if release else None)
    profile = review_identity(request)
    actor = profile.get("user_id")
    if not actor:
        raise HTTPException(403, "A registered reviewer session is required")
    own_document = await self_review(request, document, version)
    profile["self_review_override"] = bool(docs.is_document_admin(request) and own_document)
    if own_document and not docs.is_document_admin(request):
        raise HTTPException(403, "The document owner or preparer cannot review their own document")
    comments = body.review_comments.strip()
    if not release and not comments:
        raise HTTPException(400, "Review comments are required when returning a document for correction")
    if version.get("status") != "UNDER_REVIEW":
        raise HTTPException(409, "This version is no longer awaiting review. Refresh the queue.")
    # Share the upload reservation: concurrent uploads/decisions cannot interleave.
    token = secrets.token_urlsafe(16)
    now = datetime.utcnow()
    document_id = document["_id"]
    reserved = await docs.documents_collection.find_one_and_update({"_id": document_id, "$or": [{"upload_lock_until": {"$exists": False}}, {"upload_lock_until": {"$lte": now}}]}, {"$set": {"upload_lock": token, "upload_lock_until": now + timedelta(minutes=10)}})
    if not reserved:
        raise HTTPException(409, "Another upload or review decision is in progress")
    try:
        version = await docs.document_versions_collection.find_one({"_id": version["_id"]})
        if version.get("status") != "UNDER_REVIEW":
            raise HTTPException(409, "This version is no longer awaiting review")
        if release:
            from api.media import validate_media_release
            if docs.is_document_admin(request):
                await validate_media_release(version_id, actor, admin_actor=profile)
            else:
                await validate_media_release(version_id, actor)
            effective = {**reserved, **version.get("proposed_metadata", {})}
            if effective.get("classification") not in ("D2", "D3"):
                raise HTTPException(400, "Classification must be D2 or D3")
            if not effective.get("reader_class_ids"):
                raise HTTPException(400, "At least one active reader class is required")
            for reader_id in effective["reader_class_ids"]:
                reader = await docs.reader_classes_collection.find_one({"_id": docs.oid(str(reader_id), "reader class")})
                if not reader or not reader.get("is_active"):
                    raise HTTPException(409, "A selected reader class is no longer active. Return this version for correction.")
            if version.get("file_type") in docs.ALLOWED_FILE_TYPES:
                root = Path(docs.UPLOAD_DIR).resolve()
                target = (root / (version.get("storage_key") or "")).resolve()
                if target.parent != root or not target.is_file():
                    raise HTTPException(409, "The uploaded document file is unavailable. Return this version for correction.")
        review = {"decision": "RELEASED" if release else "RETURNED", "review_comments": comments, "reviewed_by": actor, "reviewer_name": profile["full_name"], "reviewer_kind": profile["kind"], "reviewer_email": profile.get("email"), "self_review_override": profile["self_review_override"], "reviewed_at": now}
        status = "APPROVED_CURRENT" if release else "RETURNED_FOR_CORRECTION"
        previous = await docs.approved_version(reserved)
        # Persist the decision on its version; the pointer is the publication boundary.
        try:
            await docs.document_versions_collection.update_one({"_id": version["_id"]}, {"$set": {"status": status, "review": review, "released_by": actor if release else None, "released_at": now if release else None, "releaser_name": profile["full_name"] if release else None}})
            if release:
                if previous:
                    await docs.document_versions_collection.update_one({"_id": previous["_id"]}, {"$set": {"status": "SUPERSEDED", "superseded_at": now}})
                await docs.documents_collection.update_one({"_id": document_id, "upload_lock": token}, {"$set": {"current_version_id": version_id, "updated_at": now, **version.get("proposed_metadata", {})}})
        except Exception:
            # Also handle an acknowledged-late pointer write before restoring version states.
            saved = await docs.documents_collection.find_one({"_id": document_id})
            if release and saved and str(saved.get("current_version_id")) == version_id:
                restore = {"current_version_id": reserved.get("current_version_id"), "updated_at": reserved.get("updated_at")}
                restore.update({key: reserved.get(key) for key in version.get("proposed_metadata", {})})
                await docs.documents_collection.update_one({"_id": document_id, "upload_lock": token}, {"$set": restore})
            # Compensate a failed publication; the candidate must never leak into the library.
            await docs.document_versions_collection.update_one({"_id": version["_id"]}, {"$set": {"status": "UNDER_REVIEW", "released_by": None, "released_at": None}, "$unset": {"review": "", "releaser_name": ""}})
            if previous:
                await docs.document_versions_collection.update_one({"_id": previous["_id"]}, {"$set": {"status": previous["status"], "superseded_at": previous.get("superseded_at")}})
            raise
        return {"message": "Document approved and released" if release else "Document returned for correction", "document_id": str(document_id), "version_id": version_id, "status": status, "review": review}
    finally:
        await docs.documents_collection.update_one({"_id": document_id, "upload_lock": token}, {"$unset": {"upload_lock": "", "upload_lock_until": ""}})


@router.post("/document-versions/{version_id}/release")
async def release_version(version_id: str, body: ReviewDecision, request: Request):
    return await decide(version_id, request, body, True)


@router.post("/document-versions/{version_id}/return")
async def return_version(version_id: str, body: ReviewDecision, request: Request):
    return await decide(version_id, request, body, False)
