"""Controlled media API.

Requires FFmpeg/ffprobe, private MEDIA_STORAGE_DIR, and an authenticated upstream
request.state.user_id or HS256 bearer JWT (JWT_SECRET_KEY, subject=user ObjectId).
The existing release workflow must call validate_media_release before publishing.
Optional Whisper CLI generates draft captions; manual reviewed WebVTT is accepted.
Playback eligibility is evidence for Step 10, never an acknowledgement itself.
"""
import asyncio
import hashlib
import ipaddress
import json
import math
import os
import secrets
import shutil
import socket
import ssl
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import quote, urlparse

import jwt
from bson import ObjectId
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from starlette.background import BackgroundTask

from api.auth import db

router = APIRouter()
bearer = HTTPBearer(auto_error=False)
assets = db.media_assets
jobs = db.media_processing_jobs
captions = db.media_captions
sessions = db.media_playback_sessions
STORAGE = Path(os.getenv("MEDIA_STORAGE_DIR", "./media_storage")).resolve()
APPROVED = {"APPROVED_CURRENT", "RELEASED"}


def oid(value):
    try:
        return ObjectId(value)
    except Exception:
        raise HTTPException(400, "Invalid ObjectId")


def serialize(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, dict):
        return {k: serialize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [serialize(v) for v in value]
    return value


def stored(key):
    path = (STORAGE / key).resolve()
    if not path.is_relative_to(STORAGE):
        raise HTTPException(400, "Invalid storage key")
    return path


async def current_user(request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    subject = getattr(request.state, "user_id", None)
    if subject is None:
        if not credentials:
            raise HTTPException(401, "Authentication required")
        secret = os.getenv("JWT_SECRET_KEY")
        if not secret:
            raise HTTPException(503, "Media authentication is not configured")
        try:
            claims = jwt.decode(credentials.credentials, secret, algorithms=["HS256"],
                                options={"require": ["sub", "exp"]})
            subject = claims["sub"]
        except jwt.InvalidTokenError:
            raise HTTPException(401, "Invalid or expired session")
    if not ObjectId.is_valid(subject):
        raise HTTPException(401, "Invalid session subject")
    user = await db.users.find_one({"_id": oid(subject)})
    if not user or user.get("status", "").upper() != "ACTIVE":
        raise HTTPException(403, "An active account is required")
    return user


async def permissions(user):
    result = set()
    role_ids = user.get("role_ids", []) or [user.get("role_id")]
    for role_id in role_ids:
        if not role_id or not ObjectId.is_valid(role_id):
            continue
        role = await db.roles.find_one({"_id": oid(role_id), "is_active": True})
        if role:
            configured = role.get("permissions", [])
            if isinstance(configured, list):
                result.update(configured)
            else:
                for group, actions in configured.items():
                    if isinstance(actions, dict):
                        result.update(f"{group}.{action}" for action, enabled in actions.items() if enabled)
    return result


async def require(user, permission):
    if permission not in await permissions(user):
        raise HTTPException(403, f"Required permission: {permission}")


async def audit(user, action, asset=None, **details):
    now = datetime.utcnow()
    await db.audit_logs.insert_one({
        "user_id": user["_id"], "action": action,
        "document_id": asset.get("document_id") if asset else None,
        "version_id": asset.get("version_id") if asset else None,
        "created_at": now, "retain_until": now.replace(year=now.year + 7) if not
        (now.month == 2 and now.day == 29) else now.replace(year=now.year + 7, day=28),
        "details": details,
    })


async def get_asset(media_id):
    asset = await assets.find_one({"_id": oid(media_id)})
    if not asset:
        raise HTTPException(404, "Media not found")
    return asset


async def management_access(asset, user):
    doc = await db.documents.find_one({"_id": asset["document_id"]})
    if not doc:
        raise HTTPException(404, "Controlled item not found")
    family = await db.document_families.find_one({"_id": oid(doc["family_id"])})
    allowed = await permissions(user)
    owner = str(doc.get("owner_user_id")) == str(user["_id"])
    releaser = family and str(user["_id"]) in [str(x) for x in family.get("releaser_user_ids", [])]
    if not ((owner and "documents.prepare" in allowed) or (releaser and "documents.release" in allowed)):
        raise HTTPException(403, "Media management access denied")
    return doc


async def playback_access(asset, user):
    await require(user, "documents.read")
    doc = await db.documents.find_one({"_id": asset["document_id"], "is_active": True})
    version = await db.document_versions.find_one({"_id": asset["version_id"]})
    if (not doc or not version or version.get("status") not in APPROVED or
            str(doc.get("current_version_id")) != str(asset["version_id"]) or
            str(version.get("document_id")) != str(doc["_id"])):
        raise HTTPException(403, "Only current approved media may be played")
    rc_id = user.get("reader_class_id")
    rc = await db.reader_classes.find_one({"_id": oid(rc_id), "is_active": True}) if rc_id else None
    if not rc or doc.get("classification") not in {"D2", "D3"}:
        raise HTTPException(403, "Reader class or classification denied")
    if doc["classification"] not in rc.get("allowed_classifications", rc.get("permitted_classifications", [])):
        raise HTTPException(403, "Classification denied")
    if str(rc_id) not in [str(x) for x in doc.get("reader_class_ids", [])]:
        raise HTTPException(403, "Reader class is not permitted for this media")
    family = await db.document_families.find_one({"_id": oid(doc["family_id"]), "is_active": True})
    if not family or family.get("family_code") in rc.get("excluded_families", []):
        raise HTTPException(403, "Document family access denied")
    if rc.get("permitted_families") and family.get("family_code") not in rc["permitted_families"]:
        raise HTTPException(403, "Document family access denied")
    from api.documents import external_reader, reader_allows_document
    explicit = bool(external_reader(user, rc) or rc.get("requires_document_allowlist") or rc.get("access_basis") == "NAMED_ALLOWLIST")
    if not reader_allows_document(doc, family, user, rc, explicit=explicit):
        raise HTTPException(403, "Document family or reader-class restrictions deny access")
    if explicit:
        now = datetime.utcnow()
        grant = await db.access_grants.find_one({
            "user_id": {"$in": [user["_id"], str(user["_id"])]},
            "document_ids": {"$in": [doc["_id"], str(doc["_id"])]},
            "status": {"$in": ["ACTIVE", "PENDING"]}, "approval_status": "APPROVED", "revoked_at": None,
            "reader_class_id": str(rc_id), "approval_policy_version": 1,
            "approved_family_ids": {"$in": [str(family["_id"])]},
            "approval_authority": "CEO" if family["family_code"].upper() in {"X1", "COMMERCIAL", "COSTING", "CLIENT_DATA"} else {"$in": ["CEO", "DIVISIONAL_MANAGER"]},
            "start_date": {"$lte": now}, "expiry_date": {"$gt": now},
        })
        if not grant:
            raise HTTPException(403, "A valid document access grant is required")
    # Recheck release conditions on every delivery, even if another module released it.
    await validate_media_release(asset["version_id"], version.get("released_by"))
    return doc


async def validate_media_release(version_id, releaser_id, *, admin_actor=None):
    """Hook for the shared Step 7 release API; does not publish or mutate evidence."""
    asset = await assets.find_one({"version_id": oid(version_id)})
    if not asset:
        return  # A non-media controlled document.
    if not releaser_id:
        raise HTTPException(409, "Preparer and releaser must be different people")
    if admin_actor is None:
        # Playback revalidates media readiness using the persisted approval identity.
        version = await db.document_versions.find_one({"_id": oid(version_id)})
        review = (version or {}).get("review", {})
        if (version and version.get("status") in APPROVED and str(version.get("released_by")) == str(releaser_id)
                and review.get("reviewed_by") == str(releaser_id) and review.get("reviewer_kind") in {"BOOTSTRAP_ADMIN", "SYSTEM_ADMIN"}):
            admin_actor = {"user_id": str(releaser_id), "kind": review["reviewer_kind"], "email": review.get("reviewer_email"), "self_review_override": review.get("self_review_override", False)}
    if admin_actor is not None:
        if admin_actor.get("user_id") != str(releaser_id) or admin_actor.get("kind") not in {"BOOTSTRAP_ADMIN", "SYSTEM_ADMIN"}:
            raise HTTPException(403, "Invalid administrator review identity")
        preparer = await db.users.find_one({"_id": oid(asset["created_by"])})
        own_media = str(asset["created_by"]) == str(releaser_id) or (preparer and admin_actor.get("email") and preparer.get("email", "").strip().lower() == admin_actor["email"].strip().lower())
        if own_media and not admin_actor.get("self_review_override"):
            raise HTTPException(409, "Preparer and releaser must be different people")
    else:
        if str(asset["created_by"]) == str(releaser_id):
            raise HTTPException(409, "Preparer and releaser must be different people")
        releaser = await db.users.find_one({"_id": oid(releaser_id)})
        if not releaser or releaser.get("status", "").upper() != "ACTIVE":
            raise HTTPException(403, "An active releaser is required")
        await require(releaser, "documents.release")
        await management_access(asset, releaser)
    if asset["licence_status"] in {"LICENSED_WITH_REFERENCE", "PERMISSION_GRANTED"} and not asset.get("licence_reference"):
        raise HTTPException(409, "Licence evidence is required")
    if asset["licence_status"] == "REFERENCE_ONLY":
        if not asset.get("external_url") or asset.get("acknowledgement_required"):
            raise HTTPException(409, "Reference-only media cannot require hosted acknowledgement")
        return
    if asset["processing_status"] != "COMPLETED":
        raise HTTPException(409, "Media processing must complete before release")
    qualities = {r["quality"] for r in asset.get("renditions", [])}
    if asset["media_type"] == "VIDEO" and not {"1080p", "720p", "480p", "240p"}.issubset(qualities):
        raise HTTPException(409, "All video renditions, including 240p, are required")
    if asset.get("has_audio") and not {"128kbps", "64kbps"}.issubset(qualities):
        raise HTTPException(409, "Both audio bitrates are required")
    if asset.get("captions_required"):
        caption = await captions.find_one({"version_id": asset["version_id"], "review_status": {"$in": ["CORRECTED", "APPROVED"]}, "reviewed_by": {"$ne": None}})
        if not caption:
            raise HTTPException(409, "Human-reviewed captions are required")


async def run_command(*args):
    try:
        process = await asyncio.create_subprocess_exec(*map(str, args), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        raise RuntimeError("FFmpeg and ffprobe must be installed")
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=14400)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        process.kill()
        await process.wait()
        raise
    if process.returncode:
        raise RuntimeError(stderr.decode(errors="replace")[-1500:])
    return stdout


async def probe(path, media_type):
    raw = await run_command(os.getenv("FFPROBE_BINARY", "ffprobe"), "-v", "error", "-show_streams", "-show_format", "-of", "json", path)
    data = json.loads(raw)
    kinds = {s.get("codec_type") for s in data.get("streams", [])}
    if (media_type == "VIDEO" and "video" not in kinds) or (media_type == "AUDIO" and ("audio" not in kinds or "video" in kinds)):
        raise HTTPException(400, "File contents do not match the declared media type")
    duration = float(data.get("format", {}).get("duration", 0))
    if not math.isfinite(duration) or duration <= 0:
        raise HTTPException(400, "Media must have a finite positive duration")
    fmt = data.get("format", {}).get("format_name", "")
    if media_type == "VIDEO":
        mime = "video/mp4" if "mp4" in fmt else "video/webm" if "webm" in fmt else None
    else:
        mime = next((mime for token, mime in [("mp3", "audio/mpeg"), ("wav", "audio/wav"), ("ogg", "audio/ogg"), ("mp4", "audio/mp4"), ("flac", "audio/flac")] if token in fmt), None)
    if not mime:
        raise HTTPException(400, "Unsupported media container")
    return duration, mime, "audio" in kinds


async def process_asset(media_id):
    asset = await assets.find_one_and_update({"_id": oid(media_id), "processing_status": {"$in": ["QUEUED", "FAILED"]}}, {"$set": {"processing_status": "PROCESSING", "updated_at": datetime.utcnow()}}, return_document=ReturnDocument.AFTER)
    if not asset:
        return
    job = {"media_asset_id": asset["_id"], "version_id": asset["version_id"], "job_type": "TRANSCODE", "status": "PROCESSING", "progress_percentage": 0, "attempt_count": 1, "error_message": None, "started_at": datetime.utcnow(), "completed_at": None, "created_at": datetime.utcnow()}
    job_id = (await jobs.insert_one(job)).inserted_id
    try:
        source = stored(asset["storage_key"])
        ffmpeg = os.getenv("FFMPEG_BINARY", "ffmpeg")
        renditions = []
        targets = [(f"{height}p", ["-vf", f"scale=-2:{height}", "-c:v", "libx264", "-c:a", "aac", "-movflags", "+faststart"], ".mp4") for height in [1080, 720, 480, 240]] if asset["media_type"] == "VIDEO" else []
        if asset.get("has_audio"):
            targets += [(f"{rate}kbps", ["-vn", "-c:a", "libmp3lame", "-b:a", f"{rate}k"], ".mp3") for rate in [128, 64]]
        for index, (quality, options, extension) in enumerate(targets):
            key = f"{asset['_id']}/{quality}{extension}"
            await run_command(ffmpeg, "-nostdin", "-y", "-i", source, *options, stored(key))
            renditions.append({"quality": quality, "storage_key": key, "mime_type": "video/mp4" if extension == ".mp4" else "audio/mpeg"})
            await jobs.update_one({"_id": job_id}, {"$set": {"progress_percentage": (index + 1) * 100 / len(targets)}})
        await assets.update_one({"_id": asset["_id"]}, {"$set": {"renditions": renditions, "processing_status": "COMPLETED", "updated_at": datetime.utcnow()}})
        await jobs.update_one({"_id": job_id}, {"$set": {"status": "COMPLETED", "completed_at": datetime.utcnow()}})
        if asset.get("captions_required"):
            await generate_caption_draft(asset)
    except Exception as error:
        await assets.update_one({"_id": asset["_id"]}, {"$set": {"processing_status": "FAILED", "updated_at": datetime.utcnow()}})
        await jobs.update_one({"_id": job_id}, {"$set": {"status": "FAILED", "error_message": str(error)[:1500], "completed_at": datetime.utcnow()}})


async def generate_caption_draft(asset):
    """Optional local Whisper CLI; generated text always requires human review."""
    now = datetime.utcnow()
    job_id = (await jobs.insert_one({"media_asset_id": asset["_id"], "version_id": asset["version_id"], "job_type": "CAPTION", "status": "PROCESSING", "progress_percentage": 0, "attempt_count": 1, "error_message": None, "started_at": now, "completed_at": None, "created_at": now})).inserted_id
    output_dir = stored(f"{asset['_id']}/caption_draft_{job_id}")
    try:
        executable = os.getenv("WHISPER_BINARY", "whisper")
        if not shutil.which(executable):
            raise RuntimeError("Whisper CLI is unavailable; submit human-corrected WebVTT and transcript using captions/review")
        if not asset.get("has_audio"):
            raise RuntimeError("No audio track; provide manual captions and transcript")
        output_dir.mkdir(parents=True, exist_ok=True)
        await run_command(executable, stored(asset["storage_key"]), "--model", os.getenv("WHISPER_MODEL", "base"), "--output_format", "all", "--output_dir", output_dir)
        caption_key = (output_dir / "original.vtt").relative_to(STORAGE).as_posix()
        transcript_key = (output_dir / "original.txt").relative_to(STORAGE).as_posix()
        if not stored(caption_key).is_file() or not stored(transcript_key).is_file():
            raise RuntimeError("Caption generation did not produce WebVTT and transcript files")
        await captions.create_index([("version_id", 1), ("language_code", 1)], unique=True)
        # Never overwrite a human review if processing is retried.
        await captions.update_one({"version_id": asset["version_id"], "language_code": "en"}, {"$setOnInsert": {"media_asset_id": asset["_id"], "caption_storage_key": caption_key, "transcript_storage_key": transcript_key, "generation_method": "AI_GENERATED", "review_status": "UNVERIFIED", "reviewed_by": None, "reviewed_at": None, "created_at": now}}, upsert=True)
        await jobs.update_one({"_id": job_id}, {"$set": {"status": "COMPLETED", "progress_percentage": 100, "completed_at": datetime.utcnow()}})
    except Exception as error:
        await jobs.update_one({"_id": job_id}, {"$set": {"status": "FAILED", "error_message": str(error)[:1500], "completed_at": datetime.utcnow()}})


@router.post("/media/prepare", status_code=201)
async def prepare_media(background: BackgroundTasks, title: str = Form(..., min_length=1),
                        family_id: str = Form(...), classification: Literal["D2", "D3"] = Form(...),
                        reader_class_ids: str = Form(...), version_number: str = Form(..., min_length=1),
                        media_type: Literal["VIDEO", "AUDIO"] = Form(...),
                        licence_status: Literal["OWNED", "LICENSED_WITH_REFERENCE", "PERMISSION_GRANTED", "REFERENCE_ONLY"] = Form(...),
                        acknowledgement_required: bool = Form(...), reference: Optional[str] = Form(None),
                        description: str = Form(""), licence_reference: Optional[str] = Form(None),
                        document_id: Optional[str] = Form(None), external_url: Optional[str] = Form(None),
                        safety_or_induction: bool = Form(False), file: Optional[UploadFile] = File(None),
                        user: dict = Depends(current_user)):
    await require(user, "documents.prepare")
    family = await db.document_families.find_one({"_id": oid(family_id), "is_active": True})
    if not family or str(family.get("owner_user_id")) != str(user["_id"]):
        raise HTTPException(403, "Only the active document family owner can prepare media")
    rc_ids = list(dict.fromkeys(oid(x.strip()) for x in reader_class_ids.split(",") if x.strip()))
    if not rc_ids:
        raise HTTPException(400, "At least one reader class is required")
    for rc_id in rc_ids:
        if not await db.reader_classes.find_one({"_id": rc_id, "is_active": True}):
            raise HTTPException(400, "Invalid or inactive reader class")
    if licence_status in {"LICENSED_WITH_REFERENCE", "PERMISSION_GRANTED"} and not (licence_reference or "").strip():
        raise HTTPException(400, "Licence evidence is required")
    reference_only = licence_status == "REFERENCE_ONLY"
    if reference_only:
        parsed = urlparse(external_url or "")
        if file or acknowledgement_required or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.netloc.endswith(":"):
            raise HTTPException(400, "Reference-only media needs an HTTPS link, no file and no hosted acknowledgement")
    elif file is None:
        raise HTTPException(400, "A media file is required")
    now = datetime.utcnow()
    doc_id = oid(document_id) if document_id else ObjectId()
    if document_id:
        doc = await db.documents.find_one({"_id": doc_id, "is_active": True})
        if not doc or str(doc.get("owner_user_id")) != str(user["_id"]):
            raise HTTPException(403, "Controlled item owner required")
        if str(doc["family_id"]) != str(oid(family_id)) or doc["classification"] != classification or set(map(str, doc["reader_class_ids"])) != set(map(str, rc_ids)):
            raise HTTPException(409, "A new version must retain the controlled item's access metadata")
    elif not reference or not reference.strip():
        raise HTTPException(400, "Reference is required for a new item")
    await db.documents.create_index("reference", unique=True)
    await db.document_versions.create_index([("document_id", 1), ("version_number", 1)], unique=True)
    asset_id, version_id = ObjectId(), ObjectId()
    key, checksum, size, duration, mime, has_audio = None, None, 0, None, None, False
    inserted_doc = inserted_version = False
    try:
        if file:
            key = f"{asset_id}/original"
            path = stored(key)
            path.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            limit = 2 * 1024**3 if media_type == "VIDEO" else 200 * 1024**2
            with path.open("wb") as output:
                while chunk := await file.read(1024 * 1024):
                    size += len(chunk)
                    if size > limit:
                        raise HTTPException(413, "Media exceeds the permitted size")
                    digest.update(chunk)
                    await asyncio.to_thread(output.write, chunk)
            duration, mime, has_audio = await probe(path, media_type)
            checksum = digest.hexdigest()
        if not document_id:
            await db.documents.insert_one({"_id": doc_id, "title": title.strip(), "reference": reference.strip().upper(), "family_id": oid(family_id), "owner_user_id": user["_id"], "classification": classification, "reader_class_ids": rc_ids, "current_version_id": None, "acknowledgement_required": acknowledgement_required, "is_active": True, "created_by": user["_id"], "created_at": now, "updated_at": now})
            inserted_doc = True
        await db.document_versions.insert_one({"_id": version_id, "document_id": doc_id, "version_number": version_number.strip(), "status": "UNDER_REVIEW", "file_name": Path(file.filename or "media").name if file else None, "file_type": mime, "file_size": size, "storage_key": key, "checksum_sha256": checksum, "change_summary": description, "prepared_by": user["_id"], "prepared_at": now, "released_by": None, "released_at": None, "superseded_at": None})
        inserted_version = True
        asset = {"_id": asset_id, "document_id": doc_id, "version_id": version_id, "media_type": media_type, "title": title.strip(), "description": description, "original_file_name": Path(file.filename or "media").name if file else None, "mime_type": mime, "file_size_bytes": size, "duration_seconds": duration, "storage_key": key, "checksum_sha256": checksum, "renditions": [], "processing_status": "COMPLETED" if reference_only else "QUEUED", "licence_status": licence_status, "licence_reference": licence_reference, "external_url": external_url if reference_only else None, "captions_required": media_type == "VIDEO" or safety_or_induction, "safety_or_induction": safety_or_induction, "acknowledgement_required": acknowledgement_required, "has_audio": has_audio, "created_by": user["_id"], "created_at": now, "updated_at": now}
        await assets.insert_one(asset)
    except Exception as error:
        if inserted_version:
            await db.document_versions.delete_one({"_id": version_id})
        if inserted_doc:
            await db.documents.delete_one({"_id": doc_id})
        if key:
            shutil.rmtree(stored(str(asset_id)), ignore_errors=True)
        if isinstance(error, DuplicateKeyError):
            raise HTTPException(409, "Reference or document version already exists")
        if isinstance(error, RuntimeError):
            raise HTTPException(503, str(error))
        raise
    finally:
        if file:
            await file.close()
    await audit(user, "MEDIA_PREPARED", asset)
    if not reference_only:
        background.add_task(process_asset, str(asset_id))
    return {"message": "Media uploaded successfully", "media_asset_id": str(asset_id), "document_id": str(doc_id), "version_id": str(version_id), "processing_status": asset["processing_status"], "publication_status": "UNDER_REVIEW"}


def public_asset(asset):
    return serialize({k: v for k, v in asset.items() if k not in {"storage_key", "renditions", "licence_reference"}})


@router.get("/media")
async def list_media(skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), user: dict = Depends(current_user)):
    permitted = []
    async for asset in assets.find().sort("created_at", -1):
        try:
            await playback_access(asset, user)
        except HTTPException as error:
            if error.status_code not in {403, 404, 409}:
                raise
            try:
                await management_access(asset, user)
            except HTTPException:
                continue
        if skip:
            skip -= 1
            continue
        permitted.append(public_asset(asset))
        if len(permitted) >= limit:
            break
    return permitted


async def view_asset(media_id, user):
    asset = await get_asset(media_id)
    try:
        await management_access(asset, user)
    except HTTPException:
        await playback_access(asset, user)
    return asset


@router.get("/media/{media_id}")
async def media_metadata(media_id: str, user: dict = Depends(current_user)):
    asset = await view_asset(media_id, user)
    await audit(user, "MEDIA_METADATA_VIEWED", asset)
    return public_asset(asset)


@router.get("/media/{media_id}/processing-status")
async def processing_status(media_id: str, user: dict = Depends(current_user)):
    asset = await get_asset(media_id)
    await management_access(asset, user)
    records = await jobs.find({"media_asset_id": asset["_id"]}).sort("created_at", -1).to_list(100)
    return {"processing_status": asset["processing_status"], "jobs": serialize(records), "human_caption_review_required": asset["captions_required"]}


@router.post("/media/{media_id}/process", status_code=202)
async def request_processing(media_id: str, background: BackgroundTasks, user: dict = Depends(current_user)):
    asset = await get_asset(media_id)
    await management_access(asset, user)
    if asset["licence_status"] == "REFERENCE_ONLY" or asset["processing_status"] not in {"QUEUED", "FAILED"}:
        raise HTTPException(409, "Media is not eligible for processing")
    await audit(user, "MEDIA_PROCESS_REQUESTED", asset)
    background.add_task(process_asset, media_id)
    return {"message": "Processing requested"}


class CaptionReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    language_code: str = Field("en", pattern=r"^[a-z]{2,3}(-[A-Za-z]{2,4})?$")
    webvtt: str = Field(..., min_length=6, max_length=2000000)
    transcript: str = Field(..., min_length=1, max_length=2000000)
    corrected: Literal[True]


@router.post("/media/{media_id}/captions/review")
async def review_captions(media_id: str, review: CaptionReview, user: dict = Depends(current_user)):
    asset = await get_asset(media_id)
    await management_access(asset, user)
    version = await db.document_versions.find_one({"_id": asset["version_id"]})
    if not version or version["status"] != "UNDER_REVIEW":
        raise HTTPException(409, "Published captions are immutable; prepare a new version")
    if not review.webvtt.lstrip("\ufeff").startswith("WEBVTT") or "-->" not in review.webvtt:
        raise HTTPException(400, "Caption content must contain WebVTT cues")
    stored(str(asset["_id"])).mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(12)
    caption_key = f"{asset['_id']}/{token}.vtt"
    transcript_key = f"{asset['_id']}/{token}.txt"
    await asyncio.to_thread(stored(caption_key).write_text, review.webvtt, encoding="utf-8")
    await asyncio.to_thread(stored(transcript_key).write_text, review.transcript, encoding="utf-8")
    now = datetime.utcnow()
    await captions.create_index([("version_id", 1), ("language_code", 1)], unique=True)
    await captions.update_one({"version_id": asset["version_id"], "language_code": review.language_code}, {"$set": {"media_asset_id": asset["_id"], "caption_storage_key": caption_key, "transcript_storage_key": transcript_key, "generation_method": "MANUAL", "review_status": "CORRECTED", "reviewed_by": user["_id"], "reviewed_at": now}, "$setOnInsert": {"created_at": now}}, upsert=True)
    await audit(user, "MEDIA_CAPTIONS_CORRECTED", asset, language_code=review.language_code)
    return {"message": "Corrected captions recorded", "review_status": "CORRECTED"}


@router.get("/media/{media_id}/captions")
async def caption_details(media_id: str, language_code: str = "en", user: dict = Depends(current_user)):
    asset = await view_asset(media_id, user)
    caption = await captions.find_one({"version_id": asset["version_id"], "language_code": language_code})
    if not caption:
        raise HTTPException(404, "Captions not available")
    await audit(user, "MEDIA_CAPTIONS_VIEWED", asset)
    content = await asyncio.to_thread(stored(caption["caption_storage_key"]).read_text, encoding="utf-8")
    return {"language_code": language_code, "review_status": caption["review_status"], "webvtt": content}


@router.get("/media/{media_id}/transcript", response_class=PlainTextResponse)
async def transcript(media_id: str, language_code: str = "en", user: dict = Depends(current_user)):
    asset = await view_asset(media_id, user)
    caption = await captions.find_one({"version_id": asset["version_id"], "language_code": language_code})
    if not caption or not caption.get("transcript_storage_key"):
        raise HTTPException(404, "Transcript not available")
    await audit(user, "MEDIA_TRANSCRIPT_VIEWED", asset)
    return await asyncio.to_thread(stored(caption["transcript_storage_key"]).read_text, encoding="utf-8")


@router.get("/media/{media_id}/renditions")
async def rendition_options(media_id: str, bandwidth_kbps: Optional[float] = Query(None, gt=0), user: dict = Depends(current_user)):
    asset = await get_asset(media_id)
    await playback_access(asset, user)
    await audit(user, "MEDIA_RENDITIONS_VIEWED", asset)
    if asset["licence_status"] == "REFERENCE_ONLY":
        return {"external_url": asset["external_url"], "acknowledgement_eligible": False}
    fallback = bandwidth_kbps is not None and bandwidth_kbps < 300
    return {"renditions": [{"quality": r["quality"], "url": f"/api/v1/lumen/media/{media_id}/stream?quality={r['quality']}"} for r in asset["renditions"] if not fallback or r["quality"].endswith("kbps")], "recommended_quality": "64kbps" if fallback else "240p" if asset["media_type"] == "VIDEO" else "128kbps", "transcript_url": f"/api/v1/lumen/media/{media_id}/transcript", "watermark_required": asset["media_type"] == "VIDEO"}


@router.get("/media/{media_id}/stream")
async def stream_media(media_id: str, quality: str, user: dict = Depends(current_user)):
    asset = await get_asset(media_id)
    await playback_access(asset, user)
    rendition = next((r for r in asset.get("renditions", []) if r["quality"] == quality), None)
    if not rendition:
        raise HTTPException(404, "Rendition not available")
    source = stored(rendition["storage_key"])
    await audit(user, "MEDIA_CONTENT_VIEWED", asset, quality=quality)
    if not quality.endswith("p"):
        return FileResponse(source, media_type=rendition["mime_type"], headers={"Cache-Control": "private, no-store"})
    # Burn the viewer identity into the delivered video, rather than trusting an overlay.
    temp_dir = Path(tempfile.mkdtemp(prefix="media_viewer_"))
    try:
        text_path = temp_dir / "watermark.txt"
        text_path.write_text(f"{user['_id']} | {user.get('email', '')} | {datetime.utcnow().isoformat()}Z", encoding="utf-8")
        output = temp_dir / "viewer.mp4"
        escaped = text_path.as_posix().replace(":", "\\:")
        await run_command(os.getenv("FFMPEG_BINARY", "ffmpeg"), "-nostdin", "-y", "-i", source,
                          "-vf", f"drawtext=textfile='{escaped}':expansion=none:fontcolor=white:fontsize=14:box=1:boxcolor=black@0.5:x=10:y=h-th-10",
                          "-c:v", "libx264", "-preset", "veryfast", "-c:a", "copy", "-movflags", "+faststart", output)
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(503, "Watermarked rendition could not be generated")
    return FileResponse(output, media_type="video/mp4", headers={"Cache-Control": "private, no-store"}, background=BackgroundTask(shutil.rmtree, temp_dir, ignore_errors=True))


def merge_ranges(ranges):
    merged = []
    for start, end in sorted((r["start"], r["end"]) for r in ranges):
        if merged and start <= merged[-1]["end"]:
            merged[-1]["end"] = max(merged[-1]["end"], end)
        else:
            merged.append({"start": start, "end": end})
    return merged


def playback_result(session, asset):
    return {"session_id": str(session["_id"]), "version_id": str(asset["version_id"]), "duration_seconds": asset["duration_seconds"], "resume_position_seconds": session["last_position_seconds"], "completion_percentage": session["completion_percentage"], "acknowledgement_eligible": session["completion_percentage"] >= 90 and asset["acknowledgement_required"], "status": session["status"]}


@router.post("/media/{media_id}/playback/start")
async def start_playback(media_id: str, user: dict = Depends(current_user)):
    asset = await get_asset(media_id)
    await playback_access(asset, user)
    if asset["licence_status"] == "REFERENCE_ONLY":
        raise HTTPException(409, "Reference-only media has no hosted playback evidence")
    await sessions.create_index([("user_id", 1), ("version_id", 1)], unique=True)
    now = datetime.utcnow()
    session = await sessions.find_one_and_update({"user_id": user["_id"], "version_id": asset["version_id"]}, {"$setOnInsert": {"media_asset_id": asset["_id"], "started_at": now, "last_position_seconds": 0.0, "accumulated_played_ranges": [], "unique_played_seconds": 0.0, "completion_percentage": 0.0}, "$set": {"status": "ACTIVE", "last_activity_at": now, "ended_at": None, "playing": False}, "$inc": {"revision": 1}}, upsert=True, return_document=ReturnDocument.AFTER)
    await audit(user, "MEDIA_PLAYBACK_STARTED", asset, session_id=str(session["_id"]))
    return {"message": "Playback session started", **playback_result(session, asset)}


class PlaybackProgress(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    position_seconds: float = Field(..., ge=0)
    event: Literal["PLAY", "HEARTBEAT", "PAUSE", "SEEK", "ENDED"] = "HEARTBEAT"


async def owned_session(session_id, user):
    session = await sessions.find_one({"_id": oid(session_id), "user_id": user["_id"]})
    if not session:
        raise HTTPException(404, "Playback session not found")
    asset = await get_asset(session["media_asset_id"])
    await playback_access(asset, user)  # Recheck expiry/revocation on every request.
    return session, asset


@router.post("/media/playback/{session_id}/progress")
async def playback_progress(session_id: str, progress: PlaybackProgress, user: dict = Depends(current_user)):
    session, asset = await owned_session(session_id, user)
    if session["status"] != "ACTIVE":
        raise HTTPException(409, "Start or resume playback first")
    duration = asset["duration_seconds"]
    if progress.position_seconds > duration:
        raise HTTPException(400, "Position exceeds media duration")
    now = datetime.utcnow()
    elapsed = (now - session["last_activity_at"]).total_seconds()
    delta = progress.position_seconds - session["last_position_seconds"]
    ranges = session["accumulated_played_ranges"][:]
    # Heartbeats must be frequent; discontinuities and seeks receive no credit.
    if session.get("playing") and progress.event != "SEEK" and 0 < elapsed <= 30 and 0 < delta <= elapsed + 0.5:
        ranges.append({"start": session["last_position_seconds"], "end": session["last_position_seconds"] + min(delta, elapsed)})
    ranges = merge_ranges(ranges)
    unique = sum(r["end"] - r["start"] for r in ranges)
    percentage = min(100.0, unique * 100 / duration)
    updates = {"last_position_seconds": progress.position_seconds, "last_activity_at": now, "accumulated_played_ranges": ranges, "unique_played_seconds": unique, "completion_percentage": percentage, "playing": progress.event in {"PLAY", "HEARTBEAT"}}
    changed = await sessions.update_one({"_id": session["_id"], "revision": session["revision"]}, {"$set": updates, "$inc": {"revision": 1}})
    if not changed.modified_count:
        raise HTTPException(409, "Concurrent playback update; reload session and retry")
    session.update(updates)
    await audit(user, "MEDIA_PLAYBACK_PROGRESS", asset, session_id=session_id, event=progress.event, unique_played_seconds=unique)
    return playback_result(session, asset)


@router.post("/media/playback/{session_id}/close")
async def close_playback(session_id: str, user: dict = Depends(current_user)):
    session, asset = await owned_session(session_id, user)
    updates = {"status": "COMPLETED" if session["completion_percentage"] >= 90 else "PAUSED", "ended_at": datetime.utcnow(), "playing": False}
    result = await sessions.update_one({"_id": session["_id"], "revision": session["revision"]}, {"$set": updates, "$inc": {"revision": 1}})
    if not result.modified_count:
        raise HTTPException(409, "Concurrent playback update; retry")
    session.update(updates)
    await audit(user, "MEDIA_PLAYBACK_CLOSED", asset, session_id=session_id)
    return playback_result(session, asset)


async def validate_media_acknowledgement(user_id, version_id):
    """Step 10 hook: validate persisted playback; caller records acknowledgement."""
    asset = await assets.find_one({"version_id": oid(version_id)})
    if not asset:
        return
    user = await db.users.find_one({"_id": oid(user_id), "status": "ACTIVE"})
    if not user:
        raise HTTPException(403, "An active reader is required")
    await playback_access(asset, user)
    if asset["licence_status"] == "REFERENCE_ONLY":
        raise HTTPException(409, "Reference-only media cannot be acknowledged")
    session = await sessions.find_one({"user_id": oid(user_id), "version_id": oid(version_id)})
    if not session or session["completion_percentage"] < 90:
        raise HTTPException(409, "At least 90% unique playback is required")


async def reference_link_status(url):
    """Probe a public HTTPS address with pinned DNS; never follow redirects."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443) or parsed.username:
        raise ValueError("Only public HTTPS links on port 443 can be checked")
    hostname = parsed.hostname.encode("idna").decode("ascii")
    records = await asyncio.to_thread(socket.getaddrinfo, hostname, 443, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Private and reserved reference-link addresses are blocked")
    reader, writer = await asyncio.open_connection(addresses[0], 443, ssl=ssl.create_default_context(), server_hostname=hostname)
    try:
        target = quote(parsed.path or "/", safe="/%:@")
        if parsed.query:
            target += "?" + quote(parsed.query, safe="=&%:/?@+")
        writer.write(f"HEAD {target} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\nUser-Agent: Gaxis-Lumen-Link-Check\r\n\r\n".encode("ascii"))
        await writer.drain()
        line = await reader.readline()
        return int(line.split()[1])
    finally:
        writer.close()
        await writer.wait_closed()


async def check_reference_links():
    now = datetime.utcnow()
    async for asset in assets.find({"licence_status": "REFERENCE_ONLY", "$or": [{"link_checked_at": None}, {"link_checked_at": {"$lte": now - timedelta(days=7)}}]}):
        try:
            status = await asyncio.wait_for(reference_link_status(asset["external_url"]), timeout=15)
            health, error = ("HEALTHY" if 200 <= status < 300 else "NEEDS_REVIEW"), None
        except Exception:
            status, health, error = None, "UNAVAILABLE", "HTTPS link could not be verified"
        await assets.update_one({"_id": asset["_id"]}, {"$set": {"link_checked_at": now, "link_http_status": status, "link_health": health, "link_error": error}})
        await audit({"_id": asset["created_by"]}, "MEDIA_REFERENCE_LINK_CHECKED", asset, system_generated=True, link_health=health, http_status=status)


_reference_checker = None


async def reference_check_loop():
    while True:
        try:
            await check_reference_links()
        except Exception:
            # Database outages must not terminate the weekly checker.
            await asyncio.sleep(60)
            continue
        await asyncio.sleep(7 * 24 * 60 * 60)


@router.on_event("startup")
async def start_reference_checker():
    global _reference_checker
    _reference_checker = asyncio.create_task(reference_check_loop())


@router.on_event("shutdown")
async def stop_reference_checker():
    if _reference_checker:
        _reference_checker.cancel()
        try:
            await _reference_checker
        except asyncio.CancelledError:
            pass
