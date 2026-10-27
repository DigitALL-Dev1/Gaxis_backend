"""Opaque, revocable user sessions and permission checks against current database values."""
import hashlib
import os
import secrets
import re
from datetime import datetime, timedelta

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import HTTPException, Request, Response
from motor.motor_asyncio import AsyncIOMotorClient

from api.admin_security import basic_auth, require_admin

load_dotenv()
db = AsyncIOMotorClient(os.getenv("MONGODB_URL")).get_database("gaxis_lumen")
users_collection = db.get_collection("users")
roles_collection = db.get_collection("roles")
reader_classes_collection = db.get_collection("reader_classes")
sessions_collection = db.get_collection("user_sessions")
COOKIE_NAME = "lumen_session"
SESSION_SECONDS = 8 * 60 * 60


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def check_origin(request: Request):
    """Reject browser cookie mutations from origins outside the configured frontend."""
    origin = request.headers.get("origin")
    allowed = {value.strip().rstrip("/") for value in os.getenv("FRONTEND_ORIGINS", "").split(",") if value.strip()}
    allowed.add(str(request.base_url).rstrip("/"))
    if (origin and origin.rstrip("/") not in allowed) or request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Untrusted request origin")


async def user_profile(user_id: str) -> dict:
    if not ObjectId.is_valid(user_id):
        raise HTTPException(401, "Invalid session")
    user = await users_collection.find_one({"_id": ObjectId(user_id)})
    if not user or user.get("status", "").upper() != "ACTIVE":
        raise HTTPException(403, "An active user account is required")
    roles, permissions = [], set()
    for role_id in user.get("role_ids", []):
        if not ObjectId.is_valid(role_id):
            continue
        role = await roles_collection.find_one({"_id": ObjectId(role_id)})
        if role and role.get("is_active", False):
            roles.append({"id": str(role["_id"]), "code": role["role_code"], "name": role["role_name"]})
            permissions.update(value for value in role.get("permissions", []) if isinstance(value, str))
    class_id = user.get("reader_class_id")
    reader = await reader_classes_collection.find_one({"_id": ObjectId(class_id)}) if ObjectId.is_valid(class_id) else None
    if not reader or not reader.get("is_active", False):
        raise HTTPException(403, "An active reader class is required")
    return {
        "message": "Authenticated", "user_id": str(user["_id"]), "email": user["email"],
        "full_name": user["full_name"], "roles": roles,
        "reader_class": {"id": str(reader["_id"]), "code": reader["class_code"], "name": reader["class_name"]},
        "permissions": sorted(permissions), "gaxis_user_id": user.get("gaxis_user_id"), "status": "active",
    }


async def current_profile(request: Request) -> dict:
    if getattr(request.state, "authenticated_profile", None):
        return request.state.authenticated_profile
    token = request.cookies.get(COOKIE_NAME)
    session = await sessions_collection.find_one({"token_hash": token_hash(token), "expires_at": {"$gt": datetime.utcnow()}}) if token else None
    if not session:
        raise HTTPException(401, "Sign in required")
    profile = await user_profile(session["user_id"])
    request.state.user_id = profile["user_id"]
    request.state.authenticated_profile = profile
    return profile


async def create_session(request: Request, response: Response, user_id: str):
    old_token = request.cookies.get(COOKIE_NAME)
    if old_token:
        await sessions_collection.delete_one({"token_hash": token_hash(old_token)})
    token = secrets.token_urlsafe(32)
    await sessions_collection.insert_one({
        "token_hash": token_hash(token), "user_id": user_id,
        "created_at": datetime.utcnow(), "expires_at": datetime.utcnow() + timedelta(seconds=SESSION_SECONDS),
    })
    secure = os.getenv("SESSION_COOKIE_SECURE", "").lower() == "true" or request.url.scheme == "https"
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_SECONDS, httponly=True, secure=secure, samesite="lax", path="/api")
    response.headers["Cache-Control"] = "no-store"


def api_permissions(path: str, method: str) -> list[str]:
    """Permission codes, including existing database aliases, for each API module."""
    if "/roles" in path:
        return ["roles.manage"] + (["users.create", "users.update", "users.manage", "users.read", "document_families.manage"] if method == "GET" else [])
    if "/reader-classes" in path:
        return ["reader_classes.manage"] + (["users.create", "users.update", "users.manage", "users.read", "documents.prepare", "access_grants.manage", "grants.manage"] if method == "GET" else [])
    if "/access-grants" in path:
        return ["access_grants.manage", "grants.manage"]
    if "/users" in path:
        if method == "GET":
            return ["users.read", "users.create", "users.update", "users.manage", "document_families.manage"]
        return ["users.create" if method == "POST" else "users.update", "users.manage"]
    if "/document-families" in path:
        return ["document_families.manage"]
    if "/audit" in path:
        return ["audit.read"]
    if "/prepare" in path or "/my-prepared" in path:
        return ["documents.prepare"]
    if "/release-queue" in path or path.endswith("/documents/review-queue"):
        return ["documents.review", "documents.release"]
    if path.endswith("/reviews") or path.endswith("/file"):
        return ["documents.read", "documents.prepare", "documents.review", "documents.release"]
    if method == "POST" and re.fullmatch(r"/api/v1/lumen/documents/[^/]+/versions", path):
        return ["documents.prepare"]
    if method == "GET" and re.fullmatch(r"/api/v1/lumen/(documents/[^/]+(?:/versions)?|document-versions/[^/]+)", path):
        return ["documents.read", "documents.prepare", "documents.review", "documents.release"]
    if path.endswith("/return"):
        return ["documents.review", "documents.release"]
    if "/release" in path or "/reject" in path or "/return" in path:
        return ["documents.release"]
    if "/acknowledge" in path:
        return ["documents.acknowledge"]
    if "/media" in path:
        return ["media.read"]
    return ["documents.read"]


async def authorize_api(request: Request) -> dict:
    # The active family catalog is needed by the preparation picker before admin login.
    if request.method == "GET" and request.url.path.endswith("/document-families") and request.query_params.get("active_only", "").lower() in ("true", "1"):
        return {}
    if request.headers.get("authorization", "").lower().startswith("basic "):
        email = require_admin(await basic_auth(request))
        request.state.bootstrap_admin = True
        request.state.actor_email = email
        return {"email": email, "bootstrap_admin": True}
    profile = await current_profile(request)
    request.state.actor_email = profile["email"]
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        check_origin(request)
    needed = api_permissions(request.url.path, request.method)
    if not set(needed).intersection(profile["permissions"]):
        raise HTTPException(403, "Access denied: missing required permission")
    uploading_document = request.method == "POST" and (request.url.path.endswith("/documents/prepare") or bool(re.fullmatch(r"/api/v1/lumen/documents/[^/]+/versions", request.url.path)))
    if uploading_document and "documents.submit" not in profile["permissions"]:
        raise HTTPException(403, "Submitting for approval requires documents.submit permission")
    # Caller-supplied actor IDs never establish the identity of a cookie session.
    actor = request.query_params.get("user_id")
    if actor and actor != profile["user_id"] and "/audit" not in request.url.path and "/access-grants" not in request.url.path:
        raise HTTPException(403, "Cannot act as another user")
    if uploading_document:
        form = await request.form()
        if form.get("owner_user_id") != profile["user_id"]:
            raise HTTPException(403, "Cannot prepare as another user")
    if "/access-grants" in request.url.path and request.method not in ("GET", "HEAD", "OPTIONS"):
        if "application/json" in request.headers.get("content-type", ""):
            body = await request.json()
            if isinstance(body, dict):
                for field in ("granted_by", "approved_by", "rejected_by", "revoked_by", "renewed_by"):
                    if field in body and body[field] != profile["user_id"]:
                        raise HTTPException(403, "Cannot act as another user")
    if "/reading-sessions/" in request.url.path:
        session_id = request.path_params.get("session_id")
        if session_id and ObjectId.is_valid(session_id):
            reading_session = await db.get_collection("reading_sessions").find_one({"_id": ObjectId(session_id)})
            if reading_session and str(reading_session.get("user_id")) != profile["user_id"]:
                raise HTTPException(403, "Cannot update another user's reading session")
    return profile


async def family_manager(request: Request) -> str:
    return (await authorize_api(request))["email"]
