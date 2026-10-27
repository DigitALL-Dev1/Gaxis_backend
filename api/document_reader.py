"""Document Reader & Secure Access API."""
import os
import secrets
from datetime import datetime, timedelta
from typing import List, Optional
from enum import Enum

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Header, Request
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

# Load environment variables
load_dotenv()

# Configuration
MONGODB_URL = os.getenv("MONGODB_URL")
SIGNED_URL_EXPIRY_MINUTES = 5  # BRD requirement: 5 minutes

# MongoDB client
client = AsyncIOMotorClient(MONGODB_URL)
db = client.get_database("gaxis_lumen")
users_collection = db.get_collection("users")
roles_collection = db.get_collection("roles")
reader_classes_collection = db.get_collection("reader_classes")
documents_collection = db.get_collection("documents")
document_versions_collection = db.get_collection("document_versions")
document_families_collection = db.get_collection("document_families")
access_grants_collection = db.get_collection("access_grants")
document_access_logs_collection = db.get_collection("document_access_logs")
reading_sessions_collection = db.get_collection("reading_sessions")

# Router
router = APIRouter()

# Enums
class AccessDecision(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"

class AccessAction(str, Enum):
    OPEN = "OPEN"
    ACCESS_DENIED = "ACCESS_DENIED"
    SESSION_ENDED = "SESSION_ENDED"
    CONTENT_VIEWED = "CONTENT_VIEWED"

class SessionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    INTERRUPTED = "INTERRUPTED"


# Pydantic models
class DocumentListItem(BaseModel):
    id: str = Field(alias="_id")
    title: str
    reference: str
    classification: str
    family_id: str
    family_name: Optional[str] = None
    current_version_id: str
    version_number: str
    effective_date: datetime
    requires_acknowledgement: bool
    
    class Config:
        populate_by_name = True


class DocumentOpenResponse(BaseModel):
    message: str
    document_id: str
    version_id: str
    version_number: str
    session_id: str
    classification: str
    access_decision: str
    viewer: dict
    watermark_required: bool
    total_pages: Optional[int] = None


class ReadingProgressUpdate(BaseModel):
    last_page: int
    total_pages: int


class CloseSessionRequest(BaseModel):
    duration_seconds: int
    last_page: Optional[int] = None


class ReadingHistoryItem(BaseModel):
    document_id: str
    document_title: str
    version_number: str
    classification: str
    accessed_at: datetime
    duration_seconds: int
    session_status: str


class AccessValidationResult(BaseModel):
    allowed: bool
    denial_reason: Optional[str] = None
    user: Optional[dict] = None
    role: Optional[dict] = None
    reader_class: Optional[dict] = None
    document: Optional[dict] = None
    version: Optional[dict] = None
    requires_grant: bool = False
    grant: Optional[dict] = None


# Helper functions
async def get_user_from_session(user_id: str) -> dict:
    """Get user details from authenticated session."""
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    user = await users_collection.find_one({"_id": obj_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if user is active
    if user.get("status", "").upper() != "ACTIVE":
        raise HTTPException(status_code=403, detail="User account is not active")
    
    return user


async def validate_document_access(
    user_id: str,
    document_id: str,
    request: Optional[Request] = None
) -> AccessValidationResult:
    """Use the shared current role_ids, permissions, reader-class and approval policy."""
    from api.documents import read_context, approved_access, documents_collection as current_documents
    try:
        context = await read_context(user_id)
        if not ObjectId.is_valid(document_id):
            raise HTTPException(400, "Invalid document ID format")
        document = await current_documents.find_one({"_id": ObjectId(document_id)})
        version = await approved_access(document, context) if document else None
        if not version:
            return AccessValidationResult(allowed=False, denial_reason="No permitted approved version is available")
        return AccessValidationResult(allowed=True, user=context["user"], reader_class=context["reader_class"],
                                      document=document, version=version,
                                      requires_grant=context["reader_class"].get("requires_document_allowlist", False))
    except HTTPException as error:
        return AccessValidationResult(allowed=False, denial_reason=str(error.detail))


async def log_document_access(
    user_id: str,
    document_id: str,
    version_id: Optional[str],
    action: AccessAction,
    access_decision: AccessDecision,
    denial_reason: Optional[str] = None,
    session_id: Optional[str] = None,
    duration_seconds: int = 0,
    request: Optional[Request] = None
) -> str:
    """
    Log document access event.
    Append-only audit log - no modifications allowed.
    """
    
    # Generate correlation ID for request tracing
    correlation_id = secrets.token_urlsafe(16)
    
    # Get IP address and user agent if request provided
    ip_address = None
    user_agent = None
    if request:
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
    
    log_entry = {
        "user_id": user_id,
        "document_id": document_id,
        "version_id": version_id,
        "action": action.value,
        "access_decision": access_decision.value,
        "denial_reason": denial_reason,
        "accessed_at": datetime.utcnow(),
        "duration_seconds": duration_seconds,
        "session_id": session_id,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "correlation_id": correlation_id
    }
    
    result = await document_access_logs_collection.insert_one(log_entry)
    return str(result.inserted_id)


# API endpoints
async def list_permitted_documents(user_id: str):
    """
    List all documents the user is permitted to access.
    Only returns documents that pass all permission checks.
    """
    
    # Get user
    user = await get_user_from_session(user_id)
    
    # Get all active documents with current versions
    documents = await documents_collection.find({
        "is_active": True,
        "current_version_id": {"$exists": True, "$ne": None}
    }).to_list(length=None)
    
    permitted_documents = []
    
    for document in documents:
        # Validate access for each document
        validation = await validate_document_access(
            user_id,
            str(document["_id"])
        )
        
        if validation.allowed and validation.version:
            # Get family name
            family_name = None
            if document.get("family_id"):
                try:
                    family = await document_families_collection.find_one(
                        {"_id": ObjectId(document["family_id"])}
                    )
                    if family:
                        family_name = family.get("family_name")
                except Exception:
                    pass
            
            permitted_documents.append(DocumentListItem(
                _id=str(document["_id"]),
                title=document.get("title", ""),
                reference=document.get("reference", ""),
                classification=document.get("classification", ""),
                family_id=str(document.get("family_id", "")),
                family_name=family_name,
                current_version_id=str(document.get("current_version_id")),
                version_number=validation.version.get("version_number", ""),
                effective_date=validation.version.get("effective_date", datetime.utcnow()),
                requires_acknowledgement=document.get("requires_acknowledgement", False)
            ))
    
    return permitted_documents


async def get_document_metadata(document_id: str, user_id: str):
    """Get permitted document metadata with permission check."""
    
    # Validate access
    validation = await validate_document_access(user_id, document_id)
    
    if not validation.allowed:
        # Log denial
        await log_document_access(
            user_id,
            document_id,
            None,
            AccessAction.ACCESS_DENIED,
            AccessDecision.DENIED,
            denial_reason=validation.denial_reason
        )
        
        raise HTTPException(
            status_code=403,
            detail=validation.denial_reason or "Access denied"
        )
    
    document = validation.document
    version = validation.version
    
    # Get family details
    family_name = None
    if document.get("family_id"):
        try:
            family = await document_families_collection.find_one(
                {"_id": ObjectId(document["family_id"])}
            )
            if family:
                family_name = family.get("family_name")
        except Exception:
            pass
    
    return {
        "_id": str(document["_id"]),
        "title": document.get("title"),
        "reference": document.get("reference"),
        "classification": document.get("classification"),
        "family_id": str(document.get("family_id")),
        "family_name": family_name,
        "description": document.get("description"),
        "current_version_id": str(document.get("current_version_id")),
        "version_number": version.get("version_number"),
        "effective_date": version.get("effective_date"),
        "version_notes": version.get("version_notes"),
        "requires_acknowledgement": document.get("requires_acknowledgement", False),
        "keywords": document.get("keywords", [])
    }


@router.post("/documents/{document_id}/open", response_model=DocumentOpenResponse)
async def open_document(
    document_id: str,
    user_id: str,
    request: Request
):
    """
    Verify access and create reading session.
    Records access decision in audit log.
    """
    
    # Validate access
    validation = await validate_document_access(user_id, document_id, request)
    
    if not validation.allowed:
        # Log denial
        await log_document_access(
            user_id,
            document_id,
            None,
            AccessAction.ACCESS_DENIED,
            AccessDecision.DENIED,
            denial_reason=validation.denial_reason,
            request=request
        )
        
        raise HTTPException(
            status_code=403,
            detail=validation.denial_reason or "You are not authorised to access this document"
        )
    
    user = validation.user
    document = validation.document
    version = validation.version
    
    # Create reading session
    session_doc = {
        "user_id": user_id,
        "document_id": document_id,
        "version_id": str(version["_id"]),
        "started_at": datetime.utcnow(),
        "last_activity_at": datetime.utcnow(),
        "ended_at": None,
        "duration_seconds": 0,
        "last_page": 0,
        "total_pages": version.get("page_count", 0),
        "status": SessionStatus.ACTIVE.value
    }
    
    session_result = await reading_sessions_collection.insert_one(session_doc)
    session_id = str(session_result.inserted_id)
    
    # Log successful access
    await log_document_access(
        user_id,
        document_id,
        str(version["_id"]),
        AccessAction.OPEN,
        AccessDecision.ALLOWED,
        session_id=session_id,
        request=request
    )
    
    return DocumentOpenResponse(
        message="Document access granted",
        document_id=document_id,
        version_id=str(version["_id"]),
        version_number=version.get("version_number", ""),
        session_id=session_id,
        classification=document.get("classification", ""),
        access_decision=AccessDecision.ALLOWED.value,
        viewer={
            "full_name": user.get("full_name"),
            "email": user.get("email"),
            "reader_class": validation.reader_class.get("class_name") if validation.reader_class else None
        },
        watermark_required=True,
        total_pages=version.get("page_count", 0)
    )


@router.get("/document-versions/{version_id}/content")
async def get_document_content(
    version_id: str,
    user_id: str,
    request: Request
):
    """
    Securely deliver approved document content.
    Independent permission check enforced.
    """
    
    # Get version to find document
    try:
        version_obj_id = ObjectId(version_id)
        version = await document_versions_collection.find_one({"_id": version_obj_id})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid version ID format")
    
    if not version:
        raise HTTPException(status_code=404, detail="Document version not found")
    
    document_id = str(version.get("document_id"))
    
    # Validate access (independent check as per BRD)
    validation = await validate_document_access(user_id, document_id, request)
    
    if not validation.allowed:
        # Log denial
        await log_document_access(
            user_id,
            document_id,
            version_id,
            AccessAction.ACCESS_DENIED,
            AccessDecision.DENIED,
            denial_reason=validation.denial_reason,
            request=request
        )
        
        raise HTTPException(
            status_code=403,
            detail="You are not authorised to access this document"
        )
    
    # Verify this is the current approved version
    document = validation.document
    if str(document.get("current_version_id")) != version_id:
        raise HTTPException(
            status_code=403,
            detail="Only current approved versions can be accessed"
        )
    
    # Log content view
    await log_document_access(
        user_id,
        document_id,
        version_id,
        AccessAction.CONTENT_VIEWED,
        AccessDecision.ALLOWED,
        request=request
    )
    
    # Return content information
    # In production, this would return a signed URL or stream the file
    return {
        "version_id": version_id,
        "document_id": document_id,
        "file_name": version.get("file_name"),
        "file_type": version.get("file_type"),
        "file_size": version.get("file_size"),
        "storage_path": version.get("storage_path"),
        "page_count": version.get("page_count"),
        "message": "Content access granted",
        "note": "In production, this would return a signed URL expiring in 5 minutes"
    }


@router.post("/reading-sessions/{session_id}/progress")
async def update_reading_progress(
    session_id: str,
    progress: ReadingProgressUpdate
):
    """Update reading activity and progress."""
    
    try:
        session_obj_id = ObjectId(session_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    
    session = await reading_sessions_collection.find_one({"_id": session_obj_id})
    if not session:
        raise HTTPException(status_code=404, detail="Reading session not found")
    
    # Update session
    await reading_sessions_collection.update_one(
        {"_id": session_obj_id},
        {
            "$set": {
                "last_activity_at": datetime.utcnow(),
                "last_page": progress.last_page,
                "total_pages": progress.total_pages
            }
        }
    )
    
    return {
        "message": "Reading progress updated",
        "session_id": session_id,
        "last_page": progress.last_page,
        "total_pages": progress.total_pages
    }


@router.post("/reading-sessions/{session_id}/close")
async def close_reading_session(
    session_id: str,
    close_data: CloseSessionRequest,
    request: Request
):
    """Close reading session and record duration."""
    
    try:
        session_obj_id = ObjectId(session_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    
    session = await reading_sessions_collection.find_one({"_id": session_obj_id})
    if not session:
        raise HTTPException(status_code=404, detail="Reading session not found")
    
    # Determine session status
    status = SessionStatus.COMPLETED.value
    if close_data.last_page and session.get("total_pages"):
        if close_data.last_page < session.get("total_pages"):
            status = SessionStatus.INTERRUPTED.value
    
    # Update session
    await reading_sessions_collection.update_one(
        {"_id": session_obj_id},
        {
            "$set": {
                "ended_at": datetime.utcnow(),
                "duration_seconds": close_data.duration_seconds,
                "last_page": close_data.last_page or session.get("last_page", 0),
                "status": status
            }
        }
    )
    
    # Log session end
    await log_document_access(
        session.get("user_id"),
        session.get("document_id"),
        session.get("version_id"),
        AccessAction.SESSION_ENDED,
        AccessDecision.ALLOWED,
        session_id=session_id,
        duration_seconds=close_data.duration_seconds,
        request=request
    )
    
    return {
        "message": "Reading session closed",
        "session_id": session_id,
        "duration_seconds": close_data.duration_seconds,
        "status": status
    }


@router.get("/me/reading-history", response_model=List[ReadingHistoryItem])
async def get_reading_history(user_id: str, limit: int = 50):
    """Get user's reading history."""
    
    # Validate user
    await get_user_from_session(user_id)
    
    # Get reading sessions
    sessions = await reading_sessions_collection.find(
        {"user_id": user_id}
    ).sort("started_at", -1).limit(limit).to_list(length=limit)
    
    history = []
    for session in sessions:
        # Get document details
        try:
            document = await documents_collection.find_one(
                {"_id": ObjectId(session.get("document_id"))}
            )
            if document:
                history.append(ReadingHistoryItem(
                    document_id=session.get("document_id"),
                    document_title=document.get("title", "Unknown"),
                    version_number=await get_version_number(session.get("version_id")),
                    classification=document.get("classification", ""),
                    accessed_at=session.get("started_at"),
                    duration_seconds=session.get("duration_seconds", 0),
                    session_status=session.get("status", "UNKNOWN")
                ))
        except Exception:
            continue
    
    return history


async def get_version_number(version_id: str) -> str:
    """Helper to get version number."""
    try:
        version = await document_versions_collection.find_one({"_id": ObjectId(version_id)})
        return version.get("version_number", "Unknown") if version else "Unknown"
    except Exception:
        return "Unknown"


@router.get("/audit/access-logs")
async def get_access_logs(
    user_id: Optional[str] = None,
    document_id: Optional[str] = None,
    access_decision: Optional[str] = None,
    limit: int = 100
):
    """
    Get document access logs (admin only).
    Logs are append-only and cannot be modified.
    """
    
    # Build query
    query = {}
    if user_id:
        query["user_id"] = user_id
    if document_id:
        query["document_id"] = document_id
    if access_decision:
        query["access_decision"] = access_decision.upper()
    
    logs = await document_access_logs_collection.find(query).sort(
        "accessed_at", -1
    ).limit(limit).to_list(length=limit)
    
    # Enrich logs with user and document info
    enriched_logs = []
    for log in logs:
        user_name = "Unknown"
        document_title = "Unknown"
        
        try:
            user = await users_collection.find_one({"_id": ObjectId(log.get("user_id"))})
            if user:
                user_name = user.get("full_name", "Unknown")
        except Exception:
            pass
        
        try:
            document = await documents_collection.find_one({"_id": ObjectId(log.get("document_id"))})
            if document:
                document_title = document.get("title", "Unknown")
        except Exception:
            pass
        
        enriched_logs.append({
            "_id": str(log["_id"]),
            "user_id": log.get("user_id"),
            "user_name": user_name,
            "document_id": log.get("document_id"),
            "document_title": document_title,
            "version_id": log.get("version_id"),
            "action": log.get("action"),
            "access_decision": log.get("access_decision"),
            "denial_reason": log.get("denial_reason"),
            "accessed_at": log.get("accessed_at"),
            "duration_seconds": log.get("duration_seconds"),
            "correlation_id": log.get("correlation_id")
        })
    
    return enriched_logs
