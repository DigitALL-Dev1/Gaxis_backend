"""Document Families management API."""
import os
from datetime import datetime
from typing import List, Optional

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Depends
from api.session_security import family_manager
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

# Load environment variables
load_dotenv()

# Configuration
MONGODB_URL = os.getenv("MONGODB_URL")

# MongoDB client
client = AsyncIOMotorClient(MONGODB_URL)
db = client.get_database("gaxis_lumen")
document_families_collection = db.get_collection("document_families")
users_collection = db.get_collection("users")
roles_collection = db.get_collection("roles")

# Router
router = APIRouter()


# Pydantic models
class DocumentFamilyCreate(BaseModel):
    family_code: str
    family_name: str
    description: Optional[str] = None
    owner_user_id: Optional[str] = None
    releaser_user_ids: List[str] = []
    grant_approver_user_ids: List[str] = []
    is_active: bool = True


class DocumentFamilyUpdate(BaseModel):
    grant_approver_user_ids: Optional[List[str]] = None
    family_name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None


class DocumentFamilyOwnerUpdate(BaseModel):
    owner_user_id: Optional[str] = None


class DocumentFamilyReleasersUpdate(BaseModel):
    releaser_user_ids: List[str]


class DocumentFamilyStatusUpdate(BaseModel):
    is_active: bool


class DocumentFamilyResponse(BaseModel):
    id: str = Field(alias="_id")
    family_code: str
    family_name: str
    description: Optional[str]
    owner_user_id: Optional[str]
    releaser_user_ids: List[str]
    grant_approver_user_ids: List[str] = []
    is_active: bool
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        populate_by_name = True


# Helper functions
async def validate_user_role(user_id: str, required_role_code: str) -> dict:
    """Validate that user exists, is active, and has the required role."""
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid user ID format: {user_id}")
    
    # Get user
    user = await users_collection.find_one({"_id": obj_id})
    if not user:
        raise HTTPException(status_code=404, detail=f"User not found: {user_id}")
    
    # Check if user is active
    user_status = user.get("status", "").upper()
    if user_status != "ACTIVE":
        raise HTTPException(
            status_code=400,
            detail=f"User is not active: {user.get('full_name', user_id)}"
        )
    
    # Get user's roles
    user_role_ids = user.get("role_ids", [])
    
    # Check each role for the required role code
    has_required_role = False
    for role_id in user_role_ids:
        try:
            role_obj_id = ObjectId(role_id) if isinstance(role_id, str) else role_id
            role = await roles_collection.find_one({"_id": role_obj_id})
            if role and role.get("is_active", False) and role.get("role_code") == required_role_code:
                has_required_role = True
                break
        except Exception:
            continue
    
    if not has_required_role:
        raise HTTPException(
            status_code=400,
            detail=f"User '{user.get('full_name', user_id)}' does not have the required role: {required_role_code}"
        )
    
    return user


async def validate_grant_approvers(ids):
    for user_id in ids:
        if not ObjectId.is_valid(user_id):
            raise HTTPException(400, "Invalid grant approver ID")
        user = await users_collection.find_one({"_id": ObjectId(user_id)})
        if not user or user.get("status", "").upper() != "ACTIVE":
            raise HTTPException(400, "Select active divisional managers as grant approvers")
        codes, permissions = set(), set()
        for role_id in user.get("role_ids", []):
            role = await roles_collection.find_one({"_id": ObjectId(role_id)}) if ObjectId.is_valid(role_id) else None
            if role and role.get("is_active"):
                codes.add(role["role_code"]); permissions.update(role.get("permissions", []))
        if not codes.intersection({"MANAGER", "DIVISIONAL_MANAGER"}) or not permissions.intersection({"access_grants.manage", "grants.manage"}):
            raise HTTPException(400, "Grant approvers must be divisional managers with access grant management permission")


# API endpoints
@router.post("/document-families", response_model=DocumentFamilyResponse)
async def create_document_family(family: DocumentFamilyCreate, admin_email: str = Depends(family_manager)):
    """Create a new document family."""
    
    family_code = family.family_code.strip().upper()
    if not family_code:
        raise HTTPException(status_code=400, detail="Family code cannot be empty")
    # Check the normalized code that will be stored.
    existing_family = await document_families_collection.find_one({"family_code": family_code})
    if existing_family:
        raise HTTPException(
            status_code=400,
            detail=f"Document family with code '{family.family_code}' already exists"
        )
    
    # Validate family_name is not empty
    if not family.family_name.strip():
        raise HTTPException(status_code=400, detail="Family name cannot be empty")
    
    # Validate owner if provided
    if family.owner_user_id:
        await validate_user_role(family.owner_user_id, "DOCUMENT_OWNER")
    
    # Validate releasers if provided
    for releaser_id in family.releaser_user_ids:
        await validate_user_role(releaser_id, "DOCUMENT_RELEASER")
    
    # Create document family
    await validate_grant_approvers(family.grant_approver_user_ids)
    family_doc = {
        "family_code": family_code,
        "family_name": family.family_name.strip(),
        "description": family.description.strip() if family.description else None,
        "owner_user_id": family.owner_user_id,
        "releaser_user_ids": family.releaser_user_ids,
        "grant_approver_user_ids": list(dict.fromkeys(family.grant_approver_user_ids)),
        "is_active": family.is_active,
        "created_by": admin_email,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    result = await document_families_collection.insert_one(family_doc)
    family_doc["_id"] = str(result.inserted_id)
    
    return family_doc


@router.get("/document-families", response_model=List[DocumentFamilyResponse])
async def list_document_families(active_only: bool = False):
    """List all document families."""
    
    # Preparation can read the active catalog; the management list requires admin access.
    families = await document_families_collection.find({"is_active": True} if active_only else {}).to_list(length=None)
    
    # Convert ObjectId to string
    for family in families:
        family["_id"] = str(family["_id"])
    
    return families


@router.get("/document-families/{family_id}", response_model=DocumentFamilyResponse, dependencies=[Depends(family_manager)])
async def get_document_family(family_id: str):
    """Get document family details by ID."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(family_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid document family ID format")
    
    family = await document_families_collection.find_one({"_id": obj_id})
    if not family:
        raise HTTPException(status_code=404, detail="Document family not found")
    
    family["_id"] = str(family["_id"])
    return family


@router.patch("/document-families/{family_id}", response_model=DocumentFamilyResponse, dependencies=[Depends(family_manager)])
async def update_document_family(
    family_id: str,
    family_update: DocumentFamilyUpdate
):
    """Update document family details."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(family_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid document family ID format")
    
    # Check if family exists
    existing_family = await document_families_collection.find_one({"_id": obj_id})
    if not existing_family:
        raise HTTPException(status_code=404, detail="Document family not found")
    
    # Prepare update data
    update_data = {k: v for k, v in family_update.model_dump().items() if v is not None}
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    # Validate family_name if provided
    if "family_name" in update_data and not update_data["family_name"].strip():
        raise HTTPException(status_code=400, detail="Family name cannot be empty")
    
    if "grant_approver_user_ids" in update_data:
        await validate_grant_approvers(update_data["grant_approver_user_ids"])
        update_data["grant_approver_user_ids"] = list(dict.fromkeys(update_data["grant_approver_user_ids"]))
    update_data["updated_at"] = datetime.utcnow()
    
    # Update family
    await document_families_collection.update_one(
        {"_id": obj_id},
        {"$set": update_data}
    )
    
    # Get updated family
    updated_family = await document_families_collection.find_one({"_id": obj_id})
    updated_family["_id"] = str(updated_family["_id"])
    
    return updated_family


@router.patch("/document-families/{family_id}/owner", response_model=DocumentFamilyResponse, dependencies=[Depends(family_manager)])
async def update_document_family_owner(
    family_id: str,
    owner_update: DocumentFamilyOwnerUpdate
):
    """Assign document owner to family."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(family_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid document family ID format")
    
    # Check if family exists
    existing_family = await document_families_collection.find_one({"_id": obj_id})
    if not existing_family:
        raise HTTPException(status_code=404, detail="Document family not found")
    
    # Validate owner if provided
    if owner_update.owner_user_id:
        await validate_user_role(owner_update.owner_user_id, "DOCUMENT_OWNER")
    
    # Update owner
    await document_families_collection.update_one(
        {"_id": obj_id},
        {
            "$set": {
                "owner_user_id": owner_update.owner_user_id,
                "updated_at": datetime.utcnow()
            }
        }
    )
    
    # Get updated family
    updated_family = await document_families_collection.find_one({"_id": obj_id})
    updated_family["_id"] = str(updated_family["_id"])
    
    return updated_family


@router.patch("/document-families/{family_id}/releasers", response_model=DocumentFamilyResponse, dependencies=[Depends(family_manager)])
async def update_document_family_releasers(
    family_id: str,
    releasers_update: DocumentFamilyReleasersUpdate
):
    """Assign authorised releasers to family."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(family_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid document family ID format")
    
    # Check if family exists
    existing_family = await document_families_collection.find_one({"_id": obj_id})
    if not existing_family:
        raise HTTPException(status_code=404, detail="Document family not found")
    
    # Validate all releasers
    for releaser_id in releasers_update.releaser_user_ids:
        await validate_user_role(releaser_id, "DOCUMENT_RELEASER")
    
    # Update releasers
    await document_families_collection.update_one(
        {"_id": obj_id},
        {
            "$set": {
                "releaser_user_ids": releasers_update.releaser_user_ids,
                "updated_at": datetime.utcnow()
            }
        }
    )
    
    # Get updated family
    updated_family = await document_families_collection.find_one({"_id": obj_id})
    updated_family["_id"] = str(updated_family["_id"])
    
    return updated_family


@router.patch("/document-families/{family_id}/status", response_model=DocumentFamilyResponse, dependencies=[Depends(family_manager)])
async def update_document_family_status(
    family_id: str,
    status_update: DocumentFamilyStatusUpdate
):
    """Activate or deactivate document family."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(family_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid document family ID format")
    
    # Check if family exists
    existing_family = await document_families_collection.find_one({"_id": obj_id})
    if not existing_family:
        raise HTTPException(status_code=404, detail="Document family not found")
    
    # Update status
    await document_families_collection.update_one(
        {"_id": obj_id},
        {
            "$set": {
                "is_active": status_update.is_active,
                "updated_at": datetime.utcnow()
            }
        }
    )
    
    # Get updated family
    updated_family = await document_families_collection.find_one({"_id": obj_id})
    updated_family["_id"] = str(updated_family["_id"])
    
    return updated_family
