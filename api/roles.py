"""Roles management API."""
import os
from datetime import datetime
from typing import List, Optional

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Header
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

# Load environment variables
load_dotenv()

# Configuration
MONGODB_URL = os.getenv("MONGODB_URL")
DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD")

# MongoDB client
client = AsyncIOMotorClient(MONGODB_URL)
db = client.get_database("gaxis_lumen")
roles_collection = db.get_collection("roles")

# Router
router = APIRouter()


# Pydantic models
class RoleCreate(BaseModel):
    role_name: str
    role_code: str
    description: str
    permissions: List[str]
    is_active: bool = True


class RoleUpdate(BaseModel):
    role_name: Optional[str] = None
    role_code: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None
    is_active: Optional[bool] = None


class RoleStatusUpdate(BaseModel):
    is_active: bool


class RoleResponse(BaseModel):
    id: str = Field(alias="_id")
    role_name: str
    role_code: str
    description: str
    permissions: List[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        populate_by_name = True


# API endpoints
@router.post("/roles", response_model=RoleResponse)
async def create_role(role: RoleCreate):
    """Create a new role."""
    
    # Check if role_code already exists
    existing_role = await roles_collection.find_one({"role_code": role.role_code})
    if existing_role:
        raise HTTPException(status_code=400, detail=f"Role with code '{role.role_code}' already exists")
    
    # Create role document
    role_doc = {
        "role_name": role.role_name,
        "role_code": role.role_code,
        "description": role.description,
        "permissions": role.permissions,
        "is_active": role.is_active,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    result = await roles_collection.insert_one(role_doc)
    role_doc["_id"] = str(result.inserted_id)
    
    return role_doc


@router.get("/roles", response_model=List[RoleResponse])
async def list_roles():
    """List all roles."""
    
    roles = await roles_collection.find().to_list(length=None)
    
    # Convert ObjectId to string
    for role in roles:
        role["_id"] = str(role["_id"])
    
    return roles


@router.get("/roles/{role_id}", response_model=RoleResponse)
async def get_role(role_id: str):
    """Get role details by ID."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(role_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid role ID format")
    
    role = await roles_collection.find_one({"_id": obj_id})
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    role["_id"] = str(role["_id"])
    return role


@router.put("/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: str,
    role_update: RoleUpdate
):
    """Update role by ID."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(role_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid role ID format")
    
    # Check if role exists
    existing_role = await roles_collection.find_one({"_id": obj_id})
    if not existing_role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    # Prepare update data
    update_data = {k: v for k, v in role_update.model_dump().items() if v is not None}
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    # If role_code is being updated, check for duplicates
    if "role_code" in update_data:
        duplicate = await roles_collection.find_one({
            "role_code": update_data["role_code"],
            "_id": {"$ne": obj_id}
        })
        if duplicate:
            raise HTTPException(
                status_code=400,
                detail=f"Role with code '{update_data['role_code']}' already exists"
            )
    
    update_data["updated_at"] = datetime.utcnow()
    
    # Update role
    await roles_collection.update_one(
        {"_id": obj_id},
        {"$set": update_data}
    )
    
    # Get updated role
    updated_role = await roles_collection.find_one({"_id": obj_id})
    updated_role["_id"] = str(updated_role["_id"])
    
    return updated_role


@router.patch("/roles/{role_id}/status", response_model=RoleResponse)
async def update_role_status(
    role_id: str,
    status_update: RoleStatusUpdate
):
    """Activate or deactivate role."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(role_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid role ID format")
    
    # Check if role exists
    existing_role = await roles_collection.find_one({"_id": obj_id})
    if not existing_role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    # Update status
    await roles_collection.update_one(
        {"_id": obj_id},
        {
            "$set": {
                "is_active": status_update.is_active,
                "updated_at": datetime.utcnow()
            }
        }
    )
    
    # Get updated role
    updated_role = await roles_collection.find_one({"_id": obj_id})
    updated_role["_id"] = str(updated_role["_id"])
    
    return updated_role
