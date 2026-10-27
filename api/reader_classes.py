"""Reader Classes management API."""
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
reader_classes_collection = db.get_collection("reader_classes")

# Router
router = APIRouter()

# Valid access basis values
VALID_ACCESS_BASIS = ["ROLE_DEFAULT", "NAMED_ALLOWLIST", "ADMIN_APPOINTMENT"]


# Pydantic models
class ReaderClassCreate(BaseModel):
    class_code: str
    class_name: str
    description: str
    access_basis: str
    requires_document_allowlist: bool
    requires_expiry: bool
    max_grant_days: Optional[int] = None
    allowed_classifications: List[str] = ["D2", "D3"]
    excluded_families: List[str] = []
    is_active: bool = True


class ReaderClassUpdate(BaseModel):
    class_name: Optional[str] = None
    description: Optional[str] = None
    access_basis: Optional[str] = None
    requires_document_allowlist: Optional[bool] = None
    requires_expiry: Optional[bool] = None
    max_grant_days: Optional[int] = None
    allowed_classifications: Optional[List[str]] = None
    excluded_families: Optional[List[str]] = None
    is_active: Optional[bool] = None


class ReaderClassStatusUpdate(BaseModel):
    is_active: bool


class ReaderClassResponse(BaseModel):
    id: str = Field(alias="_id")
    class_code: str
    class_name: str
    description: str
    access_basis: str
    requires_document_allowlist: bool
    requires_expiry: bool
    max_grant_days: Optional[int]
    allowed_classifications: List[str]
    excluded_families: List[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        populate_by_name = True


# Helper functions
def validate_access_basis(access_basis: str):
    """Validate access_basis value."""
    if access_basis not in VALID_ACCESS_BASIS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid access_basis. Must be one of: {', '.join(VALID_ACCESS_BASIS)}"
        )


def validate_max_grant_days(requires_expiry: bool, max_grant_days: Optional[int]):
    """Validate max_grant_days based on requires_expiry."""
    if max_grant_days is not None and not 1 <= max_grant_days <= 90:
        raise HTTPException(status_code=400, detail="max_grant_days must be between 1 and 90")
    if requires_expiry and max_grant_days is None:
        raise HTTPException(
            status_code=400,
            detail="max_grant_days is required when requires_expiry is true"
        )
    
    if not requires_expiry and max_grant_days is not None:
        raise HTTPException(
            status_code=400,
            detail="max_grant_days must be null when requires_expiry is false"
        )


# API endpoints
@router.post("/reader-classes", response_model=ReaderClassResponse)
async def create_reader_class(reader_class: ReaderClassCreate):
    """Create a new reader class."""
    
    # Validate access_basis
    validate_access_basis(reader_class.access_basis)
    
    # Validate max_grant_days
    validate_max_grant_days(reader_class.requires_expiry, reader_class.max_grant_days)
    
    # Check if class_code already exists
    existing_class = await reader_classes_collection.find_one({"class_code": reader_class.class_code})
    if existing_class:
        raise HTTPException(
            status_code=400,
            detail=f"Reader class with code '{reader_class.class_code}' already exists"
        )
    
    # Create reader class document
    class_doc = {
        "class_code": reader_class.class_code,
        "class_name": reader_class.class_name,
        "description": reader_class.description,
        "access_basis": reader_class.access_basis,
        "requires_document_allowlist": reader_class.requires_document_allowlist,
        "requires_expiry": reader_class.requires_expiry,
        "max_grant_days": reader_class.max_grant_days,
        "allowed_classifications": reader_class.allowed_classifications,
        "excluded_families": reader_class.excluded_families,
        "is_active": reader_class.is_active,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    result = await reader_classes_collection.insert_one(class_doc)
    class_doc["_id"] = str(result.inserted_id)
    
    return class_doc


@router.get("/reader-classes", response_model=List[ReaderClassResponse])
async def list_reader_classes():
    """List all reader classes."""
    
    classes = await reader_classes_collection.find().to_list(length=None)
    
    # Convert ObjectId to string
    for cls in classes:
        cls["_id"] = str(cls["_id"])
    
    return classes


@router.get("/reader-classes/{class_id}", response_model=ReaderClassResponse)
async def get_reader_class(class_id: str):
    """Get reader class details by ID."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(class_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid reader class ID format")
    
    reader_class = await reader_classes_collection.find_one({"_id": obj_id})
    if not reader_class:
        raise HTTPException(status_code=404, detail="Reader class not found")
    
    reader_class["_id"] = str(reader_class["_id"])
    return reader_class


@router.patch("/reader-classes/{class_id}", response_model=ReaderClassResponse)
async def update_reader_class(
    class_id: str,
    class_update: ReaderClassUpdate
):
    """Update reader class by ID."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(class_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid reader class ID format")
    
    # Check if reader class exists
    existing_class = await reader_classes_collection.find_one({"_id": obj_id})
    if not existing_class:
        raise HTTPException(status_code=404, detail="Reader class not found")
    
    # Prepare update data
    update_data = {
        k: v for k, v in class_update.model_dump(exclude_unset=True).items()
        if v is not None or k == "max_grant_days"
    }
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    # Validate access_basis if provided
    if "access_basis" in update_data:
        validate_access_basis(update_data["access_basis"])
    
    # Validate max_grant_days if requires_expiry is being updated
    if "requires_expiry" in update_data or "max_grant_days" in update_data:
        requires_expiry = update_data.get("requires_expiry", existing_class["requires_expiry"])
        max_grant_days = update_data.get("max_grant_days", existing_class["max_grant_days"])
        validate_max_grant_days(requires_expiry, max_grant_days)
    
    update_data["updated_at"] = datetime.utcnow()
    
    # Update reader class
    await reader_classes_collection.update_one(
        {"_id": obj_id},
        {"$set": update_data}
    )
    
    # Get updated reader class
    updated_class = await reader_classes_collection.find_one({"_id": obj_id})
    updated_class["_id"] = str(updated_class["_id"])
    
    return updated_class


@router.patch("/reader-classes/{class_id}/status", response_model=ReaderClassResponse)
async def update_reader_class_status(
    class_id: str,
    status_update: ReaderClassStatusUpdate
):
    """Activate or deactivate reader class."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(class_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid reader class ID format")
    
    # Check if reader class exists
    existing_class = await reader_classes_collection.find_one({"_id": obj_id})
    if not existing_class:
        raise HTTPException(status_code=404, detail="Reader class not found")
    
    # Update status
    await reader_classes_collection.update_one(
        {"_id": obj_id},
        {
            "$set": {
                "is_active": status_update.is_active,
                "updated_at": datetime.utcnow()
            }
        }
    )
    
    # Get updated reader class
    updated_class = await reader_classes_collection.find_one({"_id": obj_id})
    updated_class["_id"] = str(updated_class["_id"])
    
    return updated_class
