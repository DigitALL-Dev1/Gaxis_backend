"""User Management API."""
import os
from datetime import datetime
from typing import List, Optional

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Header, Request
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field

# Load environment variables
load_dotenv()

# Configuration
MONGODB_URL = os.getenv("MONGODB_URL")
DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD")

# MongoDB client
client = AsyncIOMotorClient(MONGODB_URL)
db = client.get_database("gaxis_lumen")
users_collection = db.get_collection("users")
roles_collection = db.get_collection("roles")
reader_classes_collection = db.get_collection("reader_classes")

# Router
router = APIRouter()


@router.on_event("startup")
async def initialize_user_indexes():
    """Allow multiple users without an external GAXIS identity."""
    indexes = await users_collection.index_information()
    user_id_indexes = {
        name: index for name, index in indexes.items()
        if index.get("key") == [("gaxis_user_id", 1)]
    }
    has_sparse_unique_index = any(
        index.get("unique") and index.get("sparse")
        for index in user_id_indexes.values()
    )

    if not has_sparse_unique_index:
        for name in user_id_indexes:
            await users_collection.drop_index(name)

    await users_collection.update_many(
        {"gaxis_user_id": None},
        {"$unset": {"gaxis_user_id": ""}},
    )

    if not has_sparse_unique_index:
        await users_collection.create_index("gaxis_user_id", unique=True, sparse=True)


# Valid user types
VALID_USER_TYPES = ["EMPLOYEE", "CONTRACTOR", "CONSULTANT", "SUBCONTRACTOR", "EXTERNAL_REVIEWER"]

# Valid status values
VALID_STATUS = ["PENDING", "ACTIVE", "INACTIVE"]


# Pydantic models
class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    user_type: str = "EMPLOYEE"
    role_ids: List[str]
    reader_class_id: str
    department: Optional[str] = None


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    user_type: Optional[str] = None
    department: Optional[str] = None
    role_ids: Optional[List[str]] = None
    reader_class_id: Optional[str] = None


class UserRolesUpdate(BaseModel):
    role_ids: List[str]


class UserReaderClassUpdate(BaseModel):
    reader_class_id: str


class UserStatusUpdate(BaseModel):
    status: str


class UserResponse(BaseModel):
    id: str = Field(alias="_id")
    gaxis_user_id: Optional[str] = None
    full_name: str
    email: str
    user_type: Optional[str] = None
    role_ids: List[str]
    reader_class_id: str
    department: Optional[str] = None
    status: str
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        populate_by_name = True


# Helper functions
def validate_user_type(user_type: str):
    """Validate user_type value."""
    if user_type not in VALID_USER_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid user_type. Must be one of: {', '.join(VALID_USER_TYPES)}"
        )


def validate_status(status: str):
    """Validate status value."""
    if status not in VALID_STATUS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(VALID_STATUS)}"
        )


async def validate_roles(role_ids: List[str]):
    """Validate that all roles exist and are active."""
    if not role_ids:
        raise HTTPException(status_code=400, detail="At least one role is required")
    
    # Convert string IDs to ObjectId
    try:
        obj_ids = [ObjectId(role_id) for role_id in role_ids]
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid role ID format")
    
    # Check each role exists and is active
    for obj_id in obj_ids:
        role = await roles_collection.find_one({"_id": obj_id})
        if not role:
            raise HTTPException(status_code=404, detail=f"Role not found: {str(obj_id)}")
        if not role.get("is_active", False):
            raise HTTPException(status_code=400, detail=f"Role is not active: {role.get('role_name')}")
    
    return obj_ids


async def validate_reader_class(reader_class_id: str):
    """Validate that reader class exists and is active."""
    try:
        obj_id = ObjectId(reader_class_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid reader class ID format")
    
    reader_class = await reader_classes_collection.find_one({"_id": obj_id})
    if not reader_class:
        raise HTTPException(status_code=404, detail="Reader class not found")
    if not reader_class.get("is_active", False):
        raise HTTPException(
            status_code=400,
            detail=f"Reader class is not active: {reader_class.get('class_name')}"
        )
    
    return obj_id


def normalize_user_data(user: dict) -> dict:
    """Normalize user data by converting ObjectIds to strings and handling missing fields."""
    user["_id"] = str(user["_id"])
    if user.get("created_by") is not None:
        user["created_by"] = str(user["created_by"])
    
    # Convert role_ids ObjectIds to strings
    if "role_ids" in user:
        user["role_ids"] = [str(role_id) if isinstance(role_id, ObjectId) else role_id for role_id in user["role_ids"]]
    else:
        user["role_ids"] = []
    
    # Convert reader_class_id ObjectId to string
    if "reader_class_id" in user:
        if isinstance(user["reader_class_id"], ObjectId):
            user["reader_class_id"] = str(user["reader_class_id"])
    else:
        user["reader_class_id"] = ""
    
    # Set default values for missing fields
    if "gaxis_user_id" not in user:
        user["gaxis_user_id"] = None
    if "user_type" not in user:
        user["user_type"] = None
    if "department" not in user:
        user["department"] = None
    
    return user


# API endpoints
@router.post("/users", response_model=UserResponse)
async def create_user(user: UserCreate, request: Request):
    """Create a new user."""
    
    # Set default admin email
    admin = getattr(request.state, "actor_email", DEFAULT_ADMIN_EMAIL)
    
    # Validate user_type
    validate_user_type(user.user_type)
    
    # Check if email already exists
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail=f"User with email '{user.email}' already exists")
    
    # Validate all assigned roles exist and are active
    role_obj_ids = await validate_roles(user.role_ids)
    
    # Validate reader class exists and is active
    reader_class_obj_id = await validate_reader_class(user.reader_class_id)
    
    # Create user document
    user_doc = {
        "full_name": user.full_name,
        "email": user.email,
        "user_type": user.user_type,
        "role_ids": [str(obj_id) for obj_id in role_obj_ids],
        "reader_class_id": str(reader_class_obj_id),
        "department": user.department,
        "status": "ACTIVE",
        "created_by": admin,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    result = await users_collection.insert_one(user_doc)
    user_doc["_id"] = str(result.inserted_id)
    
    return user_doc


@router.get("/users", response_model=List[UserResponse])
async def list_users():
    """List all users."""
    
    users = await users_collection.find().to_list(length=None)
    
    # Convert ObjectId to string and handle missing fields
    for user in users:
        user["_id"] = str(user["_id"])
        
        # Convert role_ids ObjectIds to strings
        if "role_ids" in user:
            user["role_ids"] = [str(role_id) if isinstance(role_id, ObjectId) else role_id for role_id in user["role_ids"]]
        else:
            user["role_ids"] = []
        
        # Convert reader_class_id ObjectId to string
        if "reader_class_id" in user:
            if isinstance(user["reader_class_id"], ObjectId):
                user["reader_class_id"] = str(user["reader_class_id"])
        else:
            user["reader_class_id"] = ""
        
        # Set default values for missing fields
        if "gaxis_user_id" not in user:
            user["gaxis_user_id"] = None
        if "user_type" not in user:
            user["user_type"] = None
        if "department" not in user:
            user["department"] = None
    
    return [normalize_user_data(user) for user in users]


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: str):
    """Get user details by ID."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    user = await users_collection.find_one({"_id": obj_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user["_id"] = str(user["_id"])
    
    # Convert role_ids ObjectIds to strings
    if "role_ids" in user:
        user["role_ids"] = [str(role_id) if isinstance(role_id, ObjectId) else role_id for role_id in user["role_ids"]]
    else:
        user["role_ids"] = []
    
    # Convert reader_class_id ObjectId to string
    if "reader_class_id" in user:
        if isinstance(user["reader_class_id"], ObjectId):
            user["reader_class_id"] = str(user["reader_class_id"])
    else:
        user["reader_class_id"] = ""
    
    # Set default values for missing fields
    if "gaxis_user_id" not in user:
        user["gaxis_user_id"] = None
    if "user_type" not in user:
        user["user_type"] = None
    if "department" not in user:
        user["department"] = None
    
    return normalize_user_data(user)


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_update: UserUpdate
):
    """Update user details by ID."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    # Check if user exists
    existing_user = await users_collection.find_one({"_id": obj_id})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prepare update data
    update_data = {k: v for k, v in user_update.model_dump().items() if v is not None}
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    # Validate user_type if provided
    if "user_type" in update_data:
        validate_user_type(update_data["user_type"])

    if "role_ids" in update_data:
        update_data["role_ids"] = [str(value) for value in await validate_roles(update_data["role_ids"])]
    if "reader_class_id" in update_data:
        update_data["reader_class_id"] = str(await validate_reader_class(update_data["reader_class_id"]))
    
    # Check email uniqueness if being updated
    if "email" in update_data:
        duplicate = await users_collection.find_one({
            "email": update_data["email"],
            "_id": {"$ne": obj_id}
        })
        if duplicate:
            raise HTTPException(status_code=400, detail=f"User with email '{update_data['email']}' already exists")
    
    update_data["updated_at"] = datetime.utcnow()
    
    # Update user
    await users_collection.update_one(
        {"_id": obj_id},
        {"$set": update_data}
    )
    
    # Get updated user
    updated_user = await users_collection.find_one({"_id": obj_id})
    return normalize_user_data(updated_user)


@router.patch("/users/{user_id}/roles", response_model=UserResponse)
async def update_user_roles(
    user_id: str,
    roles_update: UserRolesUpdate
):
    """Assign/update user roles."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    # Check if user exists
    existing_user = await users_collection.find_one({"_id": obj_id})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate all assigned roles exist and are active
    role_obj_ids = await validate_roles(roles_update.role_ids)
    
    # Update user roles
    await users_collection.update_one(
        {"_id": obj_id},
        {
            "$set": {
                "role_ids": [str(obj_id) for obj_id in role_obj_ids],
                "updated_at": datetime.utcnow()
            }
        }
    )
    
    # Get updated user
    updated_user = await users_collection.find_one({"_id": obj_id})
    return normalize_user_data(updated_user)


@router.patch("/users/{user_id}/reader-class", response_model=UserResponse)
async def update_user_reader_class(
    user_id: str,
    reader_class_update: UserReaderClassUpdate
):
    """Change user reader class."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    # Check if user exists
    existing_user = await users_collection.find_one({"_id": obj_id})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate reader class exists and is active
    reader_class_obj_id = await validate_reader_class(reader_class_update.reader_class_id)
    
    # Update user reader class
    await users_collection.update_one(
        {"_id": obj_id},
        {
            "$set": {
                "reader_class_id": str(reader_class_obj_id),
                "updated_at": datetime.utcnow()
            }
        }
    )
    
    # Get updated user
    updated_user = await users_collection.find_one({"_id": obj_id})
    return normalize_user_data(updated_user)


@router.patch("/users/{user_id}/status", response_model=UserResponse)
async def update_user_status(
    user_id: str,
    status_update: UserStatusUpdate
):
    """Activate or deactivate user."""
    
    # Validate ObjectId
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    # Check if user exists
    existing_user = await users_collection.find_one({"_id": obj_id})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate status
    validate_status(status_update.status)
    
    # Update user status
    await users_collection.update_one(
        {"_id": obj_id},
        {
            "$set": {
                "status": status_update.status,
                "updated_at": datetime.utcnow()
            }
        }
    )
    
    # Get updated user
    updated_user = await users_collection.find_one({"_id": obj_id})
    return normalize_user_data(updated_user)
