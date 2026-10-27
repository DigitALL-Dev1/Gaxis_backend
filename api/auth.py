"""Simple admin authentication."""
import os
import asyncio
from html import escape
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.security import HTTPBasicCredentials
from api.admin_security import require_admin
from api.session_security import COOKIE_NAME, token_hash, user_profile, current_profile, create_session, check_origin, sessions_collection
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr

# Load environment variables
load_dotenv()

# Configuration
MONGODB_URL = os.getenv("MONGODB_URL")
DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD")

# SMTP Configuration
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM = os.getenv("SMTP_FROM")

# MongoDB client
client = AsyncIOMotorClient(MONGODB_URL)
db = client.get_database("gaxis_lumen")
users_collection = db.get_collection("users")
login_tokens_collection = db.get_collection("login_tokens")

# Router
router = APIRouter()


# Pydantic models
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    message: str
    email: str


class RequestLoginLinkRequest(BaseModel):
    email: EmailStr


class RequestLoginLinkResponse(BaseModel):
    message: str


class VerifyLoginTokenRequest(BaseModel):
    token: str


class VerifyLoginTokenResponse(BaseModel):
    message: str
    user_id: str
    email: str
    full_name: str
    roles: list
    reader_class: dict
    permissions: list
    gaxis_user_id: str | None
    status: str


# Helper functions
def send_login_email(to_email: str, login_link: str, user_name: str):
    """Send login link via email."""
    user_name = escape(user_name)
    login_link = escape(login_link, quote=True)
    try:
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Your GAXIS Lumen Sign-in Link"
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        
        # Create HTML email body
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #2d5016; color: white; padding: 20px; text-align: center; }}
                .content {{ background-color: #f9f9f9; padding: 30px; border: 1px solid #ddd; }}
                .button {{ display: inline-block; background-color: #2d5016; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #666; }}
                .warning {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🍃 GREEN LIMITED</h1>
                    <p>GAXIS-Lumen Knowledge Workspace</p>
                </div>
                <div class="content">
                    <h2>Hello {user_name},</h2>
                    <p>You requested a sign-in link to access GAXIS Lumen. Click the button below to sign in:</p>
                    
                    <div style="text-align: center;">
                        <a href="{login_link}" class="button">Sign in to Lumen</a>
                    </div>
                    
                    <p>Or copy and paste this link in your browser:</p>
                    <p style="background-color: #e9ecef; padding: 10px; border-radius: 3px; word-break: break-all;">
                        {login_link}
                    </p>
                    
                    <div class="warning">
                        <strong>⚠️ Important:</strong>
                        <ul>
                            <li>This link expires in <strong>15 minutes</strong></li>
                            <li>It can only be used <strong>once</strong></li>
                            <li>If you didn't request this link, please ignore this email</li>
                        </ul>
                    </div>
                </div>
                <div class="footer">
                    <p>GREEN Limited · GAXIS-Lumen · Authorised access only</p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create plain text alternative
        text = f"""
        Hello {user_name},
        
        You requested a sign-in link to access GAXIS Lumen.
        
        Click or copy this link to sign in:
        {login_link}
        
        Important:
        - This link expires in 15 minutes
        - It can only be used once
        - If you didn't request this link, please ignore this email
        
        GREEN Limited · GAXIS-Lumen · Authorised access only
        """
        
        # Attach both plain text and HTML versions
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        msg.attach(part1)
        msg.attach(part2)
        
        # Send email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        
        return True
    except Exception:
        print("Failed to send login email")
        return False


# API endpoints
@router.post("/login", response_model=LoginResponse)
async def admin_login(login_data: LoginRequest):
    """Admin login endpoint - verify email and password."""
    email = require_admin(HTTPBasicCredentials(
        username=str(login_data.email), password=login_data.password
    ))
    
    return LoginResponse(
        message="Login successful",
        email=email
    )


@router.post("/request-login-link", response_model=RequestLoginLinkResponse)
async def request_login_link(data: RequestLoginLinkRequest):
    """Send the single-use secret only to the registered mailbox."""
    email = str(data.email).strip().lower()
    message = "If that email is registered and active, a sign-in link has been sent."
    user = await users_collection.find_one({"email": email})
    if not user or user.get("status", "").upper() != "ACTIVE":
        return {"message": message}
    token = secrets.token_urlsafe(32)
    digest = token_hash(token)
    await login_tokens_collection.insert_one({
        "token_hash": digest, "user_id": str(user["_id"]), "email": email,
        "expires_at": datetime.utcnow() + timedelta(minutes=15), "used": False,
        "created_at": datetime.utcnow(),
    })
    frontend = os.getenv("FRONTEND_BASE_URL", "http://127.0.0.1:8081").rstrip("/")
    link = f"{frontend}/verify-login#token={token}"
    sent = await asyncio.to_thread(send_login_email, email, link, user.get("full_name", "User"))
    if not sent:
        await login_tokens_collection.delete_one({"token_hash": digest})
        raise HTTPException(503, "Unable to send the sign-in email. Please try again later.")
    return {"message": message}


@router.post("/verify-login-token", response_model=VerifyLoginTokenResponse)
async def verify_login_token(data: VerifyLoginTokenRequest, request: Request, response: Response):
    """Atomically consume a valid login token and establish an HttpOnly session."""
    check_origin(request)
    token_doc = await login_tokens_collection.find_one_and_update({
        "token_hash": token_hash(data.token), "used": False,
        "expires_at": {"$gt": datetime.utcnow()},
    }, {"$set": {"used": True, "used_at": datetime.utcnow()}})
    if not token_doc:
        raise HTTPException(401, "This sign-in link is invalid, expired, or has already been used.")
    profile = await user_profile(token_doc["user_id"])
    await create_session(request, response, profile["user_id"])
    return profile


@router.get("/me", response_model=VerifyLoginTokenResponse)
async def me(request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return await current_profile(request)


@router.post("/logout")
async def logout(request: Request, response: Response):
    check_origin(request)
    token = request.cookies.get(COOKIE_NAME)
    if token:
        await sessions_collection.delete_one({"token_hash": token_hash(token)})
    response.delete_cookie(COOKIE_NAME, path="/api", httponly=True, samesite="lax")
    response.headers["Cache-Control"] = "no-store"
    return {"message": "Signed out"}
