"""Shared authentication for administrator management APIs."""
import os
import secrets

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials


basic_auth = HTTPBasic(auto_error=False)


def require_admin(credentials: HTTPBasicCredentials = Depends(basic_auth)) -> str:
    email = os.getenv("DEFAULT_ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("DEFAULT_ADMIN_PASSWORD", "")
    if not email or not password:
        raise HTTPException(status_code=503, detail="Administrator login is not configured")
    if credentials is None:
        raise HTTPException(status_code=401, detail="Administrator sign in required",
                            headers={"WWW-Authenticate": "Basic"})
    valid_email = secrets.compare_digest(credentials.username.strip().lower().encode(), email.encode())
    valid_password = secrets.compare_digest(credentials.password.encode(), password.encode())
    if not (valid_email and valid_password):
        raise HTTPException(status_code=401, detail="Invalid email or password",
                            headers={"WWW-Authenticate": "Basic"})
    return email
