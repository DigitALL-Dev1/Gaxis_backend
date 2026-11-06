"""Lumen development API. Replace bootstrap auth with GAXIS M1 for production."""
import os
from fastapi import Depends, FastAPI, Request, status
from fastapi.responses import JSONResponse
from api.session_security import authorize_api
from fastapi.middleware.cors import CORSMiddleware
from api.auth import router as auth_router
from api.roles import router as roles_router
from api.reader_classes import router as reader_classes_router
from api.users import router as users_router
from api.document_families import router as document_families_router
from api.documents import router as documents_router
from api.document_reviews import router as reviews_router
from api.access_grants import router as access_grants_router
from api.document_reader import router as document_reader_router
from api.media import router as media_router
from dotenv import load_dotenv
import traceback

# Load environment variables
load_dotenv()

# Create FastAPI app
app = FastAPI(title="Gaxis Lumen API", version="1.0.0")

# Global exception handler for better debugging
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"Global exception handler caught: {type(exc).__name__}")
    print(f"Error: {str(exc)}")
    print(f"Traceback: {traceback.format_exc()}")
    
    # Return proper error response
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": f"Internal server error: {str(exc)}",
            "type": type(exc).__name__
        },
        headers={
            "Access-Control-Allow-Origin": request.headers.get("origin", "*"),
            "Access-Control-Allow-Credentials": "true",
        }
    )

# CORS configuration
FRONTEND_ORIGINS = [origin.strip() for origin in os.getenv("FRONTEND_ORIGINS", "").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Include routers
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(roles_router, prefix="/api/v1", tags=["Roles Management"], dependencies=[Depends(authorize_api)])
app.include_router(reader_classes_router, prefix="/api/v1/lumen", tags=["Reader Classes"], dependencies=[Depends(authorize_api)])
app.include_router(users_router, prefix="/api/v1/lumen", tags=["User Management"], dependencies=[Depends(authorize_api)])
app.include_router(document_families_router, prefix="/api/v1/lumen", tags=["Document Families"], dependencies=[Depends(authorize_api)])
app.include_router(reviews_router, prefix="/api/v1/lumen", tags=["Document Reviews"], dependencies=[Depends(authorize_api)])
app.include_router(documents_router, prefix="/api/v1/lumen", tags=["Document Management"], dependencies=[Depends(authorize_api)])
app.include_router(document_reader_router, prefix="/api/v1/lumen", tags=["Document Reader & Secure Access"], dependencies=[Depends(authorize_api)])
app.include_router(access_grants_router, prefix="/api/v1/lumen", tags=["Access Grants Management"], dependencies=[Depends(authorize_api)])
app.include_router(media_router, prefix="/api/v1/lumen", tags=["Media Management"], dependencies=[Depends(authorize_api)])


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Gaxis Lumen API", "status": "running"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=True)
