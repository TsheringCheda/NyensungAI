
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

# =========================================
# APPLICATION CONFIGURATION
# =========================================

from app.config import settings


# =========================================
# DATABASE CONFIGURATION
# =========================================

from app.database import (
    Base,
    engine,
    migrate_security_event_columns
)


# =========================================
# DATABASE MODELS
# =========================================

from app.models.user import User
from app.models.revoked_token import RevokedToken
from app.models.security_event import SecurityEvent
from app.models.incident import Incident, IncidentNote, IncidentAction
from app.models.audit_log import AuditLog


# =========================================
# API ROUTERS
# =========================================

from app.routers import auth
from app.routers import security_events
from app.routers import incidents


# =========================================
# DATABASE INITIALIZATION
# =========================================

# Create any database tables that do not exist.
Base.metadata.create_all(bind=engine)

# Add missing structured endpoint telemetry columns.
# Existing database records are preserved.
migrate_security_event_columns()


# =========================================
# CREATE FASTAPI APPLICATION
# =========================================

IS_PRODUCTION = settings.ENVIRONMENT.lower() == "production"

app = FastAPI(
    title="NyensungAI",
    description=(
        "Intelligent Cyber Threat Detection "
        "and Incident Response Platform"
    ),
    version="1.0.0",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)


# =========================================
# CORS CONFIGURATION
# =========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=(
        [settings.FRONTEND_URL]
        if IS_PRODUCTION
        else list(dict.fromkeys([
            settings.FRONTEND_URL,
            "http://127.0.0.1:5173",
            "http://localhost:5173",
        ]))
    ),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"]
)


# =========================================
# SECURITY RESPONSE HEADERS
# =========================================

@app.middleware("http")
async def security_response_headers(request, call_next):

    response = await call_next(request)

    response.headers.setdefault(
        "X-Content-Type-Options",
        "nosniff"
    )

    response.headers.setdefault(
        "X-Frame-Options",
        "DENY"
    )

    response.headers.setdefault(
        "Referrer-Policy",
        "strict-origin-when-cross-origin"
    )

    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()"
    )

    if IS_PRODUCTION:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains"
        )

    return response


# =========================================
# REGISTER API ROUTERS
# =========================================

app.include_router(auth.router)

app.include_router(security_events.router)

app.include_router(incidents.router)


# =========================================
# ROOT ENDPOINT
# =========================================

@app.get("/")
def root():

    return {
        "project": "NyensungAI",
        "status": "online",
        "message": (
            "NyensungAI defensive threat detection "
            "platform is running"
        )
    }


# =========================================
# HEALTH CHECK ENDPOINT
# =========================================

@app.get("/api/health")
def health():
    """Check actual database connectivity."""

    try:

        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

    except SQLAlchemyError as error:

        raise HTTPException(
            status_code=503,
            detail="Database connection is unavailable"
        ) from error

    return {
        "status": "healthy",
        "database": "connected"
    }
