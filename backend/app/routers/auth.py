
from uuid import uuid4
from typing import Optional, Literal

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Request,
    Query
)

from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials
)

from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from jose.exceptions import JWTError

from app.database import get_db

from app.models.user import User
from app.models.revoked_token import RevokedToken
from app.models.security_event import SecurityEvent
from app.models.audit_log import AuditLog
from app.services.audit import write_audit_log

from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    UserResponse
)

from app.services.security import (
    verify_password,
    create_access_token,
    decode_access_token
)

from app.services.login_protection import (
    check_login_restriction,
    record_failed_login
)


# =========================================
# AUTHENTICATION ROUTER
# =========================================

router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)

security = HTTPBearer()


# =========================================
# REQUEST EVIDENCE
# =========================================

def generate_request_id() -> str:
    """
    Generate a unique server-side request ID.
    """
    return str(uuid4())


def get_client_ip(request: Request) -> str:
    """
    Get the direct network peer address.

    Forwarded headers are intentionally not trusted.
    Configure trusted proxy handling separately when
    deploying behind a reverse proxy.
    """
    if request.client:
        return request.client.host

    return "unknown"


def get_user_agent(request: Request) -> str:
    """
    Capture the browser or client software information.
    """
    return request.headers.get(
        "user-agent",
        "unknown"
    )[:500]


# =========================================
# RECORD AUTHENTICATION EVENTS
# =========================================

def record_auth_event(
    db: Session,
    event_type: str,
    username: str,
    source_ip: str,
    description: str,
    severity: str = "LOW",
    risk_score: int = 0,
    is_suspicious: bool = False,
    request_id: Optional[str] = None,
    user_agent: Optional[str] = None,
    auth_result: Optional[str] = None,
    failure_reason: Optional[str] = None
):
    """
    Save authentication activity and its evidence
    into the security_events database table.
    """

    try:

        event = SecurityEvent(
            event_type=event_type,
            source="NyensungAI Authentication",
            source_ip=source_ip,
            username=username,
            description=description,
            severity=severity,
            risk_score=risk_score,
            status="NEW",
            is_suspicious=is_suspicious,

            # Authentication evidence
            request_id=request_id,
            user_agent=user_agent,
            auth_result=auth_result,
            failure_reason=failure_reason
        )

        db.add(event)
        db.commit()

    except Exception:

        db.rollback()

        print(
            "Warning: Failed to record authentication event."
        )


# =========================================
# AUTHENTICATION ERROR
# =========================================

def authentication_error():

    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"}
    )


# =========================================
# GET CURRENT AUTHENTICATED USER
# =========================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):

    token = credentials.credentials

    credentials_error = authentication_error()

    try:

        payload = decode_access_token(token)

        user_id = payload.get("sub")
        jti = payload.get("jti")

        if not user_id or not jti:
            raise credentials_error

        user_id = int(user_id)

    except (JWTError, ValueError):

        raise credentials_error

    revoked = db.query(RevokedToken).filter(
        RevokedToken.jti == jti
    ).first()

    if revoked:
        raise credentials_error

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user or not user.is_active:
        raise credentials_error

    return user


# =========================================
# ROLE-BASED AUTHORIZATION
# =========================================

def require_role(*roles):

    def role_checker(
        current_user: User = Depends(get_current_user)
    ):

        if current_user.role not in roles:

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )

        return current_user

    return role_checker


# =========================================
# LOGIN ENDPOINT WITH RATE LIMITING
# =========================================

@router.post(
    "/login",
    response_model=TokenResponse
)
def login(
    request: LoginRequest,
    http_request: Request,
    db: Session = Depends(get_db)
):

    # Generate evidence for this login request
    request_id = generate_request_id()

    email = str(request.email).strip().lower()

    source_ip = get_client_ip(http_request)

    user_agent = get_user_agent(http_request)

    # -------------------------------------
    # STEP 1: CHECK LOGIN RESTRICTIONS
    # -------------------------------------

    restriction = check_login_restriction(
        source_ip=source_ip,
        email=email
    )

    if restriction["blocked"]:

        record_auth_event(
            db=db,
            event_type="RATE_LIMIT_TRIGGERED",
            username=email,
            source_ip=source_ip,
            description=(
                "Login request rejected because a temporary "
                "authentication restriction was active."
            ),
            severity="HIGH",
            risk_score=80,
            is_suspicious=True,
            request_id=request_id,
            user_agent=user_agent,
            auth_result="BLOCKED",
            failure_reason="RATE_LIMITED"
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "Too many login attempts. Try again later.",
                "reason": restriction["reason"],
                "retry_after_seconds": restriction["retry_after"]
            },
            headers={
                "Retry-After": str(restriction["retry_after"])
            }
        )

    # -------------------------------------
    # STEP 2: FIND USER
    # -------------------------------------

    user = db.query(User).filter(
        User.email == email
    ).first()

    # -------------------------------------
    # STEP 3: VERIFY PASSWORD
    # -------------------------------------

    if not user or not verify_password(
        request.password,
        user.hashed_password
    ):

        # Record failed attempt in protection engine
        protection_result = record_failed_login(
            source_ip=source_ip,
            email=email
        )

        account_failures = protection_result[
            "account_failures"
        ]

        # Determine severity and risk
        if (
            protection_result["account_blocked"]
            or protection_result["ip_blocked"]
        ):

            severity = "HIGH"
            risk_score = 80
            suspicious = True

        elif account_failures >= 3:

            severity = "MEDIUM"
            risk_score = 50
            suspicious = True

        else:

            severity = "LOW"
            risk_score = 20
            suspicious = False

        # Record failed login
        record_auth_event(
            db=db,
            event_type="LOGIN_FAILURE",
            username=user.username if user else email,
            source_ip=source_ip,
            description=(
                f"Failed login attempt for account "
                f"{user.username if user else email} "
                f"from IP address {source_ip}. "
                f"Failed attempts for this account and IP: "
                f"{account_failures}."
            ),
            severity=severity,
            risk_score=risk_score,
            is_suspicious=suspicious,
            request_id=request_id,
            user_agent=user_agent,
            auth_result="FAILURE",
            failure_reason="INVALID_CREDENTIALS"
        )

        # Record dedicated rate-limit detection
        if (
            protection_result["account_blocked"]
            or protection_result["ip_blocked"]
        ):

            record_auth_event(
                db=db,
                event_type="RATE_LIMIT_TRIGGERED",
                username=user.username if user else email,
                source_ip=source_ip,
                description=(
                    "NyensungAI activated a temporary login "
                    "restriction after repeated failed "
                    f"authentication attempts from {source_ip}."
                ),
                severity="HIGH",
                risk_score=80,
                is_suspicious=True,
                request_id=request_id,
                user_agent=user_agent,
                auth_result="BLOCKED",
                failure_reason="RATE_LIMITED"
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    # -------------------------------------
    # STEP 4: CHECK ACCOUNT STATUS
    # -------------------------------------

    if not user.is_active:

        record_auth_event(
            db=db,
            event_type="LOGIN_FAILURE",
            username=user.username,
            source_ip=source_ip,
            description=(
                f"Login attempt against disabled account "
                f"{user.username} from {source_ip}."
            ),
            severity="MEDIUM",
            risk_score=40,
            is_suspicious=True,
            request_id=request_id,
            user_agent=user_agent,
            auth_result="FAILURE",
            failure_reason="ACCOUNT_DISABLED"
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )

    # -------------------------------------
    # STEP 5: RECORD SUCCESSFUL LOGIN
    # -------------------------------------

    record_auth_event(
        db=db,
        event_type="LOGIN_SUCCESS",
        username=user.username,
        source_ip=source_ip,
        description=(
            f"User {user.username} successfully logged in "
            f"from IP address {source_ip}."
        ),
        severity="LOW",
        risk_score=0,
        is_suspicious=False,
        request_id=request_id,
        user_agent=user_agent,
        auth_result="SUCCESS",
        failure_reason=None
    )

    # -------------------------------------
    # STEP 6: GENERATE JWT ACCESS TOKEN
    # -------------------------------------

    write_audit_log(db, actor=user, action="USER_LOGIN", target_type="user", target_id=user.id, source_ip=source_ip)
    db.commit()

    access_token = create_access_token(user.id)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }


# =========================================
# GET CURRENT USER
# =========================================

@router.post("/ws-ticket")
def create_websocket_ticket(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user),
):
    """Issue a one-use 30-second ticket; never put the long-lived JWT in a URL."""
    from app.services.realtime import websocket_tickets

    try:
        payload = decode_access_token(credentials.credentials)
        token_jti = payload.get("jti")
        if not token_jti:
            raise JWTError("Missing token ID")
    except JWTError:
        raise authentication_error()

    ticket = websocket_tickets.issue(current_user.id, token_jti)
    return {"ticket": ticket, "expires_in": 30, "single_use": True}


@router.get(
    "/me",
    response_model=UserResponse
)
def get_me(
    current_user: User = Depends(get_current_user)
):

    return current_user


# =========================================
# LOGOUT ENDPOINT
# =========================================

@router.post("/logout")
def logout(
    http_request: Request,
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):

    token = credentials.credentials

    try:

        payload = decode_access_token(token)

        jti = payload.get("jti")

        if not jti:
            raise JWTError("Missing token ID")

    except JWTError:

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    existing = db.query(RevokedToken).filter(
        RevokedToken.jti == jti
    ).first()

    if not existing:

        db.add(RevokedToken(jti=jti))
        db.commit()

    write_audit_log(
        db, actor=current_user, action="USER_LOGOUT", target_type="user",
        target_id=current_user.id, source_ip=get_client_ip(http_request),
    )
    db.commit()

    # Record logout evidence
    request_id = generate_request_id()

    record_auth_event(
        db=db,
        event_type="LOGOUT",
        username=current_user.username,
        source_ip=get_client_ip(http_request),
        description=(
            f"User {current_user.username} logged out."
        ),
        severity="LOW",
        risk_score=0,
        is_suspicious=False,
        request_id=request_id,
        user_agent=get_user_agent(http_request),
        auth_result="SUCCESS",
        failure_reason=None
    )

    return {
        "message": "Successfully logged out"
    }


# =========================================
# ADMINISTRATOR-ONLY TEST ENDPOINT
# =========================================

@router.get("/admin-check")
def admin_check(
    current_user: User = Depends(
        require_role("admin")
    )
):

    return {
        "message": "Administrator access verified",
        "username": current_user.username,
        "role": current_user.role
    }


# =========================================
# ADMINISTRATOR USER AND AUDIT MANAGEMENT
# =========================================

class AdminUserUpdate(BaseModel):
    role: Literal["admin", "analyst", "viewer"] | None = None
    is_active: bool | None = None


@router.get("/users", response_model=list[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    """List account metadata. Password hashes and credentials are never returned."""
    return db.query(User).order_by(User.created_at.desc()).all()


@router.patch("/users/{user_id}", response_model=UserResponse)
def update_user_access(
    user_id: int,
    payload: AdminUserUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No update fields provided")
    if any(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail="Role and active status cannot be null")

    if target.id == admin.id and changes.get("is_active") is False:
        raise HTTPException(status_code=400, detail="You cannot disable your own administrator account")
    if target.id == admin.id and changes.get("role") not in (None, "admin"):
        raise HTTPException(status_code=400, detail="You cannot remove your own administrator role")

    would_remove_admin = (
        target.role == "admin"
        and target.is_active
        and (changes.get("role", target.role) != "admin" or changes.get("is_active", target.is_active) is False)
    )
    if would_remove_admin:
        other_admin_count = db.query(User).filter(
            User.role == "admin", User.is_active.is_(True), User.id != target.id
        ).count()
        if other_admin_count == 0:
            raise HTTPException(status_code=409, detail="At least one active administrator must remain")

    before = {"role": target.role, "is_active": target.is_active}
    for field, value in changes.items():
        setattr(target, field, value)
    write_audit_log(
        db, actor=admin, action="USER_ACCESS_UPDATED", target_type="user",
        target_id=target.id,
        details=f"Account access changed from {before} to {{'role': {target.role!r}, 'is_active': {target.is_active!r}}}",
    )
    try:
        db.commit()
        db.refresh(target)
    except Exception:
        db.rollback()
        raise
    return target


@router.get("/audit-logs")
def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: str | None = Query(None, max_length=100),
    actor: str | None = Query(None, max_length=100),
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action.upper())
    if actor:
        query = query.filter(AuditLog.actor_username.ilike(f"%{actor.strip()}%"))
    total = query.count()
    rows = query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [{
            "id": row.id, "actor_user_id": row.actor_user_id,
            "actor_username": row.actor_username, "action": row.action,
            "target_type": row.target_type, "target_id": row.target_id,
            "details": row.details, "source_ip": row.source_ip,
            "created_at": row.created_at,
        } for row in rows],
        "page": page, "page_size": page_size, "total": total,
        "pages": (total + page_size - 1) // page_size,
    }
