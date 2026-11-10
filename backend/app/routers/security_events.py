

from datetime import datetime, timedelta, timezone
from uuid import uuid4
from typing import Optional, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Header, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from sqlalchemy import func, or_

from app.database import get_db
from app.models.security_event import SecurityEvent
from app.models.incident import Incident

from app.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventResponse,
    SecurityEventUpdate
)

from app.services.threat_detection import analyze_failed_logins
from app.services.anomaly_detection import anomaly_detector
from app.services.llm_investigation import investigate_with_ai
from app.config import settings
from app.services.realtime import event_hub
from app.services.network_detection import detect_possible_port_scan
from app.services.web_attack_detection import inspect_web_request
from app.services.credential_abuse_detection import detect_credential_abuse
from app.routers.auth import get_current_user, require_role
from app.models.audit_log import AuditLog
from app.services.audit import write_audit_log
from app.models.user import User
from app.models.revoked_token import RevokedToken
import hmac


router = APIRouter(
    prefix="/api/security-events",
    tags=["Security Events"]
)



def create_incident_for_alert(db: Session, event: SecurityEvent) -> None:
    """Create one incident for each high/critical detection alert."""
    if event.severity not in ("HIGH", "CRITICAL") and not event.event_type.endswith("_DETECTED"):
        return
    existing = db.query(Incident).filter(Incident.security_event_id == event.id).first()
    if existing:
        return
    priority = "P1" if event.severity == "CRITICAL" else "P2" if event.severity == "HIGH" else "P3"
    incident = Incident(
        incident_number=f"NY-{datetime.now(timezone.utc):%Y%m%d}-{uuid4().hex[:6].upper()}",
        security_event_id=event.id,
        title=event.event_type.replace("_", " ").title(),
        description=event.description, severity=event.severity, priority=priority,
        status="NEW", source_ip=event.source_ip
    )
    db.add(incident)
    db.commit()

# =====================================================
# HELPER 1: CURRENT UTC TIME
# =====================================================

def get_current_utc_time() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# =====================================================
# HELPER 2: PASSWORD SPRAYING DETECTION
# =====================================================

PASSWORD_SPRAYING_WINDOW_MINUTES = 10
PASSWORD_SPRAYING_MIN_FAILURES = 5
PASSWORD_SPRAYING_MIN_USERNAMES = 5
PASSWORD_SPRAYING_MAX_FAILURES_PER_USERNAME = 3


def detect_password_spraying(
    db: Session,
    source_ip: str
) -> dict:
    """
    Detect a possible password-spraying pattern.

    This prototype rule looks for at least five failed logins
    against at least five distinct usernames from one source IP
    during a ten-minute window, with no username receiving more
    than three failures in that window.
    """

    if not source_ip:
        return {
            "detected": False,
            "alert_created": False,
            "message": "A source IP is required."
        }

    cutoff_time = (
        get_current_utc_time()
        - timedelta(minutes=PASSWORD_SPRAYING_WINDOW_MINUTES)
    )

    failed_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_type == "LOGIN_FAILURE",
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= cutoff_time,
            SecurityEvent.username.isnot(None)
        )
        .all()
    )

    username_counts = {}
    for failed_event in failed_events:
        normalized_username = (
            failed_event.username.strip().casefold()
            if failed_event.username else ""
        )
        if normalized_username:
            username_counts[normalized_username] = (
                username_counts.get(normalized_username, 0) + 1
            )

    total_failures = sum(username_counts.values())
    unique_usernames = len(username_counts)
    max_failures_per_username = (
        max(username_counts.values()) if username_counts else 0
    )

    detected = (
        total_failures >= PASSWORD_SPRAYING_MIN_FAILURES
        and unique_usernames >= PASSWORD_SPRAYING_MIN_USERNAMES
        and max_failures_per_username
        <= PASSWORD_SPRAYING_MAX_FAILURES_PER_USERNAME
    )

    if not detected:
        return {
            "detected": False,
            "alert_created": False,
            "total_failed_attempts": total_failures,
            "unique_usernames": unique_usernames,
            "max_failures_per_username": max_failures_per_username,
            "message": "No password-spraying pattern detected."
        }

    existing_alert = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_type == "PASSWORD_SPRAYING_DETECTED",
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= cutoff_time
        )
        .first()
    )

    if existing_alert:
        return {
            "detected": True,
            "alert_created": False,
            "total_failed_attempts": total_failures,
            "unique_usernames": unique_usernames,
            "message": "A password-spraying alert already exists in this window."
        }

    alert = SecurityEvent(
        event_type="PASSWORD_SPRAYING_DETECTED",
        source="NyensungAI Password Spraying Detection Engine",
        source_ip=source_ip,
        username=None,
        description=(
            "Potential password-spraying activity detected: "
            f"{total_failures} failed login attempts across "
            f"{unique_usernames} distinct usernames within "
            f"{PASSWORD_SPRAYING_WINDOW_MINUTES} minutes."
        ),
        severity="HIGH",
        risk_score=85,
        status="NEW",
        is_suspicious=True
    )

    db.add(alert)
    db.commit()

    return {
        "detected": True,
        "alert_created": True,
        "total_failed_attempts": total_failures,
        "unique_usernames": unique_usernames,
        "max_failures_per_username": max_failures_per_username,
        "time_window_minutes": PASSWORD_SPRAYING_WINDOW_MINUTES,
        "severity": "HIGH",
        "risk_score": 85,
        "message": "Potential password-spraying activity detected."
    }


# =====================================================
# HELPER 3: ML AUTHENTICATION ANOMALY DETECTION
# =====================================================

def analyze_authentication_anomaly(
    db: Session,
    source_ip: str,
    username: Optional[str]
):

    cutoff_time = (
        get_current_utc_time()
        - timedelta(minutes=10)
    )

    auth_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.event_type.in_([
                "LOGIN_SUCCESS",
                "LOGIN_FAILURE"
            ]),
            SecurityEvent.timestamp >= cutoff_time
        )
    )

    total_events = auth_events.count()

    failed_logins = (
        auth_events
        .filter(
            SecurityEvent.event_type == "LOGIN_FAILURE"
        )
        .count()
    )

    unique_usernames = (
        db.query(
            func.count(
                func.distinct(SecurityEvent.username)
            )
        )
        .filter(
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.event_type.in_([
                "LOGIN_SUCCESS",
                "LOGIN_FAILURE"
            ]),
            SecurityEvent.timestamp >= cutoff_time,
            SecurityEvent.username.isnot(None)
        )
        .scalar() or 0
    )

    metrics = {
        "failed_logins_10m": failed_logins,
        "total_events_10m": total_events,
        "unique_usernames_10m": unique_usernames
    }

    result = anomaly_detector.analyze(metrics)

    if not result["is_anomaly"]:
        return result

    existing_alert = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_type == "ML_ANOMALY_DETECTED",
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= cutoff_time
        )
        .first()
    )

    if existing_alert:
        return result

    risk_score = result["risk_score"]

    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 60:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    alert = SecurityEvent(
        event_type="ML_ANOMALY_DETECTED",
        source="NyensungAI Isolation Forest ML Engine",
        source_ip=source_ip,
        username=username,
        description=(
            "Unusual authentication behaviour detected "
            "by the Isolation Forest model. "
            f"Risk score: {risk_score}/100. "
            f"Anomaly score: {result['anomaly_score']}. "
            f"Features: {result['features']}."
        ),
        severity=severity,
        risk_score=risk_score,
        status="NEW",
        is_suspicious=True
    )

    db.add(alert)
    db.commit()

    return result


# =====================================================
# HELPER 4: DETECTION METHOD
# =====================================================

def get_detection_method(event_type: str) -> str:

    if event_type == "ML_ANOMALY_DETECTED":
        return "MACHINE_LEARNING"

    elif event_type in [
        "BRUTE_FORCE_DETECTED",
        "PASSWORD_SPRAYING_DETECTED"
    ]:
        return "RULE_BASED"

    elif event_type == "RATE_LIMIT_TRIGGERED":
        return "RATE_LIMITING"

    return "GENERAL_EVENT"


# =====================================================
# HELPER 5: INVESTIGATION EXPLANATION
# =====================================================

def get_detection_explanation(event: SecurityEvent) -> str:

    if event.event_type == "ML_ANOMALY_DETECTED":

        return (
            "The Isolation Forest machine learning model "
            "identified unusual authentication behaviour. "
            "The activity differed from the model's learned "
            "baseline and was marked for investigation."
        )

    elif event.event_type == "BRUTE_FORCE_DETECTED":

        return (
            "The rule-based detection engine identified "
            "repeated failed login attempts from the same "
            "source IP within the configured time window."
        )

    elif event.event_type == "PASSWORD_SPRAYING_DETECTED":

        return (
            "The rule-based detection engine identified failed login "
            "attempts distributed across multiple usernames from the "
            "same source IP within the configured time window. This "
            "pattern may indicate password-spraying activity and "
            "requires investigation."
        )

    elif event.event_type == "RATE_LIMIT_TRIGGERED":

        return (
            "The login protection service activated a "
            "temporary restriction after repeated failed "
            "authentication attempts."
        )

    elif event.event_type == "LOGIN_FAILURE":

        return (
            "A failed authentication attempt was recorded. "
            "Review related login activity to determine "
            "whether this is part of a suspicious pattern."
        )

    elif event.event_type == "LOGIN_SUCCESS":

        return (
            "A successful authentication event was recorded. "
            "Review the source IP and surrounding activity "
            "if the login appears unusual."
        )

    return (
        "This event was recorded by the monitoring system. "
        "Review its source, timestamp and related activity."
    )


# =====================================================
# HELPER 6: RECOMMENDED DEFENSIVE ACTIONS
# =====================================================

def get_recommended_actions(event: SecurityEvent):

    if event.event_type == "BRUTE_FORCE_DETECTED":

        return [
            "Review the failed login attempts from this IP.",
            "Check whether any login attempt was successful.",
            "Verify whether the targeted account is legitimate.",
            "Consider an authorised temporary IP restriction.",
            "Notify the system administrator if activity continues."
        ]

    elif event.event_type == "PASSWORD_SPRAYING_DETECTED":

        return [
            "Review the failed login events and usernames targeted from this IP.",
            "Check whether any targeted account had a subsequent successful login.",
            "Verify whether the source IP belongs to an authorised user or system.",
            "Review affected accounts for unusual activity and enforce MFA where available.",
            "Escalate confirmed suspicious activity to the system administrator."
        ]

    elif event.event_type == "ML_ANOMALY_DETECTED":

        return [
            "Review authentication activity from this IP.",
            "Check the number of unique usernames accessed.",
            "Compare activity with normal user behaviour.",
            "Verify whether the account owner recognises the activity.",
            "Escalate if suspicious behaviour is confirmed."
        ]

    elif event.event_type == "RATE_LIMIT_TRIGGERED":

        return [
            "Review the failed login attempts.",
            "Check whether multiple accounts were targeted.",
            "Review the source IP and account activity.",
            "Keep the temporary restriction active while investigating.",
            "Escalate repeated suspicious activity to an administrator."
        ]

    return [
        "Review the event details and timestamp.",
        "Check related activity from the same source IP.",
        "Verify whether the activity is expected.",
        "Escalate if additional suspicious evidence is found."
    ]


# =====================================================
# 1. CREATE SECURITY EVENT
# =====================================================

@router.post(
    "/",
    response_model=SecurityEventResponse,
    status_code=201
)
def create_security_event(
    event: SecurityEventCreate,
    x_agent_key: Optional[str] = Header(default=None, alias="X-Agent-Key"),
    db: Session = Depends(get_db)
):
    # Agent ingestion is a machine-to-machine boundary. Fail closed until a
    # unique key has been configured in backend/.env.
    configured_key = settings.AGENT_API_KEY
    if not configured_key:
        raise HTTPException(status_code=503, detail="Endpoint ingestion is not configured. Set AGENT_API_KEY in backend/.env.")
    if not x_agent_key or not hmac.compare_digest(x_agent_key, configured_key):
        raise HTTPException(status_code=401, detail="Invalid endpoint agent credentials")

    # Stable endpoint request IDs make ingestion retry-safe if the agent
    # crashes after server commit but before its local checkpoint is saved.
    if event.request_id:
        existing_event = db.query(SecurityEvent).filter(
            SecurityEvent.source == event.source,
            SecurityEvent.request_id == event.request_id
        ).first()
        if existing_event:
            return existing_event

    new_event = SecurityEvent(**event.model_dump())

    db.add(new_event)
    db.commit()
    db.refresh(new_event)
    event_hub.publish_from_sync_route({
        "id": new_event.id,
        "event_type": new_event.event_type,
        "source": new_event.source,
        "source_ip": new_event.source_ip,
        "username": new_event.username,
        "description": new_event.description,
        "severity": new_event.severity,
        "risk_score": new_event.risk_score,
        "status": new_event.status,
        "is_suspicious": new_event.is_suspicious,
        "timestamp": new_event.timestamp.isoformat() if new_event.timestamp else None,
        **get_windows_event_metadata(new_event),
    })

    # Application-layer signatures are evaluated only for explicitly typed
    # HTTP/web request telemetry; arbitrary event descriptions are not scanned.
    web_alerts = inspect_web_request(db, new_event)
    for web_alert in web_alerts:
        event_hub.publish_from_sync_route({
            "id": web_alert.id,
            "event_type": web_alert.event_type,
            "source": web_alert.source,
            "source_ip": web_alert.source_ip,
            "username": web_alert.username,
            "description": web_alert.description,
            "severity": web_alert.severity,
            "risk_score": web_alert.risk_score,
            "status": web_alert.status,
            "is_suspicious": web_alert.is_suspicious,
            "timestamp": web_alert.timestamp.isoformat() if web_alert.timestamp else None,
        })

    # Passive network telemetry detection. This is an indicator for review,
    # not proof of hostile intent or a packet-level scan verdict.
    if new_event.event_type == "NETWORK_CONNECTION_OBSERVED" and new_event.source_ip:
        network_result = detect_possible_port_scan(db, new_event.source_ip)
        if network_result.get("alert_created"):
            network_alert = db.query(SecurityEvent).filter(
                SecurityEvent.id == network_result.get("alert_id")
            ).first()
            if network_alert:
                event_hub.publish_from_sync_route({
                    "id": network_alert.id,
                    "event_type": network_alert.event_type,
                    "source": network_alert.source,
                    "source_ip": network_alert.source_ip,
                    "username": network_alert.username,
                    "description": network_alert.description,
                    "severity": network_alert.severity,
                    "risk_score": network_alert.risk_score,
                    "status": network_alert.status,
                    "is_suspicious": network_alert.is_suspicious,
                    "timestamp": network_alert.timestamp.isoformat() if network_alert.timestamp else None,
                })

    # RULE-BASED BRUTE-FORCE DETECTION

    if (
        new_event.event_type == "LOGIN_FAILURE"
        and new_event.source_ip
    ):

        detection = analyze_failed_logins(
            db,
            new_event.source_ip
        )

        if detection["detected"]:

            cutoff_time = (
                get_current_utc_time()
                - timedelta(minutes=10)
            )

            existing_alert = (
                db.query(SecurityEvent)
                .filter(
                    SecurityEvent.event_type == "BRUTE_FORCE_DETECTED",
                    SecurityEvent.source_ip == new_event.source_ip,
                    SecurityEvent.timestamp >= cutoff_time
                )
                .first()
            )

            if not existing_alert:

                alert = SecurityEvent(
                    event_type="BRUTE_FORCE_DETECTED",
                    source="NyensungAI Threat Detection Engine",
                    source_ip=new_event.source_ip,
                    username=new_event.username,
                    description=(
                        f"Brute-force activity detected. "
                        f"{detection['failed_attempts']} failed "
                        f"login attempts from "
                        f"{new_event.source_ip}."
                    ),
                    severity=detection["severity"],
                    risk_score=detection["risk_score"],
                    status="NEW",
                    is_suspicious=True
                )

                
                db.add(alert)
                db.commit()
                db.refresh(alert)

                # Publish brute-force alert to the real-time dashboard
                event_hub.publish_from_sync_route({
                    "id": alert.id,
                    "event_type": alert.event_type,
                    "source": alert.source,
                    "source_ip": alert.source_ip,
                    "username": alert.username,
                    "description": alert.description,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "status": alert.status,
                    "is_suspicious": alert.is_suspicious,
                    "timestamp": (
                        alert.timestamp.isoformat()
                        if alert.timestamp else None
                    ),
                })


    # PASSWORD SPRAYING DETECTION
    if (
        new_event.event_type == "LOGIN_FAILURE"
        and new_event.source_ip
    ):
        detect_password_spraying(
            db=db,
            source_ip=new_event.source_ip
        )

    # Repeated multi-account failures can indicate credential abuse. This
    # heuristic does not claim credential stuffing without identity-provider evidence.
    if new_event.event_type == "LOGIN_FAILURE" and new_event.source_ip:
        abuse_result = detect_credential_abuse(db, new_event.source_ip)
        if abuse_result.get("alert_created"):
            abuse_alert = db.query(SecurityEvent).filter(
                SecurityEvent.id == abuse_result.get("alert_id")
            ).first()
            if abuse_alert:
                event_hub.publish_from_sync_route({
                    "id": abuse_alert.id,
                    "event_type": abuse_alert.event_type,
                    "source": abuse_alert.source,
                    "source_ip": abuse_alert.source_ip,
                    "username": abuse_alert.username,
                    "description": abuse_alert.description,
                    "severity": abuse_alert.severity,
                    "risk_score": abuse_alert.risk_score,
                    "status": abuse_alert.status,
                    "is_suspicious": abuse_alert.is_suspicious,
                    "timestamp": abuse_alert.timestamp.isoformat() if abuse_alert.timestamp else None,
                })

    # MACHINE LEARNING ANOMALY DETECTION

    if (
        new_event.event_type in [
            "LOGIN_SUCCESS",
            "LOGIN_FAILURE"
        ]
        and new_event.source_ip
    ):

        analyze_authentication_anomaly(
            db=db,
            source_ip=new_event.source_ip,
            username=new_event.username
        )

    # Automatically open incidents for newly generated high/critical alerts.
    recent_alerts = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.source_ip == new_event.source_ip,
            SecurityEvent.timestamp >= get_current_utc_time() - timedelta(minutes=2),
            SecurityEvent.severity.in_(["HIGH", "CRITICAL"]),
            SecurityEvent.event_type.in_(["BRUTE_FORCE_DETECTED", "PASSWORD_SPRAYING_DETECTED", "ML_ANOMALY_DETECTED", "RATE_LIMIT_TRIGGERED", "CREDENTIAL_ABUSE_PATTERN", "WEB_SQL_INJECTION_INDICATOR", "WEB_XSS_INDICATOR", "WEB_PATH_TRAVERSAL_INDICATOR"])
        ).all()
    )
    for alert_event in recent_alerts:
        create_incident_for_alert(db, alert_event)

    # Real endpoint observations explicitly marked HIGH/CRITICAL and
    # suspicious (e.g. Defender detection or audit-log clearing) open incidents.
    create_incident_for_alert(db, new_event)

    return new_event


# =====================================================

# =====================================================
# 2. DASHBOARD STATISTICS
# =====================================================

@router.get("/stats")
def get_security_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 1. Total security events
    total_events = (
        db.query(func.count(SecurityEvent.id))
        .scalar() or 0
    )

    # 2. Active suspicious threats
    active_threats = (
        db.query(func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.is_suspicious.is_(True),
            SecurityEvent.status != "RESOLVED"
        )
        .scalar() or 0
    )

    # 3. Active critical alerts
    critical_alerts = (
        db.query(func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.is_suspicious.is_(True),
            SecurityEvent.severity == "CRITICAL",
            SecurityEvent.status != "RESOLVED"
        )
        .scalar() or 0
    )

    # 4. Open incidents
    open_incidents = (
        db.query(func.count(Incident.id))
        .filter(
            Incident.status.in_([
                "NEW",
                "INVESTIGATING",
                "CONTAINED"
            ])
        )
        .scalar() or 0
    )

    # 5. Machine-learning anomalies
    ml_anomalies = (
        db.query(func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.event_type == "ML_ANOMALY_DETECTED"
        )
        .scalar() or 0
    )

    # 6. Rule-based alerts
    rule_based_alerts = (
        db.query(func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.event_type.in_([
                "BRUTE_FORCE_DETECTED",
                "PASSWORD_SPRAYING_DETECTED"
            ])
        )
        .scalar() or 0
    )

    # Return all six dashboard statistics
    return {
        "total_events": total_events,
        "active_threats": active_threats,
        "critical_alerts": critical_alerts,
        "open_incidents": open_incidents,
        "ml_anomalies": ml_anomalies,
        "rule_based_alerts": rule_based_alerts
    }


# =====================================================
# 3. THREAT ACTIVITY - LAST 24 HOURS
# =====================================================

@router.get("/activity")
def get_threat_activity(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    now = get_current_utc_time()

    current_hour = now.replace(
        minute=0,
        second=0,
        microsecond=0
    )

    start_time = current_hour - timedelta(hours=23)

    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.timestamp >= start_time,
            SecurityEvent.timestamp <= now
        )
        .all()
    )

    hourly_data = {}

    for hour_offset in range(24):

        bucket_time = (
            start_time + timedelta(hours=hour_offset)
        )

        hourly_data[bucket_time] = {
            "time": bucket_time.isoformat() + "Z",
            "normal": 0,
            "suspicious": 0,
            "critical": 0
        }

    for event in events:

        if event.timestamp is None:
            continue

        event_hour = event.timestamp.replace(
            minute=0,
            second=0,
            microsecond=0
        )

        if event_hour not in hourly_data:
            continue

        if event.severity == "CRITICAL":
            hourly_data[event_hour]["critical"] += 1

        elif event.is_suspicious:
            hourly_data[event_hour]["suspicious"] += 1

        else:
            hourly_data[event_hour]["normal"] += 1

    return list(hourly_data.values())


# =====================================================
# 4. GET AND FILTER SECURITY EVENTS
# =====================================================

@router.get(
    "/",
    response_model=list[SecurityEventResponse]
)
def get_security_events(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),

    severity: Optional[
        Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    ] = None,

    status: Optional[
        Literal["NEW", "INVESTIGATING", "RESOLVED"]
    ] = None,

    source_ip: Optional[str] = Query(
        default=None,
        min_length=1,
        max_length=45
    ),
    event_type: Optional[str] = Query(default=None, min_length=2, max_length=100),
    username: Optional[str] = Query(default=None, min_length=1, max_length=100),
    q: Optional[str] = Query(default=None, min_length=1, max_length=200),
    min_risk: Optional[int] = Query(default=None, ge=0, le=100),
    max_risk: Optional[int] = Query(default=None, ge=0, le=100),
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,

    is_suspicious: Optional[bool] = None,

    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    query = db.query(SecurityEvent)

    if min_risk is not None and max_risk is not None and min_risk > max_risk:
        raise HTTPException(status_code=422, detail="min_risk cannot exceed max_risk")
    if since and until and since > until:
        raise HTTPException(status_code=422, detail="since must be earlier than until")
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type.upper())
    if username:
        query = query.filter(SecurityEvent.username.ilike(f"%{username.strip()}%"))
    if q:
        term = f"%{q.strip()}%"
        query = query.filter(
            SecurityEvent.description.ilike(term)
            | SecurityEvent.event_type.ilike(term)
            | SecurityEvent.source.ilike(term)
        )
    if min_risk is not None:
        query = query.filter(SecurityEvent.risk_score >= min_risk)
    if max_risk is not None:
        query = query.filter(SecurityEvent.risk_score <= max_risk)
    if since:
        query = query.filter(SecurityEvent.timestamp >= since)
    if until:
        query = query.filter(SecurityEvent.timestamp <= until)

    if severity:
        query = query.filter(
            SecurityEvent.severity == severity
        )

    if status:
        query = query.filter(
            SecurityEvent.status == status
        )

    if source_ip:
        query = query.filter(
            SecurityEvent.source_ip.contains(source_ip)
        )

    if is_suspicious is not None:
        query = query.filter(
            SecurityEvent.is_suspicious == is_suspicious
        )

    return (
        query
        .order_by(SecurityEvent.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


# =====================================================
# 5. GET SECURITY EVENT BY ID
# =====================================================

@router.get(
    "/{event_id}",
    response_model=SecurityEventResponse
)
def get_security_event(
    event_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id)
        .first()
    )

    if not event:

        raise HTTPException(
            status_code=404,
            detail="Security event not found"
        )

    return event


# =====================================================
# 6. UPDATE INVESTIGATION STATUS
# =====================================================

@router.patch(
    "/{event_id}",
    response_model=SecurityEventResponse
)
def update_security_event(
    event_id: int,
    update_data: SecurityEventUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    if current_user.role not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id)
        .first()
    )

    if not event:

        raise HTTPException(
            status_code=404,
            detail="Security event not found"
        )

    previous_status = event.status
    event.status = update_data.status
    write_audit_log(
        db, actor=current_user, action="SECURITY_EVENT_STATUS_UPDATED",
        target_type="security_event", target_id=event.id,
        details=f"Status changed from {previous_status} to {event.status}",
    )

    db.commit()
    db.refresh(event)

    return event


# =====================================================
# 7. AI THREAT INVESTIGATION
# =====================================================

INVESTIGATION_WINDOW_MINUTES = 10
MAX_RELATED_EVENTS = 100


def format_utc_timestamp(value):
    """Format timestamps consistently; database timestamps are stored as UTC."""
    if value is None:
        return None

    # SQLite commonly returns naive datetimes. This application stores those
    # values as UTC, so append Z. Preserve an explicit offset if one exists.
    if value.tzinfo is None:
        return value.isoformat() + "Z"

    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def get_windows_event_metadata(event: SecurityEvent) -> dict:
    """Return native Windows Event Log fields without conflating them with DB IDs."""
    return {
        "windows_event_id": getattr(event, "windows_event_id", None),
        "windows_record_id": getattr(event, "windows_record_id", None),
        "windows_channel": getattr(event, "windows_channel", None),
        "windows_status": getattr(event, "windows_status", None),
        "windows_sub_status": getattr(event, "windows_sub_status", None),
        "windows_logon_type": getattr(event, "windows_logon_type", None),
        "windows_event_timestamp": format_utc_timestamp(
            getattr(event, "windows_event_timestamp", None)
        ),
    }


def retrieve_related_evidence(
    db: Session,
    event: SecurityEvent
) -> tuple[list, bool, datetime | None]:
    """Retrieve related historical events, never events after the alert.

    An event is related when its source IP, username, or request ID matches.
    Request IDs can connect multiple records generated by the same HTTP request.
    Only records in the configured time window ending at the investigated
    event timestamp are eligible. Fetch one extra row to detect truncation.
    """
    if event.timestamp is None:
        return [], False, None

    window_start = event.timestamp - timedelta(
        minutes=INVESTIGATION_WINDOW_MINUTES
    )

    correlation_conditions = []

    if event.source_ip and event.source_ip.strip():
        correlation_conditions.append(
            SecurityEvent.source_ip == event.source_ip.strip()
        )

    if event.username and event.username.strip():
        # SQL lower() is supported by SQLite and common SQL databases.
        correlation_conditions.append(
            func.lower(func.trim(SecurityEvent.username))
            == event.username.strip().lower()
        )

    if event.request_id and event.request_id.strip():
        correlation_conditions.append(
            SecurityEvent.request_id == event.request_id.strip()
        )

    if not correlation_conditions:
        return [], False, window_start

    matches = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.id != event.id,
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.timestamp <= event.timestamp,
            or_(*correlation_conditions)
        )
        .order_by(
            SecurityEvent.timestamp.asc(),
            SecurityEvent.id.asc()
        )
        .limit(MAX_RELATED_EVENTS + 1)
        .all()
    )

    truncated = len(matches) > MAX_RELATED_EVENTS
    return matches[:MAX_RELATED_EVENTS], truncated, window_start


@router.get("/{event_id}/investigation")
def investigate_security_event(
    event_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Build an evidence-backed investigation and request local AI analysis.

    AI recommendations are advisory only. This endpoint does not block IPs,
    change firewall rules, disable accounts, or execute response actions.
    """

    # 1. Retrieve the event being investigated.
    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id)
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=404,
            detail="Security event not found"
        )

    # 2. Retrieve time-bounded related evidence.
    related_events, evidence_truncated, window_start = (
        retrieve_related_evidence(db, event)
    )

    # 3. Summarise only the records actually retrieved.
    failed_logins = sum(
        1 for item in related_events
        if item.event_type == "LOGIN_FAILURE"
    )
    successful_logins = sum(
        1 for item in related_events
        if item.event_type == "LOGIN_SUCCESS"
    )
    suspicious_events = sum(
        1 for item in related_events
        if bool(item.is_suspicious)
    )
    unique_usernames = len({
        item.username.strip().casefold()
        for item in related_events
        if item.username and item.username.strip()
    })

    detection_method = get_detection_method(event.event_type)
    explanation = get_detection_explanation(event)
    recommended_actions = get_recommended_actions(event)

    # 4. Build factual risk factors. A risk score is not proof of compromise.
    risk_factors = []

    if event.risk_score is not None and event.risk_score >= 40:
        risk_factors.append(
            f"The detection system assigned risk score {event.risk_score}/100."
        )

    if failed_logins:
        risk_factors.append(
            f"{failed_logins} failed-login event(s) were retrieved "
            "in the historical evidence window."
        )

    if successful_logins:
        risk_factors.append(
            f"{successful_logins} successful-login event(s) were retrieved "
            "in the historical evidence window."
        )

    if failed_logins and successful_logins:
        risk_factors.append(
            "Both failed and successful authentication events were recorded "
            "in the historical window; this alone does not prove compromise."
        )

    if suspicious_events:
        risk_factors.append(
            f"{suspicious_events} retrieved event(s) are marked suspicious "
            "by the detection system."
        )

    if unique_usernames:
        risk_factors.append(
            f"The retrieved activity contains {unique_usernames} distinct username(s)."
        )

    failure_reasons = sorted({
        item.failure_reason
        for item in related_events
        if item.failure_reason
    })
    if failure_reasons:
        risk_factors.append(
            "Recorded authentication failure/block reasons: "
            + ", ".join(failure_reasons)
            + "."
        )

    if not related_events:
        risk_factors.append(
            "No related events were found in the configured historical window."
        )

    if evidence_truncated:
        risk_factors.append(
            f"More than {MAX_RELATED_EVENTS} related records matched; "
            "the timeline is limited to the earliest retrieved records."
        )

    # 5. Format a chronological timeline and show each correlation reason.
    formatted_related_events = []

    for item in related_events:
        matched_by = []

        if (
            event.source_ip and item.source_ip
            and item.source_ip.strip() == event.source_ip.strip()
        ):
            matched_by.append("SOURCE_IP")

        if (
            event.username and item.username
            and item.username.strip().casefold()
            == event.username.strip().casefold()
        ):
            matched_by.append("USERNAME")

        if (
            event.request_id and item.request_id
            and item.request_id.strip() == event.request_id.strip()
        ):
            matched_by.append("REQUEST_ID")

        formatted_related_events.append({
            "id": item.id,
            "event_type": item.event_type,
            "source": item.source,
            "source_ip": item.source_ip,
            "username": item.username,
            "request_id": item.request_id,
            "user_agent": item.user_agent,
            "auth_result": item.auth_result,
            "failure_reason": item.failure_reason,
            "severity": item.severity,
            "risk_score": item.risk_score,
            "status": item.status,
            "is_suspicious": bool(item.is_suspicious),
            "timestamp": format_utc_timestamp(item.timestamp),
            "description": item.description,
            **get_windows_event_metadata(item),
            "matched_by": matched_by
        })

    # 6. Evidence collection metadata for transparency in the UI and AI prompt.
    evidence_metadata = {
        "window_minutes": INVESTIGATION_WINDOW_MINUTES,
        "window_start": format_utc_timestamp(window_start),
        "window_end": format_utc_timestamp(event.timestamp),
        "retrieved_events": len(related_events),
        "maximum_events": MAX_RELATED_EVENTS,
        "truncated": evidence_truncated,
        "future_events_included": False,
        "correlation_methods": ["SOURCE_IP", "USERNAME", "REQUEST_ID"],
        "timestamp_available": event.timestamp is not None
    }

    # 7. Send structured evidence to the local model.
    ai_evidence = {
        "event": {
            "id": event.id,
            "event_type": event.event_type,
            "source": event.source,
            "source_ip": event.source_ip,
            "username": event.username,
            "request_id": event.request_id,
            "user_agent": event.user_agent,
            "auth_result": event.auth_result,
            "failure_reason": event.failure_reason,
            "description": event.description,
            "severity": event.severity,
            "risk_score": event.risk_score,
            "status": event.status,
            "is_suspicious": bool(event.is_suspicious),
            "timestamp": format_utc_timestamp(event.timestamp),
            **get_windows_event_metadata(event),
        },
        "detection_method": detection_method,
        "evidence_metadata": evidence_metadata,
        "evidence_summary": {
            "related_events_found": len(related_events),
            "failed_login_events": failed_logins,
            "successful_login_events": successful_logins,
            "additional_suspicious_events": suspicious_events,
            "unique_usernames": unique_usernames,
            "authentication_successes": sum(
                1 for item in related_events
                if item.auth_result == "SUCCESS"
                or (
                    item.auth_result is None
                    and item.event_type == "LOGIN_SUCCESS"
                )
            ),
            "authentication_failures": sum(
                1 for item in related_events
                if item.auth_result == "FAILURE"
                or (
                    item.auth_result is None
                    and item.event_type == "LOGIN_FAILURE"
                )
            ),
            "authentication_blocks": sum(
                1 for item in related_events
                if item.auth_result == "BLOCKED"
                or (
                    item.auth_result is None
                    and item.event_type == "RATE_LIMIT_TRIGGERED"
                )
            )
        },
        "related_activity": formatted_related_events,
        "risk_factors": risk_factors
    }

    ai_result = investigate_with_ai(ai_evidence)

    # 8. Return fields expected by the existing frontend, plus metadata.
    return {
        "investigation": {
            "event_id": event.id,
            "event_type": event.event_type,
            "detection_method": detection_method,
            "severity": event.severity,
            "risk_score": event.risk_score,
            "status": event.status,
            "source_ip": event.source_ip,
            "username": event.username,
            "request_id": event.request_id,
            "user_agent": event.user_agent,
            "auth_result": event.auth_result,
            "failure_reason": event.failure_reason,
            "description": event.description,
            "explanation": explanation,
            "timestamp": format_utc_timestamp(event.timestamp),
            **get_windows_event_metadata(event),
        },
        "evidence": {
            "related_events_found": len(related_events),
            "failed_login_events": failed_logins,
            "successful_login_events": successful_logins,
            "additional_suspicious_events": suspicious_events,
            "unique_usernames": unique_usernames,
            "authentication_successes": sum(
                1 for item in related_events
                if item.auth_result == "SUCCESS"
                or (
                    item.auth_result is None
                    and item.event_type == "LOGIN_SUCCESS"
                )
            ),
            "authentication_failures": sum(
                1 for item in related_events
                if item.auth_result == "FAILURE"
                or (
                    item.auth_result is None
                    and item.event_type == "LOGIN_FAILURE"
                )
            ),
            "authentication_blocks": sum(
                1 for item in related_events
                if item.auth_result == "BLOCKED"
                or (
                    item.auth_result is None
                    and item.event_type == "RATE_LIMIT_TRIGGERED"
                )
            )
        },
        "evidence_metadata": evidence_metadata,
        "risk_factors": risk_factors,
        "related_activity": formatted_related_events,
        "recommended_actions": recommended_actions,
        "ai_investigation": ai_result
    }


@router.websocket("/ws")
async def security_events_websocket(websocket: WebSocket, ticket: str = ""):
    """Accept only a short-lived, single-use ticket issued over authenticated HTTPS."""
    from app.database import SessionLocal
    from app.services.realtime import websocket_tickets
    from app.config import settings

    allowed_origins = {settings.FRONTEND_URL.rstrip("/")}
    if settings.ENVIRONMENT.lower() != "production":
        allowed_origins.update({
            "http://127.0.0.1:5173",
            "http://localhost:5173",
        })
    origin = websocket.headers.get("origin")
    if origin and origin.rstrip("/") not in allowed_origins:
        await websocket.close(code=4403)
        return

    identity = websocket_tickets.consume(ticket)
    if not identity:
        await websocket.close(code=4401)
        return

    user_id, token_jti = identity
    db = SessionLocal()
    try:
        if db.query(RevokedToken).filter(RevokedToken.jti == token_jti).first():
            await websocket.close(code=4401)
            return
        user = db.query(User).filter(
            User.id == user_id,
            User.is_active.is_(True)
        ).first()
        if not user:
            await websocket.close(code=4401)
            return
    finally:
        db.close()

    await event_hub.connect(websocket)
    try:
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        event_hub.disconnect(websocket)
    except Exception:
        event_hub.disconnect(websocket)
        try:
            await websocket.close()
        except Exception:
            pass

