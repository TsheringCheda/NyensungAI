
"""Safe normalization of selected Windows Event Log records into SOC telemetry."""

from uuid import uuid5, NAMESPACE_URL
from datetime import datetime
import socket
import xml.etree.ElementTree as ET


NS = {
    "ev": "http://schemas.microsoft.com/win/2004/08/events/event"
}


SECURITY_EVENTS = {
    4624: ("LOGIN_SUCCESS", "LOW", 0, False, "Successful Windows logon"),
    4625: ("LOGIN_FAILURE", "LOW", 20, False, "Failed Windows logon"),
    4634: ("LOGOUT", "LOW", 0, False, "Windows logon session ended"),
    4647: ("USER_LOGOUT", "LOW", 0, False, "User initiated Windows logoff"),
    4740: ("WINDOWS_ACCOUNT_LOCKOUT", "MEDIUM", 55, True, "Windows account locked out"),
    4720: ("WINDOWS_USER_CREATED", "MEDIUM", 45, False, "Windows user account created"),
    4722: ("WINDOWS_USER_ENABLED", "MEDIUM", 40, False, "Windows user account enabled"),
    4724: ("WINDOWS_PASSWORD_RESET_ATTEMPT", "MEDIUM", 50, False, "Password reset attempt recorded"),
    4728: ("WINDOWS_GLOBAL_GROUP_MEMBER_ADDED", "MEDIUM", 55, True,
          "Member added to a security-enabled global group"),
    4732: ("WINDOWS_LOCAL_GROUP_MEMBER_ADDED", "MEDIUM", 55, True,
          "Member added to a security-enabled local group"),
    4688: ("WINDOWS_PROCESS_CREATED", "LOW", 10, False, "Windows process creation audited"),
    4697: ("WINDOWS_SERVICE_INSTALLED", "HIGH", 70, True,
          "Service installation recorded in Security log"),
    1102: ("WINDOWS_AUDIT_LOG_CLEARED", "CRITICAL", 95, True,
          "Windows Security audit log was cleared"),
}

SYSTEM_EVENTS = {
    7045: ("WINDOWS_SERVICE_INSTALLED", "HIGH", 70, True,
           "New Windows service installed")
}

DEFENDER_EVENTS = {
    1116: ("DEFENDER_MALWARE_DETECTED", "HIGH", 90, True,
           "Microsoft Defender detected a threat"),
    1117: ("DEFENDER_REMEDIATION_ACTION", "MEDIUM", 60, True,
           "Microsoft Defender took action on a threat"),
}

CHANNEL_MAP = {
    "Security": SECURITY_EVENTS,
    "System": SYSTEM_EVENTS,
    "Microsoft-Windows-Windows Defender/Operational": DEFENDER_EVENTS,
}


def parse_event_xml(xml_data):
    """Extract Windows System metadata and named EventData fields."""

    root = ET.fromstring(xml_data)
    system = root.find("ev:System", NS)

    if system is None:
        raise ValueError("Missing Windows Event System section")

    def system_text(path, default=""):
        node = system.find(path, NS)
        return (node.text or "").strip() if node is not None else default

    event_id = int(system_text("ev:EventID", "0"))
    record_id = int(system_text("ev:EventRecordID", "0"))

    created = system.find("ev:TimeCreated", NS)
    occurred_at = (
        created.attrib.get("SystemTime")
        if created is not None else None
    )

    fields = {}
    for node in root.findall(".//ev:EventData/ev:Data", NS):
        name = node.attrib.get("Name")
        if name:
            fields[name] = node.text or ""

    return event_id, record_id, fields, occurred_at


def _pick(fields, *names, default=None):
    """Return the first available, non-empty event field."""

    for name in names:
        value = str(fields.get(name, "")).strip()
        if value and value not in {"-", "Unknown", "(null)"}:
            return value

    return default


def _parse_integer(value):
    if value is None:
        return None
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None


def _parse_windows_timestamp(value):
    """Parse the original Windows UTC timestamp without substituting now."""

    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
        return parsed.isoformat()
    except (TypeError, ValueError):
        return None


def normalize_windows_event(
    xml_data,
    channel,
    computer_name=None,
    agent_name="NyensungAI-Windows-Agent",
):
    """Normalize a supported Windows event into structured SOC telemetry."""

    event_id, record_id, fields, occurred_at = parse_event_xml(xml_data)

    mapping = CHANNEL_MAP.get(channel, {})
    spec = mapping.get(event_id)

    if not spec:
        return None

    event_type, severity, risk, suspicious, label = spec
    computer_name = computer_name or socket.gethostname()

    if event_id == 4634:
        username = _pick(
            fields, "TargetUserName", "SubjectUserName", "AccountName", "User"
        )
    elif event_id == 4647:
        username = _pick(
            fields, "SubjectUserName", "TargetUserName", "AccountName", "User"
        )
    else:
        username = _pick(
            fields, "TargetUserName", "SubjectUserName", "AccountName",
            "User", "MemberName"
        )

    source_ip = _pick(fields, "IpAddress", "SourceAddress", "ClientAddress")

    if source_ip in {"127.0.0.1", "::1", "-"}:
        source_ip = None

    # Ignore routine Windows service logons.
    if event_id == 4624 and _pick(fields, "LogonType") == "5":
        return None

    # Retain executable basename only. Do not collect command lines.
    process = _pick(fields, "NewProcessName", "ProcessName", "Image")
    if process:
        process = process.replace("\\", "/").rsplit("/", 1)[-1][:180]

    threat = _pick(fields, "Threat Name", "ThreatName", "Name")
    target = _pick(
        fields, "TargetUserName", "TargetAccountName", "ServiceName", "GroupName"
    )

    windows_status = _pick(fields, "Status")
    windows_sub_status = _pick(fields, "SubStatus")

    windows_logon_type = _parse_integer(_pick(fields, "LogonType"))

    details = [
        f"{label} on {computer_name}."
    ]

    if username:
        details.append(f"Account: {username}.")

    if target and target != username:
        details.append(f"Target: {target}.")

    if source_ip:
        details.append(f"Source IP: {source_ip}.")

    if process and event_id == 4688:
        details.append(f"Process image: {process}.")

    if threat:
        details.append(f"Defender threat: {threat[:180]}.")

    if windows_status:
        details.append(f"Windows authentication status: {windows_status}.")

    if windows_sub_status:
        details.append(
            f"Windows authentication substatus: {windows_sub_status}."
        )

    if windows_logon_type is not None:
        details.append(f"Windows logon type: {windows_logon_type}.")

    if event_id in (4634, 4647):
        logon_id = _pick(fields, "TargetLogonId", "SubjectLogonId")
        if logon_id:
            details.append(f"Logon ID: {logon_id}.")

    details.append(f"Windows Event ID: {event_id}.")
    details.append(f"Windows Record ID: {record_id}.")
    details.append(f"Windows Channel: {channel}.")

    if occurred_at:
        details.append(f"Original Windows event time: {occurred_at}.")

    request_id = str(
        uuid5(
            NAMESPACE_URL,
            f"nyensungai:{computer_name}:{channel}:{record_id}",
        )
    )

    return {
        "event_type": event_type,
        "source": f"{agent_name} - {computer_name} [{channel}]",
        "source_ip": source_ip,
        "username": username,
        "description": " ".join(details),
        "severity": severity,
        "risk_score": risk,
        "status": "NEW",
        "is_suspicious": suspicious,
        "request_id": request_id,

        # Structured Windows evidence
        "windows_event_id": event_id,
        "windows_record_id": record_id,
        "windows_channel": channel,
        "windows_status": windows_status if event_id == 4625 else None,
        "windows_sub_status": windows_sub_status if event_id == 4625 else None,
        "windows_logon_type": windows_logon_type,
        "windows_event_timestamp": _parse_windows_timestamp(occurred_at),
    }
