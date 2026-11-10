
"""Passive TCP connection observer with structured process attribution.

Does not scan, inject, or modify network traffic.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Iterable

import psutil

logger = logging.getLogger("NyensungAI.NetworkMonitor")


def is_usable_remote_ip(value: str | None) -> bool:
    """Check whether a remote IP is suitable for recording."""
    if not value:
        return False

    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False

    return not (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
    )


def get_process_details(pid: int | None) -> dict:
    """Collect process ID and executable name only."""
    if not pid or pid <= 0:
        return {
            "process_id": None,
            "process_name": "Unknown",
        }

    try:
        process = psutil.Process(pid)

        return {
            "process_id": pid,
            "process_name": process.name() or "Unknown",
        }

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
    ):
        return {
            "process_id": pid,
            "process_name": "Unavailable",
        }

    except (OSError, ValueError) as exc:
        logger.debug("Could not identify process %s: %s", pid, exc)

        return {
            "process_id": pid,
            "process_name": "Unavailable",
        }


def connection_event(
    local_ip: str,
    local_port: int,
    remote_ip: str,
    remote_port: int,
    computer_name: str,
    agent_name: str,
    pid: int | None = None,
    process_name: str | None = None,
) -> dict | None:
    """Normalize an established TCP connection into a security event."""

    if not is_usable_remote_ip(remote_ip):
        return None

    try:
        local_port = int(local_port)
        remote_port = int(remote_port)
    except (TypeError, ValueError):
        return None

    if not (
        1 <= local_port <= 65535
        and 1 <= remote_port <= 65535
    ):
        return None

    # Validate local address without rejecting private/local addresses.
    try:
        ipaddress.ip_address(local_ip.split("%", 1)[0])
    except (ValueError, AttributeError):
        local_ip = ""

    process_name = process_name or "Unknown"

    # Ordinary connections are not automatically suspicious.
    severity = "LOW"
    risk_score = 0
    is_suspicious = False

    description = (
        f"Passive TCP socket observation on {computer_name}: "
        f"local_ip={local_ip or 'unknown'} "
        f"local_port={local_port} "
        f"remote_ip={remote_ip} "
        f"remote_port={remote_port} "
        f"protocol=TCP "
        f"state=ESTABLISHED "
        f"process_id={pid if pid else 'unknown'} "
        f"process_name={process_name}."
    )

    return {
        "event_type": "NETWORK_CONNECTION_OBSERVED",
        "source": (
            f"{agent_name} - {computer_name} "
            f"- Passive Network Monitor"
        ),

        # Keep source_ip for compatibility with existing detection rules.
        # For this event, source_ip represents the remote endpoint.
        "source_ip": remote_ip,

        # Structured endpoint telemetry.
        "local_ip": local_ip or None,
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "protocol": "TCP",

        # Structured process attribution.
        "process_id": pid if pid and pid > 0 else None,
        "process_name": process_name,

        "username": None,
        "description": description,
        "severity": severity,
        "risk_score": risk_score,
        "status": "NEW",
        "is_suspicious": is_suspicious,
    }


def collect_new_connections(
    previous: set[tuple],
    rows: Iterable,
    computer_name: str,
    agent_name: str,
) -> tuple[list[dict], set[tuple]]:
    """Collect newly established TCP connections with process attribution."""

    current: set[tuple] = set()
    events: list[dict] = []

    for row in rows:

        # Observe TCP connections only.
        if getattr(row, "type", None) != socket.SOCK_STREAM:
            continue

        # Observe established connections only.
        if str(getattr(row, "status", "")).upper() != "ESTABLISHED":
            continue

        local = getattr(row, "laddr", None)
        remote = getattr(row, "raddr", None)

        if not local or not remote:
            continue

        try:
            local_ip = local.ip
            local_port = int(local.port)
            remote_ip = remote.ip
            remote_port = int(remote.port)

        except (AttributeError, TypeError, ValueError):
            continue

        pid = getattr(row, "pid", None)

        # PID distinguishes processes using the same socket tuple.
        key = (
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            pid,
        )

        current.add(key)

        if key in previous:
            continue

        process_details = get_process_details(pid)

        event = connection_event(
            local_ip=local_ip,
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            computer_name=computer_name,
            agent_name=agent_name,
            pid=process_details["process_id"],
            process_name=process_details["process_name"],
        )

        if event:
            events.append(event)

    return events, current
