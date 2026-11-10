
"""NyensungAI passive Windows endpoint telemetry collector."""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from pathlib import Path

import psutil
import requests

from config import (
    API_URL,
    POLL_INTERVAL,
    AGENT_NAME,
    AGENT_API_KEY,
    INITIAL_BACKFILL_HOURS,
    ENABLE_PROCESS_EVENTS,
    ENABLE_DEFENDER_EVENTS,
)

from network_monitor import collect_new_connections
from windows_event_monitor import CHANNEL_MAP, normalize_windows_event, parse_event_xml


BASE_DIR = Path(__file__).resolve().parent

CHECKPOINT_FILE = BASE_DIR / "agent_checkpoint.json"

COMPUTER_NAME = socket.gethostname()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("NyensungAI.Agent")


# ---------------------------------------------------------
# CHECKPOINT MANAGEMENT
# ---------------------------------------------------------

def load_checkpoints() -> dict:
    """Load Windows event collection checkpoints."""

    if not CHECKPOINT_FILE.exists():
        return {}

    try:
        data = json.loads(
            CHECKPOINT_FILE.read_text(encoding="utf-8")
        )

        if not isinstance(data, dict):
            raise ValueError("Checkpoint must contain a JSON object")

        return data

    except (OSError, json.JSONDecodeError, ValueError):
        logger.exception(
            "Invalid checkpoint file. Refusing to skip collected records."
        )

        raise RuntimeError(
            "Could not safely read endpoint checkpoint"
        )


def save_checkpoints(checkpoints: dict) -> None:
    """Save checkpoints atomically."""

    temp_file = CHECKPOINT_FILE.with_suffix(".tmp")

    temp_file.write_text(
        json.dumps(checkpoints, indent=2),
        encoding="utf-8",
    )

    os.replace(temp_file, CHECKPOINT_FILE)


# ---------------------------------------------------------
# WINDOWS EVENT CHANNEL CONFIGURATION
# ---------------------------------------------------------

def enabled_channels() -> dict:
    """Return enabled Windows Event Log channels."""

    channels = {
        "Security": [
            event_id
            for event_id in CHANNEL_MAP["Security"]
            # Logout events use independent checkpoints below. This prevents
            # the general Security checkpoint from skipping logout records.
            if event_id not in {4634, 4647}
            and (event_id != 4688 or ENABLE_PROCESS_EVENTS)
        ],

        "System": list(CHANNEL_MAP["System"]),
    }

    defender_channel = (
        "Microsoft-Windows-Windows Defender/Operational"
    )

    if ENABLE_DEFENDER_EVENTS:
        channels[defender_channel] = list(
            CHANNEL_MAP[defender_channel]
        )

    return channels


# ---------------------------------------------------------
# BACKEND COMMUNICATION
# ---------------------------------------------------------

def send_event(event_data: dict) -> bool:
    """Submit a normalized security event to the backend."""

    if not AGENT_API_KEY:
        logger.error(
            "NYENSUNG_AGENT_API_KEY is missing. Event not submitted."
        )
        return False

    try:
        response = requests.post(
            API_URL,
            json=event_data,
            headers={
                "X-Agent-Key": AGENT_API_KEY,
            },
            timeout=10,
        )

        response.raise_for_status()

        logger.info(
            "EVENT SUBMITTED | Type: %s | User: %s",
            event_data.get("event_type", "UNKNOWN"),
            event_data.get("username") or "No account",
        )

        # Show process attribution for network observations.
        if event_data.get("event_type") == "NETWORK_CONNECTION_OBSERVED":

            description = event_data.get("description", "")

            logger.info(
                "NETWORK EVIDENCE | %s",
                description,
            )

        return True

    except requests.RequestException as exc:

        logger.error(
            "BACKEND DELIVERY FAILED | Event: %s | Error: %s",
            event_data.get("event_type", "UNKNOWN"),
            exc,
        )

        return False


# ---------------------------------------------------------
# WINDOWS EVENT LOG COLLECTION
# ---------------------------------------------------------

def monitor_channel(
    channel: str,
    event_ids: list,
    last_record: int | None,
) -> int:
    """Read Windows events and submit them to the backend."""

    import win32evtlog

    ids = " or ".join(
        f"EventID={int(event_id)}"
        for event_id in event_ids
    )

    if last_record is None:

        # First run: collect only the configured recent history.
        millis = max(1, INITIAL_BACKFILL_HOURS) * 60 * 60 * 1000

        query = (
            f"*[System[({ids}) and "
            f"TimeCreated[timediff(@SystemTime) <= {millis}]]]"
        )

    else:

        query = (
            f"*[System[({ids}) and "
            f"EventRecordID > {int(last_record)}]]"
        )

    handle = win32evtlog.EvtQuery(
        channel,
        (
            win32evtlog.EvtQueryChannelPath
            | win32evtlog.EvtQueryForwardDirection
        ),
        query,
    )

    highest = int(last_record or 0)

    try:

        while True:

            events = win32evtlog.EvtNext(
                handle,
                32,
                1000,
            )

            if not events:
                break

            for event in events:

                try:

                    xml = win32evtlog.EvtRender(
                        event,
                        win32evtlog.EvtRenderEventXml,
                    )

                    normalized = normalize_windows_event(
                        xml,
                        channel,
                        COMPUTER_NAME,
                        AGENT_NAME,
                    )

                    _, record_id, _, _ = parse_event_xml(xml)

                    # Only advance after successful delivery or
                    # after deliberately ignoring an unsupported event.
                    if normalized is not None:

                        if not send_event(normalized):
                            return highest

                    highest = max(
                        highest,
                        int(record_id),
                    )

                except Exception:

                    logger.exception(
                        "Could not process %s event. "
                        "Checkpoint held for retry.",
                        channel,
                    )

                    return highest

                finally:

                    try:
                        win32evtlog.EvtClose(event)
                    except Exception:
                        pass

    finally:

        try:
            win32evtlog.EvtClose(handle)
        except Exception:
            pass

    return highest


# ---------------------------------------------------------
# PASSIVE NETWORK CONNECTION MONITORING
# ---------------------------------------------------------

_previous_network_connections: set[tuple] = set()


def monitor_network_connections() -> None:
    """Collect newly established TCP connections."""

    global _previous_network_connections

    try:

        rows = psutil.net_connections(
            kind="tcp"
        )

        events, current_connections = collect_new_connections(
            _previous_network_connections,
            rows,
            COMPUTER_NAME,
            AGENT_NAME,
        )

        # Update the snapshot after successful enumeration.
        _previous_network_connections = current_connections

        for event in events:

            process_information = event.get(
                "description",
                "",
            )

            logger.info(
                "NEW NETWORK CONNECTION | %s",
                process_information,
            )

            if not send_event(event):

                logger.warning(
                    "Network event delivery failed. "
                    "Persistent network retry is not yet implemented."
                )

    except (psutil.AccessDenied, PermissionError):

        logger.warning(
            "Socket enumeration denied. "
            "Run PowerShell as Administrator for fuller visibility."
        )

    except Exception:

        logger.exception(
            "Passive network monitoring failed."
        )


# ---------------------------------------------------------
# MAIN AGENT LOOP
# ---------------------------------------------------------

def main() -> None:

    logger.info(
        "NyensungAI real Windows telemetry agent starting on %s",
        COMPUTER_NAME,
    )

    channels = enabled_channels()

    logger.info(
        "Enabled Windows channels: %s",
        ", ".join(channels),
    )

    logger.info(
        "Initial backfill: %s hours | Process events: %s | Defender: %s",
        INITIAL_BACKFILL_HOURS,
        ENABLE_PROCESS_EVENTS,
        ENABLE_DEFENDER_EVENTS,
    )

    checkpoints = load_checkpoints()

    while True:

        for channel, event_ids in channels.items():

            if channel == "Security":

                # Each Security Event ID has an independent checkpoint.
                # This prevents newer records of one type from skipping
                # older records of another type in the same channel.
                security_event_ids = sorted(set(event_ids) | {4634, 4647})

                for event_id in security_event_ids:

                    checkpoint_key = f"Security:{event_id}"

                    try:

                        previous = checkpoints.get(checkpoint_key)

                        latest = monitor_channel(
                            "Security",
                            [event_id],
                            previous,
                        )

                        if latest > int(previous or 0):

                            checkpoints[checkpoint_key] = latest
                            save_checkpoints(checkpoints)

                    except Exception as exc:

                        logger.warning(
                            "Cannot read Security event %s: %s. "
                            "Other event collection will continue.",
                            event_id,
                            exc,
                        )

            else:

                # System and Defender retain channel-level checkpoints.
                try:

                    previous = checkpoints.get(channel)

                    latest = monitor_channel(
                        channel,
                        event_ids,
                        previous,
                    )

                    if latest > int(previous or 0):

                        checkpoints[channel] = latest
                        save_checkpoints(checkpoints)

                except Exception as exc:

                    logger.warning(
                        "Cannot read channel '%s': %s. "
                        "Other channels will continue.",
                        channel,
                        exc,
                    )

        # Collect passive TCP connection observations.
        monitor_network_connections()

        time.sleep(max(1, POLL_INTERVAL))


# ---------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------

if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:

        logger.info(
            "NyensungAI endpoint agent stopped by user."
        )

    except Exception:

        logger.exception(
            "NyensungAI endpoint agent stopped unexpectedly."
        )
