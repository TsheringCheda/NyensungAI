import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")


# =========================================
# SENTINELAI WINDOWS ENDPOINT AGENT
# CONFIGURATION
# =========================================


# Central NyensungAI Backend API
API_URL = os.getenv("NYENSUNG_API_URL", "http://127.0.0.1:8000/api/security-events/")
AGENT_API_KEY = os.getenv("NYENSUNG_AGENT_API_KEY", "")


# Agent monitoring interval (seconds)
POLL_INTERVAL = max(2, int(os.getenv("NYENSUNG_POLL_INTERVAL", "10")))
INITIAL_BACKFILL_HOURS = max(1, int(os.getenv("NYENSUNG_INITIAL_BACKFILL_HOURS", "24")))
ENABLE_PROCESS_EVENTS = os.getenv("NYENSUNG_ENABLE_PROCESS_EVENTS", "false").strip().lower() in {"1", "true", "yes", "on"}
ENABLE_DEFENDER_EVENTS = os.getenv("NYENSUNG_ENABLE_DEFENDER_EVENTS", "true").strip().lower() in {"1", "true", "yes", "on"}


# Windows Event Log to monitor
WINDOWS_LOG_NAME = "Security"


# Endpoint Agent identification
AGENT_NAME = "NyensungAI-Windows-Agent"


# Windows Security Event IDs
MONITORED_EVENT_IDS = [
    4624,  # Successful login
    4625   # Failed login
]


# HTTP request timeout (seconds)
REQUEST_TIMEOUT = 10


# Logging configuration
LOG_LEVEL = "INFO"
