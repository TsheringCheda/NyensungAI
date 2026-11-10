"""In-process WebSocket fan-out for authenticated SOC clients.

For a single-process local deployment this is sufficient. Multi-worker production
must replace this with Redis pub/sub or another shared broker.
"""
import asyncio
import json
import logging
import secrets
import threading
import time
from typing import Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class EventHub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.loop = asyncio.get_running_loop()
        self.clients.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.clients.discard(websocket)

    async def publish(self, event: dict[str, Any]) -> None:
        payload = json.dumps({"type": "security_event", "data": event}, default=str)
        stale: list[WebSocket] = []
        for client in tuple(self.clients):
            try:
                await client.send_text(payload)
            except Exception:
                stale.append(client)
        for client in stale:
            self.disconnect(client)

    def publish_from_sync_route(self, event: dict[str, Any]) -> None:
        loop = self.loop
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(self.publish(event), loop)


class WebSocketTicketStore:
    """Single-use, short-lived tickets for browser WebSocket authentication.

    Tickets are deliberately in-memory: run a single Uvicorn worker for this
    local deployment. Multi-worker deployments need a shared ticket store.
    """
    def __init__(self, ttl_seconds: int = 30) -> None:
        self.ttl_seconds = ttl_seconds
        self._tickets: dict[str, tuple[int, str, float]] = {}
        self._lock = threading.Lock()

    def issue(self, user_id: int, token_jti: str) -> str:
        ticket = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            self._tickets[ticket] = (user_id, token_jti, now + self.ttl_seconds)
        return ticket

    def consume(self, ticket: str) -> tuple[int, str] | None:
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            record = self._tickets.pop(ticket, None)
        if not record:
            return None
        user_id, token_jti, expires_at = record
        if expires_at <= now:
            return None
        return user_id, token_jti

    def _purge(self, now: float) -> None:
        expired = [key for key, value in self._tickets.items() if value[2] <= now]
        for key in expired:
            self._tickets.pop(key, None)


websocket_tickets = WebSocketTicketStore(ttl_seconds=30)
event_hub = EventHub()
