
import { API_BASE_URL } from "./api";

export type RealtimeStatus =
  | "connecting"
  | "connected"
  | "reconnecting"
  | "error";

export interface RealtimeSecurityEvent {
  id?: number;
  event_type?: string;
  source?: string;
  source_ip?: string | null;
  username?: string | null;
  description?: string;
  severity?: string;
  risk_score?: number;
  status?: string;
  is_suspicious?: boolean;
  timestamp?: string | null;
}

interface RealtimeCallbacks {
  onEvent: (event: RealtimeSecurityEvent) => void;
  onStatus: (status: RealtimeStatus) => void;
}

interface TicketResponse {
  ticket?: string;
}

export function connectSecurityEvents(
  token: string,
  callbacks: RealtimeCallbacks
): () => void {
  let stopped = false;
  let socket: WebSocket | null = null;
  let reconnectTimer: number | null = null;
  let pingTimer: number | null = null;
  let ticketController: AbortController | null = null;
  let attempts = 0;

  const clearPing = () => {
    if (pingTimer !== null) {
      window.clearInterval(pingTimer);
      pingTimer = null;
    }
  };

  const scheduleReconnect = () => {
    if (stopped || reconnectTimer !== null) return;

    attempts += 1;

    const delay = Math.min(
      1000 * Math.pow(2, attempts - 1),
      30000
    );

    callbacks.onStatus("reconnecting");

    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = null;
      void connect();
    }, delay);
  };

  const connect = async () => {
    if (stopped) return;

    callbacks.onStatus(
      attempts === 0 ? "connecting" : "reconnecting"
    );

    ticketController = new AbortController();

    try {
      // Request a fresh, single-use WebSocket ticket.
      const response = await fetch(
        `${API_BASE_URL}/auth/ws-ticket`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: "application/json",
          },
          signal: ticketController.signal,
        }
      );

      if (stopped) return;

      if (response.status === 401 || response.status === 403) {
        callbacks.onStatus("error");
        return;
      }

      if (!response.ok) {
        throw new Error("Unable to obtain WebSocket ticket.");
      }

      const result =
        (await response.json()) as TicketResponse;

      if (!result.ticket) {
        throw new Error("Invalid WebSocket ticket response.");
      }

      if (stopped) return;

      // Build the WebSocket URL from the configured API URL.
      const apiUrl = new URL(
        API_BASE_URL,
        window.location.origin
      );

      const wsUrl = new URL(
        `${apiUrl.pathname.replace(/\/+$/, "")}/security-events/ws`,
        apiUrl.origin
      );

      wsUrl.protocol =
        apiUrl.protocol === "https:" ? "wss:" : "ws:";

      wsUrl.searchParams.set("ticket", result.ticket);

      const ws = new WebSocket(wsUrl.toString());
      socket = ws;

      ws.onopen = () => {
        if (stopped) {
          ws.close();
          return;
        }

        attempts = 0;
        callbacks.onStatus("connected");

        // Keep the connection alive.
        pingTimer = window.setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "ping" }));
          }
        }, 25000);
      };

      ws.onmessage = (message: MessageEvent) => {
        if (stopped) return;

        try {
          const payload = JSON.parse(
            String(message.data)
          ) as {
            type?: string;
            data?: unknown;
          };

          if (
            payload.type === "security_event" &&
            payload.data &&
            typeof payload.data === "object"
          ) {
            callbacks.onEvent(
              payload.data as RealtimeSecurityEvent
            );
          }
        } catch (error) {
          console.error(
            "Invalid real-time security event:",
            error
          );
        }
      };

      ws.onerror = () => {
        if (!stopped) {
          ws.close();
        }
      };

      ws.onclose = () => {
        clearPing();

        if (socket === ws) {
          socket = null;
        }

        if (!stopped) {
          scheduleReconnect();
        }
      };
    } catch (error) {
      if (stopped) return;

      if (
        error instanceof DOMException &&
        error.name === "AbortError"
      ) {
        return;
      }

      console.error(
        "NyensungAI real-time connection error:",
        error
      );

      scheduleReconnect();
    }
  };

  if (!token) {
    callbacks.onStatus("error");
  } else {
    void connect();
  }

  // Cleanup when the user logs out or leaves the dashboard.
  return () => {
    stopped = true;

    ticketController?.abort();

    if (reconnectTimer !== null) {
      window.clearTimeout(reconnectTimer);
    }

    clearPing();

    if (socket) {
      socket.close();
      socket = null;
    }
  };
}
