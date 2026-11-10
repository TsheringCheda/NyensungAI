import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, RefreshCw, Search, Radio, ShieldAlert } from "lucide-react";
import { getSecurityEvents, type SecurityEvent } from "../services/securityEvents";
import { getThreatActivity, type ThreatActivity } from "../services/api";

const token = () => sessionStorage.getItem("nyensung_token") || sessionStorage.getItem("sentinel_token") || "";

export default function ThreatMonitoring() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [activity, setActivity] = useState<ThreatActivity[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [streamConnected, setStreamConnected] = useState(false);

  const refresh = useCallback(async () => {
    setError("");
    try {
      const [eventRows, activityRows] = await Promise.all([
        getSecurityEvents(token()),
        getThreatActivity(),
      ]);
      setEvents(eventRows);
      setActivity(activityRows);
      setLastUpdated(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Monitoring data could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const interval = Number(localStorage.getItem("nyensung_monitor_interval") || 15000);
    const id = window.setInterval(() => void refresh(), interval);
    return () => window.clearInterval(id);
  }, [refresh]);

  // Authenticated WebSocket push; periodic polling remains as a resilient fallback.
  useEffect(() => {
    const accessToken = token();
    if (!accessToken) return;
    let socket: WebSocket | null = null;
    let heartbeatId = 0;
    let cancelled = false;
    const apiBase = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api").replace(/\/$/, "");
    const wsBase = apiBase.replace(/^http:/i, "ws:").replace(/^https:/i, "wss:");

    const connect = async () => {
      try {
        const ticketResponse = await fetch(`${apiBase}/auth/ws-ticket`, {
          method: "POST",
          headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
        });
        if (!ticketResponse.ok) throw new Error("Unable to create live-stream ticket");
        const ticketData = await ticketResponse.json() as { ticket?: string };
        if (!ticketData.ticket || cancelled) return;
        socket = new WebSocket(`${wsBase}/security-events/ws?ticket=${encodeURIComponent(ticketData.ticket)}`);
        socket.onopen = () => {
          setStreamConnected(true);
          heartbeatId = window.setInterval(() => {
            if (socket?.readyState === WebSocket.OPEN) socket.send("ping");
          }, 25000);
        };
        socket.onclose = () => {
          setStreamConnected(false);
          window.clearInterval(heartbeatId);
        };
        socket.onerror = () => setStreamConnected(false);
        socket.onmessage = (message) => {
          try {
            const packet = JSON.parse(message.data) as { type?: string; data?: SecurityEvent };
            if (packet.type === "security_event" && packet.data) {
              setEvents((current) => [packet.data!, ...current.filter((item) => item.id !== packet.data!.id)].slice(0, 100));
              setLastUpdated(new Date());
            }
          } catch {
            // Ignore malformed frames; polling remains available.
          }
        };
      } catch {
        setStreamConnected(false);
      }
    };
    void connect();
    return () => {
      cancelled = true;
      window.clearInterval(heartbeatId);
      socket?.close();
    };
  }, []);

  const visible = useMemo(() => events.filter((event) =>
    [event.event_type, event.source, event.source_ip || "", event.username || "", event.description]
      .join(" ").toLowerCase().includes(query.toLowerCase())
  ), [events, query]);

  const suspicious = events.filter((event) => event.is_suspicious).length;
  const critical = events.filter((event) => event.severity === "CRITICAL").length;
  const total24h = activity.reduce((sum, bucket) => sum + bucket.normal + bucket.suspicious + bucket.critical, 0);

  return <section className="module-page">
    <header className="module-heading">
      <div><span className="module-eyebrow">OPERATIONS / TELEMETRY</span><h1>Threat Monitoring</h1><p>Review ingested security events and the last 24 hours of observed activity.</p></div>
      <button className="module-button" onClick={() => void refresh()} disabled={loading}><RefreshCw size={15}/> Refresh</button>
    </header>
    <div className="module-metrics">
      <article><span>Events loaded</span><strong>{events.length}</strong><small>Latest API result</small></article>
      <article><span>Suspicious events</span><strong>{suspicious}</strong><small>Marked by detection pipeline</small></article>
      <article><span>Critical events</span><strong>{critical}</strong><small>Current result set</small></article>
      <article><span>Events in 24h</span><strong>{total24h}</strong><small>Hourly activity buckets</small></article>
    </div>
    <div className="module-card">
      <div className="module-card-heading"><div><h2><Activity size={17}/> Activity timeline</h2><p>Hourly event counts returned by the backend.</p></div><span className={`module-live ${streamConnected ? "is-connected" : ""}`}><Radio size={13}/> {streamConnected ? "Live stream connected" : "Polling fallback active"}</span></div>
      <div className="activity-bars" role="img" aria-label="24 hour event activity chart">
        {activity.map((bucket) => {
          const total = bucket.normal + bucket.suspicious + bucket.critical;
          const max = Math.max(1, ...activity.map((item) => item.normal + item.suspicious + item.critical));
          return <div className="activity-bar-column" key={bucket.time} title={`${new Date(bucket.time).toLocaleString()}: ${total} events`}>
            <div className="activity-bar-track">
              <span className="bar-normal" style={{height: `${bucket.normal / max * 100}%`}} />
              <span className="bar-suspicious" style={{height: `${bucket.suspicious / max * 100}%`}} />
              <span className="bar-critical" style={{height: `${bucket.critical / max * 100}%`}} />
            </div>
            <small>{new Date(bucket.time).toLocaleTimeString([], {hour:"2-digit"})}</small>
          </div>;
        })}
      </div>
      <div className="module-legend"><span><i className="legend-normal"/>Normal</span><span><i className="legend-suspicious"/>Suspicious</span><span><i className="legend-critical"/>Critical</span></div>
    </div>
    <div className="module-toolbar">
      <label className="module-search"><Search size={16}/><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search event, source IP or account..."/></label>
      <span>{lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : "Waiting for data"}</span>
    </div>
    {error && <div className="module-error" role="alert">{error}</div>}
    <div className="module-card module-table-wrap">
      <table className="module-table"><thead><tr><th>Event</th><th>Source IP</th><th>Account</th><th>Severity</th><th>Risk</th><th>Time</th></tr></thead>
        <tbody>{loading ? <tr><td colSpan={6}>Loading telemetry…</td></tr> : visible.length === 0 ? <tr><td colSpan={6} className="module-empty"><ShieldAlert size={22}/>{events.length ? "No events match your search." : "No telemetry has been ingested yet."}</td></tr> : visible.map((event) => <tr key={event.id}>
          <td><b>{event.event_type.replaceAll("_", " ")}</b><small>{event.description}</small></td><td>{event.source_ip || "—"}</td><td>{event.username || "—"}</td>
          <td><span className={`module-pill ${event.severity.toLowerCase()}`}>{event.severity}</span></td><td>{event.risk_score}/100</td><td>{new Date(event.timestamp.endsWith("Z") || /[+-]\d\d:\d\d$/.test(event.timestamp) ? event.timestamp : `${event.timestamp}Z`).toLocaleString()}</td>
        </tr>)}</tbody>
      </table>
    </div>
  </section>;
}
