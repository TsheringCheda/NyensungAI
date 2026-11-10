import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Search, RefreshCw, BrainCircuit, ClipboardList, X, ShieldCheck, Clock3 } from "lucide-react";
import { getSecurityEvents, getSecurityInvestigation, type SecurityEvent, type SecurityInvestigation } from "../services/securityEvents";
import { createIncidentFromEvent } from "../services/incidents";
import "./securityAlerts.css";

const token = () => sessionStorage.getItem("nyensung_token") || sessionStorage.getItem("sentinel_token") || "";
const formatTime = (value: string) => new Date(value.endsWith("Z") || /[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`).toLocaleString("en-IN", { timeZone:"Asia/Kolkata", dateStyle:"medium", timeStyle:"short" });

export default function SecurityAlerts() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [status, setStatus] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState<number | null>(null);
  const [investigation, setInvestigation] = useState<SecurityInvestigation | null>(null);
  const [investigationError, setInvestigationError] = useState("");
  const [investigatingEvent, setInvestigatingEvent] = useState<SecurityEvent | null>(null);
  const [notice, setNotice] = useState("");

  const load = async () => {
    setLoading(true); setError("");
    try { setEvents(await getSecurityEvents(token())); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not load security events."); }
    finally { setLoading(false); }
  };
  useEffect(() => { void load(); }, []);

  const filtered = useMemo(() => events.filter(e => {
    const haystack = [e.event_type, e.source, e.source_ip || "", e.username || "", e.description].join(" ").toLowerCase();
    return haystack.includes(query.toLowerCase()) &&
      (severity === "ALL" || e.severity === severity) &&
      (status === "ALL" || e.status === status);
  }), [events, query, severity, status]);

  const investigate = async (event: SecurityEvent) => {
    setBusyId(event.id);
    setInvestigatingEvent(event);
    setInvestigation(null);
    setInvestigationError("");
    try {
      const result = await getSecurityInvestigation(event.id, token());
      setInvestigation(result);
      if (!result.ai_investigation?.success) {
        setInvestigationError(result.ai_investigation?.error || "Evidence was retrieved, but the AI model did not return a successful report.");
      }
    } catch (e) {
      setInvestigationError(e instanceof Error ? e.message : "Investigation request failed.");
    } finally { setBusyId(null); }
  };

  const closeInvestigation = () => {
    if (busyId !== null) return;
    setInvestigatingEvent(null);
    setInvestigation(null);
    setInvestigationError("");
  };

  const escalate = async (event: SecurityEvent) => {
    setBusyId(event.id); setError(""); setNotice("");
    try {
      const incident = await createIncidentFromEvent(event.id);
      setNotice(`${incident.incident_number} is available in Incident Response.`);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not create incident."); }
    finally { setBusyId(null); }
  };

  const counts = {
    critical: events.filter(e => e.severity === "CRITICAL" && e.is_suspicious).length,
    high: events.filter(e => e.severity === "HIGH" && e.is_suspicious).length,
    medium: events.filter(e => e.severity === "MEDIUM" && e.is_suspicious).length,
  };
  const report = investigation?.ai_investigation?.report;
  const evidence = investigation?.evidence;

  return <section className="security-alerts-page">
    <div className="sa-heading">
      <div><span className="sa-eyebrow">SECURITY OPERATIONS / DETECTION QUEUE</span><h1>Security Alerts</h1><p>Search, triage and investigate security events collected by NyensungAI.</p></div>
      <button className="sa-refresh" onClick={() => void load()} disabled={loading}><RefreshCw size={16}/> Refresh</button>
    </div>
    <div className="sa-metrics">
      <article><span>Critical alerts</span><strong className="critical">{counts.critical}</strong></article>
      <article><span>High alerts</span><strong className="high">{counts.high}</strong></article>
      <article><span>Medium suspicious</span><strong className="medium">{counts.medium}</strong></article>
      <article><span>Events loaded</span><strong>{events.length}</strong></article>
    </div>
    <div className="sa-toolbar">
      <label className="sa-search"><Search size={18}/><input aria-label="Search security events" value={query} onChange={e => setQuery(e.target.value)} placeholder="Search IP, username, event type or description..."/></label>
      <select aria-label="Filter by severity" value={severity} onChange={e => setSeverity(e.target.value)}><option value="ALL">All severities</option>{["CRITICAL","HIGH","MEDIUM","LOW"].map(x=><option key={x}>{x}</option>)}</select>
      <select aria-label="Filter by status" value={status} onChange={e => setStatus(e.target.value)}><option value="ALL">All statuses</option>{["NEW","INVESTIGATING","RESOLVED"].map(x=><option key={x}>{x}</option>)}</select>
      <span>{filtered.length} results</span>
    </div>
    {error && <div className="sa-error" role="alert">{error}</div>}
    {notice && <div className="sa-notice" role="status">{notice}</div>}
    <div className="sa-table-wrap"><table className="sa-table"><thead><tr><th>Event</th><th>Source IP</th><th>User</th><th>Severity</th><th>Risk</th><th>Status</th><th>Time (IST)</th><th>Actions</th></tr></thead>
      <tbody>{loading ? <tr><td colSpan={8} className="sa-empty">Loading security events...</td></tr> : filtered.length === 0 ? <tr><td colSpan={8} className="sa-empty"><AlertTriangle size={25}/><b>No matching events</b><span>Try another search or clear the filters.</span></td></tr> : filtered.map(event => <tr key={event.id}>
        <td><b>{event.event_type.replaceAll("_"," ")}</b><small>{event.description}</small></td><td>{event.source_ip || "—"}</td><td>{event.username || "—"}</td>
        <td><span className={`sa-pill ${event.severity.toLowerCase()}`}>{event.severity}</span></td><td>{event.risk_score}/100</td>
        <td>{event.status}</td><td>{formatTime(event.timestamp)}</td>
        <td><div className="sa-actions"><button onClick={() => void investigate(event)} disabled={busyId !== null}><BrainCircuit size={14}/> {busyId === event.id ? "Investigating…" : "Investigate"}</button>{event.is_suspicious && event.severity !== "LOW" && <button onClick={() => void escalate(event)} disabled={busyId !== null}><ClipboardList size={14}/> Incident</button>}</div></td>
      </tr>)}</tbody></table></div>

    {investigatingEvent && <div className="sa-modal-backdrop" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget) closeInvestigation(); }}>
      <section className="sa-investigation sa-investigation-modal" role="dialog" aria-modal="true" aria-labelledby="sa-investigation-title">
        <button className="sa-close" onClick={closeInvestigation} disabled={busyId !== null} aria-label="Close investigation"><X size={18}/></button>
        <div className="sa-report-kicker"><BrainCircuit size={17}/> AI-ASSISTED SECURITY INVESTIGATION</div>
        <h2 id="sa-investigation-title">Event #{investigatingEvent.id} · {investigatingEvent.event_type.replaceAll("_"," ")}</h2>
        <div className="sa-report-meta"><span>{investigatingEvent.severity} severity</span><span>Risk {investigatingEvent.risk_score}/100</span><span><Clock3 size={13}/> {formatTime(investigatingEvent.timestamp)}</span></div>
        {busyId !== null && <div className="sa-loading"><span className="sa-spinner"/> <div><b>Analyzing evidence with local AI</b><p>Correlating event history and preparing the analyst report. This can take several minutes on local hardware.</p></div></div>}
        {investigationError && <div className="sa-error" role="alert"><b>AI report status:</b> {investigationError}</div>}
        {investigation && <>
          <div className="sa-report-summary"><span>Event explanation</span><p>{investigation.investigation.explanation}</p></div>
          {report ? <div className="sa-report-summary"><span>AI assessment</span><h3>{report.possible_attack}</h3><p>{report.assessment}</p><div className="sa-report-meta"><span>Confidence: {report.confidence}</span><span>Model: {investigation.ai_investigation.model || "Local model"}</span></div></div> : <div className="sa-report-summary"><span>Evidence collection</span><p>The backend returned the evidence package, but no valid AI report is available. Review the error above.</p></div>}
          <div className="sa-report-grid">
            <article><span>Related events</span><b>{evidence?.related_events_found ?? 0}</b></article>
            <article><span>Failed logins</span><b>{evidence?.failed_login_events ?? 0}</b></article>
            <article><span>Successful logins</span><b>{evidence?.successful_login_events ?? 0}</b></article>
            <article><span>Suspicious events</span><b>{evidence?.additional_suspicious_events ?? 0}</b></article>
          </div>
          {report && <>
            <div className="sa-report-section"><h3>Evidence analysis</h3><ul>{report.evidence_analysis.map((item,index)=><li key={index}>{item}</li>)}</ul></div>
            <div className="sa-report-section"><h3>Potential impact</h3><p>{report.potential_impact}</p></div>
            <div className="sa-report-section"><h3>Recommended actions</h3><ul>{report.recommended_actions.map((item,index)=><li key={index}>{item}</li>)}</ul></div>
            <div className="sa-report-section"><h3>Limitations</h3><ul>{report.limitations.map((item,index)=><li key={index}>{item}</li>)}</ul></div>
          </>}
          {investigation.risk_factors.length > 0 && <div className="sa-report-section"><h3>Detection risk factors</h3><ul>{investigation.risk_factors.map((item,index)=><li key={index}>{item}</li>)}</ul></div>}
          {investigation.evidence_metadata && <p className="sa-report-footnote">Correlation: {(investigation.evidence_metadata.correlation_methods || []).join(", ") || "Not specified"} · Evidence window: {investigation.evidence_metadata.window_minutes ?? 10} minutes{investigation.evidence_metadata.truncated ? " · Results limited to the configured evidence cap" : ""}.</p>}
          <div className="sa-report-footnote"><ShieldCheck size={14}/> AI output is advisory. Verify the underlying evidence before taking response actions. No firewall or account changes are executed by this investigation.</div>
        </>}
      </section>
    </div>}
  </section>;
}
