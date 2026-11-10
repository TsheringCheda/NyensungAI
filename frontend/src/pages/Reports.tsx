import { useEffect, useState } from "react";
import { Download, FileJson, FileSpreadsheet, RefreshCw } from "lucide-react";
import { getSecurityEvents, type SecurityEvent } from "../services/securityEvents";
import { getIncidents, type Incident } from "../services/incidents";

const token = () => sessionStorage.getItem("nyensung_token") || sessionStorage.getItem("sentinel_token") || "";
const download = (name: string, content: string, type: string) => {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement("a");
  anchor.href = url; anchor.download = name; anchor.click();
  URL.revokeObjectURL(url);
};
const csvCell = (value: unknown) => `"${String(value ?? "").replaceAll('"', '""')}"`;

export default function Reports() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true); setError("");
    try {
      const [eventRows, incidentRows] = await Promise.all([getSecurityEvents(token()), getIncidents()]);
      setEvents(eventRows); setIncidents(incidentRows);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Report data could not be loaded.");
    } finally { setLoading(false); }
  };
  useEffect(() => { void load(); }, []);

  const exportEvents = () => {
    const columns = ["id","event_type","source","source_ip","username","severity","risk_score","status","is_suspicious","timestamp","description"] as const;
    const rows = [columns.join(","), ...events.map((event) => columns.map((key) => csvCell(event[key])).join(","))];
    download("nyensungai-security-events.csv", rows.join("\r\n"), "text/csv;charset=utf-8");
  };
  const exportIncidents = () => {
    const columns = ["incident_number","security_event_id","title","severity","priority","status","source_ip","assigned_to","created_at","updated_at"] as const;
    const rows = [columns.join(","), ...incidents.map((incident) => columns.map((key) => csvCell(incident[key])).join(","))];
    download("nyensungai-incidents.csv", rows.join("\r\n"), "text/csv;charset=utf-8");
  };
  const exportSnapshot = () => download("nyensungai-security-snapshot.json", JSON.stringify({generated_at:new Date().toISOString(),events,incidents}, null, 2), "application/json");

  return <section className="module-page">
    <header className="module-heading"><div><span className="module-eyebrow">SECURITY OPERATIONS / OUTPUT</span><h1>Reports</h1><p>Export the security events and incident records currently available through the API.</p></div><button className="module-button" onClick={() => void load()} disabled={loading}><RefreshCw size={15}/> Refresh data</button></header>
    {error && <div className="module-error" role="alert">{error}</div>}
    <div className="report-grid">
      <article className="module-card report-card"><FileSpreadsheet size={24}/><h2>Security event register</h2><p>CSV export of the latest event records returned by the security-events API.</p><strong>{loading ? "…" : `${events.length} records loaded`}</strong><button className="module-button" onClick={exportEvents} disabled={loading || events.length === 0}><Download size={15}/> Export CSV</button></article>
      <article className="module-card report-card"><FileSpreadsheet size={24}/><h2>Incident register</h2><p>CSV export of incident status, priority, ownership and timestamps.</p><strong>{loading ? "…" : `${incidents.length} records loaded`}</strong><button className="module-button" onClick={exportIncidents} disabled={loading || incidents.length === 0}><Download size={15}/> Export CSV</button></article>
      <article className="module-card report-card"><FileJson size={24}/><h2>Combined snapshot</h2><p>JSON snapshot containing the loaded events and incidents for further analysis.</p><strong>{loading ? "…" : `${events.length + incidents.length} records included`}</strong><button className="module-button" onClick={exportSnapshot} disabled={loading}><Download size={15}/> Export JSON</button></article>
    </div>
    <div className="module-note"><b>Export scope:</b> These reports contain records returned by the current API limits (up to 100 security events per request). They are not a complete forensic archive and do not include AI analysis unless it has been separately saved by a future report-persistence feature.</div>
  </section>;
}
