import { useEffect, useState } from "react";
import { Activity, CheckCircle2, CircleAlert, RefreshCw, Save, Server, ShieldCheck } from "lucide-react";
import { getApiHealth, getAdminUsers, getAdminAuditLogs, updateAdminUserAccess, type User, type AuditLogRecord } from "../services/api";

type HealthState = { api: "checking" | "online" | "offline"; database: string; detail: string };

export default function Settings({ user }: { user: User }) {
  const [health, setHealth] = useState<HealthState>({api:"checking",database:"Unknown",detail:"Checking API connectivity…"});
  const [interval, setIntervalValue] = useState(localStorage.getItem("nyensung_monitor_interval") || "15000");
  const [saved, setSaved] = useState(false);
  const [adminUsers, setAdminUsers] = useState<User[]>([]);
  const [auditRows, setAuditRows] = useState<AuditLogRecord[]>([]);
  const [adminLoading, setAdminLoading] = useState(false);
  const [adminError, setAdminError] = useState("");
  const [adminMessage, setAdminMessage] = useState("");

  const checkHealth = async () => {
    setHealth({api:"checking",database:"Checking",detail:"Checking API and database response…"});
    try {
      const result = await getApiHealth();
      setHealth({api:"online",database:result.database || "Connected",detail:`API status: ${result.status}`});
    } catch (e) {
      setHealth({api:"offline",database:"Unknown",detail:e instanceof Error ? e.message : "API health check failed."});
    }
  };
  useEffect(() => { void checkHealth(); }, []);

  const loadAdminData = async () => {
    setAdminLoading(true);
    setAdminError("");
    try {
      const [users, logs] = await Promise.all([getAdminUsers(), getAdminAuditLogs()]);
      setAdminUsers(users);
      setAuditRows(logs);
    } catch (error) {
      setAdminError(error instanceof Error ? error.message : "Unable to load administrator data.");
    } finally {
      setAdminLoading(false);
    }
  };

  useEffect(() => {
    if (user.role === "admin") void loadAdminData();
  }, [user.role]);

  const changeRole = async (target: User, role: "admin" | "analyst" | "viewer") => {
    setAdminMessage("");
    try {
      await updateAdminUserAccess(target.id, { role });
      setAdminMessage(`Updated role for ${target.username}.`);
      await loadAdminData();
    } catch (error) {
      setAdminError(error instanceof Error ? error.message : "Role update failed.");
    }
  };

  const changeActive = async (target: User) => {
    setAdminMessage("");
    try {
      await updateAdminUserAccess(target.id, { is_active: !target.is_active });
      setAdminMessage(`Updated account status for ${target.username}.`);
      await loadAdminData();
    } catch (error) {
      setAdminError(error instanceof Error ? error.message : "Account update failed.");
    }
  };

  const savePreferences = () => {
    localStorage.setItem("nyensung_monitor_interval", interval);
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2500);
  };

  return <section className="module-page">
    <header className="module-heading"><div><span className="module-eyebrow">SYSTEM / CONFIGURATION</span><h1>Settings</h1><p>Review service connectivity and manage this browser’s monitoring preferences.</p></div><button className="module-button" onClick={() => void checkHealth()}><RefreshCw size={15}/> Run diagnostics</button></header>
    <div className="module-card settings-health">
      <div className="module-card-heading"><div><h2><Server size={17}/> Service health</h2><p>Live check against the backend health endpoint.</p></div><span className={`module-live ${health.api === "online" ? "online" : health.api === "offline" ? "offline" : ""}`}>{health.api === "online" ? <CheckCircle2 size={13}/> : <CircleAlert size={13}/>} {health.api.toUpperCase()}</span></div>
      <div className="settings-health-grid"><div><span>Backend API</span><b>{health.api === "online" ? "Reachable" : health.api === "offline" ? "Unreachable" : "Checking…"}</b></div><div><span>Database</span><b>{health.database}</b></div><div><span>Details</span><b>{health.detail}</b></div></div>
    </div>
    <div className="module-card settings-card">
      <div className="module-card-heading"><div><h2><Activity size={17}/> Monitoring preferences</h2><p>Browser-side refresh preference for the monitoring view.</p></div></div>
      <label className="settings-field"><span>Monitoring refresh interval</span><select value={interval} onChange={(e) => setIntervalValue(e.target.value)}><option value="15000">15 seconds</option><option value="30000">30 seconds</option><option value="60000">60 seconds</option></select></label>
      <p className="settings-help">This setting controls the monitoring page refresh cadence in this browser. It does not change backend detection thresholds or endpoint-agent polling.</p>
      <button className="module-button" onClick={savePreferences}><Save size={15}/> Save preferences</button>{saved && <span className="settings-saved"><CheckCircle2 size={14}/> Saved in this browser</span>}
    </div>
    {user.role === "admin" && <div className="module-card settings-card">
      <div className="module-card-heading"><div><h2><ShieldCheck size={17}/> Administrator access</h2><p>Manage analyst roles and account activation. Passwords are never displayed here.</p></div><button className="module-button" onClick={() => void loadAdminData()} disabled={adminLoading}><RefreshCw size={14}/> Refresh</button></div>
      {adminError && <p role="alert" className="settings-help" style={{color:"#f87171"}}>{adminError}</p>}
      {adminMessage && <p className="settings-saved">{adminMessage}</p>}
      {adminLoading ? <p className="settings-help">Loading administrator data…</p> : <div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",textAlign:"left"}}><thead><tr><th style={{padding:"10px"}}>Account</th><th style={{padding:"10px"}}>Role</th><th style={{padding:"10px"}}>Status</th></tr></thead><tbody>{adminUsers.map((account) => <tr key={account.id} style={{borderTop:"1px solid rgba(148,163,184,.15)"}}><td style={{padding:"10px"}}><strong>{account.username}</strong><div className="settings-help">{account.email}</div></td><td style={{padding:"10px"}}><select aria-label={`Role for ${account.username}`} value={account.role} onChange={(event) => void changeRole(account, event.target.value as "admin" | "analyst" | "viewer")}><option value="admin">Administrator</option><option value="analyst">Analyst</option><option value="viewer">Read only</option></select></td><td style={{padding:"10px"}}><button className="module-button" disabled={account.id === user.id} onClick={() => void changeActive(account)}>{account.is_active ? "Active · Disable" : "Disabled · Enable"}</button></td></tr>)}</tbody></table></div>}
      <div style={{marginTop:24}}><h3 style={{marginBottom:8}}>Recent audit activity</h3>{auditRows.length === 0 ? <p className="settings-help">No audit records available.</p> : auditRows.map((row) => <div key={row.id} style={{padding:"10px 0",borderTop:"1px solid rgba(148,163,184,.12)"}}><strong>{row.action.replaceAll("_", " ")}</strong><div className="settings-help">{row.actor_username} · {row.target_type || "system"} {row.target_id || ""} · {new Date(row.created_at).toLocaleString()}</div>{row.details && <div className="settings-help">{row.details}</div>}</div>)}</div>
    </div>}
    <div className="module-note"><ShieldCheck size={16}/><span><b>Security controls:</b> Detection thresholds, firewall actions, account lockouts and agent deployment are not configurable from this screen. Those controls require server-side configuration and authorization; this interface does not claim to enforce them.</span></div>
  </section>;
}
