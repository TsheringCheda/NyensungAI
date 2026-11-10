
import { useEffect, useState } from "react";
import {
  RefreshCw,
  Search,
  ShieldCheck,
  ClipboardList,
  BrainCircuit,
  AlertTriangle,
  Sparkles,
} from "lucide-react";

import {
  addIncidentAction,
  addIncidentNote,
  getIncidentDetail,
  getIncidents,
  updateIncident,
  getIncidentTimeline,
  type Incident,
  type IncidentAction,
  type IncidentNote,
  type IncidentStatus,
  type IncidentTimeline,
  getIncidentSlaSummary,
  type IncidentSlaSummary,
} from "../services/incidents";

import {
  getSecurityInvestigation,
  type SecurityInvestigation,
} from "../services/securityEvents";

import "./incidents.css";

const NEXT_STATUS: Partial<Record<IncidentStatus, IncidentStatus>> = {
  NEW: "INVESTIGATING",
  INVESTIGATING: "CONTAINED",
  CONTAINED: "RESOLVED",
  RESOLVED: "CLOSED",
};

export default function Incidents() {
  const [items, setItems] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [slaSummary, setSlaSummary] = useState<IncidentSlaSummary | null>(null);
  const [assigneeDraft, setAssigneeDraft] = useState("");

  const [selected, setSelected] = useState<number | null>(null);
  const [note, setNote] = useState("");
  const [action, setAction] = useState("");
  const [resolution, setResolution] = useState("");

  const [pendingStatus, setPendingStatus] =
    useState<IncidentStatus | null>(null);

  const [busy, setBusy] = useState(false);
  const [notes, setNotes] = useState<IncidentNote[]>([]);
  const [actions, setActions] = useState<IncidentAction[]>([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [timeline, setTimeline] = useState<IncidentTimeline | null>(null);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [timelineError, setTimelineError] = useState("");

  // AI investigation state
  const [investigation, setInvestigation] =
    useState<SecurityInvestigation | null>(null);

  const [investigationLoading, setInvestigationLoading] =
    useState(false);

  const [investigationError, setInvestigationError] =
    useState("");

  const load = async () => {
    try {
      setLoading(true);
      setError("");
      const [incidentRows, sla] = await Promise.all([getIncidents(), getIncidentSlaSummary()]);
      setItems(incidentRows);
      setSlaSummary(sla);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Could not load incidents"
      );
      setSlaSummary(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const active = items.filter(
    x => !["RESOLVED", "CLOSED"].includes(x.status)
  ).length;

  const filtered = items.filter(x =>
    [
      x.incident_number,
      x.title,
      x.source_ip || "",
      x.status,
    ]
      .join(" ")
      .toLowerCase()
      .includes(query.toLowerCase())
  );

  const current = items.find(x => x.id === selected);

  useEffect(() => {
    setAssigneeDraft(current?.assigned_to || "");
  }, [current?.id, current?.assigned_to]);

  const loadDetail = async (id: number) => {
    setDetailLoading(true);

    try {
      const detail = await getIncidentDetail(id);
      setNotes(detail.notes || []);
      setActions(detail.actions || []);
      setTimelineLoading(true);
      setTimelineError("");
      try {
        setTimeline(await getIncidentTimeline(id));
      } catch (timelineException) {
        setTimeline(null);
        setTimelineError(timelineException instanceof Error ? timelineException.message : "Could not load incident timeline");
      } finally {
        setTimelineLoading(false);
      }
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Could not load incident history"
      );
    } finally {
      setDetailLoading(false);
    }
  };

  useEffect(() => {
    if (selected !== null) {
      setAssigneeDraft("");
      void loadDetail(selected);
    } else {
      setNotes([]);
      setActions([]);
      setTimeline(null);
      setTimelineError("");
      setTimelineLoading(false);
      setInvestigation(null);
      setInvestigationError("");
      setInvestigationLoading(false);
      setAssigneeDraft("");
    }
  }, [selected]);

  const refreshIncident = async (id: number) => {
    await load();
    await loadDetail(id);
  };

  // ========================================
  // AI INVESTIGATION
  // ========================================

  const investigateWithAI = async () => {
    if (!current) return;

    setInvestigationLoading(true);
    setInvestigationError("");
    setInvestigation(null);

    try {
      const token =
        sessionStorage.getItem("nyensung_token") ||
        sessionStorage.getItem("sentinel_token") ||
        "";

      const result = await getSecurityInvestigation(
        current.security_event_id,
        token
      );

      setInvestigation(result);

      if (!result.ai_investigation?.success) {
        setInvestigationError(
          result.ai_investigation?.error ||
            "The investigation was retrieved, but the AI model did not return a successful report."
        );
      }
    } catch (e) {
      setInvestigationError(
        e instanceof Error
          ? e.message
          : "AI investigation failed."
      );
    } finally {
      setInvestigationLoading(false);
    }
  };

  // ========================================
  // INCIDENT STATUS MANAGEMENT
  // ========================================

  const changeStatus = async (status: IncidentStatus) => {
    if (!current) return;

    setError("");

    // Resolution and closure require an explanation.
    if (status === "RESOLVED" || status === "CLOSED") {
      setPendingStatus(status);
      setResolution("");
      return;
    }

    setBusy(true);

    try {
      await updateIncident(current.id, { status });
      await refreshIncident(current.id);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Status update failed"
      );
    } finally {
      setBusy(false);
    }
  };

  const confirmResolution = async () => {
    if (!current || !pendingStatus || !resolution.trim()) {
      setError("Please enter a resolution explanation.");
      return;
    }

    setBusy(true);
    setError("");

    try {
      await updateIncident(current.id, {
        status: pendingStatus,
        resolution: resolution.trim(),
      });

      setPendingStatus(null);
      setResolution("");

      await refreshIncident(current.id);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Resolution update failed"
      );
    } finally {
      setBusy(false);
    }
  };

  // ========================================
  // ANALYST NOTES
  // ========================================

  const submitNote = async () => {
    if (!current || !note.trim()) return;

    setBusy(true);
    setError("");

    try {
      await addIncidentNote(current.id, note.trim());
      setNote("");
      await loadDetail(current.id);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Could not save note"
      );
    } finally {
      setBusy(false);
    }
  };

  // ========================================
  // RESPONSE ACTION LOG
  // ========================================

  const submitAction = async () => {
    if (!current || !action.trim()) return;

    setBusy(true);
    setError("");

    try {
      await addIncidentAction(
        current.id,
        "ANALYST_RESPONSE",
        action.trim()
      );

      setAction("");
      await loadDetail(current.id);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Could not save action"
      );
    } finally {
      setBusy(false);
    }
  };

  const saveAssignment = async () => {
    if (!current) return;
    setBusy(true);
    setError("");
    try {
      await updateIncident(current.id, { assigned_to: assigneeDraft.trim() || null });
      await refreshIncident(current.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not update assignment");
    } finally {
      setBusy(false);
    }
  };

  // ========================================
  // USER INTERFACE
  // ========================================

  return (
    <section className="incidents-page">

      <div className="incident-heading">
        <div>
          <div className="eyebrow">
            SECURITY OPERATIONS / CASE MANAGEMENT
          </div>

          <h1>Incident Response</h1>

          <p>
            Track, investigate and document security incidents
            generated by NyensungAI.
          </p>
        </div>

        <button
          className="incident-refresh"
          onClick={() => void load()}
          disabled={loading}
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {/* INCIDENT METRICS */}

      <div className="incident-metrics">
        <article>
          <span>Total incidents</span>
          <strong>{items.length}</strong>
          <small>Recorded cases</small>
        </article>

        <article>
          <span>Open incidents</span>
          <strong>{active}</strong>
          <small>Require attention</small>
        </article>

        <article>
          <span>Critical</span>
          <strong>
            {
              items.filter(
                x =>
                  x.severity === "CRITICAL" &&
                  !["RESOLVED", "CLOSED"].includes(x.status)
              ).length
            }
          </strong>
          <small>Highest severity</small>
        </article>

        <article>
          <span>Resolved</span>
          <strong>
            {
              items.filter(x =>
                ["RESOLVED", "CLOSED"].includes(x.status)
              ).length
            }
          </strong>
          <small>Completed cases</small>
        </article>
      </div>

      <section className="incident-sla-strip" aria-label="Incident response target summary">
        <div className="incident-sla-heading">
          <div><span className="eyebrow">RESPONSE PERFORMANCE</span><h3>Priority target status</h3></div>
          <small>{slaSummary ? "Operational targets · calculated from incident creation" : "SLA summary unavailable"}</small>
        </div>
        <div className="incident-sla-counts">
          <div><b>{slaSummary?.counts.ON_TRACK ?? "—"}</b><span>On track</span></div>
          <div><b>{slaSummary?.counts.AT_RISK ?? "—"}</b><span>At risk</span></div>
          <div><b>{slaSummary?.counts.BREACHED ?? "—"}</b><span>Breached</span></div>
          <div><b>{slaSummary?.counts.COMPLETED ?? "—"}</b><span>Completed</span></div>
        </div>
        {slaSummary && <p className="incident-sla-disclaimer">{slaSummary.disclaimer}</p>}
      </section>

      {/* SEARCH */}

      <div className="incident-toolbar">
        <div className="incident-search">
          <Search size={17} />

          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search incident, IP or status..."
          />
        </div>

        <span>{filtered.length} incidents</span>
      </div>

      {error && (
        <div className="incident-error" role="alert">
          {error}
        </div>
      )}

      {/* INCIDENT TABLE */}

      <div className="incident-table-wrap">
        <table className="incident-table">
          <thead>
            <tr>
              <th>Incident</th>
              <th>Threat</th>
              <th>Source IP</th>
              <th>Severity</th>
              <th>Priority</th>
              <th>Status</th>
              <th>Response target</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>

          <tbody>
            {loading ? (
              <tr>
                <td colSpan={9}>Loading incidents...</td>
              </tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={9} className="incident-empty">
                  <ClipboardList size={28} />
                  <b>No incidents found</b>
                  <span>
                    High and critical detection alerts will appear here
                    automatically.
                  </span>
                </td>
              </tr>
            ) : (
              filtered.map(x => (
                <tr key={x.id}>
                  <td>
                    <b>{x.incident_number}</b>
                    <small>Event #{x.security_event_id}</small>
                  </td>

                  <td>{x.title}</td>

                  <td>{x.source_ip || "—"}</td>

                  <td>
                    <span
                      className={`severity-pill ${x.severity.toLowerCase()}`}
                    >
                      {x.severity}
                    </span>
                  </td>

                  <td>{x.priority}</td>

                  <td>
                    <span
                      className={`status-pill ${x.status.toLowerCase()}`}
                    >
                      {x.status.replace("_", " ")}
                    </span>
                  </td>

                  <td>
                    {(() => {
                      const sla = slaSummary?.incidents.find(row => row.incident_id === x.id);
                      return sla ? <span className={`incident-sla-pill ${sla.state.toLowerCase()}`}>{sla.state.replace("_", " ")}</span> : "—";
                    })()}
                  </td>

                  <td>
                    {new Date(x.created_at).toLocaleString("en-IN", {
                      timeZone: "Asia/Kolkata",
                      dateStyle: "medium",
                      timeStyle: "short",
                    })}{" "}
                    IST
                  </td>

                  <td>
                    <button
                      className="incident-open"
                      onClick={() => setSelected(x.id)}
                    >
                      Manage
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* INCIDENT MANAGEMENT MODAL */}

      {current && (
        <div
          className="incident-modal-backdrop"
          onClick={() => setSelected(null)}
        >
          <section
            className="incident-modal"
            onClick={e => e.stopPropagation()}
          >
            <button
              className="modal-close"
              onClick={() => setSelected(null)}
            >
              ×
            </button>

            <div className="eyebrow">
              {current.incident_number}
            </div>

            <h2>{current.title}</h2>
            <p>{current.description}</p>

            {/* INCIDENT DETAILS */}

            <div className="incident-detail-grid">
              <div>
                <span>Source IP</span>
                <b>{current.source_ip || "Unknown"}</b>
              </div>

              <div>
                <span>Severity / Priority</span>
                <b>
                  {current.severity} / {current.priority}
                </b>
              </div>

              <div>
                <span>Assigned analyst</span>
                <b>{current.assigned_to || "Unassigned"}</b>
              </div>
            </div>

            <div className="incident-assignment-editor">
              <label htmlFor="incident-assignee">Assign analyst</label>
              <div className="incident-assignment-row">
                <input id="incident-assignee" value={assigneeDraft} onChange={e => setAssigneeDraft(e.target.value)} placeholder="Analyst username" maxLength={100} disabled={busy} />
                <button className="incident-primary" onClick={() => void saveAssignment()} disabled={busy}>{busy ? "Saving..." : "Save assignment"}</button>
                <button className="incident-cancel" onClick={() => setAssigneeDraft("")} disabled={busy}>Clear</button>
              </div>
              <small>Assignment changes are recorded in the incident response audit history. Enter an existing analyst username.</small>
            </div>

            {/* EVIDENCE AND INVESTIGATION TIMELINE */}
            <section className="incident-evidence-panel" aria-labelledby="incident-evidence-title">
              <div className="incident-section-heading">
                <div>
                  <div className="eyebrow">CORRELATED TELEMETRY</div>
                  <h3 id="incident-evidence-title">Evidence &amp; activity timeline</h3>
                  <p>Events are correlated by exact metadata matches within a bounded time window. Correlation does not establish causation.</p>
                </div>
                <span className="incident-evidence-count">{timeline?.risk_summary.event_count ?? "—"} events</span>
              </div>

              {timelineLoading ? (
                <p className="history-empty">Loading evidence timeline...</p>
              ) : timelineError ? (
                <div className="incident-error" role="alert">{timelineError}</div>
              ) : timeline ? (
                <>
                  <div className="incident-evidence-metrics">
                    <div><span>Maximum risk</span><b>{timeline.risk_summary.max_risk_score}/100</b></div>
                    <div><span>Average risk</span><b>{timeline.risk_summary.average_risk_score}/100</b></div>
                    <div><span>Related events</span><b>{timeline.related_events.length}</b></div>
                    <div><span>Correlation window</span><b>±{timeline.correlation.window_minutes} min</b></div>
                  </div>
                  <div className="incident-severity-breakdown">
                    {Object.entries(timeline.risk_summary.severity_counts).map(([severity, count]) => (
                      <span key={severity} className={`severity-pill ${severity.toLowerCase()}`}>{severity}: {count}</span>
                    ))}
                  </div>
                  <div className="incident-correlation-note">
                    <b>Matched on:</b> {timeline.correlation.matched_on.length ? timeline.correlation.matched_on.join(", ") : "No shared metadata fields"}. {timeline.correlation.limitation}
                    {timeline.correlation.truncated ? " Results are capped at 200 related events." : ""}
                  </div>
                  <div className="incident-timeline">
                    {timeline.timeline.map((entry, index) => (
                      <article className="incident-timeline-entry" key={`${entry.kind}-${entry.id}-${index}`}>
                        <span className={`incident-timeline-marker ${entry.kind.toLowerCase()}`} />
                        <div className="incident-timeline-content">
                          <div className="incident-timeline-meta">
                            <b>{entry.title}{entry.is_primary ? " · PRIMARY EVENT" : ""}</b>
                            <time>{entry.timestamp ? new Date(entry.timestamp).toLocaleString("en-IN", { timeZone: "Asia/Kolkata", dateStyle: "medium", timeStyle: "short" }) + " IST" : "Time unavailable"}</time>
                          </div>
                          <p>{entry.description}</p>
                          <div className="incident-timeline-tags">
                            {entry.severity && <span className={`severity-pill ${entry.severity.toLowerCase()}`}>{entry.severity}</span>}
                            {typeof entry.risk_score === "number" && <span>Risk {entry.risk_score}/100</span>}
                            {entry.source_ip && <span>IP {entry.source_ip}</span>}
                            {entry.actor && <span>By {entry.actor}</span>}
                          </div>
                        </div>
                      </article>
                    ))}
                    {timeline.timeline.length === 0 && <p className="history-empty">No timeline activity is available.</p>}
                  </div>
                </>
              ) : (
                <p className="history-empty">Timeline is not available for this incident.</p>
              )}
            </section>

            {/* AI INVESTIGATION */}

            <div className="ai-investigation-panel">
              <div className="ai-investigation-heading">
                <div>
                  <div className="eyebrow">
                    <Sparkles size={14} /> AI POWERED ANALYSIS
                  </div>

                  <h3>
                    <BrainCircuit size={20} />
                    AI Threat Investigation
                  </h3>

                  <p>
                    Analyze this security event using the local
                    Qwen3:4b AI model.
                  </p>
                </div>
              </div>

              <button
                className="incident-primary"
                onClick={() => void investigateWithAI()}
                disabled={investigationLoading}
              >
                {investigationLoading
                  ? "AI Investigating..."
                  : "Investigate with AI"}
              </button>

              {investigationLoading && (
                <p className="history-empty">
                  <BrainCircuit size={16} />
                  Analyzing security evidence. This may take a
                  little time...
                </p>
              )}

              {investigationError && (
                <div className="incident-error" role="alert">
                  {investigationError}
                </div>
              )}

              {investigation && (
                <div className="ai-investigation-results">

                  <div className="ai-results-title">
                    <h3>Investigation Results</h3>

                    <span>
                      {investigation.ai_investigation.success
                        ? "AI analysis completed"
                        : "AI analysis unavailable"}
                    </span>
                  </div>

                  {/* RISK AND CONFIDENCE */}

                  <div className="incident-detail-grid">
                    <div>
                      <span>Attack Classification</span>
                      <b>
                        {investigation.ai_investigation.report
                          ?.possible_attack || "Unavailable"}
                      </b>
                    </div>

                    <div>
                      <span>Detection Risk Score</span>
                      <b>
                        {investigation.investigation.risk_score}/100
                      </b>
                    </div>

                    <div>
                      <span>AI Confidence</span>
                      <b>
                        {investigation.ai_investigation.report
                          ?.confidence || "Unavailable"}
                      </b>
                    </div>

                    <div>
                      <span>AI Model</span>
                      <b>
                        {investigation.ai_investigation.model || "Unknown"}
                      </b>
                    </div>
                  </div>

                  {/* SOURCE IP */}

                  <div className="ai-result-section">
                    <h4>Source Information</h4>

                    <p>
                      Source IP:{" "}
                      <strong>
                        {investigation.investigation.source_ip ||
                          "Unknown"}
                      </strong>
                    </p>

                    <p>
                      Username:{" "}
                      <strong>
                        {investigation.investigation.username ||
                          "Unknown"}
                      </strong>
                    </p>

                    {investigation.investigation.source_ip ===
                      "127.0.0.1" && (
                      <div className="incident-safety">
                        <AlertTriangle size={16} />
                        This is a loopback IP address. It does not
                        identify an external attacker. Do not
                        automatically block it.
                      </div>
                    )}
                  </div>

                  {/* EVIDENCE SUMMARY */}

                  <div className="ai-result-section">
                    <h4>Evidence Summary</h4>

                    <div className="incident-detail-grid">
                      <div>
                        <span>Related Events</span>
                        <b>
                          {investigation.evidence.related_events_found}
                        </b>
                      </div>

                      <div>
                        <span>Failed Logins</span>
                        <b>
                          {investigation.evidence.failed_login_events}
                        </b>
                      </div>

                      <div>
                        <span>Successful Logins</span>
                        <b>
                          {investigation.evidence.successful_login_events}
                        </b>
                      </div>

                      <div>
                        <span>Suspicious Events</span>
                        <b>
                          {investigation.evidence.additional_suspicious_events}
                        </b>
                      </div>
                    </div>
                  </div>

                  {/* AI ASSESSMENT */}

                  <div className="ai-result-section">
                    <h4>AI Assessment</h4>

                    <p>
                      {investigation.ai_investigation.report?.assessment ||
                        "No AI assessment available."}
                    </p>
                  </div>

                  {/* RISK FACTORS */}

                  <div className="ai-result-section">
                    <h4>Risk Factors</h4>

                    {investigation.risk_factors.length > 0 ? (
                      <ul>
                        {investigation.risk_factors.map(
                          (factor, index) => (
                            <li key={index}>{factor}</li>
                          )
                        )}
                      </ul>
                    ) : (
                      <p>No risk factors returned.</p>
                    )}
                  </div>

                  {/* EVIDENCE ANALYSIS */}

                  <div className="ai-result-section">
                    <h4>Evidence Analysis</h4>

                    {investigation.ai_investigation.report
                      ?.evidence_analysis?.length ? (
                      <ul>
                        {investigation.ai_investigation.report.evidence_analysis.map(
                          (item, index) => (
                            <li key={index}>{item}</li>
                          )
                        )}
                      </ul>
                    ) : (
                      <p>No evidence analysis available.</p>
                    )}
                  </div>

                  {/* POTENTIAL IMPACT */}

                  <div className="ai-result-section">
                    <h4>Potential Impact</h4>

                    <p>
                      {investigation.ai_investigation.report
                        ?.potential_impact || "Not available."}
                    </p>
                  </div>

                  {/* RECOMMENDED ACTIONS */}

                  <div className="ai-result-section">
                    <h4>AI Recommended Actions</h4>

                    {investigation.ai_investigation.report
                      ?.recommended_actions?.length ? (
                      <ul>
                        {investigation.ai_investigation.report.recommended_actions.map(
                          (item, index) => (
                            <li key={index}>{item}</li>
                          )
                        )}
                      </ul>
                    ) : (
                      <p>No AI recommendations available.</p>
                    )}
                  </div>

                  {/* DETECTION ENGINE RECOMMENDATIONS */}

                  <div className="ai-result-section">
                    <h4>Detection Engine Recommendations</h4>

                    {investigation.recommended_actions.length > 0 ? (
                      <ul>
                        {investigation.recommended_actions.map(
                          (item, index) => (
                            <li key={index}>{item}</li>
                          )
                        )}
                      </ul>
                    ) : (
                      <p>No additional recommendations available.</p>
                    )}
                  </div>

                  {/* LIMITATIONS */}

                  <div className="ai-result-section">
                    <h4>Investigation Limitations</h4>

                    {investigation.ai_investigation.report
                      ?.limitations?.length ? (
                      <ul>
                        {investigation.ai_investigation.report.limitations.map(
                          (item, index) => (
                            <li key={index}>{item}</li>
                          )
                        )}
                      </ul>
                    ) : (
                      <p>No limitations were returned.</p>
                    )}
                  </div>

                  <div className="incident-safety">
                    <ShieldCheck size={16} />
                    AI recommendations are advisory only. No IP
                    blocking, firewall changes or system modifications
                    are performed automatically.
                  </div>
                </div>
              )}
            </div>

            {/* INCIDENT STATUS */}

            <label>Current status</label>

            <div className="incident-current-status">
              {current.status.replace("_", " ")}
            </div>

            {NEXT_STATUS[current.status] ? (
              <>
                <label>Next status</label>

                <select
                  value={pendingStatus || ""}
                  disabled={busy}
                  onChange={e => {
                    const value = e.target.value as IncidentStatus;

                    if (value) {
                      void changeStatus(value);
                    } else {
                      setPendingStatus(null);
                    }
                  }}
                >
                  <option value="">Select next status</option>
                  <option value={NEXT_STATUS[current.status]}>
                    {NEXT_STATUS[current.status]}
                  </option>
                </select>
              </>
            ) : (
              <p className="history-empty">
                This incident has completed its workflow.
              </p>
            )}

            {/* RESOLUTION */}

            {pendingStatus && (
              <div className="incident-resolution-panel">
                <h3>
                  {pendingStatus === "RESOLVED"
                    ? "Resolve incident"
                    : "Close incident"}
                </h3>

                <p>
                  Provide an explanation before submitting this
                  status change.
                </p>

                <textarea
                  value={resolution}
                  onChange={e => setResolution(e.target.value)}
                  placeholder="Explain the investigation findings, containment measures and verification..."
                  maxLength={5000}
                  disabled={busy}
                />

                <small>
                  {resolution.length}/5000 characters
                </small>

                <button
                  className="incident-primary"
                  disabled={busy || resolution.trim().length < 2}
                  onClick={() => void confirmResolution()}
                >
                  {busy ? "Saving..." : `Confirm ${pendingStatus}`}
                </button>

                <button
                  className="incident-cancel"
                  disabled={busy}
                  onClick={() => {
                    setPendingStatus(null);
                    setResolution("");
                  }}
                >
                  Cancel
                </button>
              </div>
            )}

            {current.resolution && (
              <div className="incident-resolution-panel">
                <h3>Saved resolution</h3>
                <p>{current.resolution}</p>
              </div>
            )}

            {/* ANALYST NOTES */}

            <label>Analyst note</label>

            <textarea
              value={note}
              onChange={e => setNote(e.target.value)}
              placeholder="Record evidence, findings or investigation notes..."
            />

            <button
              className="incident-primary"
              disabled={busy || !note.trim()}
              onClick={() => void submitNote()}
            >
              Add note
            </button>

            <div className="incident-history">
              <h3>Investigation notes</h3>

              {detailLoading ? (
                <p>Loading history...</p>
              ) : notes.length === 0 ? (
                <p className="history-empty">
                  No analyst notes recorded yet.
                </p>
              ) : (
                notes.map(n => (
                  <article key={n.id}>
                    <div>
                      <b>{n.author}</b>

                      <time>
                        {new Date(n.created_at).toLocaleString("en-IN", {
                          timeZone: "Asia/Kolkata",
                          dateStyle: "medium",
                          timeStyle: "short",
                        })}{" "}
                        IST
                      </time>
                    </div>

                    <p>{n.note}</p>
                  </article>
                ))
              )}
            </div>

            {/* RESPONSE ACTION LOG */}

            <label>Response action log</label>

            <textarea
              value={action}
              onChange={e => setAction(e.target.value)}
              placeholder="Describe a defensive action taken. This only records the action; it does not block an IP..."
            />

            <button
              className="incident-primary secondary"
              disabled={busy || !action.trim()}
              onClick={() => void submitAction()}
            >
              Record response action
            </button>

            <div className="incident-history">
              <h3>Response action history</h3>

              {detailLoading ? (
                <p>Loading history...</p>
              ) : actions.length === 0 ? (
                <p className="history-empty">
                  No response actions recorded yet.
                </p>
              ) : (
                actions.map(a => (
                  <article key={a.id}>
                    <div>
                      <b>
                        {a.actor} · {a.action_type}
                      </b>

                      <time>
                        {new Date(a.created_at).toLocaleString("en-IN", {
                          timeZone: "Asia/Kolkata",
                          dateStyle: "medium",
                          timeStyle: "short",
                        })}{" "}
                        IST
                      </time>
                    </div>

                    <p>{a.details}</p>
                    <small>{a.outcome}</small>
                  </article>
                ))
              )}
            </div>

            {/* SAFETY NOTICE */}

            <div className="incident-safety">
              <ShieldCheck size={16} />
              Response actions are audit records only. No host or
              network is modified automatically.
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
