
import { Fragment, useEffect, useState } from "react";

import {
  Eye,
  ShieldAlert,
  AlertTriangle,
  Info,
  BrainCircuit,
  Search,
  ChevronDown,
  ChevronUp,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Lightbulb,
  Activity,
  ShieldCheck,
} from "lucide-react";

import {
  getSecurityEvents,
  getSecurityInvestigation,
  type SecurityEvent,
  type SecurityInvestigation,
} from "../services/securityEvents";

function AlertTable() {
  const [alerts, setAlerts] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [selectedEvent, setSelectedEvent] = useState<number | null>(null);

  const [investigation, setInvestigation] =
    useState<SecurityInvestigation | null>(null);

  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [investigationError, setInvestigationError] = useState("");

  // ========================================
  // AUTHENTICATION TOKEN
  // ========================================

  function getAuthToken(): string {
    return (
      sessionStorage.getItem("nyensung_token") ||
      sessionStorage.getItem("sentinel_token") ||
      ""
    );
  }

  // ========================================
  // FETCH SECURITY EVENTS
  // ========================================

  async function fetchAlerts() {
    try {
      setLoading(true);
      setError("");

      const token = getAuthToken();

      if (!token) {
        throw new Error(
          "Authentication token not found. Please log in again."
        );
      }

      const data = await getSecurityEvents(token);

      setAlerts(data);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load security events."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void fetchAlerts();
  }, []);

  // ========================================
  // FETCH AI INVESTIGATION
  // ========================================

  async function handleInvestigation(eventId: number) {
    // Close investigation if the same event is clicked.
    if (selectedEvent === eventId) {
      setSelectedEvent(null);
      setInvestigation(null);
      setInvestigationError("");
      return;
    }

    setSelectedEvent(eventId);
    setInvestigation(null);
    setInvestigationError("");
    setInvestigationLoading(true);

    try {
      const token = getAuthToken();

      if (!token) {
        throw new Error(
          "Authentication token not found. Please log in again."
        );
      }

      const result = await getSecurityInvestigation(eventId, token);

      setInvestigation(result);
    } catch (err) {
      setInvestigationError(
        err instanceof Error
          ? err.message
          : "Unable to generate investigation."
      );
    } finally {
      setInvestigationLoading(false);
    }
  }

  // ========================================
  // SEVERITY ICON
  // ========================================

  function getSeverityIcon(severity: string) {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
      case "HIGH":
        return <ShieldAlert size={16} />;

      case "MEDIUM":
        return <AlertTriangle size={16} />;

      default:
        return <Info size={16} />;
    }
  }

  // ========================================
  // FORMAT TIME IN IST
  // ========================================

  function formatTime(timestamp: string) {
    const eventDate = new Date(timestamp);

    if (Number.isNaN(eventDate.getTime())) {
      return "Unknown";
    }

    return (
      eventDate.toLocaleString("en-IN", {
        timeZone: "Asia/Kolkata",
        dateStyle: "medium",
        timeStyle: "medium",
      }) + " IST"
    );
  }

  // ========================================
  // FORMAT NETWORK ENDPOINT
  // ========================================

  function formatEndpoint(
    ip: string | null | undefined,
    port: number | null | undefined
  ) {
    if (!ip) {
      return "N/A";
    }

    return port != null ? `${ip}:${port}` : ip;
  }

  // ========================================
  // AI INVESTIGATION PANEL
  // ========================================

  function InvestigationPanel() {
    if (investigationLoading) {
      return (
        <div className="ai-investigation-panel">
          <Loader2 className="ai-spin" size={28} />

          <h3>AI Investigation in Progress</h3>

          <p>
            Qwen3 is analysing the security evidence.
            Please wait...
          </p>
        </div>
      );
    }

    if (investigationError) {
      return (
        <div className="ai-investigation-panel">
          <AlertCircle size={28} color="#EF4444" />

          <h3>Investigation Failed</h3>

          <p>{investigationError}</p>

          <button
            className="investigate-button"
            onClick={() => {
              if (selectedEvent !== null) {
                void handleInvestigation(selectedEvent);
              }
            }}
          >
            Retry Investigation
          </button>
        </div>
      );
    }

    if (!investigation) {
      return null;
    }

    const ai = investigation.ai_investigation;

    return (
      <div className="ai-investigation-panel">

        {/* HEADER */}

        <div className="ai-panel-header">
          <div className="ai-panel-title">
            <BrainCircuit size={25} color="#22D3EE" />

            <div>
              <h3>NyensungAI Investigation Report</h3>
              <p>Local AI model: {ai.model}</p>
            </div>
          </div>

          <span className="ai-live-status">
            {ai.success ? "ANALYSIS COMPLETE" : "AI UNAVAILABLE"}
          </span>
        </div>

        {/* EVENT INFORMATION */}

        <div className="investigation-event-info">
          <div>
            <small>EVENT ID</small>
            <strong>
              ALT-
              {String(investigation.investigation.event_id).padStart(3, "0")}
            </strong>
          </div>

          <div>
            <small>EVENT TYPE</small>
            <strong>
              {investigation.investigation.event_type.replaceAll("_", " ")}
            </strong>
          </div>

          <div>
            <small>RISK SCORE</small>
            <strong>
              {investigation.investigation.risk_score}/100
            </strong>
          </div>

          <div>
            <small>SEVERITY</small>
            <strong>{investigation.investigation.severity}</strong>
          </div>
        </div>

        {/* EVIDENCE SUMMARY */}

        <div className="investigation-section">
          <h4>
            <Activity size={17} />
            Evidence Summary
          </h4>

          <div className="evidence-grid">
            <div className="evidence-item">
              <strong>
                {investigation.evidence.related_events_found}
              </strong>
              <span>Related Events</span>
            </div>

            <div className="evidence-item">
              <strong>
                {investigation.evidence.failed_login_events}
              </strong>
              <span>Failed Logins</span>
            </div>

            <div className="evidence-item">
              <strong>
                {investigation.evidence.successful_login_events}
              </strong>
              <span>Successful Logins</span>
            </div>

            <div className="evidence-item">
              <strong>
                {investigation.evidence.additional_suspicious_events}
              </strong>
              <span>Suspicious Events</span>
            </div>
          </div>
        </div>

        {/* DETERMINISTIC INVESTIGATION */}

        <div className="investigation-section">
          <h4>
            <Search size={17} />
            Investigation Findings
          </h4>

          <p>{investigation.investigation.explanation}</p>

          {investigation.risk_factors.length > 0 && (
            <ul>
              {investigation.risk_factors.map((factor, index) => (
                <li key={index}>{factor}</li>
              ))}
            </ul>
          )}
        </div>

        {/* AI REPORT */}

        {!ai.success ? (
          <div className="ai-error-box">
            <AlertCircle size={20} />

            <div>
              <strong>AI analysis unavailable</strong>
              <p>
                {ai.error || "The AI report could not be generated."}
              </p>
            </div>
          </div>
        ) : ai.report ? (
          <>
            {/* ASSESSMENT */}

            <div className="investigation-section">
              <h4>
                <BrainCircuit size={17} />
                AI Assessment
              </h4>

              <p>{ai.report.assessment}</p>

              <div className="ai-classification">
                <div>
                  <small>POSSIBLE ATTACK</small>
                  <strong>{ai.report.possible_attack}</strong>
                </div>

                <div>
                  <small>AI CONFIDENCE</small>
                  <strong>{ai.report.confidence}</strong>
                </div>
              </div>

              <p className="ai-disclaimer">
                AI confidence is an assessment of the available
                evidence, not a probability of compromise.
              </p>
            </div>

            {/* EVIDENCE ANALYSIS */}

            <div className="investigation-section">
              <h4>
                <Search size={17} />
                AI Evidence Analysis
              </h4>

              <ul>
                {ai.report.evidence_analysis.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>

            {/* POTENTIAL IMPACT */}

            <div className="investigation-section">
              <h4>
                <AlertTriangle size={17} />
                Potential Impact
              </h4>

              <p>{ai.report.potential_impact}</p>
            </div>

            {/* RECOMMENDED ACTIONS */}

            <div className="investigation-section">
              <h4>
                <ShieldCheck size={17} />
                AI Recommended Actions
              </h4>

              <ul className="recommendation-list">
                {ai.report.recommended_actions.map((item, index) => (
                  <li key={index}>
                    <CheckCircle2 size={16} />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* LIMITATIONS */}

            <div className="investigation-section">
              <h4>
                <Info size={17} />
                Investigation Limitations
              </h4>

              <ul>
                {ai.report.limitations.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>
          </>
        ) : null}

        {/* BACKEND RECOMMENDATIONS */}

        <div className="investigation-section">
          <h4>
            <Lightbulb size={17} />
            Backend Recommendations
          </h4>

          <ul>
            {investigation.recommended_actions.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        </div>

        {/* DISCLAIMER */}

        <div className="ai-footer">
          <Info size={15} />

          AI recommendations are advisory only.
          Analyst verification is required before taking action.
        </div>
      </div>
    );
  }

  // ========================================
  // MAIN ALERT TABLE
  // ========================================

  return (
    <div className="alert-table-card">

      {/* TABLE HEADER */}

      <div className="alert-table-header">
        <div>
          <h3>Recent Security Alerts</h3>

          <p>
            Latest security events from NyensungAI database
          </p>
        </div>

        <button
          className="view-all-button"
          onClick={() => void fetchAlerts()}
          disabled={loading}
        >
          <Eye size={16} />
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      {/* LOADING STATE */}

      {loading ? (
        <p className="table-message">
          Loading security events...
        </p>
      ) : error ? (
        <p className="table-message error-message">
          {error}
        </p>
      ) : alerts.length === 0 ? (
        <p className="table-message">
          No security events found.
        </p>
      ) : (

        /* SECURITY EVENTS TABLE */

        <div className="table-wrapper">
          <table className="alert-table">

            <thead>
              <tr>
                <th>ALERT ID</th>
                <th>EVENT</th>
                <th>SOURCE IP</th>
                <th>PROCESS</th>
                <th>PID</th>
                <th>LOCAL ENDPOINT</th>
                <th>REMOTE ENDPOINT</th>
                <th>PROTOCOL</th>
                <th>SEVERITY</th>
                <th>STATUS</th>
                <th>DETECTED</th>
                <th>INVESTIGATE</th>
              </tr>
            </thead>

            <tbody>
              {alerts.map((alert) => (
                <Fragment key={alert.id}>

                  {/* ALERT ROW */}

                  <tr>
                    <td className="alert-id">
                      ALT-{String(alert.id).padStart(3, "0")}
                    </td>

                    <td className="alert-event">
                      <strong>
                        {alert.event_type.replaceAll("_", " ")}
                      </strong>

                      <small>{alert.description}</small>
                    </td>

                    <td className="alert-source">
                      {alert.source_ip || "N/A"}
                    </td>

                    <td>
                      {alert.process_name || "N/A"}
                    </td>

                    <td>
                      {alert.process_id ?? "N/A"}
                    </td>

                    <td>
                      {formatEndpoint(
                        alert.local_ip,
                        alert.local_port
                      )}
                    </td>

                    <td>
                      {formatEndpoint(
                        alert.remote_ip,
                        alert.remote_port
                      )}
                    </td>

                    <td>
                      {alert.protocol || "N/A"}
                    </td>

                    <td>
                      <span
                        className={`severity-badge severity-${alert.severity.toLowerCase()}`}
                      >
                        {getSeverityIcon(alert.severity)}
                        {alert.severity}
                      </span>
                    </td>

                    <td>{alert.status}</td>

                    <td className="alert-time">
                      {formatTime(alert.timestamp)}
                    </td>

                    <td>
                      <button
                        className="investigate-button"
                        onClick={() =>
                          void handleInvestigation(alert.id)
                        }
                        disabled={
                          investigationLoading &&
                          selectedEvent === alert.id
                        }
                      >
                        {selectedEvent === alert.id ? (
                          <>
                            Close <ChevronUp size={15} />
                          </>
                        ) : (
                          <>
                            Investigate <ChevronDown size={15} />
                          </>
                        )}
                      </button>
                    </td>
                  </tr>

                  {/* AI INVESTIGATION ROW */}

                  {selectedEvent === alert.id && (
                    <tr>
                      <td
                        colSpan={12}
                        className="investigation-table-cell"
                      >
                        <InvestigationPanel />
                      </td>
                    </tr>
                  )}

                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default AlertTable;
