import { useCallback, useEffect, useRef, useState } from "react";

import {
  Activity,
  ShieldAlert,
  Bell,
  ClipboardList,
  BrainCircuit,
  ShieldCheck,
  RefreshCw,
  Clock3,
  Radio,
  X,
  AlertTriangle,
} from "lucide-react";

import Sidebar from "../components/Sidebar";
import Topbar from "../components/Topbar";
import StatCard from "../components/StatCard";
import ThreatChart from "../components/ThreatChart";
import AlertTable from "../components/AlertTable";
import Incidents from "./Incidents";
import SecurityAlerts from "./SecurityAlerts";
import ThreatMonitoring from "./ThreatMonitoring";
import Reports from "./Reports";
import Settings from "./Settings";

import { getSecurityStats } from "../services/api";
import type { User, SecurityStats } from "../services/api";

import {
  connectSecurityEvents,
  type RealtimeStatus,
  type RealtimeSecurityEvent,
} from "../services/realtime";

interface DashboardProps {
  user: User;
  token: string;
  onLogout: () => void;
}

const emptyStats: SecurityStats = {
  total_events: 0,
  active_threats: 0,
  critical_alerts: 0,
  open_incidents: 0,
  ml_anomalies: 0,
  rule_based_alerts: 0,
};

const ALERT_AUTO_DISMISS_MS = 12000;
const EVENT_REFRESH_DEBOUNCE_MS = 500;

function Dashboard({ user, token, onLogout }: DashboardProps) {
  const [activePage, setActivePage] = useState("Dashboard");

  const [stats, setStats] = useState<SecurityStats>(emptyStats);
  const [statsLoading, setStatsLoading] = useState(true);
  const [statsError, setStatsError] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const [dashboardRefreshKey, setDashboardRefreshKey] = useState(0);
  const [realtimeStatus, setRealtimeStatus] =
    useState<RealtimeStatus>("connecting");
  const [liveAlert, setLiveAlert] =
    useState<RealtimeSecurityEvent | null>(null);

  const refreshTimerRef = useRef<number | null>(null);
  const alertTimerRef = useRef<number | null>(null);
  const seenEventsRef = useRef<Set<string>>(new Set());

  // Fetch dashboard statistics without allowing a failed request to crash the UI.
  const fetchDashboardData = useCallback(
    async (manual = false) => {
      if (manual) {
        setRefreshing(true);
      }

      try {
        const statsData = await getSecurityStats(token);
        setStats(statsData);
        setStatsError(false);
        setLastUpdated(new Date());
      } catch (error) {
        console.error("Dashboard data error:", error);
        setStatsError(true);
      } finally {
        setStatsLoading(false);
        if (manual) {
          setRefreshing(false);
        }
      }
    },
    [token]
  );

  // Initial load and 30-second fallback polling.
  useEffect(() => {
    void fetchDashboardData();

    const intervalId = window.setInterval(() => {
      void fetchDashboardData();
    }, 30000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [fetchDashboardData]);

  // Keep the authenticated real-time connection stable for this token.
  useEffect(() => {
    const disconnect = connectSecurityEvents(token, {
      onStatus: (status) => {
        setRealtimeStatus(status);
      },

      onEvent: (event) => {
        console.log("NyensungAI live security event:", event);

        // Avoid displaying the same delivered event more than once.
        const eventKey = JSON.stringify(event);
        if (seenEventsRef.current.has(eventKey)) {
          return;
        }

        seenEventsRef.current.add(eventKey);

        // Bound the in-memory de-duplication cache.
        if (seenEventsRef.current.size > 100) {
          const oldestKey = seenEventsRef.current.values().next().value;
          if (oldestKey) {
            seenEventsRef.current.delete(oldestKey);
          }
        }

        const severity = (event.severity || "").toUpperCase();
        const eventType = (event.event_type || "").toUpperCase();

        const shouldRaiseAlert =
          Boolean(event.is_suspicious) ||
          severity === "HIGH" ||
          severity === "CRITICAL" ||
          eventType.includes("DETECTED");

        if (shouldRaiseAlert) {
          setLiveAlert(event);

          if (alertTimerRef.current !== null) {
            window.clearTimeout(alertTimerRef.current);
          }

          alertTimerRef.current = window.setTimeout(() => {
            setLiveAlert(null);
            alertTimerRef.current = null;
          }, ALERT_AUTO_DISMISS_MS);
        }

        // Debounce refreshes so a burst of events does not cause request storms.
        if (refreshTimerRef.current !== null) {
          window.clearTimeout(refreshTimerRef.current);
        }

        refreshTimerRef.current = window.setTimeout(() => {
          setDashboardRefreshKey((key) => key + 1);
          void fetchDashboardData();
          refreshTimerRef.current = null;
        }, EVENT_REFRESH_DEBOUNCE_MS);
      },
    });

    return () => {
      disconnect();

      if (refreshTimerRef.current !== null) {
        window.clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }

      if (alertTimerRef.current !== null) {
        window.clearTimeout(alertTimerRef.current);
        alertTimerRef.current = null;
      }
    };
  }, [token, fetchDashboardData]);

  const dismissLiveAlert = () => {
    setLiveAlert(null);

    if (alertTimerRef.current !== null) {
      window.clearTimeout(alertTimerRef.current);
      alertTimerRef.current = null;
    }
  };

  const dashboardStats = [
    {
      title: "Total security events",
      value: statsLoading
        ? "—"
        : statsError && !lastUpdated
          ? "N/A"
          : stats.total_events.toLocaleString(),
      change: "ALL RECORDED",
      description: "Events ingested by the platform",
      icon: Activity,
      color: "#52c7e8",
    },
    {
      title: "Active threats",
      value: statsLoading
        ? "—"
        : statsError && !lastUpdated
          ? "N/A"
          : stats.active_threats.toLocaleString(),
      change: "INVESTIGATE",
      description: "Events currently marked suspicious",
      icon: ShieldAlert,
      color: "#ff657a",
    },
    {
      title: "Critical alerts",
      value: statsLoading
        ? "—"
        : statsError && !lastUpdated
          ? "N/A"
          : stats.critical_alerts.toLocaleString(),
      change: "HIGH PRIORITY",
      description: "Critical-severity security events",
      icon: Bell,
      color: "#ffb454",
    },
    {
      title: "Open incidents",
      value: statsLoading
        ? "—"
        : statsError && !lastUpdated
          ? "N/A"
          : stats.open_incidents.toLocaleString(),
      change: "CASE QUEUE",
      description: "Incidents not yet closed",
      icon: ClipboardList,
      color: "#a995ff",
    },
    {
      title: "ML anomalies",
      value: statsLoading
        ? "—"
        : statsError && !lastUpdated
          ? "N/A"
          : stats.ml_anomalies.toLocaleString(),
      change: "ISOLATION FOREST",
      description: "Events flagged by anomaly detection",
      icon: BrainCircuit,
      color: "#d28cff",
    },
    {
      title: "Rule-based alerts",
      value: statsLoading
        ? "—"
        : statsError && !lastUpdated
          ? "N/A"
          : stats.rule_based_alerts.toLocaleString(),
      change: "DETECTION RULES",
      description: "Events raised by deterministic rules",
      icon: ShieldCheck,
      color: "#69d6b0",
    },
  ];

  const pageInfo: Record<string, { title: string; description: string }> = {
    Dashboard: {
      title: "Security operations overview",
      description:
        "A consolidated view of detections, investigations and incident response.",
    },
    Incidents: {
      title: "Incident response",
      description: "Investigate, track and manage security incidents.",
    },
    "Security Alerts": {
      title: "Security alerts",
      description: "Review and investigate detected security alerts.",
    },
    "Threat Monitoring": {
      title: "Threat monitoring",
      description: "Review security telemetry and detection activity.",
    },
    Reports: {
      title: "Security reports",
      description: "Export event and incident records for review.",
    },
    Settings: {
      title: "System settings",
      description: "Review service health and monitoring preferences.",
    },
  };

  const currentPage = pageInfo[activePage] || {
    title: activePage,
    description: "Manage your NyensungAI security environment.",
  };

  const formatUpdated = (date: Date) =>
    date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });

  const realtimeLabel: Record<RealtimeStatus, string> = {
    connecting: "CONNECTING LIVE STREAM",
    connected: "REAL-TIME CONNECTED",
    reconnecting: "RECONNECTING LIVE STREAM",
    error: "LIVE STREAM AUTHENTICATION ERROR",
  };

  const alertSeverity = (liveAlert?.severity || "HIGH").toUpperCase();
  const alertTitle =
    liveAlert?.event_type || "Suspicious security activity";
  const alertDescription =
    liveAlert?.description || "A security event requires analyst attention.";

  return (
    <div className="dashboard-layout">
      <Sidebar activePage={activePage} onNavigate={setActivePage} />

      <main className="dashboard-main">
        <Topbar
          activePage={activePage}
          user={user}
          onLogout={onLogout}
        />

        {liveAlert && (
          <div
            role="alert"
            aria-live="assertive"
            style={{
              position: "fixed",
              right: "24px",
              bottom: "24px",
              zIndex: 9999,
              width: "min(440px, calc(100vw - 32px))",
              padding: "18px",
              border: "1px solid rgba(255, 101, 122, 0.75)",
              borderLeft: "5px solid #ff657a",
              borderRadius: "12px",
              background: "#171b27",
              color: "#f4f6fb",
              boxShadow: "0 16px 48px rgba(0, 0, 0, 0.45)",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "12px",
                marginBottom: "10px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  color: "#ff8796",
                  fontWeight: 800,
                  fontSize: "12px",
                  letterSpacing: "0.08em",
                }}
              >
                <AlertTriangle size={17} />
                LIVE SECURITY ALERT · {alertSeverity}
              </div>

              <button
                type="button"
                onClick={dismissLiveAlert}
                aria-label="Dismiss security alert"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  border: 0,
                  borderRadius: "6px",
                  padding: "5px",
                  color: "#d9deea",
                  background: "transparent",
                  cursor: "pointer",
                }}
              >
                <X size={18} />
              </button>
            </div>

            <div
              style={{
                fontSize: "16px",
                fontWeight: 750,
                marginBottom: "6px",
                overflowWrap: "anywhere",
              }}
            >
              {alertTitle}
            </div>

            <div
              style={{
                color: "#c4cada",
                fontSize: "13px",
                lineHeight: 1.5,
                overflowWrap: "anywhere",
              }}
            >
              {alertDescription}
            </div>

            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: "12px",
                marginTop: "12px",
                color: "#ffb7c0",
                fontSize: "12px",
                fontWeight: 650,
              }}
            >
              {liveAlert.source_ip && (
                <span>Source IP: {liveAlert.source_ip}</span>
              )}
              {typeof liveAlert.risk_score === "number" && (
                <span>Risk score: {liveAlert.risk_score}</span>
              )}
            </div>

            <div
              style={{
                marginTop: "12px",
                color: "#929bad",
                fontSize: "11px",
              }}
            >
              This notification closes automatically after 12 seconds.
            </div>
          </div>
        )}

        <div className="dashboard-content">
          {activePage !== "Incidents" && (
            <section className="soc-page-heading">
              <div>
                <div className="soc-eyebrow">
                  NYENSUNGAI / SECURITY OPERATIONS
                </div>

                <h1>{currentPage.title}</h1>
                <p>{currentPage.description}</p>
              </div>

              {activePage === "Dashboard" && (
                <div className="soc-heading-actions">
                  <div
                    className={`soc-live-state ${
                      statsError ? "is-degraded" : ""
                    }`}
                  >
                    <span className="soc-live-dot" />
                    {statsError
                      ? "API CONNECTION ISSUE"
                      : statsLoading
                        ? "CONNECTING"
                        : "API CONNECTED"}
                  </div>

                  <div
                    className={`soc-live-state ${
                      realtimeStatus !== "connected" ? "is-degraded" : ""
                    }`}
                    aria-live="polite"
                  >
                    <span className="soc-live-dot" />
                    {realtimeLabel[realtimeStatus]}
                  </div>

                  <button
                    type="button"
                    className="soc-refresh-button"
                    onClick={() => void fetchDashboardData(true)}
                    disabled={refreshing}
                  >
                    <RefreshCw
                      size={15}
                      className={refreshing ? "soc-spin" : ""}
                    />
                    {refreshing ? "Refreshing" : "Refresh"}
                  </button>
                </div>
              )}
            </section>
          )}

          {activePage === "Incidents" ? (
            <Incidents />
          ) : activePage === "Security Alerts" ? (
            <SecurityAlerts />
          ) : activePage === "Threat Monitoring" ? (
            <ThreatMonitoring />
          ) : activePage === "Reports" ? (
            <Reports />
          ) : activePage === "Settings" ? (
            <Settings user={user} />
          ) : activePage === "Dashboard" ? (
            <>
              <section
                className="soc-status-strip"
                aria-label="Monitoring status"
              >
                <div className="soc-status-item">
                  <span className="soc-status-icon">
                    <Radio size={16} />
                  </span>
                  <div>
                    <small>ENVIRONMENT</small>
                    <strong>Local security lab</strong>
                  </div>
                </div>

                <div className="soc-status-item">
                  <span className="soc-status-icon">
                    <Activity size={16} />
                  </span>
                  <div>
                    <small>DATA REFRESH</small>
                    <strong>Real-time + 30-sec fallback</strong>
                  </div>
                </div>

                <div className="soc-status-item">
                  <span className="soc-status-icon">
                    <Clock3 size={16} />
                  </span>
                  <div>
                    <small>LAST SUCCESSFUL UPDATE</small>
                    <strong>
                      {lastUpdated ? formatUpdated(lastUpdated) : "Awaiting data"}
                    </strong>
                  </div>
                </div>

                <div className="soc-status-item soc-status-note">
                  <span className="soc-status-icon">
                    <ShieldCheck size={16} />
                  </span>
                  <div>
                    <small>PLATFORM MODE</small>
                    <strong>Defensive monitoring</strong>
                  </div>
                </div>
              </section>

              {statsError && (
                <div className="soc-inline-warning" role="status">
                  Statistics could not be refreshed.{" "}
                  {lastUpdated
                    ? "Showing the last successfully loaded values."
                    : "Check that the backend is running."}
                </div>
              )}

              <div className="soc-section-heading">
                <div>
                  <h2>Security posture</h2>
                  <p>Key indicators from the event and incident database</p>
                </div>

                <span>REAL-TIME · 30 SEC FALLBACK</span>
              </div>

              <section className="stats-grid soc-stats-grid">
                {dashboardStats.map((stat) => (
                  <StatCard key={stat.title} {...stat} />
                ))}
              </section>

              <div className="soc-dashboard-grid">
                <section className="soc-panel soc-activity-panel">
                  <div className="soc-panel-heading">
                    <div>
                      <h2>Detection activity</h2>
                      <p>Recorded event volume and severity over time</p>
                    </div>

                    <span className="soc-panel-tag">24 HOURS</span>
                  </div>

                  <ThreatChart key={`threat-chart-${dashboardRefreshKey}`} />
                </section>

                <section className="soc-panel soc-alert-panel">
                  <div className="soc-panel-heading">
                    <div>
                      <h2>Recent security alerts</h2>
                      <p>Latest events requiring analyst attention</p>
                    </div>

                    <button
                      type="button"
                      className="soc-text-action"
                      onClick={() => setActivePage("Security Alerts")}
                    >
                      View all alerts →
                    </button>
                  </div>

                  <AlertTable key={`alert-table-${dashboardRefreshKey}`} />
                </section>
              </div>

              <div className="soc-footnote">
                <ShieldCheck size={14} />
                Detection and AI investigation are decision-support
                capabilities. Validate findings against source telemetry
                before taking response action.
              </div>
            </>
          ) : (
            <div className="coming-soon">
              <Activity size={35} />
              <h2>{activePage}</h2>
              <p>This section is not available in this build.</p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default Dashboard;
