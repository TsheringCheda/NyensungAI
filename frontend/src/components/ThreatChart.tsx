
import { useEffect, useState } from "react";

import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend
} from "recharts";

import { getThreatActivity } from "../services/api";
import type { ThreatActivity } from "../services/api";


function formatChartTime(timestamp: string) {
  if (!timestamp) {
    return "";
  }

  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }

  return new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true
  }).format(date);
}


function formatTooltipTime(timestamp: string) {
  if (!timestamp) {
    return "";
  }

  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }

  return new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true
  }).format(date) + " IST";
}


function ThreatChart() {
  const [threatData, setThreatData] = useState<ThreatActivity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    const fetchThreatActivity = async () => {
      try {
        const data = await getThreatActivity();

        if (isMounted) {
          setThreatData(data);
          setError(null);
        }
      } catch (err) {
        console.error("Failed to load threat activity:", err);

        if (isMounted) {
          setError(
            "Unable to load threat activity. Check your backend connection."
          );
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchThreatActivity();

    const refreshInterval = window.setInterval(() => {
      fetchThreatActivity();
    }, 30000);

    return () => {
      isMounted = false;
      window.clearInterval(refreshInterval);
    };
  }, []);

  return (
    <div className="threat-chart-card">
      <div className="chart-header">
        <div>
          <h3>Threat Activity</h3>
          <p>Real security event distribution over time (IST)</p>
        </div>

        <span className="chart-period">
          LAST 24 HOURS
        </span>
      </div>

      <div className="chart-container">
        {loading ? (
          <div className="chart-message">
            Loading threat activity...
          </div>
        ) : error && threatData.length === 0 ? (
          <div className="chart-message chart-error">
            {error}
          </div>
        ) : threatData.length === 0 ? (
          <div className="chart-message">
            No threat activity data available.
          </div>
        ) : (
          <>
            {error && (
              <div className="chart-error">
                {error} Showing the last successfully loaded data.
              </div>
            )}

            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={threatData}>
                <defs>
                  <linearGradient
                    id="normalGradient"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
                  </linearGradient>

                  <linearGradient
                    id="suspiciousGradient"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop offset="5%" stopColor="#F59E0B" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#F59E0B" stopOpacity={0} />
                  </linearGradient>

                  <linearGradient
                    id="criticalGradient"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                </defs>

                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#26374B"
                  vertical={false}
                />

                <XAxis
                  dataKey="time"
                  stroke="#8293A8"
                  tickLine={false}
                  minTickGap={30}
                  tickFormatter={formatChartTime}
                />

                <YAxis
                  stroke="#8293A8"
                  tickLine={false}
                  axisLine={false}
                  allowDecimals={false}
                />

                <Tooltip
                  labelFormatter={(label) =>
                    formatTooltipTime(String(label))
                  }
                  contentStyle={{
                    backgroundColor: "#111F30",
                    border: "1px solid #26374B",
                    borderRadius: "8px",
                    color: "#FFFFFF"
                  }}
                />

                <Legend />

                <Area
                  type="monotone"
                  dataKey="normal"
                  name="Normal Events"
                  stroke="#06B6D4"
                  fill="url(#normalGradient)"
                />

                <Area
                  type="monotone"
                  dataKey="suspicious"
                  name="Suspicious Events"
                  stroke="#F59E0B"
                  fill="url(#suspiciousGradient)"
                />

                <Area
                  type="monotone"
                  dataKey="critical"
                  name="Critical Events"
                  stroke="#EF4444"
                  fill="url(#criticalGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </>
        )}
      </div>
    </div>
  );
}

export default ThreatChart;
