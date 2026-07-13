import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import PortalShell from "../components/PortalShell";
import { apiRequest } from "../api";

export default function DashboardPage() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [alerts, setAlerts] = useState([]);
  const [alertsLoading, setAlertsLoading] = useState(true);
  const [alertsError, setAlertsError] = useState("");
  const [xaiStatus, setXaiStatus] = useState("");
  const [xaiLoading, setXaiLoading] = useState(false);

  useEffect(() => {
    apiRequest("/dashboard")
      .then((res) => setData(res))
      .catch((err) => {
        setError(err.message || "Session invalid");
        localStorage.removeItem("hp_token");
        localStorage.removeItem("hp_user");
      });

    loadXaiAlerts();
  }, []);

  async function loadXaiAlerts() {
    setAlertsLoading(true);
    setAlertsError("");

    try {
      const res = await apiRequest("/logs/backend?limit=100");
      const filtered = (res.entries || [])
        .map((entry) => {
          const severity =
            entry.details?.severity ||
            (entry.details?.attackType && entry.details.attackType !== "web_activity"
              ? "warning"
              : "info");
          return { ...entry, severity };
        })
        .filter((entry) => entry.severity === "warning" || entry.severity === "critical")
        .slice(0, 12);

      setAlerts(filtered);
    } catch (err) {
      setAlertsError(err.message || "Could not load XAI alerts");
    } finally {
      setAlertsLoading(false);
    }
  }

  function logout() {
    localStorage.removeItem("hp_token");
    localStorage.removeItem("hp_user");
    navigate("/");
  }

  function formatPayload(entry) {
    return (
      entry.details?.payload || entry.details?.path || entry.details?.query || entry.event || "n/a"
    );
  }

  function severityClass(severity) {
    return severity === "critical" ? "badge badge-critical" : "badge badge-warning";
  }

  async function generateXaiReport() {
    setXaiStatus("");
    setXaiLoading(true);

    const topAlert = alerts.find((entry) => entry.severity === "critical") || alerts[0];
    if (!topAlert) {
      setXaiStatus("No critical or warning alerts are available to generate a report.");
      setXaiLoading(false);
      return;
    }

    const payload = {
      source_ip: topAlert.details?.ip || topAlert.details?.ip_address || "unknown",
      attack_type: topAlert.details?.attackType || topAlert.details?.findings?.[0] || "unknown",
      severity: topAlert.severity,
      service: topAlert.details?.service || "website",
      timestamp: topAlert.timestamp || new Date().toISOString(),
      payload: formatPayload(topAlert),
      username: topAlert.details?.username,
      password: topAlert.details?.password,
      report_source: "dashboard_xai_button",
    };

    try {
      const response = await fetch("http://localhost:5678/webhook/xai-honeypot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => response.statusText);
        throw new Error(errorText || `Webhook failed (${response.status})`);
      }

      setXaiStatus("XAI report generated and sent to Telegram successfully.");
    } catch (err) {
      setXaiStatus(`Failed to send XAI report: ${err.message}`);
    } finally {
      setXaiLoading(false);
    }
  }

  return (
    <PortalShell title="Honeypot Dashboard" subtitle="Threat signal overview after successful login.">
      <section className="card">
        <div className="topbar">
          <h2 style={{ margin: 0 }}>Security Panel</h2>
          <button onClick={logout}>Logout</button>
        </div>

        {error ? <p className="msg">{error}</p> : null}

        {data ? (
          <>
            <p className="good">Welcome, {data.user.username}</p>
            <div className="kpis">
              <article className="kpi">
                <div>Alerts Today</div>
                <div className="num">{data.panel.alertsToday}</div>
              </article>
              <article className="kpi">
                <div>Suspicious Logins</div>
                <div className="num">{data.panel.suspiciousLogins}</div>
              </article>
              <article className="kpi">
                <div>Active Decoys</div>
                <div className="num">{data.panel.activeDecoys}</div>
              </article>
            </div>

            <section className="card xai-card">
              <div className="topbar">
                <div>
                  <h3 style={{ margin: 0 }}>XAI Alerts</h3>
                  <p style={{ margin: "6px 0 0", color: "var(--muted)" }}>
                    Showing the latest warning and critical alerts only.
                  </p>
                </div>
                <div className="xai-actions">
                  <button onClick={loadXaiAlerts} disabled={alertsLoading}>
                    Refresh Alerts
                  </button>
                  <button onClick={generateXaiReport} disabled={xaiLoading || alerts.length === 0}>
                    {xaiLoading ? "Sending report..." : "Generate XAI Report"}
                  </button>
                </div>
              </div>

              {alertsError ? <p className="msg">{alertsError}</p> : null}
              {xaiStatus ? <p className="msg" style={{ color: "var(--action)" }}>{xaiStatus}</p> : null}
              {alertsLoading ? (
                <p>Loading XAI alerts...</p>
              ) : alerts.length === 0 ? (
                <p>No warning or critical alerts found.</p>
              ) : (
                <table className="alert-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Severity</th>
                      <th>Attack</th>
                      <th>Source</th>
                      <th>Payload</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.map((alert, idx) => (
                      <tr key={idx}>
                        <td>{new Date(alert.timestamp).toLocaleString()}</td>
                        <td>
                          <span className={severityClass(alert.severity)}>{alert.severity}</span>
                        </td>
                        <td>{alert.details?.attackType || alert.event || "unknown"}</td>
                        <td>{alert.details?.ip || alert.details?.path || "n/a"}</td>
                        <td>{formatPayload(alert)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
          </>
        ) : (
          <p>Loading panel...</p>
        )}
      </section>
    </PortalShell>
  );
}
