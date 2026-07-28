import { useEffect, useMemo, useState } from "react";
import { apiRequest } from "../api";
import AnalystFeedbackPanel from "./AnalystFeedbackPanel";
import XAIExplanationPanel from "./XAIExplanationPanel";

const IDS_REFRESH_MS = 10000;

function formatConfidence(value) {
  return Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : "n/a";
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "n/a" : date.toLocaleString();
}

function badgeClass(value) {
  return `badge badge-${String(value || "neutral").toLowerCase()}`;
}

function xaiSummary(result) {
  return result?.xai?.human_reason?.summary || result?.fusion_reason || "No explanation available.";
}

function uniqueValues(results, field) {
  return [...new Set(results.map((result) => result[field]).filter(Boolean))].sort();
}

function reviewLabel(feedback) {
  if (feedback?.verdict === "confirmed_attack") {
    return "Confirmed";
  }
  if (feedback?.verdict === "false_positive") {
    return "False positive";
  }
  return "Awaiting";
}

export default function IDSInsights() {
  const [results, setResults] = useState([]);
  const [stats, setStats] = useState(null);
  const [feedbackStats, setFeedbackStats] = useState(null);
  const [latestFeedback, setLatestFeedback] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(null);
  const [search, setSearch] = useState("");
  const [service, setService] = useState("");
  const [threatLevel, setThreatLevel] = useState("");
  const [prediction, setPrediction] = useState("");
  const [reviewStatus, setReviewStatus] = useState("");

  async function loadResults(showLoading = false) {
    if (showLoading) {
      setLoading(true);
    }
    setError("");

    try {
      const [resultData, statsData] = await Promise.all([
        apiRequest("/api/ids-results?limit=100"),
        apiRequest("/api/ids-results/stats"),
      ]);
      const recentResults = resultData.results || [];
      const eventIds = recentResults.map((result) => result.event_id).join(",");
      const [latestData, reviewStatsData] = await Promise.all([
        apiRequest(
          `/api/analyst-feedback/latest?event_ids=${encodeURIComponent(eventIds)}`
        ),
        apiRequest("/api/analyst-feedback/stats"),
      ]);

      setResults(recentResults);
      setStats(statsData);
      setLatestFeedback(latestData.latest_by_event || {});
      setFeedbackStats(reviewStatsData);
      setSelected((current) => {
        if (!current) {
          return null;
        }
        return recentResults.find((result) => result.event_id === current.event_id) || current;
      });
    } catch (requestError) {
      setError(requestError.message || "Could not load final IDS results");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadResults(true);
    const timer = window.setInterval(() => loadResults(false), IDS_REFRESH_MS);
    return () => window.clearInterval(timer);
  }, []);

  const services = useMemo(() => uniqueValues(results, "service"), [results]);
  const threatLevels = useMemo(() => uniqueValues(results, "threat_level"), [results]);

  const filteredResults = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return results.filter((result) => {
      const feedback = latestFeedback[result.event_id];
      const matchesSearch =
        !needle ||
        [
          result.source_ip,
          result.attack_type,
          result.event,
          result.model_used,
          xaiSummary(result),
          reviewLabel(feedback),
        ].some((value) => String(value || "").toLowerCase().includes(needle));

      const matchesReview =
        !reviewStatus ||
        (reviewStatus === "awaiting" && !feedback) ||
        (reviewStatus === "confirmed" && feedback?.verdict === "confirmed_attack") ||
        (reviewStatus === "false_positive" && feedback?.verdict === "false_positive");

      return (
        matchesSearch &&
        matchesReview &&
        (!service || result.service === service) &&
        (!threatLevel || result.threat_level === threatLevel) &&
        (!prediction || result.prediction === prediction)
      );
    });
  }, [
    results,
    latestFeedback,
    search,
    service,
    threatLevel,
    prediction,
    reviewStatus,
  ]);

  const averageConfidence = useMemo(() => {
    const values = results
      .map((result) => result.confidence)
      .filter((value) => Number.isFinite(value));
    return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
  }, [results]);

  const criticalCount = stats?.by_threat_level?.Critical || 0;

  function handleFeedbackSaved(feedback, updatedStats) {
    setLatestFeedback((current) => ({
      ...current,
      [feedback.event_id]: feedback,
    }));
    if (updatedStats) {
      setFeedbackStats(updatedStats);
    }
  }

  return (
    <section className="card ids-insights" id="ids-insights" aria-labelledby="ids-insights-title">
      <div className="ids-heading">
        <div>
          <p className="ids-kicker">Explainable security operations</p>
          <h2 id="ids-insights-title">Live Hybrid IDS Details</h2>
          <p>Final predictions, privacy-safe XAI evidence, and analyst feedback in one review queue.</p>
        </div>
        <button className="ids-refresh" onClick={() => loadResults(true)} disabled={loading}>
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      {error ? <p className="msg">{error}</p> : null}

      <div className="ids-summary ids-summary-primary" aria-label="IDS result summary">
        <article className="kpi">
          <div className="ids-summary-label">Total Results</div>
          <div className="ids-summary-value">{stats?.total_results ?? results.length}</div>
        </article>
        <article className="kpi">
          <div className="ids-summary-label">Attacks Detected</div>
          <div className="ids-summary-value">{stats?.attacks_detected ?? 0}</div>
        </article>
        <article className="kpi">
          <div className="ids-summary-label">Critical Results</div>
          <div className="ids-summary-value">{criticalCount}</div>
        </article>
        <article className="kpi">
          <div className="ids-summary-label">Average Confidence</div>
          <div className="ids-summary-value">{formatConfidence(averageConfidence)}</div>
        </article>
      </div>

      <div className="ids-review-summary" aria-label="Analyst review summary">
        <article>
          <span>Confirmed attacks</span>
          <strong>{feedbackStats?.confirmed_attacks ?? 0}</strong>
        </article>
        <article>
          <span>False positives</span>
          <strong>{feedbackStats?.false_positives ?? 0}</strong>
        </article>
        <article>
          <span>Awaiting review</span>
          <strong>{feedbackStats?.awaiting_review ?? results.length}</strong>
        </article>
        <article>
          <span>Severity overrides</span>
          <strong>{feedbackStats?.severity_overrides ?? 0}</strong>
        </article>
      </div>

      <div className="ids-filter-bar" aria-label="IDS result filters">
        <label>
          Search
          <input
            id="ids-search"
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="IP, attack, model, explanation, review"
          />
        </label>
        <label>
          Service
          <select
            id="ids-service-filter"
            value={service}
            onChange={(event) => setService(event.target.value)}
          >
            <option value="">All services</option>
            {services.map((value) => (
              <option key={value} value={value}>
                {value.toUpperCase()}
              </option>
            ))}
          </select>
        </label>
        <label>
          Threat level
          <select
            id="ids-threat-filter"
            value={threatLevel}
            onChange={(event) => setThreatLevel(event.target.value)}
          >
            <option value="">All levels</option>
            {threatLevels.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label>
          Prediction
          <select
            id="ids-prediction-filter"
            value={prediction}
            onChange={(event) => setPrediction(event.target.value)}
          >
            <option value="">All predictions</option>
            <option value="attack">Attack</option>
            <option value="normal">Normal</option>
          </select>
        </label>
        <label>
          Analyst review
          <select
            id="ids-review-filter"
            value={reviewStatus}
            onChange={(event) => setReviewStatus(event.target.value)}
          >
            <option value="">All reviews</option>
            <option value="awaiting">Awaiting review</option>
            <option value="confirmed">Confirmed attacks</option>
            <option value="false_positive">False positives</option>
          </select>
        </label>
      </div>

      <p className="ids-result-count" aria-live="polite">
        Showing {filteredResults.length} of {results.length} recent results
      </p>

      <div className="ids-table-wrap">
        <table className="ids-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Service</th>
              <th>Attack Type</th>
              <th>Prediction</th>
              <th>Effective Threat</th>
              <th>Confidence</th>
              <th>Model</th>
              <th>Review</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {filteredResults.map((result) => {
              const feedback = latestFeedback[result.event_id];
              const effectiveThreat = feedback?.severity_override || result.threat_level;
              return (
                <tr key={result.event_id}>
                  <td>{formatTime(result.timestamp)}</td>
                  <td>{String(result.service || "n/a").toUpperCase()}</td>
                  <td>{result.attack_type || "unknown"}</td>
                  <td>
                    <span className={badgeClass(result.prediction)}>{result.prediction}</span>
                  </td>
                  <td>
                    <span className={badgeClass(effectiveThreat)}>{effectiveThreat}</span>
                    {feedback?.severity_override ? <small className="override-label">Override</small> : null}
                  </td>
                  <td>{formatConfidence(result.confidence)}</td>
                  <td>{result.model_used || "n/a"}</td>
                  <td>
                    <span className={`review-state review-${feedback?.review_status || "awaiting"}`}>
                      {reviewLabel(feedback)}
                    </span>
                  </td>
                  <td>
                    <button type="button" onClick={() => setSelected(result)}>
                      Review
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!loading && filteredResults.length === 0 ? (
          <div className="ids-empty">No IDS results match the selected filters.</div>
        ) : null}
      </div>

      {selected ? (
        <div
          className="ids-dialog-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              setSelected(null);
            }
          }}
        >
          <section
            className="ids-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="ids-dialog-title"
          >
            <div className="topbar ids-dialog-heading">
              <div>
                <p className="ids-kicker">Investigation workspace</p>
                <h3 id="ids-dialog-title">IDS Event Review</h3>
                <p>Sanitized final result for event {selected.event_id}</p>
              </div>
              <button type="button" onClick={() => setSelected(null)}>
                Close
              </button>
            </div>

            <div className="ids-dialog-grid">
              <div className="ids-detail">
                <span>Timestamp</span>
                <strong>{formatTime(selected.timestamp)}</strong>
              </div>
              <div className="ids-detail">
                <span>Source IP</span>
                <strong>{selected.source_ip || "n/a"}</strong>
              </div>
              <div className="ids-detail">
                <span>Service / Port</span>
                <strong>
                  {String(selected.service || "n/a").toUpperCase()} /{" "}
                  {selected.destination_port ?? "n/a"}
                </strong>
              </div>
              <div className="ids-detail">
                <span>Event / Status</span>
                <strong>
                  {selected.event || "n/a"} / {selected.status || "n/a"}
                </strong>
              </div>
              <div className="ids-detail">
                <span>Prediction / Attack</span>
                <strong>
                  {selected.prediction || "n/a"} / {selected.attack_type || "n/a"}
                </strong>
              </div>
              <div className="ids-detail">
                <span>Original Threat Score</span>
                <strong>
                  {selected.threat_level || "n/a"} / {selected.threat_score ?? "n/a"}
                </strong>
              </div>
              <div className="ids-detail">
                <span>Request</span>
                <strong>
                  {selected.request_method || "n/a"} {selected.request_path || ""}
                </strong>
              </div>
              <div className="ids-detail">
                <span>Anomaly Score</span>
                <strong>
                  {Number.isFinite(selected.anomaly_score)
                    ? selected.anomaly_score.toFixed(4)
                    : "n/a"}
                </strong>
              </div>
            </div>

            <XAIExplanationPanel result={selected} />
            <AnalystFeedbackPanel
              result={selected}
              latestFeedback={latestFeedback[selected.event_id]}
              onSaved={handleFeedbackSaved}
            />
          </section>
        </div>
      ) : null}
    </section>
  );
}
