import { useEffect, useState } from "react";
import { apiRequest } from "../api";

const SEVERITIES = ["Low", "Medium", "High", "Critical"];

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "n/a" : date.toLocaleString();
}

function verdictLabel(value) {
  if (value === "confirmed_attack") {
    return "Confirmed attack";
  }
  if (value === "false_positive") {
    return "False positive";
  }
  return "Awaiting review";
}

export default function AnalystFeedbackPanel({
  result,
  latestFeedback,
  onSaved,
}) {
  const [verdict, setVerdict] = useState("");
  const [severityOverride, setSeverityOverride] = useState("");
  const [notes, setNotes] = useState("");
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    let active = true;
    setVerdict(latestFeedback?.verdict || "");
    setSeverityOverride(latestFeedback?.severity_override || "");
    setNotes("");
    setLoading(true);
    setError("");
    setMessage("");

    apiRequest(
      `/api/analyst-feedback?event_id=${encodeURIComponent(result.event_id)}&limit=50`
    )
      .then((data) => {
        if (active) {
          setHistory(data.feedback || []);
        }
      })
      .catch((requestError) => {
        if (active) {
          setError(requestError.message || "Could not load feedback history");
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [result.event_id, latestFeedback?.feedback_id]);

  async function submitFeedback(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    if (!verdict) {
      setError("Select Confirmed attack or False positive.");
      return;
    }

    setSubmitting(true);
    try {
      const response = await apiRequest(
        `/api/analyst-feedback/${encodeURIComponent(result.event_id)}`,
        {
          method: "POST",
          body: JSON.stringify({
            verdict,
            severity_override: severityOverride || null,
            notes,
          }),
        }
      );
      setHistory((current) => [response.feedback, ...current]);
      setNotes("");
      setMessage("Review saved. The original IDS result remains unchanged.");
      onSaved?.(response.feedback, response.stats);
    } catch (requestError) {
      setError(requestError.message || "Could not save analyst feedback");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="analyst-feedback-panel" aria-labelledby="analyst-feedback-title">
      <div className="feedback-heading">
        <div>
          <p className="xai-eyebrow">Human in the loop</p>
          <h4 id="analyst-feedback-title">Analyst review</h4>
        </div>
        <span className={`review-state review-${latestFeedback?.review_status || "awaiting"}`}>
          {verdictLabel(latestFeedback?.verdict)}
        </span>
      </div>

      <p className="feedback-original">
        Original IDS result: <strong>{result.prediction}</strong> ·{" "}
        <strong>{result.threat_level}</strong>. Feedback adds an audit record and
        never overwrites this model output.
      </p>

      <form className="feedback-form" onSubmit={submitFeedback}>
        <fieldset>
          <legend>Analyst decision</legend>
          <label className={verdict === "confirmed_attack" ? "feedback-choice selected" : "feedback-choice"}>
            <input
              type="radio"
              name="analyst-verdict"
              value="confirmed_attack"
              checked={verdict === "confirmed_attack"}
              onChange={(event) => setVerdict(event.target.value)}
            />
            <span>
              <strong>Confirm attack</strong>
              <small>The IDS classification is supported by investigation.</small>
            </span>
          </label>
          <label className={verdict === "false_positive" ? "feedback-choice selected" : "feedback-choice"}>
            <input
              type="radio"
              name="analyst-verdict"
              value="false_positive"
              checked={verdict === "false_positive"}
              onChange={(event) => setVerdict(event.target.value)}
            />
            <span>
              <strong>Mark false positive</strong>
              <small>The event is benign or incorrectly classified.</small>
            </span>
          </label>
        </fieldset>

        <label className="feedback-field">
          Severity override
          <select
            value={severityOverride}
            onChange={(event) => setSeverityOverride(event.target.value)}
          >
            <option value="">Keep model severity ({result.threat_level})</option>
            {SEVERITIES.map((severity) => (
              <option key={severity} value={severity}>
                {severity}
              </option>
            ))}
          </select>
          <small>The model-generated severity is preserved separately.</small>
        </label>

        <label className="feedback-field">
          Analyst notes
          <textarea
            value={notes}
            onChange={(event) => setNotes(event.target.value)}
            maxLength={2000}
            rows={4}
            placeholder="Record investigation evidence or follow-up action. Do not paste credentials or raw payloads."
          />
          <small>{notes.length}/2000 characters</small>
        </label>

        {error ? <p className="feedback-error">{error}</p> : null}
        {message ? <p className="feedback-success">{message}</p> : null}

        <button type="submit" disabled={submitting}>
          {submitting ? "Saving review..." : "Save analyst review"}
        </button>
      </form>

      <details className="feedback-history">
        <summary>Feedback history ({history.length})</summary>
        {loading ? (
          <p>Loading audit history...</p>
        ) : history.length ? (
          <ol>
            {history.map((entry) => (
              <li key={entry.feedback_id}>
                <div>
                  <strong>{verdictLabel(entry.verdict)}</strong>
                  <span>{formatTime(entry.created_at)}</span>
                </div>
                <p>
                  Analyst: {entry.analyst?.username || "unknown"} · Severity:{" "}
                  {entry.severity_override || `unchanged (${entry.original_severity})`}
                </p>
                {entry.notes ? <blockquote>{entry.notes}</blockquote> : null}
              </li>
            ))}
          </ol>
        ) : (
          <p>No analyst feedback has been recorded for this event.</p>
        )}
      </details>
    </section>
  );
}
