function percent(value, scale = 1) {
  if (!Number.isFinite(value)) {
    return null;
  }
  return Math.max(0, Math.min(100, value * scale));
}

function formatPercent(value) {
  return Number.isFinite(value) ? `${value.toFixed(1)}%` : "n/a";
}

function formatFeatureName(value) {
  return String(value || "unnamed feature")
    .replace(/^(numeric|categorical)__/, "")
    .replaceAll("_", " ");
}

function safetyState(value) {
  return value === false ? "Protected" : "Check";
}

function safetyClass(value) {
  return value === false ? "xai-safe" : "xai-check";
}

export default function XAIExplanationPanel({ result }) {
  const xai = result?.xai || {};
  const humanReason = xai.human_reason || {};
  const shap = xai.shap || {};
  const features = Array.isArray(shap.top_features) ? shap.top_features : [];
  const largestContribution = Math.max(
    0.000001,
    ...features.map((feature) => Math.abs(Number(feature.shap_value) || 0))
  );
  const confidence = percent(result?.confidence, 100);
  const threatScore = percent(result?.threat_score);
  const shapSupportsFinalDecision = shap.supports_final_decision === true;

  return (
    <section className="xai-explanation-panel" aria-labelledby="xai-explanation-title">
      <div className="xai-panel-heading">
        <div>
          <p className="xai-eyebrow">Explainable AI</p>
          <h4 id="xai-explanation-title">Decision evidence</h4>
        </div>
        <span className="xai-model-chip">{result?.model_used || "model unavailable"}</span>
      </div>

      <div className="xai-score-grid">
        <article className="xai-score-card">
          <div className="xai-score-label">
            <span>Model confidence</span>
            <strong>{formatPercent(confidence)}</strong>
          </div>
          <div
            className="xai-meter"
            role="progressbar"
            aria-label="Model confidence"
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow={confidence ?? 0}
          >
            <span style={{ width: `${confidence ?? 0}%` }} />
          </div>
        </article>
        <article className="xai-score-card">
          <div className="xai-score-label">
            <span>Threat score</span>
            <strong>{formatPercent(threatScore)}</strong>
          </div>
          <div
            className="xai-meter xai-meter-threat"
            role="progressbar"
            aria-label="Threat score"
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow={threatScore ?? 0}
          >
            <span style={{ width: `${threatScore ?? 0}%` }} />
          </div>
        </article>
      </div>

      <div className="xai-reason-grid">
        <article>
          <span>Decision explanation</span>
          <p>{humanReason.decision || humanReason.summary || result?.fusion_reason}</p>
        </article>
        <article>
          <span>Threat explanation</span>
          <p>{humanReason.threat || "No separate threat-score explanation was recorded."}</p>
        </article>
        <article>
          <span>Feature explanation</span>
          <p>{humanReason.feature || "No separate feature explanation was recorded."}</p>
        </article>
      </div>

      <div className="xai-feature-heading">
        <h5>SHAP feature contributions</h5>
        <span className={shap.status === "ready" ? "xai-safe" : "xai-check"}>
          {shap.status || "unavailable"}
        </span>
      </div>

      {shap.status === "ready" && features.length ? (
        <div className="xai-feature-list">
          {features.map((feature, index) => {
            const contribution = Number(feature.shap_value) || 0;
            const supports =
              feature.direction === "supports_explained_class" || contribution >= 0;
            const width = (Math.abs(contribution) / largestContribution) * 100;
            return (
              <div className="xai-feature-row" key={`${feature.feature}-${index}`}>
                <div className="xai-feature-meta">
                  <strong>{formatFeatureName(feature.feature)}</strong>
                  <span>
                    {supports ? "Supports" : "Opposes"} explained class ·{" "}
                    {contribution.toFixed(4)}
                  </span>
                </div>
                <div className="xai-feature-track" aria-hidden="true">
                  <span
                    className={supports ? "xai-feature-support" : "xai-feature-oppose"}
                    style={{ width: `${width}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="xai-empty">
          SHAP feature contributions are not available for this stored result.
        </p>
      )}

      {!shapSupportsFinalDecision ? (
        <p className="xai-limitation">
          SHAP explains the stored tabular component only; it is not the final
          decision source for this event.
        </p>
      ) : (
        <p className="xai-limitation xai-limitation-safe">
          The SHAP component supports the model source used for this final decision.
        </p>
      )}

      <div className="xai-safety-grid" aria-label="XAI privacy and safety status">
        <span className={safetyClass(xai.privacy?.raw_payload_included)}>
          Raw payload: {safetyState(xai.privacy?.raw_payload_included)}
        </span>
        <span className={safetyClass(xai.privacy?.source_ip_included)}>
          XAI source IP: {safetyState(xai.privacy?.source_ip_included)}
        </span>
        <span className={safetyClass(xai.privacy?.credentials_included)}>
          Credentials: {safetyState(xai.privacy?.credentials_included)}
        </span>
        <span className={safetyClass(result?.safety?.xai_changed_prediction)}>
          Prediction: {safetyState(result?.safety?.xai_changed_prediction)}
        </span>
      </div>
    </section>
  );
}
