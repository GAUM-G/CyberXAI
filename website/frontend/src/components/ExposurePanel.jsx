function displayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "N/A";
  }
  return String(value);
}

export default function ExposurePanel({ exposure, onClose }) {
  if (!exposure) {
    return null;
  }

  return (
    <section className="exposure-panel" aria-live="polite" aria-labelledby="exposure-title">
      <div className="exposure-heading">
        <div>
          <p className="console-label">Legacy response console</p>
          <h2 id="exposure-title">{exposure.title}</h2>
          <p>
            Source: <code>{exposure.source}</code>
          </p>
          <p>
            {exposure.attack_type.replaceAll("_", " ")} / {exposure.technique}
          </p>
        </div>
        <button className="quiet-button" type="button" onClick={onClose}>
          Clear output
        </button>
      </div>

      <div className="exposure-meta">
        {(exposure.exposed_items || []).map((item) => (
          <div key={item.label}>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>

      <div className="exposure-table-wrap">
        <table className="exposure-table">
          <thead>
            <tr>
              {(exposure.columns || []).map((column) => (
                <th key={column}>{column}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {(exposure.rows || []).map((row) => (
              <tr key={row.employee_id}>
                {exposure.columns.map((column) => (
                  <td key={column}>{displayValue(row[column])}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
