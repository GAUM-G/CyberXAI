import { useEffect, useState } from "react";
import PortalShell from "../components/PortalShell";
import ExposurePanel from "../components/ExposurePanel";
import { API_BASE, apiRequest } from "../api";

export default function HomePage() {
  const [files, setFiles] = useState([]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [query, setQuery] = useState("");
  const [loginMessage, setLoginMessage] = useState("");
  const [searchMessage, setSearchMessage] = useState("");
  const [searchResults, setSearchResults] = useState([]);
  const [exposure, setExposure] = useState(null);

  useEffect(() => {
    apiRequest("/files")
      .then((data) => setFiles(data.files || []))
      .catch(() => setFiles([]));
  }, []);

  async function onLogin(event) {
    event.preventDefault();
    setLoginMessage("");
    setExposure(null);

    try {
      const data = await apiRequest("/api/decoy/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      setExposure(data.exposure || null);
      setLoginMessage(data.message || "Authentication response received");
    } catch (err) {
      setLoginMessage(err.message || "Login failed");
    }
  }

  async function onSearch(event) {
    event.preventDefault();
    setSearchMessage("");
    setExposure(null);

    try {
      const data = await apiRequest(`/api/decoy/search?q=${encodeURIComponent(query)}`);
      setSearchResults(data.results || []);
      setExposure(data.exposure || null);
      setSearchMessage(
        data.exposure
          ? data.exposure.title
          : `${data.results?.length || 0} resource${data.results?.length === 1 ? "" : "s"} found`
      );
    } catch (err) {
      setSearchResults([]);
      setSearchMessage(err.message || "Search failed");
    }
  }

  return (
    <PortalShell
      title="Everything your workday needs."
      subtitle="Access company resources, search internal documents, and sign in to employee services."
    >
      <section className="company-strip" id="company" aria-label="Company overview">
        <article><strong>24</strong><span>Global offices</span></article>
        <article><strong>4,800+</strong><span>Team members</span></article>
        <article><strong>99.9%</strong><span>Service availability</span></article>
      </section>

      <section className="portal-grid">
        <article className="card access-card" id="employee-access">
          <p className="section-kicker">Secure workspace</p>
          <h2>Employee sign in</h2>
          <p className="card-copy">Use your employee ID to continue to internal services.</p>
          <form onSubmit={onLogin}>
            <div className="field">
              <label htmlFor="username">Employee ID</label>
              <input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. NS-1042"
                autoComplete="username"
              />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <div className="password-wrap">
                <input
                  id="password"
                  type={passwordVisible ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                />
                <button type="button" className="password-toggle" onClick={() => setPasswordVisible(!passwordVisible)} aria-label={passwordVisible ? "Hide password" : "Show password"} aria-pressed={passwordVisible}>
                  {passwordVisible ? "🙈" : "👁"}
                </button>
              </div>
            </div>
            <button type="submit">Sign in</button>
          </form>
          {loginMessage ? <div className="msg">{loginMessage}</div> : null}
        </article>

        <article className="card search-card" id="resources">
          <p className="section-kicker">Knowledge center</p>
          <h2>Search company resources</h2>
          <p className="card-copy">Find policies, benefit information, technical guides, and forms.</p>
          <form onSubmit={onSearch}>
            <div className="field">
              <label htmlFor="q">Keyword</label>
              <input
                id="q"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Try policy, payroll, VPN..."
              />
            </div>
            <button type="submit">Search resources</button>
          </form>
          {searchMessage ? <div className="search-status">{searchMessage}</div> : null}
          {searchResults.length > 0 ? (
            <ul className="search-results">
              {searchResults.map((result) => (
                <li key={result.title}>
                  <strong>{result.title}</strong>
                  <span>{result.category} / {result.classification}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </article>
      </section>

      <ExposurePanel exposure={exposure} onClose={() => setExposure(null)} />

      <section className="card files-card">
        <div>
          <p className="section-kicker">Quick access</p>
          <h2>Shared company files</h2>
          <p className="card-copy">Frequently requested internal documents.</p>
        </div>
        <ul className="file-list">
          {files.map((file) => (
            <li key={file}>
              <a href={`${API_BASE}/files/${encodeURIComponent(file)}`} target="_blank" rel="noreferrer">
                <span className="file-icon" aria-hidden="true">DOC</span>
                <span>{file}</span>
              </a>
            </li>
          ))}
        </ul>
      </section>
    </PortalShell>
  );
}
