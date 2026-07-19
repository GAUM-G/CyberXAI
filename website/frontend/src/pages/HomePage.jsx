import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import PortalShell from "../components/PortalShell";
import { API_BASE, apiRequest } from "../api";

export default function HomePage() {
  const navigate = useNavigate();
  const [files, setFiles] = useState([]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [query, setQuery] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    apiRequest("/files")
      .then((data) => setFiles(data.files || []))
      .catch(() => setFiles([]));
  }, []);

  async function onLogin(event) {
    event.preventDefault();
    setMessage("");

    try {
      const data = await apiRequest("/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      localStorage.setItem("hp_token", data.token);
      localStorage.setItem("hp_user", JSON.stringify(data.user));
      navigate("/dashboard");
    } catch (err) {
      setMessage(err.message || "Login failed");
    }
  }

  async function onSearch(event) {
    event.preventDefault();
    try {
      await apiRequest(`/search?q=${encodeURIComponent(query)}`);
      setMessage("Search submitted");
    } catch (err) {
      setMessage(err.message || "Search failed");
    }
  }

  return (
    <PortalShell
      title="Employee Service Portal"
      subtitle="Internal HR, security, and decoy resources for monitoring suspicious activity."
    >
      <section className="grid">
        <article className="card">
          <h2>Sign In</h2>
          <form onSubmit={onLogin}>
            <div className="field">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="employee id"
              />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="password"
              />
            </div>
            <button type="submit">Login</button>
          </form>
          <p>
            New user? <Link to="/signup">Create account</Link>
          </p>
          {message ? <div className="msg">{message}</div> : null}
        </article>

        <article className="card">
          <h2>Resource Search</h2>
          <form onSubmit={onSearch}>
            <div className="field">
              <label htmlFor="q">Keyword</label>
              <input
                id="q"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="policy, payroll, handbook"
              />
            </div>
            <button type="submit">Search</button>
          </form>
          <p>Search route is kept as /search.</p>
        </article>
      </section>

      <section className="card">
        <h2>Shared Files</h2>
        <ul className="file-list">
          {files.map((file) => (
            <li key={file}>
              <a href={`${API_BASE}/files/${encodeURIComponent(file)}`} target="_blank" rel="noreferrer">
                {file}
              </a>
            </li>
          ))}
        </ul>
      </section>
    </PortalShell>
  );
}
