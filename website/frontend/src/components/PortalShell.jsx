import { NavLink } from "react-router-dom";

export default function PortalShell({ title, subtitle, children }) {
  const hasSession = Boolean(localStorage.getItem("hp_token"));

  return (
    <main className="shell">
      <nav className="portal-nav" aria-label="Portal navigation">
        <NavLink className="portal-brand" to="/">
          Employee Portal
        </NavLink>
        <div className="portal-links">
          <NavLink to="/" end>
            Home
          </NavLink>
          {!hasSession ? <NavLink to="/signup">Create Account</NavLink> : null}
          {hasSession ? <NavLink to="/dashboard">Security Dashboard</NavLink> : null}
          {hasSession && window.location.pathname === "/dashboard" ? (
            <a href="#ids-insights">IDS Details</a>
          ) : null}
        </div>
      </nav>
      <section className="hero">
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </section>
      {children}
    </main>
  );
}
