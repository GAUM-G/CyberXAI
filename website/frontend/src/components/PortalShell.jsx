export default function PortalShell({ title, subtitle, children }) {
  return (
    <main className="shell public-portal">
      <nav className="portal-nav" aria-label="Portal navigation">
        <a className="portal-brand" href="/">
          <span className="brand-mark" aria-hidden="true">N</span>
          <span>Northstar Dynamics</span>
        </a>
        <div className="portal-links">
          <a href="#company">Company</a>
          <a href="#resources">Resources</a>
          <a href="#employee-access">Employee Access</a>
        </div>
      </nav>
      <section className="hero">
        <p className="eyebrow">Northstar employee services</p>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </section>
      {children}
    </main>
  );
}
