export default function PortalShell({ title, subtitle, children }) {
  return (
    <main className="shell">
      <section className="hero">
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </section>
      {children}
    </main>
  );
}
