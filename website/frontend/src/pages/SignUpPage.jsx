import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import PortalShell from "../components/PortalShell";
import { apiRequest } from "../api";

export default function SignUpPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  async function onSubmit(event) {
    event.preventDefault();
    setMessage("");

    try {
      await apiRequest("/signup", {
        method: "POST",
        body: JSON.stringify({ username, email, password }),
      });
      setMessage("Signup successful. You can now login.");
      setTimeout(() => navigate("/"), 800);
    } catch (err) {
      setMessage(err.message || "Signup failed");
    }
  }

  return (
    <PortalShell title="Sign Up" subtitle="Create an employee portal account.">
      <section className="card" style={{ maxWidth: 520 }}>
        <form onSubmit={onSubmit}>
          <div className="field">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="employee username"
            />
          </div>
          <div className="field">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="name@company.com"
            />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <button type="submit">Create account</button>
        </form>
        {message ? <p className={message.startsWith("Signup successful") ? "good" : "msg"}>{message}</p> : null}
        <p>
          Back to <Link to="/">login</Link>
        </p>
      </section>
    </PortalShell>
  );
}
