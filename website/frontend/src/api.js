export const API_BASE =
  import.meta.env.VITE_API_BASE ||
  `${window.location.protocol}//${window.location.hostname || "127.0.0.1"}:5000`;

export async function apiRequest(path, options = {}) {
  const token = localStorage.getItem("hp_token");
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }

  return data;
}

export async function logFrontendEvent(event, details = {}) {
  const token = localStorage.getItem("hp_token");
  const headers = {
    "Content-Type": "application/json",
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  try {
    await fetch(`${API_BASE}/frontend/log`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        event,
        path: window.location.pathname,
        details,
        level: "info",
      }),
    });
  } catch (_err) {
    // Logging should never block the UI flow.
  }
}
