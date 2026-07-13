import { useEffect } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useLocation } from "react-router-dom";
import HomePage from "./pages/HomePage";
import SignUpPage from "./pages/SignUpPage";
import DashboardPage from "./pages/DashboardPage";
import { logFrontendEvent } from "./api";

function ProtectedRoute({ children }) {
  const token = localStorage.getItem("hp_token");
  if (!token) {
    return <Navigate to="/" replace />;
  }
  return children;
}

export default function App() {
  const location = useLocation();

  useEffect(() => {
    logFrontendEvent("route_visit", {
      pathname: location.pathname,
      search: location.search,
    });
  }, [location.pathname, location.search]);

  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/signup" element={<SignUpPage />} />
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
