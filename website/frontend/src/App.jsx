import { useEffect } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useLocation } from "react-router-dom";
import HomePage from "./pages/HomePage";
import { logFrontendEvent } from "./api";

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
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
