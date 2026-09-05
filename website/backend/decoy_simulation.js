const DECOY_EMPLOYEE_RECORDS = Object.freeze([
  {
    employee_id: "NS-1042",
    name: "Aarav Mehta",
    email: "aarav.mehta@northstar.example",
    department: "Finance",
    role: "Senior Accountant",
    access_level: "finance-internal",
  },
  {
    employee_id: "NS-1187",
    name: "Maya Chen",
    email: "maya.chen@northstar.example",
    department: "People Operations",
    role: "HR Business Partner",
    access_level: "hr-confidential",
  },
  {
    employee_id: "NS-1214",
    name: "Noah Williams",
    email: "noah.williams@northstar.example",
    department: "Infrastructure",
    role: "Systems Engineer",
    access_level: "it-operations",
  },
  {
    employee_id: "NS-1308",
    name: "Isha Kapoor",
    email: "isha.kapoor@northstar.example",
    department: "Legal",
    role: "Compliance Analyst",
    access_level: "legal-review",
  },
  {
    employee_id: "NS-1421",
    name: "Lucas Martin",
    email: "lucas.martin@northstar.example",
    department: "Sales",
    role: "Regional Manager",
    access_level: "sales-internal",
  },
  {
    employee_id: "NS-1503",
    name: "Sara Ahmed",
    email: "sara.ahmed@northstar.example",
    department: "Executive Office",
    role: "Executive Assistant",
    access_level: "executive-confidential",
  },
]);

const DECOY_SEARCH_RECORDS = Object.freeze([
  { title: "Employee handbook", category: "Policy", classification: "Internal" },
  { title: "Remote access guide", category: "IT", classification: "Internal" },
  { title: "Q2 payroll calendar", category: "Finance", classification: "Confidential" },
  { title: "VPN rollout notes", category: "IT", classification: "Restricted" },
]);

function detectAttack(payload) {
  const text = String(payload || "").toLowerCase();
  const findings = [];

  if (
    /union(?:\s+all)?\s+select|\bor\s+['"]?[a-z0-9]+['"]?\s*=\s*['"]?[a-z0-9]+['"]?|drop\s+table|--|information_schema/.test(
      text
    )
  ) {
    findings.push("sql_injection");
  }
  if (/<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(/.test(text)) {
    findings.push("xss");
  }
  if (/\.\.\/|etc\/passwd|\.git|phpmyadmin|\.env|wp-admin/.test(text)) {
    findings.push("directory_scanning");
  }

  return findings;
}

function buildDecoyExposure(attackType, entryPoint) {
  if (attackType === "sql_injection") {
    return {
      simulation: true,
      attack_type: "sql_injection",
      entry_point: entryPoint,
      title: "Legacy directory query returned additional rows",
      technique: "UNION-style query response",
      source: "northstar_hr.employee_directory",
      columns: ["employee_id", "name", "email", "department", "role", "access_level"],
      rows: DECOY_EMPLOYEE_RECORDS,
      exposed_items: [
        { label: "Database", value: "northstar_hr" },
        { label: "Table", value: "employee_directory" },
        { label: "Rows returned", value: String(DECOY_EMPLOYEE_RECORDS.length) },
      ],
    };
  }

  if (attackType === "xss") {
    return {
      simulation: true,
      attack_type: "xss",
      entry_point: entryPoint,
      title: "Client-side portal cache was read",
      technique: "Reflected script execution",
      source: "window.__NORTHSTAR_PORTAL_CACHE__.employeeDirectory",
      columns: ["employee_id", "name", "email", "department", "role", "access_level"],
      rows: DECOY_EMPLOYEE_RECORDS.slice(0, 4),
      exposed_items: [
        { label: "Session", value: "ns_demo_session_7f31c9" },
        { label: "User", value: "guest.contractor@northstar.example" },
        { label: "Cached records", value: "4" },
      ],
    };
  }

  return null;
}

function searchDecoyRecords(query) {
  const normalized = String(query || "").trim().toLowerCase();
  if (!normalized) {
    return [];
  }

  return DECOY_SEARCH_RECORDS.filter((record) =>
    Object.values(record).some((value) => String(value).toLowerCase().includes(normalized))
  );
}

module.exports = {
  DECOY_EMPLOYEE_RECORDS,
  DECOY_SEARCH_RECORDS,
  buildDecoyExposure,
  detectAttack,
  searchDecoyRecords,
};
