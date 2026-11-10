
const configuredApiBase = (
  import.meta.env.VITE_API_BASE_URL ||
  "http://127.0.0.1:8000/api"
).trim();

/**
 * Keep the API root canonical.
 * Corrects accidental /api/n configuration and trailing slashes.
 */
const normalizedApiBase = configuredApiBase
  .replace(/\s+/g, "")
  .replace(/\/+$/, "")
  .replace(/\/api\/n$/i, "/api");

export const API_BASE_URL = /\/api$/i.test(normalizedApiBase)
  ? normalizedApiBase
  : `${normalizedApiBase}/api`;

const API_ROOT_URL = API_BASE_URL.replace(/\/api$/i, "");

export function getStoredAccessToken(): string {
  return sessionStorage.getItem("nyensung_token") || sessionStorage.getItem("sentinel_token") || "";
}

if (import.meta.env.DEV && configuredApiBase !== API_BASE_URL) {
  console.warn(
    `[NyensungAI] Normalized API base URL from "${configuredApiBase}" to "${API_BASE_URL}".`
  );
}

// ========================================
// 1. USER INTERFACES
// ========================================

export interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
}

// ========================================
// 2. LOGIN RESPONSE
// ========================================

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user: User;
}

// ========================================
// 3. SECURITY STATISTICS
// ========================================

export interface SecurityStats {
  total_events: number;
  active_threats: number;
  critical_alerts: number;
  open_incidents: number;
  ml_anomalies: number;
  rule_based_alerts: number;
}

// ========================================
// 4. LOGIN FUNCTION
// ========================================

export async function loginUser(
  email: string,
  password: string
): Promise<LoginResponse> {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email, password }),
  });

  const data: unknown = await response.json().catch(() => null);

  if (!response.ok) {
    const detail =
      data && typeof data === "object" && "detail" in data
        ? String((data as { detail?: unknown }).detail || "")
        : "";

    throw new Error(
      detail ||
        `Login failed (${response.status}). Check the API URL and backend logs.`
    );
  }

  if (
    !data ||
    typeof data !== "object" ||
    !("access_token" in data) ||
    !("user" in data)
  ) {
    throw new Error(
      "The login endpoint returned an unexpected response."
    );
  }

  return data as LoginResponse;
}

// ========================================
// 5. GET AUTHENTICATED USER
// ========================================

export async function getCurrentUser(
  token: string
): Promise<User> {
  const response = await fetch(`${API_BASE_URL}/auth/me`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  const data: unknown = await response.json().catch(() => null);

  if (!response.ok) {
    const detail =
      data && typeof data === "object" && "detail" in data
        ? String((data as { detail?: unknown }).detail || "")
        : "";

    throw new Error(
      detail ||
        `Unable to retrieve user information (${response.status}).`
    );
  }

  return data as User;
}

// ========================================
// 6. LOGOUT FUNCTION
// ========================================

export async function logoutUser(token: string): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/auth/logout`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error("Logout failed.");
  }
}

// ========================================
// 7. GET ALL SECURITY STATISTICS
// ========================================

export async function getSecurityStats(token: string = getStoredAccessToken()): Promise<SecurityStats> {
  const response = await fetch(
    `${API_BASE_URL}/security-events/stats`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
    }
  );

  if (!response.ok) {
    throw new Error("Failed to fetch security statistics.");
  }

  return response.json() as Promise<SecurityStats>;
}

// ========================================
// 8. THREAT ACTIVITY DATA
// ========================================

export interface ThreatActivity {
  time: string;
  normal: number;
  suspicious: number;
  critical: number;
}

export async function getThreatActivity(token: string = getStoredAccessToken()): Promise<ThreatActivity[]> {
  const response = await fetch(
    `${API_BASE_URL}/security-events/activity`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
    }
  );

  if (!response.ok) {
    throw new Error("Failed to fetch threat activity.");
  }

  return response.json() as Promise<ThreatActivity[]>;
}

// ========================================
// 9. API HEALTH
// ========================================

/**
 * Fetch the API health endpoint for the
 * System Settings diagnostics page.
 */

export interface ApiHealth {
  status: string;
  database: string;
}

export async function getApiHealth(): Promise<ApiHealth> {
  const response = await fetch(
    `${API_ROOT_URL}/api/health`,
    {
      headers: {
        Accept: "application/json",
      },
    }
  );

  if (!response.ok) {
    throw new Error(
      `API health check failed (${response.status}).`
    );
  }

  return response.json() as Promise<ApiHealth>;
}

export interface AuditLogRecord {
  id: number;
  actor_user_id: number | null;
  actor_username: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  details: string | null;
  source_ip: string | null;
  created_at: string;
}

export async function getAdminUsers(token: string = getStoredAccessToken()): Promise<User[]> {
  const response = await fetch(`${API_BASE_URL}/auth/users`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  if (!response.ok) throw new Error(response.status === 403 ? "Administrator access is required." : "Unable to load user accounts.");
  return response.json() as Promise<User[]>;
}

export async function updateAdminUserAccess(
  userId: number,
  changes: { role?: "admin" | "analyst" | "viewer"; is_active?: boolean },
  token: string = getStoredAccessToken(),
): Promise<User> {
  const response = await fetch(`${API_BASE_URL}/auth/users/${userId}`, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(changes),
  });
  const data: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data && typeof data === "object" && "detail" in data ? String((data as {detail?: unknown}).detail || "") : "";
    throw new Error(detail || "Unable to update account access.");
  }
  return data as User;
}

export async function getAdminAuditLogs(token: string = getStoredAccessToken()): Promise<AuditLogRecord[]> {
  const response = await fetch(`${API_BASE_URL}/auth/audit-logs?page=1&page_size=12`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  if (!response.ok) throw new Error(response.status === 403 ? "Administrator access is required." : "Unable to load audit history.");
  const data = await response.json() as { items?: AuditLogRecord[] };
  return data.items || [];
}
