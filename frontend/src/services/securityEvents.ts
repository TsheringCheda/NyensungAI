import { API_BASE_URL } from "./api";

// ========================================
// SECURITY EVENT INTERFACE
// ========================================


export interface SecurityEvent {
  id: number;
  event_type: string;
  source: string;
  source_ip: string | null;
  username: string | null;
  description: string;
  severity: string;
  risk_score: number;
  status: string;
  is_suspicious: boolean;
  timestamp: string;

  // Network telemetry
  process_name?: string | null;
  process_id?: number | null;
  local_ip?: string | null;
  local_port?: number | null;
  remote_ip?: string | null;
  remote_port?: number | null;
  protocol?: string | null;
}


// ========================================
// INVESTIGATION INTERFACES
// ========================================

export interface InvestigationDetails {
  event_id: number;
  event_type: string;
  detection_method: string;
  severity: string;
  risk_score: number;
  status: string;
  source_ip: string | null;
  username: string | null;
  description: string;
  explanation: string;
  timestamp: string;
}

export interface InvestigationEvidence {
  related_events_found: number;
  failed_login_events: number;
  successful_login_events: number;
  additional_suspicious_events: number;
  unique_usernames?: number;
  authentication_successes?: number;
  authentication_failures?: number;
  authentication_blocks?: number;
}

export interface EvidenceMetadata {
  window_minutes?: number;
  window_start?: string | null;
  truncated?: boolean;
  correlation_methods?: string[];
}

export interface AIInvestigationReport {
  assessment: string;
  possible_attack: string;
  confidence: "Low" | "Medium" | "High";
  evidence_analysis: string[];
  potential_impact: string;
  recommended_actions: string[];
  limitations: string[];
}

export interface AIInvestigation {
  success: boolean;
  model: string;
  report?: AIInvestigationReport;
  error?: string;
}

export interface SecurityInvestigation {
  investigation: InvestigationDetails;
  evidence: InvestigationEvidence;
  evidence_metadata?: EvidenceMetadata;
  risk_factors: string[];
  related_activity: Array<Record<string, unknown>>;
  recommended_actions: string[];
  ai_investigation: AIInvestigation;
}

// ========================================
// GET SECURITY EVENTS
// ========================================

export async function getSecurityEvents(
  token: string
): Promise<SecurityEvent[]> {

  const response = await fetch(
    `${API_BASE_URL}/security-events/?skip=0&limit=100`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
    }
  );

  if (!response.ok) {
    throw new Error("Failed to fetch security events.");
  }

  return response.json();
}

// ========================================
// GET AI INVESTIGATION
// ========================================

export async function getSecurityInvestigation(
  eventId: number,
  token: string
): Promise<SecurityInvestigation> {

  if (!token) {
    throw new Error("Your session has expired. Please sign in again.");
  }

  const headers: Record<string, string> = {
    Accept: "application/json",
    Authorization: `Bearer ${token}`,
  };

  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 330_000);

  try {
    const response = await fetch(
      `${API_BASE_URL}/security-events/${eventId}/investigation`,
      {
        method: "GET",
        headers,
        signal: controller.signal,
      }
    );

    const payload: unknown = await response.json().catch(() => null);

    if (!response.ok) {
      const detail =
        payload && typeof payload === "object" && "detail" in payload
          ? String((payload as { detail?: unknown }).detail || "")
          : "";
      throw new Error(detail || `Investigation request failed (${response.status}).`);
    }

    if (!payload || typeof payload !== "object" || !("investigation" in payload) || !("ai_investigation" in payload)) {
      throw new Error("The server returned an unexpected investigation response. Check the backend response schema.");
    }

    return payload as SecurityInvestigation;
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("The investigation took longer than 5 minutes. Check that Ollama is running and try again.");
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}
