import { API_BASE_URL } from "./api";

const API = `${API_BASE_URL}/incidents`;
export type IncidentStatus = "NEW" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "CLOSED";
export interface IncidentNote { id:number; incident_id:number; author:string; note:string; created_at:string; }
export interface IncidentAction { id:number; incident_id:number; actor:string; action_type:string; details:string; outcome:string; created_at:string; }
export interface IncidentDetail { incident: Incident; notes: IncidentNote[]; actions: IncidentAction[]; }
export interface Incident { id:number; incident_number:string; security_event_id:number; title:string; description:string; severity:string; priority:string; status:IncidentStatus; source_ip:string|null; assigned_to:string|null; resolution:string|null; created_at:string; updated_at:string; }
const headers = (): Record<string, string> => ({ "Content-Type":"application/json", Authorization:`Bearer ${sessionStorage.getItem("nyensung_token") || sessionStorage.getItem("sentinel_token") || ""}` });
async function request<T>(path:string, init:RequestInit = {}):Promise<T>{ const r=await fetch(`${API}${path}`,{...init,headers:{...headers(),...(init.headers||{})}}); if(!r.ok){const d=await r.json().catch(()=>({})); throw new Error(d.detail || `Request failed (${r.status})`);} return r.json() as Promise<T>; }
export const getIncidents=()=>request<Incident[]>("/");
export const getIncidentDetail=(id:number)=>request<IncidentDetail>(`/${id}`);
export const updateIncident=(id:number,data:Partial<Pick<Incident,"status"|"severity"|"priority"|"assigned_to"|"resolution">>)=>request<Incident>(`/${id}`,{method:"PATCH",body:JSON.stringify(data)});
export const addIncidentNote=(id:number,note:string)=>request(`/`+id+`/notes`,{method:"POST",body:JSON.stringify({note})});
export const addIncidentAction=(id:number,action_type:string,details:string)=>request(`/`+id+`/actions`,{method:"POST",body:JSON.stringify({action_type,details,outcome:"RECORDED"})});

export const createIncidentFromEvent = (eventId:number) => request<Incident>(`/from-event/${eventId}`, {method:"POST"});


export interface IncidentTimelineEntry {
  kind: "SECURITY_EVENT" | "ANALYST_NOTE" | "RESPONSE_ACTION" | string;
  id: number;
  timestamp: string | null;
  title: string;
  description: string;
  severity?: string;
  risk_score?: number;
  source_ip?: string | null;
  username?: string | null;
  actor?: string;
  outcome?: string;
  is_primary?: boolean;
}
export interface IncidentTimeline {
  incident_id: number;
  primary_event: { id: number; event_type: string; timestamp: string | null; source_ip: string | null; username: string | null; severity: string; risk_score: number } | null;
  related_events: IncidentTimelineEntry[];
  timeline: IncidentTimelineEntry[];
  risk_summary: { event_count: number; max_risk_score: number; average_risk_score: number; severity_counts: Record<string, number> };
  correlation: { window_minutes: number; matched_on: string[]; limitation: string; truncated?: boolean };
}
export const getIncidentTimeline = (id:number, windowMinutes=30) => request<IncidentTimeline>(`/${id}/timeline?window_minutes=${windowMinutes}`);


export type IncidentSlaState = "ON_TRACK" | "AT_RISK" | "BREACHED" | "COMPLETED";
export interface IncidentSlaItem { incident_id:number; incident_number:string; priority:string; status:IncidentStatus; assigned_to:string|null; target_minutes:number; due_at:string; elapsed_minutes:number; remaining_minutes:number; state:IncidentSlaState; }
export interface IncidentSlaSummary { policy:Record<string,number>; counts:Record<IncidentSlaState,number>; incidents:IncidentSlaItem[]; disclaimer:string; }
export const getIncidentSlaSummary=()=>request<IncidentSlaSummary>("/sla/summary");
