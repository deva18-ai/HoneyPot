export interface User {
  id: number;
  username: string;
  email?: string;
  role: 'admin' | 'analyst' | 'viewer';
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

export interface Token {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface Event {
  id: number;
  timestamp: string;
  source_ip: string;
  service: string;
  event_type: string;
  username?: string;
  password?: string;
  request_path?: string;
  payload?: string;
  result?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  session_id?: number;
  fingerprint?: string;
  country?: string;
  threat_score: number;
  classification?: string;
  mitre_techniques?: string;
  confidence?: string;
  enriched_data?: string;
}

export interface Session {
  id: number;
  source_ip: string;
  service: string;
  started_at: string;
  ended_at?: string;
  event_count: number;
  risk_level: string;
  classification?: string;
  threat_score: number;
  mitre_techniques?: string;
}

export interface Alert {
  id: number;
  event_id: number;
  alert_type: string;
  message: string;
  created_at: string;
  acknowledged: boolean;
  acknowledged_at?: string;
  acknowledged_by?: number;
}

export interface IPStats {
  source_ip: string;
  total_events: number;
  failed_logins: number;
  services_hit: number;
  threat_score: number;
  country?: string;
  asn?: string;
  isp?: string;
  reputation_score: number;
  last_seen: string;
  first_seen: string;
  is_blocked: boolean;
}

export interface Incident {
  id: number;
  incident_id: string;
  title?: string;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threat_score: number;
  classification: string;
  status: 'open' | 'in_progress' | 'acknowledged' | 'resolved' | 'closed' | 'false_positive';
  source_ip: string;
  target_service?: string;
  first_seen: string;
  last_seen: string;
  duration_seconds: number;
  event_count: number;
  alert_count: number;
  assignee_id?: number;
  assignee?: User;
  mitre_techniques?: string;
  tags?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
  closed_by?: number;
}

export interface IncidentEvent {
  id: number;
  incident_id: number;
  event_id: number;
  sequence: number;
  behavior_stage?: string;
  is_key_event: boolean;
  event?: Event;
}

export interface IncidentNote {
  id: number;
  incident_id: number;
  author_id?: number;
  author?: User;
  content: string;
  is_internal: boolean;
  created_at: string;
  updated_at: string;
}

export interface IncidentEvidence {
  id: number;
  incident_id: number;
  evidence_type: string;
  title: string;
  description?: string;
  file_path?: string;
  content?: string;
  mime_type?: string;
  size_bytes: number;
  created_at: string;
}

export interface MitreTechnique {
  id: number;
  technique_id: string;
  name: string;
  description?: string;
  tactic: string;
  platform?: string;
  detection?: string;
  mitigation?: string;
  references?: string;
  sub_techniques?: string;
  is_subtechnique: boolean;
  parent_technique?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface DashboardStats {
  active_incidents: number;
  critical_incidents: number;
  high_incidents: number;
  medium_incidents: number;
  low_incidents: number;
  total_incidents: number;
  unique_sources: number;
  events_last_hour: number;
  events_last_24h: number;
  avg_threat_score: number;
  top_classifications: { classification: string; count: number }[];
  attack_trend: { timestamp: string; count: number; high_severity: number }[];
  service_heatmap: Record<string, number>[];
}

export interface ThreatOverview {
  kpis: {
    total_events: number;
    high_severity_events: number;
    unique_ips: number;
    active_incidents: number;
    critical_incidents: number;
    alerts_generated: number;
    honeypot_services_active: number;
  };
  top_attackers: { ip: string; event_count: number; max_threat_score: number }[];
  attack_distribution: Record<string, number>;
  recent_incidents: {
    incident_id: string;
    classification: string;
    risk_level: string;
    threat_score: number;
    source_ip: string;
    first_seen: string;
    status: string;
  }[];
}

export interface WebSocketMessage {
  type: 'event' | 'alert' | 'incident';
  data: any;
}

export interface TimeRange {
  label: string;
  value: number;
}