// Contrat de l'API du back-for-front (services/supervision-dashboard/app/main.py) et formes du moteur de remédiation
// (GET /api/incidents/{id}, relayé tel quel) : voir le README du dashboard.

export type SourceName = "prometheus" | "alertmanager" | "loki" | "engine";

export interface SourceStatus {
  ok: boolean;
  error: string | null;
  age_s: number;
  latency_ms: number;
}

export interface Envelope {
  server_time: string;
  sources: Partial<Record<SourceName, SourceStatus>>;
}

export type Phase = "operational" | "incident" | "remediation" | "restored" | "unknown";

export interface GlobalStatus {
  phase: Phase;
  step_key: string;
  step: string;
  since: string | null;
  duration_s: number | null;
  reaction_s: number | null;
  incident_id: string | null;
  alertname: string | null;
  service: string | null;
  nature: string | null;
  decision: string | null;
  escalated: boolean;
  open_incidents: number;
  notes: string[];
}

export type ComponentState = "ok" | "degraded" | "down" | "unknown" | "active";

export interface ComponentTile {
  id: string;
  label: string;
  role: string;
  state: ComponentState;
  reason: string;
}

export interface Overview extends Envelope {
  status: GlobalStatus;
  components: ComponentTile[];
  integrity: { ok: boolean | null; last_check_age_s: number | null };
  anomaly: { threshold: number | null; scores: { service: string; score: number | null }[] };
}

export interface AlertItem {
  name: string;
  severity: string;
  domain: string;
  service: string;
  client_ip: string | null;
  summary: string;
  starts_at: string | null;
  state: "firing" | "pending";
  source: "prometheus" | "loki";
  silenced: boolean;
  business: boolean;
}

export interface AlertsResponse extends Envelope {
  alerts: AlertItem[];
}

export interface Decision {
  kind?: string;
  nature?: string;
  reason?: string;
  action?: string;
  service?: string;
  target?: string;
  chain?: string[];
  checks?: string[];
  evidence?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface TimelineEntry {
  ts: number;
  at: string;
  state: string;
  event: string;
  detail?: Record<string, unknown>;
}

export interface EngineAction {
  ts?: number;
  at: string;
  action: string;
  target: string;
  result: string;
  duration_ms?: number;
  ttl_s?: number;
  expires_at?: string;
  [key: string]: unknown;
}

export interface IncidentSummary {
  id: string;
  key?: string;
  alertname: string;
  rule?: string;
  strategy?: string;
  updated_at?: string;
  nature: string;
  domain?: string;
  severity?: string;
  service: string | null;
  state: string;
  open: boolean;
  outcome: string | null;
  attempts?: number;
  created_at: string;
  closed_at: string | null;
  recovered_at: string | null;
  alert_started_at: string | null;
  duration_s: number | null;
  decision: Decision | null;
  escalation: { reason?: string; message?: string; at?: string } | null;
  last_action: EngineAction | null;
  // Incident principal auquel celui-ci est rattaché (même panne, déjà traitée) : ajouté par le back-for-front
  follow_up_of?: string | null;
}

export interface EngineAlert {
  fingerprint?: string;
  status: string;
  labels: Record<string, string>;
  annotations?: Record<string, string>;
  starts_at?: string | null;
  [key: string]: unknown;
}

export interface IncidentDetail extends Omit<IncidentSummary, "alerts"> {
  alerts: EngineAlert[] | string[];
  actions: EngineAction[];
  timeline: TimelineEntry[];
}

export interface IncidentsResponse extends Envelope {
  incidents: (IncidentSummary & { alerts?: string[] })[];
}

export interface IncidentResponse extends Envelope {
  incident: IncidentDetail | null;
}

export interface BlockItem {
  ip: string;
  expires_at: string | null;
  remaining_s: number | null;
  ttl_s: number | null;
  blocked_at: string | null;
  reason: string;
  incident_id: string | null;
}

export interface BlocksResponse extends Envelope {
  blocks: BlockItem[];
  waf_blocklist: boolean | null;
  bridge: {
    configured?: boolean;
    available?: boolean;
    runner?: string;
    heartbeat_age_s?: number;
    busy?: boolean;
  } | null;
}

export interface EventItem {
  ts: string;
  first_ts?: string;
  event_type: string;
  service: string;
  level: string;
  count: number;
  incident_id?: string;
  alertname?: string;
  nature?: string;
  state?: string;
  target_service?: string;
  client_ip?: string;
  action?: string;
  target?: string;
  result?: string;
  check?: string;
  reason?: string;
  outcome?: string;
  dominant_feature?: string;
  anomaly_score?: number;
  duration_s?: number;
  method?: string;
  uri?: string;
  status?: number;
  ip?: string;
  error?: string;
  explanation?: string;
}

export interface EventsResponse extends Envelope {
  events: EventItem[];
}
