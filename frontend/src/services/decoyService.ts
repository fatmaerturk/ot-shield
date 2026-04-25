import api from './api';

// ---------- Types (mirror backend DTOs) ----------

export type DecoyProtocol = 'MODBUS' | 'S7' | 'DNP3' | 'ETHERNET_IP' | 'OPC_UA';
export type DecoyStatus = 'RUNNING' | 'STOPPED' | 'DEGRADED' | 'STARTING' | 'STOPPING';
export type EngagementStatus = 'ACTIVE' | 'IDLE' | 'CLOSED';
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type EventDirection = 'INBOUND' | 'OUTBOUND';

export type DecoyActionType =
  | 'BLOCK_IP'
  | 'UNBLOCK_IP'
  | 'QUARANTINE_SESSION'
  | 'ADD_HONEYTOKEN'
  | 'ADD_BREADCRUMB'
  | 'ESCALATE_ALERT'
  | 'TAG_ATTACKER'
  | 'START_INSTANCE'
  | 'STOP_INSTANCE';

export interface DecoyInstance {
  id: string;
  name: string;
  protocol: DecoyProtocol;
  vendor: string;
  model: string;
  firmware: string;
  ipAddress: string;
  port: number;
  purdueLevel: number;
  status: DecoyStatus;
  uptimeSeconds: number;
  totalEngagements: number;
  activeEngagements: number;
  lastEngagementAt: string | null;
  threatScore: number;
  description: string;
  facility?: string | null;
  facilityX?: number | null;
  facilityY?: number | null;
}

export interface MitreTtp {
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  confidence: number;
}

export interface PayloadField {
  name: string;
  type: string;
  value: string;
  rawHex?: string | null;
  unit?: string | null;
  flagged?: boolean | null;
  anomalyReason?: string | null;
}

export interface PayloadDeep {
  protocolOp: string;
  functionCodeHex?: string | null;
  functionCodeName?: string | null;
  transactionId?: number | null;
  unitId?: number | null;
  addressRange?: string | null;
  byteCount?: number | null;
  rawHex?: string | null;
  rawAscii?: string | null;
  fields?: PayloadField[] | null;
  anomalyFlags?: string[] | null;
}

export interface EngagementEvent {
  id: string;
  engagementId: string;
  ts: string;
  direction: EventDirection;
  severity: Severity;
  summary: string;
  mitre?: MitreTtp | null;
  payload?: PayloadDeep | null;
}

export interface AttackerProfile {
  ip: string;
  asn: string;
  asnName: string;
  country: string;
  countryName: string;
  firstSeen: string;
  lastSeen: string;
  engagementCount: number;
  distinctDecoysHit: number;
  threatScore: number;
  tags: string[];
  threatIntelSource: string;
  blocked: boolean;
  quarantined: boolean;
}

export interface Engagement {
  id: string;
  decoyInstanceId: string;
  decoyName: string;
  protocol: DecoyProtocol;
  attackerIp: string;
  attackerCountry: string;
  attackerAsn: string;
  startedAt: string;
  lastActivityAt: string;
  endedAt: string | null;
  status: EngagementStatus;
  severity: Severity;
  threatScore: number;
  eventCount: number;
  mitreTtps: MitreTtp[];
  events?: EngagementEvent[];
  attackerProfile?: AttackerProfile;
}

export interface DecoyStats {
  activeEngagements: number;
  engagementsLast24h: number;
  uniqueAttackersLast24h: number;
  decoysRunning: number;
  decoysTotal: number;
  engagementsByProtocol: Record<string, number>;
  topMitreTactics: { tactic: string; count: number }[];
  topProtocolOps: { op: string; count: number }[];
}

export interface DecoyActionRequest {
  type: DecoyActionType;
  targetIp?: string;
  engagementId?: string;
  decoyInstanceId?: string;
  reason?: string;
  params?: Record<string, unknown>;
}

export interface DecoyActionResult {
  id: string;
  type: DecoyActionType;
  status: 'APPLIED' | 'FAILED' | 'PENDING';
  appliedAt: string;
  appliedBy: string;
  message: string;
  result?: Record<string, unknown>;
}

// ---------- API client ----------

export const decoyService = {
  listInstances: () =>
    api.get<DecoyInstance[]>('/api/decoy/instances').then(r => r.data),

  getInstance: (id: string) =>
    api.get<DecoyInstance>(`/api/decoy/instances/${id}`).then(r => r.data),

  listEngagements: (params?: { status?: EngagementStatus; decoyId?: string; page?: number; size?: number }) =>
    api.get<Engagement[]>('/api/decoy/engagements', { params }).then(r => r.data),

  getEngagement: (id: string) =>
    api.get<Engagement>(`/api/decoy/engagements/${id}`).then(r => r.data),

  getAttacker: (ip: string) =>
    api.get<AttackerProfile>(`/api/decoy/attackers/${encodeURIComponent(ip)}`).then(r => r.data),

  stats: () =>
    api.get<DecoyStats>('/api/decoy/stats').then(r => r.data),

  applyAction: (req: DecoyActionRequest) =>
    api.post<DecoyActionResult>('/api/decoy/actions', req).then(r => r.data),

  recentActions: (limit = 20) =>
    api.get<DecoyActionResult[]>('/api/decoy/actions/recent', { params: { limit } }).then(r => r.data),
};

// ---------- WebSocket helper ----------

export type DecoyStreamMessage =
  | { kind: 'CONNECTED'; sessionId: string }
  | { kind: 'PING'; ts: number }
  | { kind: 'EVENT'; engagementId: string; decoyInstanceId: string; event: EngagementEvent }
  | { kind: 'ENGAGEMENT_STARTED'; engagement: Engagement }
  | { kind: 'ENGAGEMENT_CLOSED'; engagementId: string }
  | { kind: 'INSTANCE_STATUS'; instanceId: string; status: DecoyStatus };

/**
 * Open a websocket subscription to /ws/decoy/stream.
 * Returns a function to close the socket.
 */
export function subscribeDecoyStream(onMessage: (msg: DecoyStreamMessage) => void, onError?: (err: Event) => void): () => void {
  const url = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + 'localhost:8080/ws/decoy/stream';
  const ws = new WebSocket(url);
  ws.onmessage = (ev) => {
    try { onMessage(JSON.parse(ev.data)); } catch { /* ignore */ }
  };
  if (onError) ws.onerror = onError;
  return () => { try { ws.close(); } catch { /* ignore */ } };
}
