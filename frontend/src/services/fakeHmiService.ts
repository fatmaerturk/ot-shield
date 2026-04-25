import api from './api';

// ---------- Types (mirror backend DTOs) ----------

export type HmiScenarioType = 'WATER_TREATMENT' | 'SUBSTATION' | 'OIL_GAS' | 'MANUFACTURING';
export type HmiVariantStyle = 'SIEMENS' | 'ROCKWELL' | 'SCHNEIDER' | 'GENERIC';
export type HmiStatus = 'RUNNING' | 'STOPPED' | 'DEGRADED';
export type HmiAlarmSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type HmiInteractionType =
  | 'PAGE_VIEW'
  | 'LOGIN_ATTEMPT'
  | 'CONTROL_WRITE'
  | 'ALARM_ACK'
  | 'DATA_POLL'
  | 'CONFIG_PROBE';

export interface HmiMetric {
  key: string;
  name: string;
  value: number;
  unit: string;
  min: number;
  max: number;
  alarming: boolean;
  category: 'tank' | 'pump' | 'temp' | 'pressure' | 'flow' | 'voltage' | 'current' | 'counter' | 'gauge';
  trend: number; // -1 | 0 | 1
}

export interface HmiAlarm {
  id: string;
  severity: HmiAlarmSeverity;
  tag?: string;
  message: string;
  ts: string; // ISO
  acknowledged: boolean;
  source: string;
}

export interface HmiInteraction {
  id: string;
  hmiId: string;
  ts: string;
  attackerIp: string;
  attackerCountry?: string | null;
  type: HmiInteractionType;
  target?: string;
  payload?: string;
  blocked?: boolean;
  userAgent?: string;
}

export interface FakeHmiInstance {
  id: string;
  name: string;
  scenario: HmiScenarioType;
  variant: HmiVariantStyle;
  status: HmiStatus;
  vendor: string;
  model: string;
  firmware: string;
  ipAddress: string;
  port: number;
  purdueLevel: number;
  facility: string;
  facilityX?: number;
  facilityY?: number;
  metrics: HmiMetric[];
  alarms: HmiAlarm[];
  totalInteractions: number;
  interactions24h: number;
  distinctAttackers24h: number;
  lastAccessedAt?: string | null;
  threatScore: number;
  uptimeSeconds: number;
  recentInteractions?: HmiInteraction[];
}

export interface FakeHmiStats {
  totalHmis: number;
  runningHmis: number;
  activeAlarms: number;
  interactions24h: number;
  distinctAttackers24h: number;
  mostTargetedScenario: HmiScenarioType;
}

export interface HmiInteractionRequest {
  type: HmiInteractionType;
  target?: string;
  payload?: string;
  attackerIp?: string;
  userAgent?: string;
}

// ---------- REST client ----------

export const fakeHmiService = {
  async list(): Promise<FakeHmiInstance[]> {
    const { data } = await api.get<FakeHmiInstance[]>('/api/deception/hmis');
    return data;
  },

  async get(id: string): Promise<FakeHmiInstance> {
    const { data } = await api.get<FakeHmiInstance>(`/api/deception/hmis/${id}`);
    return data;
  },

  async stats(): Promise<FakeHmiStats> {
    const { data } = await api.get<FakeHmiStats>('/api/deception/hmis/stats');
    return data;
  },

  async interact(id: string, req: HmiInteractionRequest): Promise<HmiInteraction> {
    const { data } = await api.post<HmiInteraction>(`/api/deception/hmis/${id}/interact`, req);
    return data;
  },
};

// ---------- WebSocket helper ----------

export type FakeHmiStreamMessage =
  | { kind: 'CONNECTED'; sessionId: string }
  | { kind: 'PING'; ts: number }
  | { kind: 'METRIC_UPDATE'; hmiId: string; metrics: HmiMetric[] }
  | { kind: 'ALARM'; hmiId: string; alarm: HmiAlarm }
  | { kind: 'INTERACTION'; hmiId: string; interaction: HmiInteraction };

export function subscribeFakeHmiStream(
  onMessage: (msg: FakeHmiStreamMessage) => void,
  onError?: (err: Event) => void
): () => void {
  const url =
    (window.location.protocol === 'https:' ? 'wss://' : 'ws://') +
    'localhost:8080/ws/deception/hmi-stream';
  const ws = new WebSocket(url);
  ws.onmessage = (ev) => {
    try { onMessage(JSON.parse(ev.data)); } catch { /* ignore */ }
  };
  if (onError) ws.onerror = onError;
  return () => { try { ws.close(); } catch { /* ignore */ } };
}
