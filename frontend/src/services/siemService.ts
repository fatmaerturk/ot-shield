import api from './api';

export type SiemProtocol = 'UDP' | 'TCP';
export type SiemFormat = 'CEF' | 'RFC5424';
export type SiemSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface SiemConfig {
  enabled: boolean;
  host: string;
  port: number;
  protocol: SiemProtocol;
  format: SiemFormat;
  minSeverity: SiemSeverity;
}

export interface SiemStats {
  enabled: boolean;
  target: string | null;
  format: SiemFormat;
  minSeverity: SiemSeverity;
  sent: number;
  failed: number;
  droppedBelowThreshold: number;
  lastSentAt: string | null;
  lastError: string | null;
  lastMessage: string | null;
}

export interface SiemTestResult {
  ok: boolean;
  target?: string;
  format?: SiemFormat;
  sample?: string;
  error?: string;
}

const BASE = '/api/integrations/siem';

export const siemService = {
  async getConfig(): Promise<SiemConfig> {
    const { data } = await api.get<SiemConfig>(`${BASE}/config`);
    return data;
  },
  async updateConfig(cfg: Partial<SiemConfig>): Promise<SiemConfig> {
    const { data } = await api.put<SiemConfig>(`${BASE}/config`, cfg);
    return data;
  },
  async getStats(): Promise<SiemStats> {
    const { data } = await api.get<SiemStats>(`${BASE}/stats`);
    return data;
  },
  async test(): Promise<SiemTestResult> {
    const { data } = await api.post<SiemTestResult>(`${BASE}/test`, {});
    return data;
  },
};
