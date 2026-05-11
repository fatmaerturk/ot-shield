import api from './api';

/**
 * Shape of /api/honeypot/stats payload returned by HoneypotController.
 * All fields are optional because backend may omit them depending on data.
 */
export interface HoneypotStats {
  totalAttacks?: number;
  uniqueIPs?: number;
  uniqueSessions?: number;
  attacksByProtocol?: Record<string, number>;
  attacksBySeverity?: Record<string, number>;
  topSourceIps?: Array<{
    sourceIp: string;
    count: number;
    country?: string;
    city?: string;
    lat?: number;
    lon?: number;
  }>;
  topAttackedPorts?: Array<{
    port: number;
    count: number;
    service?: string;
  }>;
  recentAttacks24h?: number;
  blockedAttacks?: number;
  hourlySeries?: Array<{ hour: string; count: number }>;
  dailySeries?: Array<{ day: string; count: number }>;
  recentEvents?: Array<{
    id?: string | number;
    sourceIp?: string;
    protocol?: string;
    attackType?: string;
    timestamp?: string;
    severity?: string;
    description?: string;
  }>;
  geoIpAvailable?: boolean;
}

export interface HoneypotLog {
  id?: string | number;
  sourceIp?: string;
  protocol?: string;
  attackType?: string;
  payload?: string;
  description?: string;
  severity?: string;
  timestamp?: string;
  sourcePort?: number;
  destinationPort?: number;
}

export interface TtpAnalysis {
  attackerProfiles?: Array<{
    sourceIp: string;
    sophistication?: number;
    country?: string;
    techniqueIds?: string[];
    firstSeen?: string;
    lastSeen?: string;
    interactions?: number;
  }>;
  mitreHeatmap?: Record<string, number>;
  observedTechniqueIds?: string[];
  tactics?: Array<{
    id: string;
    name: string;
    observed: number;
    coverage?: number;
  }>;
  toolFingerprints?: Array<{ name: string; count: number }>;
  killChains?: Array<{ sourceIp: string; steps: any[] }>;
  geographic?: Array<{ country: string; count: number }>;
  credentialIntelligence?: Record<string, any>;
  behavioralAnomalies?: any[];
  [key: string]: any;
}

export const honeypotService = {
  getStats: async (): Promise<HoneypotStats> => {
    const res = await api.get<HoneypotStats>('/api/honeypot/stats');
    return res.data ?? {};
  },

  getRecentLogs: async (count: number = 10): Promise<HoneypotLog[]> => {
    const res = await api.get<HoneypotLog[]>(`/api/honeypot/logs/recent?count=${count}`);
    return Array.isArray(res.data) ? res.data : [];
  },

  getLogs: async (
    page: number = 0,
    size: number = 50,
    sourceIp?: string,
    protocol?: string
  ): Promise<HoneypotLog[]> => {
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    if (sourceIp) params.append('sourceIp', sourceIp);
    if (protocol) params.append('protocol', protocol);
    const res = await api.get<HoneypotLog[]>(`/api/honeypot/logs?${params.toString()}`);
    return Array.isArray(res.data) ? res.data : [];
  },

  getAttacks: async (): Promise<Array<Record<string, any>>> => {
    const res = await api.get<Array<Record<string, any>>>('/api/honeypot/attacks');
    return Array.isArray(res.data) ? res.data : [];
  },

  getTtpAnalysis: async (): Promise<TtpAnalysis> => {
    const res = await api.get<TtpAnalysis>('/api/honeypot/ttp-analysis');
    return res.data ?? {};
  },
};

export default honeypotService;
