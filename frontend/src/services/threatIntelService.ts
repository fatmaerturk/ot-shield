import api from './api';

// ---------- Types (mirror backend DTOs) ----------

export interface TtpTechnique {
  id: string;
  name: string;
  observationCount: number;
  confidence: number;               // 0..100
  evidenceEventIds: string[];
}

export interface TtpTactic {
  id: string;
  name: string;
  order: number;
  techniques: TtpTechnique[];
}

export interface TtpMatrix {
  tactics: TtpTactic[];
}

export interface AttackerIntelSummary {
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
  protocols: string[];
  dominantTactic: string | null;
  distinctTechniques: number;
  blocked: boolean;
  quarantined: boolean;
  activitySparkline: number[];
  // Connection-nature classification (real IP intel; not a guaranteed VPN yes/no)
  anonymityCategory?: 'TOR_EXIT' | 'VPN_PROVIDER' | 'HOSTING_DATACENTER' | 'RESIDENTIAL_ISP' | 'INTERNAL' | 'NOT_ASSESSED';
  anonymityLabel?: string;
  anonymityConfidence?: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  anonymized?: boolean;
  anonymityNote?: string;
  anonymitySignals?: string[];
}

export interface BehavioralFingerprint {
  hash: string;
  pattern: string;
  dominantTactics: string[];
  protocolMix: Record<string, number>;
  functionCodeMix: Record<string, number>;
  repetitionScore: number;
  nightRatio: number;
  burstiness: number;
  notableAnomalies: string[];
}

export interface CampaignCluster {
  id: string;
  name: string;
  fingerprintHash: string;
  memberIps: string[];
  sharedAsns: string[];
  targetedDecoyIds: string[];
  topTechniques: string[];
  severityScore: number;
  memberCount: number;
  summary: string;
}

export interface AttackerIntelDetail {
  summary: AttackerIntelSummary;
  ttpMatrix: TtpMatrix;
  fingerprint: BehavioralFingerprint;
  engagementIds: string[];
  campaigns: CampaignCluster[];
  relatedIps: string[];
  iocHighlights: string[];
}

export type IocExportFormat = 'STIX' | 'CSV' | 'PLAIN';

export interface IocExportRequest {
  format: IocExportFormat;
  attackerIps?: string[];
  includeCampaigns?: boolean;
  includeTtps?: boolean;
}

export interface IocExportResult {
  id: string;
  format: IocExportFormat;
  generatedAt: string;
  iocCount: number;
  content: string;
  filename: string;
}

export type IntelPushTarget = 'TAXII' | 'MISP' | 'SIEM';

export interface IntelPushRequest {
  target: IntelPushTarget;
  endpoint?: string;
  attackerIps: string[];
  reason?: string;
}

export interface IntelPushResult {
  id: string;
  target: IntelPushTarget;
  status: 'ACCEPTED' | 'FAILED';
  pushedAt: string;
  pushedIocs: number;
  externalRef: string;
  message: string;
}

// ---------- API client ----------

export const threatIntelService = {
  listAttackers: (params?: { country?: string; asn?: string; minScore?: number }) =>
    api.get<AttackerIntelSummary[]>('/api/threat-intel/attackers', { params }).then(r => r.data),

  getAttacker: (ip: string) =>
    api.get<AttackerIntelDetail>(`/api/threat-intel/attackers/${encodeURIComponent(ip)}`).then(r => r.data),

  getMatrix: () =>
    api.get<TtpMatrix>('/api/threat-intel/ttp-matrix').then(r => r.data),

  listCampaigns: () =>
    api.get<CampaignCluster[]>('/api/threat-intel/campaigns').then(r => r.data),

  export: (req: IocExportRequest) =>
    api.post<IocExportResult>('/api/threat-intel/export', req).then(r => r.data),

  push: (req: IntelPushRequest) =>
    api.post<IntelPushResult>('/api/threat-intel/push', req).then(r => r.data),

  // ---- First-party OT threat-intel feed (outbound production) ----
  getFeedSummary: () =>
    api.get<FeedSummary>('/api/threat-intel/feed/summary').then(r => r.data),
  getFeed: () =>
    api.get<string>('/api/threat-intel/feed', { transformResponse: (d) => d }).then(r => r.data),

  // ---- IP connection-nature (Tor / hosting / VPN vs residential) ----
  ipIntelStatus: () =>
    api.get<{ asnDbAvailable: boolean; torNodes: number; torUpdatedAt: string | null }>('/api/threat-intel/ip-intel/status').then(r => r.data),
  classifyIp: (ip: string) =>
    api.get<IpAnonymity>(`/api/threat-intel/ip-intel/classify`, { params: { ip } }).then(r => r.data),
};

export interface IpAnonymity {
  category: 'TOR_EXIT' | 'VPN_PROVIDER' | 'HOSTING_DATACENTER' | 'RESIDENTIAL_ISP' | 'INTERNAL' | 'NOT_ASSESSED';
  label: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  anonymized: boolean;
  signals: string[];
  asn: number | null;
  asnOrg: string | null;
  note: string;
}

export interface FeedSummary {
  producedIocs: number;
  highRisk: number;
  countries: number;
  protocols: string[];
  tacticsCovered: number;
  lastUpdated: string | null;
  generatedAt: string;
  formats: string[];
  feedUrl: string;
}
