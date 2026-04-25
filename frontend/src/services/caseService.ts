import api from './api';

// ---------- Enums (mirror backend) ----------

export type CaseStatus =
  | 'NEW'
  | 'TRIAGING'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE'
  | 'CLOSED';

export type CasePriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type CaseCategory =
  | 'MALWARE'
  | 'UNAUTHORIZED_ACCESS'
  | 'POLICY_VIOLATION'
  | 'ANOMALY'
  | 'RECON'
  | 'LATERAL_MOVEMENT'
  | 'OT_DISRUPTION'
  | 'DATA_EXFIL'
  | 'INSIDER_THREAT'
  | 'OTHER';

export type CaseTimelineEntryType =
  | 'CREATED'
  | 'STATUS_CHANGE'
  | 'PRIORITY_CHANGE'
  | 'ASSIGNED'
  | 'UNASSIGNED'
  | 'COMMENT'
  | 'ARTIFACT_ADDED'
  | 'ARTIFACT_REMOVED'
  | 'ALERT_LINKED'
  | 'ALERT_UNLINKED'
  | 'TAG_ADDED'
  | 'TAG_REMOVED'
  | 'ESCALATED'
  | 'RESOLUTION';

export type CaseArtifactType =
  | 'IP'
  | 'DOMAIN'
  | 'URL'
  | 'HASH'
  | 'FILE'
  | 'PCAP'
  | 'HMI_INTERACTION'
  | 'CVE'
  | 'USER_ACCOUNT'
  | 'PROCESS'
  | 'REGISTRY_KEY'
  | 'COMMAND'
  | 'OTHER';

// ---------- DTOs ----------

export interface CaseTimelineEntry {
  id: string;
  caseId: string;
  ts: string;
  entryType: CaseTimelineEntryType;
  actorId?: string | null;
  actorName?: string | null;
  content?: string | null;
  metadataJson?: string | null;
}

export interface CaseArtifact {
  id: string;
  caseId: string;
  artifactType: CaseArtifactType;
  value: string;
  label?: string | null;
  description?: string | null;
  addedBy?: string | null;
  addedAt: string;
  malicious?: boolean | null;
}

export interface CaseDTO {
  id: string;
  caseNumber: string;
  title: string;
  description?: string | null;
  status: CaseStatus;
  priority: CasePriority;
  severity?: AlertSeverity | null;
  category?: CaseCategory | null;
  assigneeId?: string | null;
  assigneeName?: string | null;
  reporterId?: string | null;
  reporterName?: string | null;
  createdAt: string;
  updatedAt?: string | null;
  acknowledgedAt?: string | null;
  containedAt?: string | null;
  resolvedAt?: string | null;
  closedAt?: string | null;
  resolutionSummary?: string | null;
  mttAcknowledgeSeconds?: number | null;
  mttContainSeconds?: number | null;
  mttResolveSeconds?: number | null;
  tags?: string[] | null;
  linkedAlertCount?: number | null;
  artifactCount?: number | null;
  timelineCount?: number | null;
  linkedAlertIds?: string[] | null;
  timeline?: CaseTimelineEntry[] | null;
  artifacts?: CaseArtifact[] | null;
}

export interface CaseStats {
  total: number;
  open: number;
  inProgress: number;
  contained: number;
  resolved7d: number;
  falsePositive7d: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  avgMttResolveSeconds7d?: number | null;
  avgMttAcknowledgeSeconds7d?: number | null;
  statusDistribution: Record<string, number>;
  priorityDistribution: Record<string, number>;
}

export interface CreateCaseRequest {
  title: string;
  description?: string;
  priority?: CasePriority;
  severity?: AlertSeverity;
  category?: CaseCategory;
  assigneeId?: string;
  assigneeName?: string;
  reporterId?: string;
  reporterName?: string;
  tags?: string[];
  alertIds?: string[];
}

export interface UpdateCaseRequest {
  title?: string;
  description?: string;
  priority?: CasePriority;
  severity?: AlertSeverity;
  category?: CaseCategory;
  tags?: string[];
  resolutionSummary?: string;
}

export interface CaseTransitionRequest {
  toStatus: CaseStatus;
  note?: string;
  resolutionSummary?: string;
  actorName?: string;
}

export interface CaseAssignRequest {
  assigneeId?: string;
  assigneeName?: string;
  actorName?: string;
}

export interface CaseCommentRequest {
  content: string;
  actorName?: string;
}

export interface CaseArtifactRequest {
  artifactType: CaseArtifactType;
  value: string;
  label?: string;
  description?: string;
  malicious?: boolean;
  actorName?: string;
}

// Spring Data Page envelope
export interface Page<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  number: number;
  size: number;
  first?: boolean;
  last?: boolean;
  numberOfElements?: number;
}

// ---------- API client ----------

export interface CaseListParams {
  status?: CaseStatus;
  priority?: CasePriority;
  assigneeId?: string;
  search?: string;
  page?: number;
  size?: number;
  sortBy?: string;
  sortDir?: 'asc' | 'desc';
}

export const caseService = {
  async list(params: CaseListParams = {}): Promise<Page<CaseDTO>> {
    const { data } = await api.get<Page<CaseDTO>>('/api/cases', { params });
    return data;
  },

  async get(id: string): Promise<CaseDTO> {
    const { data } = await api.get<CaseDTO>(`/api/cases/${id}`);
    return data;
  },

  async stats(): Promise<CaseStats> {
    const { data } = await api.get<CaseStats>('/api/cases/stats');
    return data;
  },

  async create(req: CreateCaseRequest): Promise<CaseDTO> {
    const { data } = await api.post<CaseDTO>('/api/cases', req);
    return data;
  },

  async update(id: string, req: UpdateCaseRequest, actor?: string): Promise<CaseDTO> {
    const { data } = await api.patch<CaseDTO>(`/api/cases/${id}`, req, {
      headers: actor ? { 'X-Actor-Name': actor } : undefined,
    });
    return data;
  },

  async transition(id: string, req: CaseTransitionRequest): Promise<CaseDTO> {
    const { data } = await api.post<CaseDTO>(`/api/cases/${id}/transition`, req);
    return data;
  },

  async assign(id: string, req: CaseAssignRequest): Promise<CaseDTO> {
    const { data } = await api.post<CaseDTO>(`/api/cases/${id}/assign`, req);
    return data;
  },

  async delete(id: string): Promise<void> {
    await api.delete(`/api/cases/${id}`);
  },

  async addComment(id: string, req: CaseCommentRequest): Promise<CaseDTO> {
    const { data } = await api.post<CaseDTO>(`/api/cases/${id}/comments`, req);
    return data;
  },

  async addArtifact(id: string, req: CaseArtifactRequest): Promise<CaseArtifact> {
    const { data } = await api.post<CaseArtifact>(`/api/cases/${id}/artifacts`, req);
    return data;
  },

  async removeArtifact(id: string, artifactId: string, actor?: string): Promise<void> {
    await api.delete(`/api/cases/${id}/artifacts/${artifactId}`, {
      headers: actor ? { 'X-Actor-Name': actor } : undefined,
    });
  },

  async linkAlert(id: string, alertId: string, actor?: string): Promise<CaseDTO> {
    const { data } = await api.post<CaseDTO>(`/api/cases/${id}/alerts/${alertId}`, null, {
      headers: actor ? { 'X-Actor-Name': actor } : undefined,
    });
    return data;
  },

  async unlinkAlert(id: string, alertId: string, actor?: string): Promise<CaseDTO> {
    const { data } = await api.delete<CaseDTO>(`/api/cases/${id}/alerts/${alertId}`, {
      headers: actor ? { 'X-Actor-Name': actor } : undefined,
    });
    return data;
  },
};

// ---------- UI helpers ----------

export function statusTone(s: CaseStatus): string {
  switch (s) {
    case 'NEW': return 'bg-sky-100 text-sky-700 ring-sky-200';
    case 'TRIAGING': return 'bg-amber-100 text-amber-800 ring-amber-200';
    case 'INVESTIGATING': return 'bg-violet-100 text-violet-700 ring-violet-200';
    case 'CONTAINED': return 'bg-indigo-100 text-indigo-700 ring-indigo-200';
    case 'RESOLVED': return 'bg-emerald-100 text-emerald-700 ring-emerald-200';
    case 'FALSE_POSITIVE': return 'bg-slate-100 text-slate-600 ring-slate-200';
    case 'CLOSED': return 'bg-slate-200 text-slate-700 ring-slate-300';
  }
}

export function priorityTone(p: CasePriority): string {
  switch (p) {
    case 'CRITICAL': return 'bg-rose-100 text-rose-700 ring-rose-200';
    case 'HIGH': return 'bg-orange-100 text-orange-700 ring-orange-200';
    case 'MEDIUM': return 'bg-amber-100 text-amber-700 ring-amber-200';
    case 'LOW': return 'bg-slate-100 text-slate-600 ring-slate-200';
  }
}

export function severityDot(s?: AlertSeverity | null): string {
  switch (s) {
    case 'CRITICAL': return 'bg-rose-500';
    case 'HIGH': return 'bg-orange-500';
    case 'MEDIUM': return 'bg-amber-400';
    case 'LOW': return 'bg-sky-400';
    case 'INFO': return 'bg-slate-300';
    default: return 'bg-slate-300';
  }
}

export function formatDuration(seconds?: number | null): string {
  if (seconds === null || seconds === undefined) return '-';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

export function ageSince(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  return formatDuration(ms / 1000);
}
