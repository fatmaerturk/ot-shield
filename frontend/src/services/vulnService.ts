import api from './api';
import type { AssistantCitation } from './assistantService';

/**
 * Client for the Vulnerability Observations surface
 * ({@code /api/research/vulns}).
 *
 * <p>Aligned with the HMGCC Co-Creation "Smart personal assistant for
 * security researchers" call - every observation carries a lifecycle,
 * a confidence grade, an optional "needs more sources" flag and the
 * thread/message it was promoted from so the analyst can rewind the
 * conversation weeks later.
 */

// ---------------------------------------------------------------------------
// Enums mirrored from the backend. Narrow string-literal unions give us
// exhaustive switches without a runtime enum.
// ---------------------------------------------------------------------------

export type VulnStatus =
  | 'DRAFT'
  | 'UNDER_REVIEW'
  | 'VERIFIED'
  | 'MITIGATED'
  | 'DISMISSED'
  | 'FALSE_POSITIVE';

export type VulnSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type VulnConfidence = 'HIGH' | 'MEDIUM' | 'LOW';

export type VulnComponentType =
  | 'PROTOCOL'
  | 'INTERFACE'
  | 'FIRMWARE'
  | 'SOFTWARE'
  | 'HARDWARE_COMPONENT'
  | 'CONFIGURATION'
  | 'SUPPLY_CHAIN'
  | 'OTHER';

export type VulnEventKind =
  | 'CREATED'
  | 'PROMOTED'
  | 'TRANSITION'
  | 'EDITED'
  | 'COMMENT';

// ---------------------------------------------------------------------------
// Projections
// ---------------------------------------------------------------------------

export interface VulnObservation {
  id: string;
  title: string;
  summary: string | null;
  componentType: VulnComponentType;
  componentRef: string | null;
  affectedProduct: string | null;
  severity: VulnSeverity;
  cveId: string | null;
  cvssV31: string | null;
  confidence: VulnConfidence;
  needsMoreSources: boolean;
  status: VulnStatus;
  mitigationSummary: string | null;
  sourceThreadId: string | null;
  sourceMessageId: string | null;
  citations: AssistantCitation[];
  alternativeHypotheses: string | null;
  tags: string | null;
  createdAt: string;
  updatedAt: string;
  createdBy: string | null;
  verifiedBy: string | null;
}

export interface VulnEvent {
  id: string;
  vulnId: string;
  kind: VulnEventKind;
  fromStatus: VulnStatus | null;
  toStatus: VulnStatus | null;
  comment: string | null;
  actor: string | null;
  createdAt: string;
}

export interface VulnKpi {
  openCount: number;
  needsMoreSourcesCount: number;
  underReviewCount: number;
  verifiedHighOrCriticalCount: number;
  mitigatedCount: number;
}

export interface VulnTransitions {
  from: VulnStatus;
  next: VulnStatus[];
}

// ---------------------------------------------------------------------------
// Request DTOs (match the Java records)
// ---------------------------------------------------------------------------

export interface VulnCreateRequest {
  title: string;
  summary?: string;
  componentType: VulnComponentType;
  componentRef?: string;
  affectedProduct?: string;
  severity: VulnSeverity;
  cveId?: string;
  cvssV31?: string;
  confidence: VulnConfidence;
  needsMoreSources?: boolean;
  alternativeHypotheses?: string;
  tags?: string;
  createdBy?: string;
}

export interface VulnPromoteRequest {
  threadId: string;
  messageId: string;
  title?: string;
  componentType: VulnComponentType;
  componentRef?: string;
  affectedProduct?: string;
  severity: VulnSeverity;
  confidence: VulnConfidence;
  needsMoreSources?: boolean;
  alternativeHypotheses?: string;
  tags?: string;
  createdBy?: string;
}

export interface VulnUpdateRequest {
  title?: string;
  summary?: string;
  componentType?: VulnComponentType;
  componentRef?: string;
  affectedProduct?: string;
  severity?: VulnSeverity;
  cveId?: string;
  cvssV31?: string;
  confidence?: VulnConfidence;
  needsMoreSources?: boolean;
  mitigationSummary?: string;
  alternativeHypotheses?: string;
  tags?: string;
}

export interface VulnTransitionRequest {
  toStatus: VulnStatus;
  comment?: string;
  actor?: string;
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

export interface VulnListFilters {
  status?: VulnStatus;
  severity?: VulnSeverity;
  componentType?: VulnComponentType;
  needsMoreSources?: boolean;
}

/** Listing, most-recently-updated first. Any filter is optional. */
export async function listVulns(filters?: VulnListFilters): Promise<VulnObservation[]> {
  const params: Record<string, string> = {};
  if (filters?.status) params.status = filters.status;
  if (filters?.severity) params.severity = filters.severity;
  if (filters?.componentType) params.componentType = filters.componentType;
  if (filters?.needsMoreSources !== undefined) {
    params.needsMoreSources = String(filters.needsMoreSources);
  }
  const res = await api.get<VulnObservation[]>('/api/research/vulns', { params });
  return res.data;
}

export async function getVuln(id: string): Promise<VulnObservation> {
  const res = await api.get<VulnObservation>(`/api/research/vulns/${id}`);
  return res.data;
}

export async function getVulnEvents(id: string): Promise<VulnEvent[]> {
  const res = await api.get<VulnEvent[]>(`/api/research/vulns/${id}/events`);
  return res.data;
}

export async function getVulnTransitions(id: string): Promise<VulnTransitions> {
  const res = await api.get<VulnTransitions>(`/api/research/vulns/${id}/transitions`);
  return res.data;
}

export async function getVulnKpi(): Promise<VulnKpi> {
  const res = await api.get<VulnKpi>('/api/research/vulns/kpi');
  return res.data;
}

export async function createVuln(req: VulnCreateRequest): Promise<VulnObservation> {
  const res = await api.post<VulnObservation>('/api/research/vulns', req);
  return res.data;
}

export async function promoteVuln(req: VulnPromoteRequest): Promise<VulnObservation> {
  const res = await api.post<VulnObservation>('/api/research/vulns/promote', req);
  return res.data;
}

export async function updateVuln(
  id: string,
  req: VulnUpdateRequest,
  actor?: string
): Promise<VulnObservation> {
  const res = await api.patch<VulnObservation>(
    `/api/research/vulns/${id}`,
    req,
    { params: actor ? { actor } : undefined }
  );
  return res.data;
}

export async function transitionVuln(
  id: string,
  req: VulnTransitionRequest
): Promise<VulnObservation> {
  const res = await api.post<VulnObservation>(`/api/research/vulns/${id}/transition`, req);
  return res.data;
}

/**
 * Summary of one regex signal scan. Every non-zero category count
 * means the scanner created that many fresh DRAFT observations of
 * that flavour.
 */
export interface SignalScanResult {
  documentsScanned: number;
  chunksScanned: number;
  draftsCreated: number;
  insecureRemoteCount: number;
  weakAuthCount: number;
  cryptoCount: number;
  firmwareCount: number;
  cveCount: number;
}

/** Fast, synchronous regex scan that drafts vulnerability observations. */
export async function scanVulnSignals(): Promise<SignalScanResult> {
  const res = await api.post<SignalScanResult>('/api/research/vulns/signals/scan');
  return res.data;
}

export async function deleteVuln(id: string): Promise<void> {
  await api.delete(`/api/research/vulns/${id}`);
}

export default {
  listVulns,
  getVuln,
  getVulnEvents,
  getVulnTransitions,
  getVulnKpi,
  createVuln,
  promoteVuln,
  updateVuln,
  transitionVuln,
  deleteVuln,
  scanVulnSignals,
};
