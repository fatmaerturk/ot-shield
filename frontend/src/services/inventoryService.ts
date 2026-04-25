import api from './api';

/**
 * Client for the bundle inventory
 * ({@code /api/research/inventory}). One endpoint, four flavours
 * driven by the {@code kind} discriminator: COMPONENT, PORT, SERVICE,
 * PROTOCOL. Active bundle is injected automatically via the axios
 * X-Bundle-Id interceptor.
 */

export type InventoryKind = 'COMPONENT' | 'PORT' | 'SERVICE' | 'PROTOCOL';

export interface InventoryItem {
  id: string;
  bundleId: string;
  kind: InventoryKind;
  name: string;
  details: string | null;
  reference: string | null;
  source: string | null;
  tags: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface InventoryCreateRequest {
  kind: InventoryKind;
  name: string;
  details?: string;
  reference?: string;
  source?: string;
  tags?: string;
}

export interface InventoryUpdateRequest {
  kind?: InventoryKind;
  name?: string;
  details?: string;
  reference?: string;
  source?: string;
  tags?: string;
}

/**
 * Lists inventory for the active bundle, optionally filtered to a
 * subset of kinds (used by the Ports & Services tab).
 */
export async function listInventory(kinds?: InventoryKind[]): Promise<InventoryItem[]> {
  const params = (kinds && kinds.length > 0) ? { kinds: kinds.join(',') } : undefined;
  const res = await api.get<InventoryItem[]>('/api/research/inventory', { params });
  return res.data;
}

export async function createInventory(req: InventoryCreateRequest): Promise<InventoryItem> {
  const res = await api.post<InventoryItem>('/api/research/inventory', req);
  return res.data;
}

export async function updateInventory(
  id: string,
  req: InventoryUpdateRequest
): Promise<InventoryItem> {
  const res = await api.patch<InventoryItem>(`/api/research/inventory/${id}`, req);
  return res.data;
}

export async function deleteInventory(id: string): Promise<void> {
  await api.delete(`/api/research/inventory/${id}`);
}

// ---------------------------------------------------------------------------
// Extract-from-corpus (Faz 4.3 follow-up)
// ---------------------------------------------------------------------------

/** Summary of one regex extraction pass, returned by the quick extract endpoint. */
export interface ExtractionResult {
  documentsScanned: number;
  chunksScanned: number;
  itemsCreated: number;
  portsCreated: number;
  protocolsCreated: number;
  servicesCreated: number;
}

export type DeepJobStatus = 'IDLE' | 'GENERATING' | 'READY' | 'FAILED';

export interface DeepExtractionJob {
  bundleId: string;
  status: DeepJobStatus;
  message: string | null;
  itemsCreated: number | null;
  startedAt: string | null;
  finishedAt: string | null;
}

/** Fast, synchronous regex-based extractor. Returns the summary. */
export async function extractInventory(): Promise<ExtractionResult> {
  const res = await api.post<ExtractionResult>('/api/research/inventory/extract');
  return res.data;
}

/**
 * Kick off the slow LLM-driven deep extractor. Returns immediately in
 * GENERATING; the caller polls {@link getDeepExtractionStatus}.
 */
export async function extractInventoryDeep(): Promise<DeepExtractionJob> {
  const res = await api.post<DeepExtractionJob>('/api/research/inventory/extract/deep');
  return res.data;
}

export async function getDeepExtractionStatus(): Promise<DeepExtractionJob> {
  const res = await api.get<DeepExtractionJob>('/api/research/inventory/extract/deep/status');
  return res.data;
}

export default {
  listInventory,
  createInventory,
  updateInventory,
  deleteInventory,
  extractInventory,
  extractInventoryDeep,
  getDeepExtractionStatus,
};
