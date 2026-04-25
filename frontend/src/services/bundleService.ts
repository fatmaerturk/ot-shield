import api from './api';

/**
 * Client for the Research bundle sidebar
 * ({@code /api/research/bundles}). A bundle is a scoped workspace
 * inside Research Studio - one self-contained investigation that owns
 * its own documents, threads, findings and vulnerability observations.
 */

export interface ResearchBundle {
  id: string;
  name: string;
  slug: string;
  tags: string | null;
  description: string | null;
  watchFolderPath: string | null;
  watchEnabled: boolean;
  createdAt: string;
  updatedAt: string;
  /** Rollup counters rendered under the bundle row in the sidebar. */
  documentCount: number;
  threadCount: number;
  findingCount: number;
  vulnCount: number;
}

export interface BundleCreateRequest {
  name: string;
  slug?: string;
  tags?: string;
  description?: string;
  watchFolderPath?: string;
  watchEnabled?: boolean;
}

export interface BundleUpdateRequest {
  name?: string;
  slug?: string;
  tags?: string;
  description?: string;
  watchFolderPath?: string;
  watchEnabled?: boolean;
}

export async function listBundles(): Promise<ResearchBundle[]> {
  const res = await api.get<ResearchBundle[]>('/api/research/bundles');
  return res.data;
}

export async function getBundle(id: string): Promise<ResearchBundle> {
  const res = await api.get<ResearchBundle>(`/api/research/bundles/${id}`);
  return res.data;
}

export async function createBundle(req: BundleCreateRequest): Promise<ResearchBundle> {
  const res = await api.post<ResearchBundle>('/api/research/bundles', req);
  return res.data;
}

export async function updateBundle(id: string, req: BundleUpdateRequest): Promise<ResearchBundle> {
  const res = await api.patch<ResearchBundle>(`/api/research/bundles/${id}`, req);
  return res.data;
}

export async function deleteBundle(id: string): Promise<void> {
  await api.delete(`/api/research/bundles/${id}`);
}

export default {
  listBundles,
  getBundle,
  createBundle,
  updateBundle,
  deleteBundle,
};
