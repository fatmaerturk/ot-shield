import api from './api';

/**
 * Client for the Summary tab ({@code /api/research/summary}). One
 * summary per active bundle; the axios request interceptor injects
 * the {@code X-Bundle-Id} header automatically.
 */

export type SummaryStatus = 'IDLE' | 'GENERATING' | 'READY' | 'FAILED';

export interface BundleSummary {
  bundleId: string;
  text: string | null;
  model: string | null;
  promptTokens: number | null;
  generatedAt: string | null;
  editedAt: string | null;
  editedBy: string | null;
  sourceDocIds: string[];
  status: SummaryStatus;
}

export async function getSummary(): Promise<BundleSummary> {
  const res = await api.get<BundleSummary>('/api/research/summary');
  return res.data;
}

/**
 * Kicks off async generation. Returns immediately with the row in
 * status {@code GENERATING}; callers must poll {@link getSummary} to
 * observe the eventual {@code READY} / {@code FAILED} transition.
 * Background inference on CPU-only hosts routinely runs past 5
 * minutes on 3B / q4 quants with a 10-doc corpus - that's fine
 * because nobody is holding the HTTP connection open.
 */
export async function regenerateSummary(): Promise<BundleSummary> {
  const res = await api.post<BundleSummary>('/api/research/summary/regenerate');
  return res.data;
}

export async function updateSummary(text: string, editedBy?: string): Promise<BundleSummary> {
  const res = await api.patch<BundleSummary>('/api/research/summary', { text, editedBy });
  return res.data;
}

export default { getSummary, regenerateSummary, updateSummary };
