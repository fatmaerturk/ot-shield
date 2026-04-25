import api from './api';
import type { AssistantCitation } from './assistantService';

/**
 * Client for the curated Findings ledger. Findings are analyst-approved
 * answers - typically promoted out of a Thread but also creatable
 * ad-hoc - with editable title/text/tags and immutable provenance.
 */

/** Outbound row returned by {@code GET /api/research/findings}. */
export interface ResearchFinding {
  id: string;
  title: string;
  text: string;
  citations: AssistantCitation[];
  sourceThreadId: string | null;
  sourceMessageId: string | null;
  tags: string | null;
  createdAt: string;
  updatedAt: string;
}

export async function listFindings(): Promise<ResearchFinding[]> {
  const res = await api.get<ResearchFinding[]>('/api/research/findings');
  return res.data;
}

export async function getFinding(id: string): Promise<ResearchFinding> {
  const res = await api.get<ResearchFinding>(`/api/research/findings/${id}`);
  return res.data;
}

/** Promote an assistant message into a finding. */
export async function promoteMessage(
  messageId: string,
  options?: { title?: string; tags?: string }
): Promise<ResearchFinding> {
  const res = await api.post<ResearchFinding>('/api/research/findings/promote', {
    messageId,
    title: options?.title,
    tags: options?.tags,
  });
  return res.data;
}

/** Analyst-authored finding that did not originate from a chat turn. */
export async function createFinding(
  text: string,
  options?: { title?: string; tags?: string }
): Promise<ResearchFinding> {
  const res = await api.post<ResearchFinding>('/api/research/findings', {
    text,
    title: options?.title,
    tags: options?.tags,
  });
  return res.data;
}

/** Partial update. Undefined fields are left untouched server-side. */
export async function updateFinding(
  id: string,
  patch: { title?: string; text?: string; tags?: string }
): Promise<ResearchFinding> {
  const res = await api.patch<ResearchFinding>(
    `/api/research/findings/${id}`,
    patch
  );
  return res.data;
}

export async function deleteFinding(id: string): Promise<void> {
  await api.delete(`/api/research/findings/${id}`);
}

export default {
  listFindings,
  getFinding,
  promoteMessage,
  createFinding,
  updateFinding,
  deleteFinding,
};
