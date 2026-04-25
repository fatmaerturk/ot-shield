import api from './api';
import type { AssistantCitation, AssistantConfidence, ConsistencyWarning } from './assistantService';
import type { AlternativeTheory } from './alternativesService';

/**
 * Client for the Research Studio "Threads" tab endpoints.
 *
 * <p>A thread is a persistent copilot conversation: user questions and
 * assistant answers (with their citations) are saved so the analyst can
 * return to a prior line of investigation. New turns are appended by
 * the Assistant chat endpoint when a {@code threadId} is passed with
 * the request - this module only covers CRUD over the parent thread
 * and historical message retrieval.
 */

/** Summary row returned by {@code GET /api/research/threads}. */
export interface ResearchThread {
  id: string;
  title: string;
  lastQuestion: string | null;
  messageCount: number;
  createdAt: string;
  updatedAt: string;
}

/** Historic message row returned by {@code GET .../messages}. */
export interface ResearchMessage {
  id: string;
  threadId: string;
  role: 'user' | 'assistant' | string;
  content: string;
  citations: AssistantCitation[];
  /**
   * Persisted self-assessment. Null for user messages and for assistant
   * rows written before the confidence footer was introduced.
   */
  confidence?: AssistantConfidence | null;
  /** Mirror of the model's "needs more sources" flag. */
  needsMoreSources?: boolean | null;
  /**
   * Persisted contrarian hypotheses the user pulled on this message.
   * Empty / null until the user clicks "Show alternative theories".
   */
  alternatives?: AlternativeTheory[] | null;
  /**
   * Consistency warnings from the source cross-check. Empty array =
   * check ran, no conflicts. Null = legacy row, check never ran.
   */
  consistency?: ConsistencyWarning[] | null;
  createdAt: string;
}

/** Threads list, most recently active first. */
export async function listThreads(): Promise<ResearchThread[]> {
  const res = await api.get<ResearchThread[]>('/api/research/threads');
  return res.data;
}

/** Fetch just the thread metadata (no messages). */
export async function getThread(threadId: string): Promise<ResearchThread> {
  const res = await api.get<ResearchThread>(`/api/research/threads/${threadId}`);
  return res.data;
}

/** Full transcript, oldest first. */
export async function listMessages(threadId: string): Promise<ResearchMessage[]> {
  const res = await api.get<ResearchMessage[]>(
    `/api/research/threads/${threadId}/messages`
  );
  return res.data;
}

/**
 * Creates a new empty thread. Pass {@code firstQuestion} to pre-seed
 * the auto-generated title; omit for "New thread".
 */
export async function createThread(firstQuestion?: string): Promise<ResearchThread> {
  const res = await api.post<ResearchThread>('/api/research/threads', {
    firstQuestion: firstQuestion ?? '',
  });
  return res.data;
}

/** Rename a thread. */
export async function renameThread(
  threadId: string,
  title: string
): Promise<ResearchThread> {
  const res = await api.patch<ResearchThread>(
    `/api/research/threads/${threadId}`,
    { title }
  );
  return res.data;
}

/** Hard-delete a thread and every message in it. */
export async function deleteThread(threadId: string): Promise<void> {
  await api.delete(`/api/research/threads/${threadId}`);
}

export default {
  listThreads,
  getThread,
  listMessages,
  createThread,
  renameThread,
  deleteThread,
};
