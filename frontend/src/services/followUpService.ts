import api from './api';

/**
 * Follow-up question suggestion client. Backed by the local Ollama
 * chat model via {@code POST /api/assistant/suggest-followups}. Empty
 * list is a legitimate response - callers should hide the chip rail
 * rather than surface an error in that case.
 */

export async function fetchFollowUps(question: string, answer: string): Promise<string[]> {
  if (!question || !answer) return [];
  const res = await api.post<{ suggestions?: string[] }>(
    '/api/assistant/suggest-followups',
    { question, answer }
  );
  const list = res.data?.suggestions ?? [];
  return Array.isArray(list) ? list.slice(0, 3) : [];
}

export default { fetchFollowUps };
