import api from './api';
import type { AssistantConfidence } from './assistantService';

/**
 * Client for the "alternative theories" endpoint. Each assistant
 * message on the Research Studio can be expanded with 2-3 contrarian
 * hypotheses; this module wraps the POST endpoint plus the shared type
 * used by ThreadsTab, threadService, etc.
 */

/** One alternative hypothesis returned by the backend. */
export interface AlternativeTheory {
  index: number;
  hypothesis: string;
  rationale: string;
  /**
   * Self-reported confidence on the alternative itself. Reuses the
   * same ramp as the primary-answer pill so the UI can render both
   * with a single ConfidencePill component.
   */
  confidence: AssistantConfidence;
}

/**
 * Ask the backend to generate a fresh list of alternative theories for
 * the given assistant message. Re-running the call overwrites the
 * stored list server-side, which is the "give me another set" flow.
 *
 * <p>The underlying LLM call is synchronous on the server and may take
 * up to ~45 seconds. Call sites should show a loading state and avoid
 * firing this on component mount - it's a per-click action only.
 */
export async function generateAlternatives(
  threadId: string,
  messageId: string
): Promise<AlternativeTheory[]> {
  const res = await api.post<AlternativeTheory[]>(
    `/api/research/threads/${threadId}/messages/${messageId}/alternatives`
  );
  return res.data ?? [];
}

export default { generateAlternatives };
