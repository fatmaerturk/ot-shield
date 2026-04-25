import api from './api';

/**
 * Offline translation client for the Research Studio. Wraps the
 * backend's {@code POST /api/assistant/translate} endpoint, which in
 * turn drives the local Ollama chat model with a translation-specific
 * system prompt. No cloud calls.
 */

export type TargetLanguage = 'EN' | 'TR' | 'DE' | 'FR' | 'ES';

/** Human-friendly labels surfaced in the dropdown. */
export const LANG_LABELS: Record<TargetLanguage, string> = {
  EN: 'English',
  TR: 'Türkçe',
  DE: 'Deutsch',
  FR: 'Français',
  ES: 'Español',
};

/**
 * Translate a block of text into the target language. Can take ~10-30s
 * on a cold chat model; callers should show a loading state. Returns
 * the original text on any backend failure.
 */
export async function translateText(text: string, targetLang: TargetLanguage): Promise<string> {
  if (!text || !text.trim()) return text;
  const res = await api.post<{ translated?: string; error?: string }>(
    '/api/assistant/translate',
    { text, targetLang }
  );
  if (res.data?.error) {
    throw new Error(res.data.error);
  }
  return res.data?.translated ?? text;
}

export default { translateText, LANG_LABELS };
