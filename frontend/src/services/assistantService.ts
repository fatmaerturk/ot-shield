/**
 * Client for the OTShield AI assistant - talks to
 * {@code POST /api/assistant/chat} (Server-Sent Events) and
 * {@code GET /api/assistant/health}.
 *
 * We can't use EventSource because it only supports GET. Instead we do a
 * fetch POST and read the response body as a stream, parsing SSE frames
 * by hand. That also lets us attach the JWT from localStorage the same way
 * the rest of the app does via the axios interceptor.
 */

export interface AssistantHistoryTurn {
  role: 'user' | 'assistant';
  content: string;
}

/**
 * One knowledge-base citation returned by the RAG retriever. Matches
 * the Java record {@code AssistantService.Citation}. The {@code index}
 * lines up with inline markers like {@code [1]}, {@code [2]} that the
 * model is asked to weave into its reply.
 */
/**
 * Taxonomy stamped on every ingested document, surfaced through the
 * citation pill. Matches the Java {@code ResearchDocument.SourceType}
 * enum one-to-one.
 */
export type AssistantSourceType =
  | 'VENDOR_MANUAL'
  | 'DATASHEET'
  | 'FORUM'
  | 'ACADEMIC'
  | 'CODE'
  | 'UNKNOWN';

export interface AssistantCitation {
  index: number;
  source: string;
  page: number | null;
  snippet: string;
  score: number;
  /**
   * Document class for the source this citation points at. Null on
   * legacy rows persisted before Option C #3 shipped; UI falls back
   * to UNKNOWN styling.
   */
  sourceType?: AssistantSourceType | null;
}

/**
 * Self-assessment the backend parses out of the model's trailing
 * {@code CONFIDENCE:} / {@code NEEDS_MORE_SOURCES:} footer. Arrives on
 * the {@code meta} SSE event right before {@code done}, so the UI can
 * swap a placeholder confidence pill for the real one at completion.
 */
export type AssistantConfidence = 'HIGH' | 'MEDIUM' | 'LOW';

export interface AssistantAnswerMeta {
  confidence: AssistantConfidence;
  needsMoreSources: boolean;
}

/**
 * One consistency warning produced by the backend's
 * {@code SourceCrossCheckService}. Flags a claim where two or more
 * source-type classes gave different values for the same subject.
 */
export interface ConsistencyValueSource {
  value: string;
  sourceType: string;
  citationIndex: number;
}

export interface ConsistencyWarning {
  claim: string;
  values: ConsistencyValueSource[];
  conflictingCitations: number[];
}

/**
 * Ends a visible answer buffer if the model has already started writing
 * the footer. Used on the live-streaming bubble so the user never sees
 * the raw "CONFIDENCE: HIGH" text flash before the backend's authoritative
 * parse comes back on the {@code meta} event.
 */
export function stripConfidenceFooterFromStream(text: string): string {
  if (!text) return text;
  // If we spot either tag, cut the answer off before whichever tag
  // appears first. Matching is lenient: case-insensitive, optional
  // list bullet, optional markdown emphasis.
  const pattern =
    /\n[\s>*`-]*(CONFIDENCE|NEEDS_MORE_SOURCES)\s*:/i;
  const match = text.match(pattern);
  if (!match || match.index === undefined) return text;
  return text.slice(0, match.index).replace(/\s+$/, '');
}

export interface AssistantChatOptions {
  question: string;
  history?: AssistantHistoryTurn[];
  /**
   * Optional - when set, the backend persists both sides of this turn
   * into the named thread (Research Studio "Threads" tab). Leave unset
   * for ephemeral widget conversations.
   */
  threadId?: string;
  /** Fired once with the resolved citation list before any tokens arrive. */
  onSources?: (citations: AssistantCitation[]) => void;
  /** Fired for every partial token fragment as it arrives. */
  onToken: (token: string) => void;
  /**
   * Fired once, just before {@code onDone}, with the assistant's parsed
   * self-assessment. Defaults are MEDIUM / no if the model ignored the
   * footer.
   */
  onMeta?: (meta: AssistantAnswerMeta) => void;
  /**
   * Fired with the cross-check's consistency warnings, immediately
   * before {@code onDone}. Empty array means no conflict was found.
   */
  onConsistency?: (warnings: ConsistencyWarning[]) => void;
  /** Fired once when the stream completes successfully. */
  onDone?: () => void;
  /** Fired when Ollama or the backend surfaces an error event. */
  onError?: (message: string) => void;
  /** AbortSignal so the UI can cancel a mid-flight request. */
  signal?: AbortSignal;
}

export interface AssistantHealth {
  status: 'UP' | 'DOWN';
  service: string;
  knowledgeBaseSize: number;
}

const BASE_URL = 'http://localhost:8080';

/**
 * Streams a chat answer. Resolves (void) when the stream is complete; any
 * token payload is delivered through the {@code onToken} callback.
 *
 * <p>SSE framing recap: events are delimited by blank lines; within each
 * event, lines like {@code event: <name>} and {@code data: <payload>} carry
 * the metadata. We buffer incoming bytes, split on double-newline, and
 * dispatch per-event.
 */
export async function streamChat(opts: AssistantChatOptions): Promise<void> {
  const token = localStorage.getItem('token');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'text/event-stream',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${BASE_URL}/api/assistant/chat`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      question: opts.question,
      history: opts.history ?? [],
      threadId: opts.threadId,
    }),
    signal: opts.signal,
  });

  if (!res.ok || !res.body) {
    const text = await res.text().catch(() => '');
    throw new Error(`Assistant request failed (${res.status}): ${text || res.statusText}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let buffer = '';

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    // SSE frames end with a blank line. Split them out of the buffer one
    // at a time so partial frames stay pending until we get more bytes.
    let splitIdx = buffer.indexOf('\n\n');
    while (splitIdx !== -1) {
      const frame = buffer.slice(0, splitIdx);
      buffer = buffer.slice(splitIdx + 2);
      handleFrame(frame, opts);
      splitIdx = buffer.indexOf('\n\n');
    }
  }

  // Flush any trailing frame (e.g. when server closes without a blank line).
  if (buffer.trim().length > 0) {
    handleFrame(buffer, opts);
  }
}

function handleFrame(frame: string, opts: AssistantChatOptions) {
  const lines = frame.split('\n');
  let eventName = 'message';
  const dataParts: string[] = [];

  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, '');
    if (line.startsWith(':')) continue; // comment/heartbeat
    if (line.startsWith('event:')) {
      eventName = line.slice(6).trim();
    } else if (line.startsWith('data:')) {
      // SSE spec: strip at most one leading space after the colon.
      const payload = line.slice(5);
      dataParts.push(payload.startsWith(' ') ? payload.slice(1) : payload);
    }
  }
  if (dataParts.length === 0) return;
  const data = dataParts.join('\n');

  switch (eventName) {
    case 'sources':
      if (opts.onSources) {
        try {
          const parsed = JSON.parse(data) as AssistantCitation[];
          opts.onSources(parsed);
        } catch {
          // If the server sent something we can't parse, just skip -
          // citations are a nice-to-have, never load-bearing.
        }
      }
      break;
    case 'token':
      opts.onToken(data);
      break;
    case 'meta':
      if (opts.onMeta) {
        try {
          const parsed = JSON.parse(data) as AssistantAnswerMeta;
          opts.onMeta(parsed);
        } catch {
          // Meta is best-effort; fall back to defaults on parse failure.
          opts.onMeta({ confidence: 'MEDIUM', needsMoreSources: false });
        }
      }
      break;
    case 'consistency':
      if (opts.onConsistency) {
        try {
          const parsed = JSON.parse(data) as ConsistencyWarning[];
          opts.onConsistency(Array.isArray(parsed) ? parsed : []);
        } catch {
          opts.onConsistency([]);
        }
      }
      break;
    case 'done':
      opts.onDone?.();
      break;
    case 'error':
      opts.onError?.(data);
      break;
    default:
      // Unknown events are ignored - lets us add new event types server-side
      // without breaking older clients.
      break;
  }
}

export async function getAssistantHealth(): Promise<AssistantHealth> {
  const token = localStorage.getItem('token');
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE_URL}/api/assistant/health`, { headers });
  if (!res.ok) throw new Error(`Health check failed (${res.status})`);
  return (await res.json()) as AssistantHealth;
}

export default { streamChat, getAssistantHealth };
