import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Icon, theme } from './theme';
import {
  streamChat,
  getAssistantHealth,
  AssistantHealth,
  AssistantHistoryTurn,
  AssistantCitation,
  AssistantAnswerMeta,
  AssistantConfidence,
  stripConfidenceFooterFromStream,
} from '../services/assistantService';

/**
 * OTShield Copilot — a floating chat assistant that sits in the bottom
 * right corner of every authenticated page. Streaming answers come from
 * the local Ollama-backed backend at `/api/assistant/chat`.
 *
 * Design goals:
 *  - Match the violet/fuchsia/pink language used across the app
 *    (uses `theme.gradients` + the shared Icon set, no external icon libs).
 *  - Stay out of the way: collapsed to a ~56px bubble, expands to a
 *    ~380×520 panel on click.
 *  - Show liveness clearly (typing dots, streaming tokens appear as they
 *    arrive, backend health ping on mount).
 *  - Survive backend failures gracefully — a red banner tells the user
 *    the assistant is offline instead of leaving them staring at a spinner.
 */
const AssistantWidget: React.FC = () => {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState('');
  const [turns, setTurns] = useState<AssistantHistoryTurn[]>([]);
  const [streaming, setStreaming] = useState(false);
  const [pendingAnswer, setPendingAnswer] = useState('');
  const [pendingCitations, setPendingCitations] = useState<AssistantCitation[]>([]);
  const [pendingMeta, setPendingMeta] = useState<AssistantAnswerMeta | null>(null);
  // Citations for each completed assistant turn, keyed by turn index.
  // Stored out-of-band from `turns` so we don't have to mirror the history
  // shape the backend expects (role/content only).
  const [turnCitations, setTurnCitations] = useState<Record<number, AssistantCitation[]>>({});
  const [turnMeta, setTurnMeta] = useState<Record<number, AssistantAnswerMeta>>({});
  const [health, setHealth] = useState<AssistantHealth | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Ping health once on mount so we can flag "assistant unavailable" before
  // the user types a question and hits a confusing SSE failure.
  useEffect(() => {
    let alive = true;
    getAssistantHealth()
      .then((h) => {
        if (alive) setHealth(h);
      })
      .catch((e) => {
        if (alive) setHealthError(e?.message ?? 'Assistant health check failed');
      });
    return () => {
      alive = false;
    };
  }, []);

  // Scroll the transcript as tokens stream in.
  useEffect(() => {
    if (!scrollRef.current) return;
    scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [turns, pendingAnswer, open]);

  // Cancel any in-flight request when the widget unmounts.
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  const canSend = useMemo(
    () => input.trim().length > 0 && !streaming,
    [input, streaming]
  );

  const send = useCallback(async () => {
    const question = input.trim();
    if (!question || streaming) return;

    setInput('');
    setError(null);
    setStreaming(true);
    setPendingAnswer('');
    setPendingCitations([]);
    setPendingMeta(null);
    const historySnapshot = [...turns, { role: 'user' as const, content: question }];
    setTurns(historySnapshot);

    const controller = new AbortController();
    abortRef.current = controller;

    let accumulated = '';
    let citations: AssistantCitation[] = [];
    let meta: AssistantAnswerMeta | null = null;
    try {
      await streamChat({
        question,
        history: turns, // send prior turns as context (not the new user turn)
        signal: controller.signal,
        onSources: (cites) => {
          citations = cites;
          setPendingCitations(cites);
        },
        onToken: (tok) => {
          accumulated += tok;
          setPendingAnswer(accumulated);
        },
        onMeta: (m) => {
          meta = m;
          setPendingMeta(m);
        },
        onError: (msg) => {
          setError(msg || 'Assistant could not generate a response');
        },
      });
      // Strip the machine-readable footer so persisted history doesn't
      // contain "CONFIDENCE: HIGH" trailing text. Falls through to the
      // raw text if the model skipped the footer entirely.
      const visible = stripConfidenceFooterFromStream(accumulated);
      if (visible.length > 0) {
        const newTurns = [...historySnapshot, { role: 'assistant' as const, content: visible }];
        setTurns(newTurns);
        // Index of the assistant turn we just committed.
        const answerIndex = newTurns.length - 1;
        setTurnCitations((prev) => ({ ...prev, [answerIndex]: citations }));
        if (meta) {
          setTurnMeta((prev) => ({ ...prev, [answerIndex]: meta! }));
        }
      }
    } catch (e: any) {
      if (e?.name === 'AbortError') {
        // user cancelled - keep whatever we had so far
        const visible = stripConfidenceFooterFromStream(accumulated);
        if (visible.length > 0) {
          const newTurns = [...historySnapshot, { role: 'assistant' as const, content: visible }];
          setTurns(newTurns);
          const answerIndex = newTurns.length - 1;
          setTurnCitations((prev) => ({ ...prev, [answerIndex]: citations }));
          if (meta) {
            setTurnMeta((prev) => ({ ...prev, [answerIndex]: meta! }));
          }
        }
      } else {
        setError(e?.message ?? 'Request failed');
      }
    } finally {
      setPendingAnswer('');
      setPendingCitations([]);
      setPendingMeta(null);
      setStreaming(false);
      abortRef.current = null;
    }
  }, [input, streaming, turns]);

  const cancel = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  const clearConversation = useCallback(() => {
    if (streaming) return;
    setTurns([]);
    setTurnCitations({});
    setTurnMeta({});
    setError(null);
  }, [streaming]);

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (canSend) send();
    }
  };

  const offline = Boolean(healthError) || health?.status === 'DOWN';

  return (
    <>
      {/* Keyframes for the ambient pulse on the launcher */}
      <style>{`
        @keyframes ot-assistant-halo {
          0%, 100% { box-shadow: 0 0 0 0 rgba(168, 85, 247, 0.55), 0 12px 32px -8px rgba(124, 58, 237, 0.5); }
          50% { box-shadow: 0 0 0 14px rgba(168, 85, 247, 0), 0 12px 32px -8px rgba(236, 72, 153, 0.55); }
        }
        @keyframes ot-typing-dot {
          0%, 80%, 100% { transform: translateY(0); opacity: 0.4; }
          40% { transform: translateY(-4px); opacity: 1; }
        }
      `}</style>

      {/* Launcher */}
      <AnimatePresence>
        {!open && (
          <motion.button
            key="launcher"
            type="button"
            onClick={() => setOpen(true)}
            initial={{ opacity: 0, scale: 0.6, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.6, y: 20 }}
            transition={{ type: 'spring', stiffness: 260, damping: 22 }}
            aria-label="Open OTShield Copilot"
            className="fixed bottom-6 right-6 z-50 w-14 h-14 rounded-full flex items-center justify-center text-white"
            style={{
              background:
                'linear-gradient(135deg, #7c3aed 0%, #d946ef 55%, #ec4899 100%)',
              animation: 'ot-assistant-halo 2.6s ease-in-out infinite',
            }}
          >
            <Icon.Brain className="w-7 h-7" />
            <span className="sr-only">Open assistant</span>
          </motion.button>
        )}
      </AnimatePresence>

      {/* Panel */}
      <AnimatePresence>
        {open && (
          <motion.div
            key="panel"
            initial={{ opacity: 0, y: 24, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 24, scale: 0.96 }}
            transition={{ type: 'spring', stiffness: 240, damping: 24 }}
            className="fixed bottom-6 right-6 z-50 w-[92vw] sm:w-[380px] h-[540px] max-h-[80vh] rounded-2xl overflow-hidden flex flex-col border border-violet-200/70 shadow-2xl shadow-violet-900/20 bg-white/95 backdrop-blur-xl"
          >
            {/* Header */}
            <div
              className="relative px-4 py-3 text-white"
              style={{ background: theme.gradients.hero }}
            >
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-white/15 border border-white/25 flex items-center justify-center">
                  <Icon.Brain className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-semibold leading-tight">
                    OTShield Copilot
                  </div>
                  <div className="text-[11px] text-violet-100/90 flex items-center gap-1.5">
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        offline ? 'bg-rose-400' : 'bg-emerald-400'
                      }`}
                    />
                    {offline
                      ? 'Assistant offline'
                      : health
                      ? `Ready · ${health.knowledgeBaseSize} knowledge chunks`
                      : 'Connecting...'}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={clearConversation}
                  disabled={streaming || turns.length === 0}
                  className="text-[11px] px-2 py-1 rounded-md bg-white/10 hover:bg-white/20 disabled:opacity-40 transition"
                  title="Clear conversation"
                >
                  Clear
                </button>
                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  className="w-8 h-8 rounded-lg hover:bg-white/15 flex items-center justify-center transition"
                  aria-label="Close"
                >
                  <svg
                    viewBox="0 0 24 24"
                    className="w-4 h-4"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                </button>
              </div>
            </div>

            {/* Transcript */}
            <div
              ref={scrollRef}
              className="flex-1 overflow-y-auto px-4 py-4 space-y-3 text-sm"
              style={{
                background:
                  'linear-gradient(180deg, rgba(250,245,255,0.8) 0%, rgba(255,250,252,0.9) 100%)',
              }}
            >
              {turns.length === 0 && !pendingAnswer && (
                <EmptyState offline={offline} />
              )}

              {turns.map((t, i) => (
                <Bubble
                  key={i}
                  role={t.role}
                  text={t.content}
                  citations={t.role === 'assistant' ? turnCitations[i] : undefined}
                  meta={t.role === 'assistant' ? turnMeta[i] : undefined}
                />
              ))}

              {pendingAnswer && (
                <Bubble
                  role="assistant"
                  text={stripConfidenceFooterFromStream(pendingAnswer)}
                  streaming
                  citations={pendingCitations}
                  meta={pendingMeta ?? undefined}
                />
              )}
              {streaming && !pendingAnswer && pendingCitations.length > 0 && (
                <div className="flex justify-start">
                  <div className="max-w-[82%] space-y-2">
                    <TypingIndicator />
                    <SourceList citations={pendingCitations} />
                  </div>
                </div>
              )}
              {streaming && !pendingAnswer && pendingCitations.length === 0 && (
                <TypingIndicator />
              )}

              {error && (
                <div className="rounded-lg bg-rose-50 border border-rose-200 px-3 py-2 text-xs text-rose-700">
                  <div className="flex items-start gap-2">
                    <Icon.Alert className="w-4 h-4 mt-0.5 flex-shrink-0" />
                    <span>{error}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Input */}
            <div className="border-t border-violet-100 bg-white/90 p-3">
              <div className="relative rounded-xl border border-violet-200 focus-within:border-violet-400 focus-within:ring-2 focus-within:ring-violet-200 bg-white transition">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={onKeyDown}
                  placeholder={
                    offline
                      ? 'Assistant is currently offline'
                      : streaming
                      ? 'Generating response...'
                      : 'Ask anything about OTShield...'
                  }
                  rows={2}
                  disabled={offline}
                  className="w-full resize-none bg-transparent px-3 py-2 pr-11 text-sm leading-relaxed text-slate-800 placeholder:text-slate-400 focus:outline-none disabled:opacity-60"
                />
                <button
                  type="button"
                  onClick={streaming ? cancel : send}
                  disabled={!streaming && (!canSend || offline)}
                  className="absolute bottom-2 right-2 w-8 h-8 rounded-lg flex items-center justify-center text-white disabled:opacity-40 transition hover:shadow-lg hover:shadow-violet-500/30"
                  style={{
                    background: streaming
                      ? 'linear-gradient(135deg, #f43f5e, #ec4899)'
                      : 'linear-gradient(135deg, #7c3aed, #ec4899)',
                  }}
                  aria-label={streaming ? 'Stop' : 'Send'}
                >
                  {streaming ? (
                    <svg
                      viewBox="0 0 24 24"
                      className="w-3.5 h-3.5"
                      fill="currentColor"
                    >
                      <rect x="6" y="6" width="12" height="12" rx="1.5" />
                    </svg>
                  ) : (
                    <svg
                      viewBox="0 0 24 24"
                      className="w-4 h-4"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <line x1="22" y1="2" x2="11" y2="13" />
                      <polygon points="22 2 15 22 11 13 2 9 22 2" />
                    </svg>
                  )}
                </button>
              </div>
              <div className="mt-1.5 flex items-center justify-between text-[10px] text-slate-400">
                <span>Enter to send · Shift+Enter for newline</span>
                <span className="flex items-center gap-1">
                  <Icon.Lock className="w-3 h-3" />
                  Local LLM
                </span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};

/* ---------- Sub-components ---------- */

const EmptyState: React.FC<{ offline: boolean }> = ({ offline }) => (
  <div className="flex flex-col items-center text-center px-2 pt-6 pb-2">
    <div
      className="w-14 h-14 rounded-2xl flex items-center justify-center text-white mb-3"
      style={{
        background:
          'linear-gradient(135deg, #7c3aed 0%, #d946ef 60%, #ec4899 100%)',
        boxShadow: '0 16px 32px -12px rgba(124, 58, 237, 0.45)',
      }}
    >
      <Icon.Brain className="w-7 h-7" />
    </div>
    <div className={`text-sm font-semibold ${theme.gradients.primaryText}`}>
      OTShield Copilot
    </div>
    <p className="mt-1 text-xs text-slate-500 max-w-[260px]">
      {offline
        ? 'Local LLM is unavailable. Make sure the Ollama service is running and reopen the panel.'
        : 'Deception, honeypots, Modbus/S7, case management — what would you like explained?'}
    </p>
    {!offline && (
      <div className="mt-3 flex flex-wrap gap-2 justify-center">
        <Chip text="What is a fake HMI?" />
        <Chip text="Rare Modbus commands" />
        <Chip text="Case lifecycle" />
      </div>
    )}
  </div>
);

const Chip: React.FC<{ text: string }> = ({ text }) => (
  <span
    className="px-2.5 py-1 rounded-full text-[11px] text-violet-700 bg-violet-50 border border-violet-200"
  >
    {text}
  </span>
);

const Bubble: React.FC<{
  role: 'user' | 'assistant';
  text: string;
  streaming?: boolean;
  citations?: AssistantCitation[];
  meta?: AssistantAnswerMeta;
}> = ({ role, text, streaming, citations, meta }) => {
  const isUser = role === 'user';
  const hasCitations = !isUser && citations && citations.length > 0;
  const showMeta = !isUser && !!meta;
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18 }}
      className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}
    >
      <div className={`max-w-[82%] space-y-2 ${isUser ? '' : ''}`}>
        {showMeta && (
          <WidgetConfidencePill
            confidence={meta!.confidence}
            needsMoreSources={meta!.needsMoreSources}
          />
        )}
        <div
          className={`rounded-2xl px-3.5 py-2 text-sm leading-relaxed whitespace-pre-wrap break-words ${
            isUser
              ? 'text-white rounded-br-sm'
              : 'bg-white border border-violet-100 text-slate-800 rounded-bl-sm shadow-sm'
          }`}
          style={
            isUser
              ? {
                  background:
                    'linear-gradient(135deg, #7c3aed 0%, #d946ef 60%, #ec4899 100%)',
                }
              : undefined
          }
        >
          {text}
          {streaming && (
            <span
              className="inline-block w-1.5 h-3 ml-0.5 align-[-2px] bg-violet-500"
              style={{ animation: 'ot-typing-dot 1.2s ease-in-out infinite' }}
            />
          )}
        </div>
        {hasCitations && <SourceList citations={citations!} />}
      </div>
    </motion.div>
  );
};

/**
 * Compact confidence chip for the floating widget. Mirrors the larger
 * ConfidencePill used by ThreadsTab but sized for the 380px panel - we
 * keep the same semantic ramp (emerald / amber / rose) so the visual
 * language is identical wherever the copilot speaks.
 */
const WidgetConfidencePill: React.FC<{
  confidence: AssistantConfidence;
  needsMoreSources: boolean;
}> = ({ confidence, needsMoreSources }) => {
  const style = confidence === 'HIGH'
    ? { text: 'text-emerald-700', bg: 'bg-emerald-50', ring: 'ring-emerald-200', dot: 'bg-emerald-500' }
    : confidence === 'MEDIUM'
      ? { text: 'text-amber-700', bg: 'bg-amber-50', ring: 'ring-amber-200', dot: 'bg-amber-500' }
      : { text: 'text-rose-700', bg: 'bg-rose-50', ring: 'ring-rose-200', dot: 'bg-rose-500' };
  const label = confidence === 'HIGH' ? 'High' : confidence === 'MEDIUM' ? 'Medium' : 'Low';
  return (
    <div className="flex flex-wrap items-center gap-1">
      <span
        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider ring-1 ${style.bg} ${style.text} ${style.ring}`}
        title="Assistant self-assessment based on the attached sources."
      >
        <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
        {label} confidence
      </span>
      {needsMoreSources && (
        <span
          className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider ring-1 bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200"
          title="The assistant flagged this answer as needing more sources."
        >
          More sources needed
        </span>
      )}
    </div>
  );
};

/**
 * Renders the list of retrieved knowledge-base passages below an
 * assistant bubble. Each pill shows the {@code [n]} marker the model
 * was instructed to use, the source filename, and the page number (if
 * the source was a PDF). Hovering a pill reveals the full snippet
 * so the analyst can sanity-check the grounding without clicking
 * through to the Library.
 */
const SourceList: React.FC<{ citations: AssistantCitation[] }> = ({ citations }) => (
  <div className="flex flex-col gap-1">
    <div className="text-[10px] font-semibold uppercase tracking-wider text-violet-500/80 px-1">
      Sources · {citations.length}
    </div>
    <div className="flex flex-wrap gap-1.5">
      {citations.map((c) => (
        <span
          key={c.index}
          title={c.snippet}
          className="inline-flex items-center gap-1.5 max-w-full px-2 py-1 rounded-full text-[11px] font-medium text-violet-700 bg-violet-50 border border-violet-200 hover:bg-violet-100 transition cursor-help"
        >
          <span className="inline-flex items-center justify-center w-4 h-4 rounded-full bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white text-[9px] font-bold">
            {c.index}
          </span>
          <span className="truncate max-w-[160px]">{c.source}</span>
          {c.page != null && (
            <span className="text-violet-400">· p.{c.page}</span>
          )}
          {c.sourceType && c.sourceType !== 'UNKNOWN' && (
            <SourceTypeBadge type={c.sourceType} />
          )}
        </span>
      ))}
    </div>
  </div>
);

/**
 * Small coloured chip that sits inside a citation pill to convey
 * "where did this come from" at a glance. Colour ramp is deliberate:
 * greens / blues for high-trust (vendor manual, datasheet), ambers
 * for middling (academic), rose for forum, slate for code.
 */
const SOURCE_TYPE_STYLE: Record<string, { label: string; cls: string }> = {
  VENDOR_MANUAL: { label: 'Manual',   cls: 'bg-emerald-100 text-emerald-800' },
  DATASHEET:     { label: 'Datasheet',cls: 'bg-sky-100 text-sky-800' },
  ACADEMIC:      { label: 'Academic', cls: 'bg-amber-100 text-amber-800' },
  FORUM:         { label: 'Forum',    cls: 'bg-rose-100 text-rose-800' },
  CODE:          { label: 'Code',     cls: 'bg-slate-200 text-slate-700' },
  UNKNOWN:       { label: '?',        cls: 'bg-slate-100 text-slate-500' },
};
const SourceTypeBadge: React.FC<{ type: string }> = ({ type }) => {
  const meta = SOURCE_TYPE_STYLE[type] ?? SOURCE_TYPE_STYLE.UNKNOWN;
  return (
    <span
      className={`inline-flex items-center px-1.5 py-0 rounded text-[9px] font-semibold uppercase tracking-wider ${meta.cls}`}
      title={`Source type: ${type.replace('_', ' ')}`}
    >
      {meta.label}
    </span>
  );
};

const TypingIndicator: React.FC = () => (
  <div className="flex items-center gap-1.5 text-slate-400 text-xs px-1">
    <div className="flex gap-1">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="w-1.5 h-1.5 rounded-full bg-violet-400"
          style={{
            animation: 'ot-typing-dot 1.2s ease-in-out infinite',
            animationDelay: `${i * 0.15}s`,
          }}
        />
      ))}
    </div>
    <span>Thinking...</span>
  </div>
);

export default AssistantWidget;
