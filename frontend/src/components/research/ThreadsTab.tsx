import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Panel, Icon, pageItem, theme } from '../theme';
import {
  ResearchThread,
  ResearchMessage,
  listThreads,
  listMessages,
  createThread,
  renameThread,
  deleteThread,
} from '../../services/threadService';
import { promoteMessage } from '../../services/findingService';
import {
  promoteVuln,
  VulnComponentType,
  VulnSeverity,
  VulnConfidence,
} from '../../services/vulnService';
import {
  streamChat,
  AssistantCitation,
  AssistantAnswerMeta,
  AssistantConfidence,
  ConsistencyWarning,
  stripConfidenceFooterFromStream,
} from '../../services/assistantService';
import {
  generateAlternatives,
  AlternativeTheory,
} from '../../services/alternativesService';
import {
  translateText,
  TargetLanguage,
  LANG_LABELS,
} from '../../services/translationService';
import { fetchFollowUps } from '../../services/followUpService';
import {
  ResearchAnnotation,
  AnnotationKind,
  listAnnotationsForTarget,
  createAnnotation,
  deleteAnnotation,
} from '../../services/annotationService';
import { useBundles } from '../../contexts/BundleContext';

/* ---------------------------------------------------------------------------
 * Research Studio - Threads tab
 *
 * Left rail: list of persistent conversations, newest-updated first.
 * Right pane: messages for the selected thread, with a compose box that
 * streams the assistant response and auto-persists the turn into the
 * thread (the backend handles the actual write when we pass threadId).
 *
 * Each assistant message carries its citations and a "Promote to
 * finding" button that snapshots the turn into the curated ledger on
 * the Findings tab.
 * ------------------------------------------------------------------------ */

const formatRelative = (iso: string | null): string => {
  if (!iso) return '-';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '-';
  const diff = (Date.now() - t) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
};

/* ------------------------------------------------------------------
 * ConfidencePill
 *
 * Small coloured chip the assistant stamps on its own replies. The
 * colour ramp is semantic (emerald→amber→rose) so it reads the same
 * way as alert severity: green means "trust this", amber means "verify
 * before quoting", rose means "treat as a starting point". The
 * NeedsMoreSourcesChip sits next to it when the model explicitly asked
 * the analyst for more documents.
 *
 * Rendered only for assistant bubbles that actually carry a parsed
 * confidence value - we don't guess on legacy rows written before the
 * footer existed.
 * ---------------------------------------------------------------- */
interface ConfidencePillProps {
  confidence: AssistantConfidence;
  needsMoreSources?: boolean | null;
}
const ConfidencePill: React.FC<ConfidencePillProps> = ({ confidence, needsMoreSources }) => {
  const base = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider ring-1';
  const style = confidence === 'HIGH'
    ? 'bg-emerald-50 text-emerald-700 ring-emerald-200'
    : confidence === 'MEDIUM'
      ? 'bg-amber-50 text-amber-700 ring-amber-200'
      : 'bg-rose-50 text-rose-700 ring-rose-200';
  const label = confidence === 'HIGH'
    ? 'High confidence'
    : confidence === 'MEDIUM'
      ? 'Medium confidence'
      : 'Low confidence';
  return (
    <div className="flex flex-wrap items-center gap-1">
      <span className={`${base} ${style}`} title="The assistant's self-assessment based on the attached sources.">
        <span className={`w-1.5 h-1.5 rounded-full ${
          confidence === 'HIGH' ? 'bg-emerald-500' :
          confidence === 'MEDIUM' ? 'bg-amber-500' : 'bg-rose-500'
        }`} />
        {label}
      </span>
      {needsMoreSources && (
        <span
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider ring-1 bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200"
          title="The assistant flagged this answer as needing additional sources before acting on it."
        >
          More sources needed
        </span>
      )}
    </div>
  );
};

/* ------------------------------------------------------------------
 * SourceTypeBadge
 *
 * Tiny inline chip inside a citation row that says where the cited
 * passage came from (Manual / Datasheet / Forum / Academic / Code).
 * We keep the colour choices close to the confidence ramp semantics:
 * emerald for high-trust vendor material, sky for datasheets,
 * amber for peer-reviewed but age-prone academic work, rose for
 * forum/informal, slate for raw code. UNKNOWN is suppressed by
 * the caller so it doesn't add noise to citations that predate the
 * Option C #3 classifier.
 * ---------------------------------------------------------------- */
const SOURCE_TYPE_STYLE: Record<string, { label: string; cls: string }> = {
  VENDOR_MANUAL: { label: 'Manual',    cls: 'bg-emerald-100 text-emerald-800' },
  DATASHEET:     { label: 'Datasheet', cls: 'bg-sky-100 text-sky-800' },
  ACADEMIC:      { label: 'Academic',  cls: 'bg-amber-100 text-amber-800' },
  FORUM:         { label: 'Forum',     cls: 'bg-rose-100 text-rose-800' },
  CODE:          { label: 'Code',      cls: 'bg-slate-200 text-slate-700' },
  UNKNOWN:       { label: '?',         cls: 'bg-slate-100 text-slate-500' },
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

/* ------------------------------------------------------------------
 * NotesPanel
 *
 * Sticky-note composer + note list for one assistant message. Four
 * kinds render with their own accent colour so researchers can spot
 * the flavour at a glance without reading the body. We deliberately
 * keep the composer dead simple: a textarea, a kind dropdown, and a
 * single save button. No tag field on the initial version; the
 * backend supports it but it's noise in the default UI.
 * ---------------------------------------------------------------- */
const ANNOTATION_KIND_STYLE: Record<AnnotationKind, { label: string; row: string; dot: string }> = {
  NOTE:      { label: 'Note',      row: 'bg-slate-50 ring-slate-200',   dot: 'bg-slate-400' },
  HIGHLIGHT: { label: 'Highlight', row: 'bg-amber-50 ring-amber-200',   dot: 'bg-amber-400' },
  FLAG:      { label: 'Flag',      row: 'bg-rose-50 ring-rose-200',     dot: 'bg-rose-500' },
  VERIFIED:  { label: 'Verified',  row: 'bg-emerald-50 ring-emerald-200', dot: 'bg-emerald-500' },
};

interface NotesPanelProps {
  annotations?: ResearchAnnotation[];
  onSave: (body: string, kind: AnnotationKind) => Promise<void> | void;
  onDelete: (id: string) => Promise<void> | void;
}
const NotesPanel: React.FC<NotesPanelProps> = ({ annotations, onSave, onDelete }) => {
  const [body, setBody] = useState('');
  const [kind, setKind] = useState<AnnotationKind>('NOTE');
  const [saving, setSaving] = useState(false);
  const list = annotations ?? [];
  const submit = async () => {
    if (!body.trim() || saving) return;
    setSaving(true);
    try {
      await onSave(body, kind);
      setBody('');
    } finally {
      setSaving(false);
    }
  };
  return (
    <div className="mt-3 pt-3 border-t border-slate-200 space-y-2">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
        Researcher notes · {list.length}
      </div>
      {list.length > 0 && (
        <div className="space-y-1.5">
          {list.map((a) => {
            const style = ANNOTATION_KIND_STYLE[a.kind] ?? ANNOTATION_KIND_STYLE.NOTE;
            return (
              <div
                key={a.id}
                className={`rounded-lg p-2 text-[12px] ring-1 ${style.row} flex items-start gap-2`}
              >
                <span className={`flex-shrink-0 w-1.5 h-1.5 rounded-full mt-1.5 ${style.dot}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider text-slate-500">
                    <span className="font-semibold">{style.label}</span>
                    {a.author && <span>· {a.author}</span>}
                  </div>
                  <div className="mt-0.5 whitespace-pre-wrap text-slate-800">{a.body}</div>
                </div>
                <button
                  type="button"
                  onClick={() => void onDelete(a.id)}
                  className="text-[10px] text-slate-400 hover:text-rose-600 transition"
                  title="Delete note"
                >
                  ✕
                </button>
              </div>
            );
          })}
        </div>
      )}
      <div className="flex gap-2 items-start">
        <select
          value={kind}
          onChange={(e) => setKind(e.target.value as AnnotationKind)}
          className="text-[11px] bg-white ring-1 ring-slate-200 rounded-md px-1.5 py-1 text-slate-700 focus:ring-violet-300 focus:outline-none"
          aria-label="Annotation kind"
        >
          <option value="NOTE">Note</option>
          <option value="HIGHLIGHT">Highlight</option>
          <option value="FLAG">Flag</option>
          <option value="VERIFIED">Verified</option>
        </select>
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          rows={1}
          placeholder="Add a note…"
          className="flex-1 text-[12px] bg-white ring-1 ring-slate-200 rounded-md px-2 py-1 focus:ring-violet-300 focus:outline-none resize-none"
        />
        <button
          type="button"
          onClick={() => void submit()}
          disabled={!body.trim() || saving}
          className="text-[11px] font-semibold text-white px-3 py-1 rounded-md bg-gradient-to-r from-violet-500 to-fuchsia-500 disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
      </div>
    </div>
  );
};

/* ------------------------------------------------------------------
 * FollowUpChips
 *
 * Rail of 3 chip-style buttons under an assistant bubble. Each chip
 * is a suggested next question; clicking prefills the compose box
 * instead of sending straight away - researchers often tweak the
 * phrasing first and we'd rather not surprise them with a network
 * call. Rendered only when suggestions are actually present; the
 * surrounding code never calls this with an empty list.
 * ---------------------------------------------------------------- */
interface FollowUpChipsProps {
  suggestions: string[];
  onPick: (question: string) => void;
}
const FollowUpChips: React.FC<FollowUpChipsProps> = ({ suggestions, onPick }) => (
  <div className="mt-3 pt-3 border-t border-violet-100 space-y-1.5">
    <div className="text-[10px] font-semibold uppercase tracking-wider text-violet-500">
      Follow-up suggestions
    </div>
    <div className="flex flex-wrap gap-1.5">
      {suggestions.map((s, i) => (
        <button
          key={i}
          type="button"
          onClick={() => onPick(s)}
          className="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-medium text-violet-700 bg-violet-50 ring-1 ring-violet-200 hover:bg-violet-100 transition text-left max-w-full"
          title="Insert into the compose box"
        >
          <span className="truncate max-w-[360px]">{s}</span>
        </button>
      ))}
    </div>
  </div>
);

/* ------------------------------------------------------------------
 * ConsistencyCard
 *
 * Amber warning card rendered under an assistant bubble when the
 * source cross-check flagged a claim where two or more source types
 * disagreed. Each value chip shows the source type + value; the
 * "conflicting citations" list below lets the researcher jump to
 * the passage (by index) that voiced each side.
 *
 * When the check ran but found nothing, the whole card is hidden -
 * we don't want to clutter the bubble with a "no conflicts" state
 * that the researcher has to dismiss. Legacy rows (consistency
 * null) are treated the same way.
 * ---------------------------------------------------------------- */
interface ConsistencyCardProps {
  warnings: ConsistencyWarning[];
}
const ConsistencyCard: React.FC<ConsistencyCardProps> = ({ warnings }) => {
  if (!warnings || warnings.length === 0) return null;
  return (
    <div className="mt-3 pt-3 border-t border-amber-200/60 space-y-2">
      <div className="flex items-start gap-2">
        <span className="flex-shrink-0 w-5 h-5 rounded-full bg-amber-100 ring-1 ring-amber-300 flex items-center justify-center text-amber-700 text-[11px] font-bold">
          !
        </span>
        <div className="min-w-0">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-amber-700">
            Source consistency check · {warnings.length} conflict{warnings.length === 1 ? '' : 's'}
          </div>
          <div className="text-[11px] text-amber-700/80">
            Sources of different types gave different answers. Verify with the cited passages before acting.
          </div>
        </div>
      </div>
      <div className="space-y-2">
        {warnings.map((w, i) => (
          <div
            key={i}
            className="rounded-xl bg-amber-50 ring-1 ring-amber-200 p-3 text-[12px] leading-relaxed"
          >
            <div className="font-semibold text-amber-900">{w.claim}</div>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {w.values.map((v, vi) => (
                <span
                  key={vi}
                  className="inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-[11px] bg-white ring-1 ring-amber-200"
                  title={`Cited as [${v.citationIndex}]`}
                >
                  <SourceTypeBadge type={v.sourceType} />
                  <span className="font-semibold text-slate-800">{v.value}</span>
                  <span className="text-slate-400">[{v.citationIndex}]</span>
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

/* ------------------------------------------------------------------
 * AlternativesList
 *
 * Collapsible block of 2-3 contrarian hypotheses. Sits between the
 * primary answer and the action-button row so researchers see them
 * without scrolling past the source list. Each alternative reuses the
 * same ConfidencePill so the visual language matches the primary
 * answer's ramp.
 * ---------------------------------------------------------------- */
interface AlternativesListProps {
  alternatives: AlternativeTheory[];
}
const AlternativesList: React.FC<AlternativesListProps> = ({ alternatives }) => {
  if (!alternatives || alternatives.length === 0) return null;
  return (
    <div className="mt-3 pt-3 border-t border-slate-200 space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-fuchsia-600">
          Alternative theories · {alternatives.length}
        </span>
        <span className="text-[10px] text-slate-400">
          Contrarian review - treat as hypotheses, not answers.
        </span>
      </div>
      <ol className="space-y-2">
        {alternatives.map((a) => (
          <li
            key={a.index}
            className="rounded-xl bg-white ring-1 ring-slate-200 p-3 text-[12px] leading-relaxed"
          >
            <div className="flex items-start gap-2">
              <span className="flex-shrink-0 w-5 h-5 rounded-full text-[10px] font-bold text-white flex items-center justify-center bg-gradient-to-br from-fuchsia-500 to-rose-500">
                {a.index}
              </span>
              <div className="min-w-0 flex-1 space-y-1">
                <div className="font-semibold text-slate-900">{a.hypothesis}</div>
                {a.rationale && (
                  <div className="text-slate-600">
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mr-1">
                      Why:
                    </span>
                    {a.rationale}
                  </div>
                )}
                <ConfidencePill confidence={a.confidence} />
              </div>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
};

const ThreadsTab: React.FC = () => {
  const [threads, setThreads] = useState<ResearchThread[]>([]);
  const [loadingThreads, setLoadingThreads] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ResearchMessage[]>([]);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [question, setQuestion] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [liveAnswer, setLiveAnswer] = useState('');
  const [liveCitations, setLiveCitations] = useState<AssistantCitation[]>([]);
  const [liveMeta, setLiveMeta] = useState<AssistantAnswerMeta | null>(null);
  // Consistency warnings coming in on the `consistency` SSE event.
  // Shown under the streaming bubble until the final refresh replaces
  // the optimistic row with the canonical one.
  const [liveConsistency, setLiveConsistency] = useState<ConsistencyWarning[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The message currently being promoted into a Vulnerability Observation.
  // Null means the modal is closed.
  const [promotingVuln, setPromotingVuln] = useState<ResearchMessage | null>(null);
  // Which message id is currently waiting for alternatives to come back.
  // Used to gate the button + swap its label for a spinner.
  const [alternativesLoading, setAlternativesLoading] = useState<string | null>(null);
  // Per-message override map: once alternatives come back for a message
  // we stash them here so the UI re-renders immediately without a
  // server round-trip. Persisted values still come from the refresh on
  // the next transcript fetch; this map is just the optimistic lens.
  const [alternativesByMessage, setAlternativesByMessage] = useState<Record<string, AlternativeTheory[]>>({});
  // Translations per message id: if an entry is present the bubble
  // renders its translated body; removing the entry reverts to the
  // original content. `translatingId` gates the button while the POST
  // is in flight so the same message can't be double-submitted.
  const [translationsByMessage, setTranslationsByMessage] = useState<Record<string, { lang: TargetLanguage; text: string }>>({});
  const [translatingId, setTranslatingId] = useState<string | null>(null);
  // Remember the user's preferred target language between sessions.
  // Default EN so the first-time visitor doesn't see a translation
  // button that does nothing visible.
  const [preferredLang, setPreferredLangState] = useState<TargetLanguage>(() => {
    if (typeof window === 'undefined') return 'EN';
    const stored = window.localStorage.getItem('otshield.research.lang');
    if (stored && stored in LANG_LABELS) return stored as TargetLanguage;
    return 'EN';
  });
  const setPreferredLang = useCallback((lang: TargetLanguage) => {
    setPreferredLangState(lang);
    try { window.localStorage.setItem('otshield.research.lang', lang); } catch { /* ignore */ }
  }, []);
  // Follow-up suggestions per message id. Populated on demand when the
  // researcher clicks "Show follow-ups" - we don't auto-fire it on
  // every assistant turn because it costs another Ollama call.
  const [followUpsByMessage, setFollowUpsByMessage] = useState<Record<string, string[]>>({});
  const [followUpsLoadingId, setFollowUpsLoadingId] = useState<string | null>(null);
  // Annotations per message id. Lazily fetched when the researcher
  // opens the composer; we don't batch-load on transcript open so a
  // thread with 50 turns doesn't fire 50 GETs up front.
  const [annotationsByMessage, setAnnotationsByMessage] = useState<Record<string, ResearchAnnotation[]>>({});
  const [openComposerId, setOpenComposerId] = useState<string | null>(null);
  const { activeBundleId } = useBundles();
  const abortRef = useRef<AbortController | null>(null);

  const refreshThreads = useCallback(async () => {
    try {
      const rows = await listThreads();
      setThreads(rows);
      if (!selectedId && rows.length > 0) {
        setSelectedId(rows[0].id);
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to load threads';
      setError(msg);
    } finally {
      setLoadingThreads(false);
    }
  }, [selectedId]);

  const refreshMessages = useCallback(async (threadId: string) => {
    setLoadingMessages(true);
    try {
      const rows = await listMessages(threadId);
      setMessages(rows);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to load messages';
      setError(msg);
    } finally {
      setLoadingMessages(false);
    }
  }, []);

  useEffect(() => { void refreshThreads(); }, [refreshThreads]);

  useEffect(() => {
    if (selectedId) void refreshMessages(selectedId);
    else setMessages([]);
  }, [selectedId, refreshMessages]);

  const handleNewThread = async () => {
    try {
      const thread = await createThread();
      await refreshThreads();
      setSelectedId(thread.id);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Could not create thread';
      setError(msg);
    }
  };

  const handleRename = async (t: ResearchThread) => {
    const title = window.prompt('Rename thread', t.title);
    if (!title || title.trim() === t.title) return;
    try {
      await renameThread(t.id, title.trim());
      await refreshThreads();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Rename failed';
      setError(msg);
    }
  };

  const handleDeleteThread = async (t: ResearchThread) => {
    if (!window.confirm(`Delete thread "${t.title}" and all its messages?`)) return;
    try {
      await deleteThread(t.id);
      if (selectedId === t.id) setSelectedId(null);
      await refreshThreads();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Delete failed';
      setError(msg);
    }
  };

  const handleSend = async () => {
    const q = question.trim();
    if (!q || streaming) return;

    // Create a thread on the fly if none is selected.
    let threadId = selectedId;
    if (!threadId) {
      try {
        const t = await createThread(q);
        threadId = t.id;
        setSelectedId(t.id);
        await refreshThreads();
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : 'Could not start thread';
        setError(msg);
        return;
      }
    }

    setQuestion('');
    setStreaming(true);
    setError(null);
    setLiveAnswer('');
    setLiveCitations([]);
    setLiveMeta(null);
    setLiveConsistency(null);

    // Optimistic user bubble so the UI reflects the question immediately.
    const optimisticUser: ResearchMessage = {
      id: `tmp-u-${Date.now()}`,
      threadId,
      role: 'user',
      content: q,
      citations: [],
      createdAt: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, optimisticUser]);

    abortRef.current = new AbortController();
    try {
      await streamChat({
        question: q,
        threadId,
        history: messages
          .filter((m) => m.role === 'user' || m.role === 'assistant')
          .map((m) => ({
            role: m.role as 'user' | 'assistant',
            content: m.content,
          })),
        onSources: (cites) => setLiveCitations(cites),
        onToken: (tok) => setLiveAnswer((prev) => prev + tok),
        onMeta: (meta) => setLiveMeta(meta),
        onConsistency: (warnings) => setLiveConsistency(warnings),
        onDone: async () => {
          // Refresh from server so we replace the optimistic user row
          // with the canonical one (and pick up the assistant row with
          // its persisted citations + confidence + consistency).
          await refreshMessages(threadId!);
          await refreshThreads();
          setLiveAnswer('');
          setLiveCitations([]);
          setLiveMeta(null);
          setLiveConsistency(null);
          setStreaming(false);
        },
        onError: (m) => {
          setError(m);
          setStreaming(false);
        },
        signal: abortRef.current.signal,
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Stream failed';
      setError(msg);
      setStreaming(false);
    }
  };

  /**
   * Pull 2-3 contrarian alternative hypotheses for an assistant
   * message. Takes ~10-30s server-side; we disable the button while
   * it's in flight and show an inline status chip, rather than
   * blocking the whole pane.
   */
  const handleShowAlternatives = async (m: ResearchMessage) => {
    if (alternativesLoading) return; // only one at a time
    setAlternativesLoading(m.id);
    setError(null);
    try {
      const alts = await generateAlternatives(m.threadId, m.id);
      setAlternativesByMessage((prev) => ({ ...prev, [m.id]: alts }));
      if (alts.length === 0) {
        // Friendly hint - the model explicitly said "no alternatives",
        // or it timed out. Either way we surface a short message so
        // the user doesn't think the button did nothing.
        setError('No useful alternatives were produced - the answer may be tightly scoped to the source.');
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Could not generate alternatives';
      setError(msg);
    } finally {
      setAlternativesLoading(null);
    }
  };

  /**
   * Translate one assistant message's visible text into the given
   * language. Caches optimistically on success. On failure we leave
   * the map alone so the bubble keeps showing the original.
   */
  const handleTranslate = async (m: ResearchMessage, lang: TargetLanguage) => {
    if (translatingId) return;
    setTranslatingId(m.id);
    setPreferredLang(lang);
    setError(null);
    try {
      const translated = await translateText(m.content, lang);
      setTranslationsByMessage((prev) => ({ ...prev, [m.id]: { lang, text: translated } }));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Translation failed';
      setError(msg);
    } finally {
      setTranslatingId(null);
    }
  };

  /**
   * Fetch 3 follow-up question suggestions for the given assistant
   * message. We walk the thread transcript backwards to find the
   * most recent user question (the one this answer responds to) and
   * feed both to the backend. Empty result is rendered as "none
   * suggested" rather than an error chip - the underlying LLM call
   * often comes back dry on small models.
   */
  const handleShowFollowUps = async (m: ResearchMessage) => {
    if (followUpsLoadingId) return;
    // Find the preceding user message in the current transcript.
    let question = '';
    for (const candidate of messages) {
      if (candidate.id === m.id) break;
      if (candidate.role === 'user') question = candidate.content;
    }
    if (!question) return;
    setFollowUpsLoadingId(m.id);
    setError(null);
    try {
      const suggestions = await fetchFollowUps(question, m.content);
      setFollowUpsByMessage((prev) => ({ ...prev, [m.id]: suggestions }));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Could not fetch follow-ups';
      setError(msg);
    } finally {
      setFollowUpsLoadingId(null);
    }
  };

  /**
   * Insert a suggested follow-up into the compose box. Doesn't send
   * automatically - researchers often edit the suggestion before
   * firing, and sending behind their back would feel aggressive.
   */
  const handleUseFollowUp = (q: string) => {
    setQuestion(q);
  };

  /**
   * Open the annotation composer for an assistant message and fetch
   * the existing notes in the same call. We only do this on demand;
   * closing the composer doesn't clear the cache so re-opening is
   * instant.
   */
  const handleOpenAnnotations = async (m: ResearchMessage) => {
    setOpenComposerId((curr) => (curr === m.id ? null : m.id));
    if (annotationsByMessage[m.id] !== undefined) return;
    try {
      const rows = await listAnnotationsForTarget('MESSAGE', m.id);
      setAnnotationsByMessage((prev) => ({ ...prev, [m.id]: rows }));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Could not load annotations';
      setError(msg);
    }
  };

  const handleCreateAnnotation = async (
    m: ResearchMessage,
    body: string,
    kind: AnnotationKind
  ) => {
    const text = body.trim();
    if (!text) return;
    try {
      const row = await createAnnotation({
        targetKind: 'MESSAGE',
        targetId: m.id,
        kind,
        body: text,
        bundleId: activeBundleId ?? undefined,
        author: localStorage.getItem('username') ?? undefined,
      });
      setAnnotationsByMessage((prev) => ({
        ...prev,
        [m.id]: [...(prev[m.id] ?? []), row],
      }));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not save annotation');
    }
  };

  const handleDeleteAnnotation = async (m: ResearchMessage, annotationId: string) => {
    try {
      await deleteAnnotation(annotationId);
      setAnnotationsByMessage((prev) => ({
        ...prev,
        [m.id]: (prev[m.id] ?? []).filter((a) => a.id !== annotationId),
      }));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not delete annotation');
    }
  };

  /** Drop the per-message translation so the bubble reverts to original. */
  const handleRevertTranslation = (m: ResearchMessage) => {
    setTranslationsByMessage((prev) => {
      const next = { ...prev };
      delete next[m.id];
      return next;
    });
  };

  const handlePromote = async (m: ResearchMessage) => {
    const title = window.prompt('Finding title', m.content.slice(0, 80));
    if (title === null) return;
    const tags = window.prompt('Tags (comma-separated, optional)', '') ?? '';
    try {
      await promoteMessage(m.id, {
        title: title.trim() || undefined,
        tags: tags.trim() || undefined,
      });
      window.alert('Promoted to the Findings tab.');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Promote failed';
      setError(msg);
    }
  };

  const selectedThread = useMemo(
    () => threads.find((t) => t.id === selectedId) ?? null,
    [threads, selectedId]
  );

  return (
    <motion.div variants={pageItem} className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-6">
      {/* Left rail - thread list */}
      <div className="space-y-3">
        <button
          type="button"
          onClick={() => void handleNewThread()}
          className={`w-full px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-lg hover:shadow-violet-500/30 transition flex items-center justify-center gap-2`}
        >
          <Icon.Bolt className="w-4 h-4" />
          New thread
        </button>

        <Panel
          title="Conversations"
          subtitle={loadingThreads ? 'Loading…' : `${threads.length} saved`}
          icon={<Icon.Activity className="w-5 h-5" />}
        >
          {threads.length === 0 && !loadingThreads ? (
            <div className="py-6 text-center">
              <div className="text-xs text-slate-500">
                No threads yet. Ask the copilot a question below to start one.
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-1 -mx-1">
              {threads.map((t) => {
                const active = t.id === selectedId;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setSelectedId(t.id)}
                    className={`text-left px-3 py-2.5 rounded-lg transition ${
                      active
                        ? 'bg-violet-50 ring-1 ring-violet-200'
                        : 'hover:bg-slate-50'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className={`text-sm font-semibold truncate ${active ? 'text-violet-900' : 'text-slate-900'}`}>
                          {t.title}
                        </div>
                        <div className="text-[11px] text-slate-500 truncate mt-0.5">
                          {t.lastQuestion || 'No messages yet'}
                        </div>
                        <div className="text-[10px] uppercase tracking-wider text-slate-400 mt-1">
                          {t.messageCount} msg · {formatRelative(t.updatedAt)}
                        </div>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </Panel>
      </div>

      {/* Right pane - conversation */}
      <div className="space-y-4">
        <Panel
          title={selectedThread ? selectedThread.title : 'New conversation'}
          subtitle={
            selectedThread
              ? `${selectedThread.messageCount} message${selectedThread.messageCount === 1 ? '' : 's'} · updated ${formatRelative(selectedThread.updatedAt)}`
              : 'Ask anything about your indexed library - the copilot will cite sources.'
          }
          icon={<Icon.Brain className="w-5 h-5" />}
          actions={
            selectedThread && (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => void handleRename(selectedThread)}
                  className="px-2.5 py-1 rounded-md text-xs font-semibold text-slate-700 bg-slate-50 ring-1 ring-slate-200 hover:bg-slate-100 transition"
                >
                  Rename
                </button>
                <button
                  type="button"
                  onClick={() => void handleDeleteThread(selectedThread)}
                  className="px-2.5 py-1 rounded-md text-xs font-semibold text-rose-700 bg-rose-50 ring-1 ring-rose-200 hover:bg-rose-100 transition"
                >
                  Delete
                </button>
              </div>
            )
          }
        >
          <div className="space-y-4 max-h-[520px] overflow-y-auto pr-1">
            {loadingMessages && <div className="text-xs text-slate-500">Loading messages…</div>}

            {!loadingMessages && messages.length === 0 && !streaming && (
              <div className="py-8 text-center">
                <div className="mx-auto w-10 h-10 rounded-xl bg-slate-100 text-slate-400 flex items-center justify-center mb-2">
                  <Icon.Brain className="w-5 h-5" />
                </div>
                <div className="text-sm text-slate-600">Start by asking a question below.</div>
              </div>
            )}

            {messages.map((m) => (
              <div key={m.id} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[80%] rounded-2xl px-4 py-3 text-sm ${
                  m.role === 'user'
                    ? 'bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white'
                    : 'bg-slate-50 ring-1 ring-slate-200 text-slate-800'
                }`}>
                  {m.role === 'assistant' && (
                    <div className="mb-2">
                      <ConfidencePill
                        confidence={(m.confidence as AssistantConfidence) || 'MEDIUM'}
                        needsMoreSources={m.needsMoreSources}
                      />
                    </div>
                  )}
                  <div className="whitespace-pre-wrap">
                    {translationsByMessage[m.id]?.text ?? m.content}
                  </div>
                  {m.role === 'assistant' && translationsByMessage[m.id] && (
                    <div className="mt-1 flex items-center gap-1.5 text-[10px] text-violet-600">
                      <span className="inline-block w-1.5 h-1.5 rounded-full bg-violet-500" />
                      Translated to {LANG_LABELS[translationsByMessage[m.id].lang]}
                    </div>
                  )}
                  {m.role === 'assistant' && m.citations.length > 0 && (
                    <div className="mt-2 pt-2 border-t border-slate-200 text-[11px] text-slate-500 space-y-1">
                      <div className="font-semibold uppercase tracking-wider text-slate-400">Sources · {m.citations.length}</div>
                      {m.citations.map((c) => (
                        <div key={c.index} className="flex items-center gap-2">
                          <span className={`flex-shrink-0 w-4 h-4 rounded-full text-[10px] font-bold text-white flex items-center justify-center bg-gradient-to-br ${theme.gradients.kpiA}`}>
                            {c.index}
                          </span>
                          <span className="truncate flex-1 min-w-0">
                            {c.source}{c.page ? ` · p.${c.page}` : ''}
                          </span>
                          {c.sourceType && c.sourceType !== 'UNKNOWN' && (
                            <SourceTypeBadge type={c.sourceType} />
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                  {m.role === 'assistant' && m.consistency && m.consistency.length > 0 && (
                    <ConsistencyCard warnings={m.consistency} />
                  )}
                  {m.role === 'assistant' && followUpsByMessage[m.id] && followUpsByMessage[m.id].length > 0 && (
                    <FollowUpChips
                      suggestions={followUpsByMessage[m.id]}
                      onPick={handleUseFollowUp}
                    />
                  )}
                  {m.role === 'assistant' && openComposerId === m.id && (
                    <NotesPanel
                      annotations={annotationsByMessage[m.id]}
                      onSave={(body, kind) => handleCreateAnnotation(m, body, kind)}
                      onDelete={(id) => handleDeleteAnnotation(m, id)}
                    />
                  )}
                  {m.role === 'assistant' && (() => {
                    // Alternatives priority: optimistic (just-fetched) map
                    // wins over the persisted list from the DTO, so
                    // re-rolling feels instant. Fall back to the server
                    // copy on first render after a page reload.
                    const alts = alternativesByMessage[m.id] ?? m.alternatives ?? [];
                    if (alts.length === 0) return null;
                    return <AlternativesList alternatives={alts} />;
                  })()}
                  {m.role === 'assistant' && (
                    <div className="mt-2 flex flex-wrap justify-end items-center gap-3">
                      {/* Translate control: compact <select> paired with
                          an action. When the bubble is already showing
                          a translation we expose a "Revert" action
                          instead of firing a new one. */}
                      {translationsByMessage[m.id] ? (
                        <button
                          type="button"
                          onClick={() => handleRevertTranslation(m)}
                          className="text-[11px] font-semibold text-slate-600 hover:text-slate-900 underline underline-offset-2"
                        >
                          Revert to original
                        </button>
                      ) : (
                        <div className="inline-flex items-center gap-1">
                          <select
                            value={preferredLang}
                            onChange={(e) => setPreferredLang(e.target.value as TargetLanguage)}
                            className="text-[11px] bg-white ring-1 ring-slate-200 rounded-md px-1.5 py-0.5 text-slate-700 focus:ring-violet-300 focus:outline-none"
                            aria-label="Target language"
                          >
                            {(Object.keys(LANG_LABELS) as TargetLanguage[]).map((code) => (
                              <option key={code} value={code}>{LANG_LABELS[code]}</option>
                            ))}
                          </select>
                          <button
                            type="button"
                            onClick={() => void handleTranslate(m, preferredLang)}
                            disabled={translatingId === m.id}
                            className="text-[11px] font-semibold text-violet-700 hover:text-violet-900 underline underline-offset-2 disabled:opacity-50 disabled:cursor-wait"
                          >
                            {translatingId === m.id ? 'Translating…' : 'Translate'}
                          </button>
                        </div>
                      )}
                      <button
                        type="button"
                        onClick={() => void handleOpenAnnotations(m)}
                        className="text-[11px] font-semibold text-amber-700 hover:text-amber-900 underline underline-offset-2"
                      >
                        {openComposerId === m.id
                          ? 'Hide notes'
                          : `Notes${annotationsByMessage[m.id]?.length ? ` (${annotationsByMessage[m.id].length})` : ''}`}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleShowFollowUps(m)}
                        disabled={followUpsLoadingId === m.id}
                        className="text-[11px] font-semibold text-violet-700 hover:text-violet-900 underline underline-offset-2 disabled:opacity-50 disabled:cursor-wait"
                      >
                        {followUpsLoadingId === m.id
                          ? 'Suggesting…'
                          : followUpsByMessage[m.id] && followUpsByMessage[m.id].length > 0
                            ? 'Re-suggest follow-ups'
                            : 'Suggest follow-ups'}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleShowAlternatives(m)}
                        disabled={alternativesLoading === m.id}
                        className="text-[11px] font-semibold text-fuchsia-700 hover:text-fuchsia-900 underline underline-offset-2 disabled:opacity-50 disabled:cursor-wait"
                      >
                        {alternativesLoading === m.id
                          ? 'Thinking of alternatives…'
                          : (alternativesByMessage[m.id] ?? m.alternatives ?? []).length > 0
                            ? 'Re-roll alternatives'
                            : 'Show alternative theories'}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handlePromote(m)}
                        className="text-[11px] font-semibold text-violet-700 hover:text-violet-900 underline underline-offset-2"
                      >
                        Promote to finding
                      </button>
                      <button
                        type="button"
                        onClick={() => setPromotingVuln(m)}
                        className="text-[11px] font-semibold text-rose-700 hover:text-rose-900 underline underline-offset-2"
                      >
                        Promote to vulnerability
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))}

            {streaming && (
              <div className="flex justify-start">
                <div className="max-w-[80%] rounded-2xl px-4 py-3 text-sm bg-slate-50 ring-1 ring-slate-200 text-slate-800">
                  {liveMeta && (
                    <div className="mb-2">
                      <ConfidencePill
                        confidence={liveMeta.confidence}
                        needsMoreSources={liveMeta.needsMoreSources}
                      />
                    </div>
                  )}
                  <div className="whitespace-pre-wrap">
                    {stripConfidenceFooterFromStream(liveAnswer) || '…'}
                  </div>
                  {liveCitations.length > 0 && (
                    <div className="mt-2 pt-2 border-t border-slate-200 text-[11px] text-slate-500">
                      <div className="font-semibold uppercase tracking-wider text-slate-400">Sources · {liveCitations.length}</div>
                    </div>
                  )}
                  {liveConsistency && liveConsistency.length > 0 && (
                    <ConsistencyCard warnings={liveConsistency} />
                  )}
                </div>
              </div>
            )}
          </div>

          {error && (
            <div className="mt-4 px-4 py-3 rounded-xl bg-rose-50 ring-1 ring-rose-200 text-sm text-rose-700 flex items-center gap-2">
              <Icon.Alert className="w-4 h-4" />
              {error}
            </div>
          )}

          <div className="mt-4 flex gap-2">
            <input
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !streaming) void handleSend(); }}
              placeholder="Ask the research copilot…"
              className="flex-1 px-4 py-2.5 rounded-xl ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 focus:outline-none text-sm"
              disabled={streaming}
            />
            <button
              type="button"
              onClick={() => void handleSend()}
              disabled={streaming || !question.trim()}
              className={`px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-lg hover:shadow-violet-500/30 transition disabled:opacity-50`}
            >
              {streaming ? 'Thinking…' : 'Ask'}
            </button>
          </div>
        </Panel>
      </div>

      <AnimatePresence>
        {promotingVuln && (
          <PromoteToVulnModal
            message={promotingVuln}
            onClose={() => setPromotingVuln(null)}
            onDone={() => setPromotingVuln(null)}
          />
        )}
      </AnimatePresence>
    </motion.div>
  );
};

// ---------------------------------------------------------------------------
// PromoteToVulnModal - quick classifier sheet over an assistant message.
// The backend already copies the message text + citations verbatim; here
// the researcher just classifies it (severity / confidence / component
// type) so the resulting observation lands in a useful bucket.
// ---------------------------------------------------------------------------

interface PromoteToVulnModalProps {
  message: ResearchMessage;
  onClose: () => void;
  onDone: () => void;
}
const PromoteToVulnModal: React.FC<PromoteToVulnModalProps> = ({ message, onClose, onDone }) => {
  const defaultTitle = useMemo(() => {
    const compact = (message.content ?? '').replace(/\s+/g, ' ').trim();
    return compact.length <= 80 ? compact : compact.slice(0, 77) + '...';
  }, [message.content]);

  const [title, setTitle] = useState(defaultTitle);
  const [componentType, setComponentType] = useState<VulnComponentType>('PROTOCOL');
  const [componentRef, setComponentRef] = useState('');
  const [severity, setSeverity] = useState<VulnSeverity>('MEDIUM');
  const [confidence, setConfidence] = useState<VulnConfidence>('MEDIUM');
  const [needsMoreSources, setNeedsMoreSources] = useState(false);
  const [alternativeHypotheses, setAlternativeHypotheses] = useState('');
  const [tags, setTags] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await promoteVuln({
        threadId: message.threadId,
        messageId: message.id,
        title: title.trim() || undefined,
        componentType,
        componentRef: componentRef.trim() || undefined,
        severity,
        confidence,
        needsMoreSources,
        alternativeHypotheses: alternativeHypotheses.trim() || undefined,
        tags: tags.trim() || undefined,
      });
      window.alert('Promoted to the Vulnerabilities tab.');
      onDone();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Promote failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <motion.div
        className="fixed inset-0 bg-slate-900/30 backdrop-blur-sm z-40"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
      />
      <motion.div
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        initial={{ opacity: 0, scale: 0.98 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.98 }}
      >
        <div className="bg-white rounded-2xl shadow-2xl w-full max-w-xl max-h-[90vh] overflow-y-auto">
          <div className="p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-rose-600">
                  Promote to vulnerability
                </div>
                <h2 className="text-lg font-bold text-slate-900">Classify this observation</h2>
                <div className="text-xs text-slate-500 mt-1">
                  Creates a DRAFT observation with this message's text and citations.
                </div>
              </div>
              <button onClick={onClose} className="p-2 rounded-lg text-slate-500 hover:bg-slate-100">✕</button>
            </div>

            {error && (
              <div className="mb-4 px-4 py-3 rounded-xl bg-rose-50 ring-1 ring-rose-200 text-sm text-rose-700">
                {error}
              </div>
            )}

            <div className="space-y-3">
              <div className="flex flex-col gap-1">
                <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Title
                </label>
                <input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="flex flex-col gap-1">
                  <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Component type
                  </label>
                  <select
                    value={componentType}
                    onChange={(e) => setComponentType(e.target.value as VulnComponentType)}
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm bg-white"
                  >
                    {(['PROTOCOL','INTERFACE','FIRMWARE','SOFTWARE','HARDWARE_COMPONENT','CONFIGURATION','SUPPLY_CHAIN','OTHER'] as VulnComponentType[]).map(c =>
                      <option key={c} value={c}>{c.replace('_', ' ')}</option>
                    )}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Component ref
                  </label>
                  <input
                    value={componentRef}
                    onChange={(e) => setComponentRef(e.target.value)}
                    placeholder="Port 23 on mgmt NIC"
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Severity
                  </label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as VulnSeverity)}
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm bg-white"
                  >
                    {(['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as VulnSeverity[]).map(s =>
                      <option key={s} value={s}>{s}</option>
                    )}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Confidence
                  </label>
                  <select
                    value={confidence}
                    onChange={(e) => setConfidence(e.target.value as VulnConfidence)}
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm bg-white"
                  >
                    {(['HIGH','MEDIUM','LOW'] as VulnConfidence[]).map(c =>
                      <option key={c} value={c}>{c}</option>
                    )}
                  </select>
                </div>
              </div>

              <div className="flex flex-col gap-1">
                <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Alternative hypotheses
                </label>
                <textarea
                  rows={2}
                  value={alternativeHypotheses}
                  onChange={(e) => setAlternativeHypotheses(e.target.value)}
                  placeholder={"- Could also be...\n- Or alternatively..."}
                  className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                />
              </div>

              <div className="flex flex-col gap-1">
                <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Tags
                </label>
                <input
                  value={tags}
                  onChange={(e) => setTags(e.target.value)}
                  placeholder="comma,separated"
                  className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                />
              </div>

              <label className="inline-flex items-center gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={needsMoreSources}
                  onChange={(e) => setNeedsMoreSources(e.target.checked)}
                />
                Needs more sources before verification
              </label>
            </div>

            <div className="mt-6 flex items-center justify-end gap-2">
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-xl text-sm font-semibold text-slate-700 bg-slate-100 ring-1 ring-slate-200"
              >
                Cancel
              </button>
              <button
                onClick={submit}
                disabled={submitting}
                className={`px-4 py-2 rounded-xl text-sm font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} disabled:opacity-60 hover:shadow-lg hover:shadow-violet-500/30 transition`}
              >
                {submitting ? 'Promoting…' : 'Create observation'}
              </button>
            </div>
          </div>
        </div>
      </motion.div>
    </>
  );
};

export default ThreadsTab;
