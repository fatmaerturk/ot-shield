import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Panel, Icon, pageItem, theme } from '../theme';
import { useBundles } from '../../contexts/BundleContext';
import {
  BundleSummary,
  getSummary,
  regenerateSummary,
  updateSummary,
} from '../../services/summaryService';
import { listDocuments, ResearchDocument } from '../../services/researchService';

/* ---------------------------------------------------------------------------
 * Research Studio — Summary tab
 *
 * HMGCC requirement: "Generate a clear technical summary of the
 * product and its individual components." One summary per active
 * bundle, cached server-side so the LLM doesn't burn CPU on every tab
 * open. Researcher can regenerate or manually edit; the footer shows
 * which documents fed the generator and when it last ran.
 * ------------------------------------------------------------------------ */

const formatRelative = (iso: string | null): string => {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const diff = (Date.now() - t) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
};

const POLL_INTERVAL_MS = 3000;

const SummaryTab: React.FC = () => {
  const { activeBundle } = useBundles();
  const [summary, setSummary] = useState<BundleSummary | null>(null);
  const [docs, setDocs] = useState<ResearchDocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [editDraft, setEditDraft] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [elapsedSecs, setElapsedSecs] = useState(0);

  const refresh = useCallback(async () => {
    try {
      const [s, d] = await Promise.all([getSummary(), listDocuments()]);
      setSummary(s);
      setDocs(d);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load summary');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  // Background poll while the worker is generating. A short interval
  // keeps the UI feeling responsive; the endpoint is cheap (one row
  // read) so this is fine.
  const generating = summary?.status === 'GENERATING';
  useEffect(() => {
    if (!generating) {
      setElapsedSecs(0);
      return;
    }
    const started = Date.now();
    const poll = window.setInterval(() => { void refresh(); }, POLL_INTERVAL_MS);
    const tick = window.setInterval(
      () => setElapsedSecs(Math.floor((Date.now() - started) / 1000)),
      1000
    );
    return () => {
      window.clearInterval(poll);
      window.clearInterval(tick);
    };
  }, [generating, refresh]);

  const readyDocCount = useMemo(
    () => docs.filter(d => d.status === 'READY').length,
    [docs]
  );

  const handleRegenerate = async () => {
    setError(null);
    try {
      const s = await regenerateSummary();
      setSummary(s); // arrives as GENERATING, polling takes over
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Regeneration failed');
    }
  };

  const handleStartEdit = () => {
    setEditDraft(summary?.text ?? '');
    setEditing(true);
  };

  const handleSaveEdit = async () => {
    try {
      const s = await updateSummary(editDraft);
      setSummary(s);
      setEditing(false);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Save failed');
    }
  };

  const sourceDocNames = useMemo(() => {
    if (!summary) return [];
    return summary.sourceDocIds
      .map(id => docs.find(d => d.id === id)?.fileName ?? id)
      .filter(Boolean);
  }, [summary, docs]);

  const hasContent = summary?.text && summary.text.trim().length > 0;

  return (
    <motion.div variants={pageItem} className="space-y-6">
      <Panel
        title="Technical summary"
        subtitle={activeBundle
          ? `Product and component overview, generated from the documents in '${activeBundle.name}'.`
          : 'Product and component overview, generated from this bundle\'s documents.'}
        icon={<Icon.Brain className="w-5 h-5" />}
        actions={
          <div className="flex items-center gap-2">
            {!editing && hasContent && (
              <button
                type="button"
                onClick={handleStartEdit}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-violet-700 bg-violet-50 ring-1 ring-violet-200 hover:bg-violet-100 transition"
              >
                Edit
              </button>
            )}
            <button
              type="button"
              onClick={() => void handleRegenerate()}
              disabled={generating || readyDocCount === 0}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-md transition disabled:opacity-50 inline-flex items-center gap-1.5`}
              title={readyDocCount === 0 ? 'Upload a READY document first' : undefined}
            >
              <Icon.Refresh className={`w-3.5 h-3.5 ${generating ? 'animate-spin' : ''}`} />
              {generating ? 'Generating…' : 'Regenerate'}
            </button>
          </div>
        }
      >
        {loading && (
          <div className="py-10 text-center text-sm text-slate-500">
            Loading summary…
          </div>
        )}

        {error && (
          <div className="mb-4 px-4 py-3 rounded-xl bg-rose-50 ring-1 ring-rose-200 text-sm text-rose-700 flex items-center gap-2">
            <Icon.Alert className="w-4 h-4" />
            {error}
          </div>
        )}

        {generating && (
          <div className="mb-4 px-4 py-3 rounded-xl bg-violet-50 ring-1 ring-violet-200 text-sm text-violet-800 flex items-center gap-3">
            <Icon.Refresh className="w-4 h-4 animate-spin" />
            <div className="flex-1">
              <div className="font-semibold">Generating summary…</div>
              <div className="text-xs text-violet-700 mt-0.5">
                Running locally on Ollama ({elapsedSecs}s elapsed). This can take a couple of minutes on CPU-only hosts. You can leave this tab and come back — progress is saved server-side.
              </div>
            </div>
          </div>
        )}

        {summary?.status === 'FAILED' && (
          <div className="mb-4 px-4 py-3 rounded-xl bg-rose-50 ring-1 ring-rose-200 text-sm text-rose-700 flex items-center gap-2">
            <Icon.Alert className="w-4 h-4" />
            Generation failed. See the text panel below for the model's error message, then retry.
          </div>
        )}

        {!loading && !hasContent && !editing && !generating && (
          <div className="py-8 text-center">
            <div className="mx-auto w-12 h-12 rounded-xl bg-slate-100 text-slate-400 flex items-center justify-center mb-3">
              <Icon.Brain className="w-6 h-6" />
            </div>
            <div className="text-sm font-semibold text-slate-700">No summary yet</div>
            <div className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
              {readyDocCount === 0
                ? 'Upload at least one document in the Library tab, wait for it to become READY, then come back and hit Regenerate.'
                : `There are ${readyDocCount} READY document(s) in this bundle. Hit Regenerate to produce a summary.`}
            </div>
          </div>
        )}

        {editing && (
          <div className="space-y-3">
            <div className="text-[11px] text-slate-500">
              Markdown is rendered below when you exit edit mode.
            </div>
            <textarea
              value={editDraft}
              onChange={(e) => setEditDraft(e.target.value)}
              rows={22}
              className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm font-mono focus:ring-2 focus:ring-violet-400 focus:outline-none"
            />
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => void handleSaveEdit()}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA}`}
              >
                Save edits
              </button>
              <button
                type="button"
                onClick={() => setEditing(false)}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-700 bg-slate-100 ring-1 ring-slate-200"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {!editing && hasContent && (
          <div className="prose-summary">
            <Markdown text={summary!.text ?? ''} />
          </div>
        )}
      </Panel>

      {/* Provenance footer */}
      {summary && (hasContent || summary.generatedAt) && (
        <div className="bg-white rounded-2xl ring-1 ring-slate-200 p-4 text-xs text-slate-600 flex flex-wrap gap-x-5 gap-y-2">
          <div>
            <span className="font-semibold text-slate-500">Last generated</span>
            <span className="ml-1.5">{formatRelative(summary.generatedAt)}</span>
          </div>
          {summary.editedAt && (
            <div>
              <span className="font-semibold text-slate-500">Edited</span>
              <span className="ml-1.5">{formatRelative(summary.editedAt)}</span>
            </div>
          )}
          {summary.model && (
            <div>
              <span className="font-semibold text-slate-500">Model</span>
              <span className="ml-1.5 font-mono">{summary.model}</span>
            </div>
          )}
          {sourceDocNames.length > 0 && (
            <div className="w-full">
              <span className="font-semibold text-slate-500">Built from</span>
              <span className="ml-1.5">
                {sourceDocNames.map((n, i) => (
                  <span key={i}>
                    {i > 0 && <span className="text-slate-300 mx-1">·</span>}
                    <span className="underline decoration-dotted underline-offset-2">{n}</span>
                  </span>
                ))}
              </span>
            </div>
          )}
        </div>
      )}
    </motion.div>
  );
};

// ---------------------------------------------------------------------------
// Minimal markdown renderer for summary text
//
// Covers the subset the SummaryService system prompt produces: headings,
// bullet lists, bold, inline code, and paragraphs. Deliberately small;
// when researchers need richer output we can drop in react-markdown.
// ---------------------------------------------------------------------------

interface MarkdownProps { text: string; }
const Markdown: React.FC<MarkdownProps> = ({ text }) => {
  const blocks = splitBlocks(text);
  return (
    <div className="space-y-3 text-sm text-slate-800">
      {blocks.map((b, i) => renderBlock(b, i))}
    </div>
  );
};

type Block =
  | { kind: 'h2'; text: string }
  | { kind: 'h3'; text: string }
  | { kind: 'ul'; items: string[] }
  | { kind: 'p'; text: string };

function splitBlocks(src: string): Block[] {
  const lines = src.replace(/\r\n/g, '\n').split('\n');
  const out: Block[] = [];
  let para: string[] = [];
  let list: string[] = [];

  const flushPara = () => {
    if (para.length > 0) {
      out.push({ kind: 'p', text: para.join(' ').trim() });
      para = [];
    }
  };
  const flushList = () => {
    if (list.length > 0) {
      out.push({ kind: 'ul', items: list });
      list = [];
    }
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.length === 0) {
      flushPara();
      flushList();
      continue;
    }
    if (line.startsWith('## ')) {
      flushPara(); flushList();
      out.push({ kind: 'h2', text: line.slice(3).trim() });
      continue;
    }
    if (line.startsWith('### ')) {
      flushPara(); flushList();
      out.push({ kind: 'h3', text: line.slice(4).trim() });
      continue;
    }
    const bulletMatch = line.match(/^[-*]\s+(.*)$/);
    if (bulletMatch) {
      flushPara();
      list.push(bulletMatch[1]);
      continue;
    }
    // Plain paragraph text
    flushList();
    para.push(line);
  }
  flushPara();
  flushList();
  return out;
}

function renderBlock(b: Block, idx: number): React.ReactNode {
  switch (b.kind) {
    case 'h2':
      return (
        <h3 key={idx} className="text-sm font-bold uppercase tracking-wider text-violet-700 mt-2">
          {renderInline(b.text)}
        </h3>
      );
    case 'h3':
      return (
        <h4 key={idx} className="text-sm font-semibold text-slate-800">
          {renderInline(b.text)}
        </h4>
      );
    case 'ul':
      return (
        <ul key={idx} className="list-disc pl-5 space-y-1.5">
          {b.items.map((it, i) => (
            <li key={i}>{renderInline(it)}</li>
          ))}
        </ul>
      );
    case 'p':
      return <p key={idx}>{renderInline(b.text)}</p>;
  }
}

/** Inline formatting: **bold**, `code`, [n] citations. */
function renderInline(text: string): React.ReactNode[] {
  // Tokeniser: match bold, inline code, or citation markers [1], [2]...
  const out: React.ReactNode[] = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\[\d+\])/g;
  let last = 0;
  let match: RegExpExecArray | null;
  let k = 0;
  while ((match = re.exec(text)) !== null) {
    if (match.index > last) {
      out.push(text.slice(last, match.index));
    }
    const tok = match[0];
    if (tok.startsWith('**')) {
      out.push(<strong key={k++} className="font-semibold text-slate-900">{tok.slice(2, -2)}</strong>);
    } else if (tok.startsWith('`')) {
      out.push(<code key={k++} className="px-1 py-0.5 rounded bg-slate-100 font-mono text-[0.85em] text-slate-800">{tok.slice(1, -1)}</code>);
    } else if (/^\[\d+\]$/.test(tok)) {
      out.push(<span key={k++} className="inline-block px-1.5 text-[10px] font-semibold text-violet-700 bg-violet-50 ring-1 ring-violet-200 rounded">{tok}</span>);
    }
    last = re.lastIndex;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export default SummaryTab;
