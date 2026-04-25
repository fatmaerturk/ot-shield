import React, { useCallback, useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Panel, Icon, pageItem, theme } from '../theme';
import {
  ResearchFinding,
  listFindings,
  createFinding,
  updateFinding,
  deleteFinding,
} from '../../services/findingService';

/* ---------------------------------------------------------------------------
 * Research Studio — Findings tab
 *
 * The curated knowledge ledger. Rows land here either by promoting an
 * assistant message from the Threads tab or by authoring a finding
 * directly with the compose form at the top. Each card shows the full
 * text, its citation footer, and inline edit / delete controls.
 * ------------------------------------------------------------------------ */

const formatDate = (iso: string): string => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString();
};

const FindingsTab: React.FC = () => {
  const [findings, setFindings] = useState<ResearchFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [draftTitle, setDraftTitle] = useState('');
  const [draftText, setDraftText] = useState('');
  const [draftTags, setDraftTags] = useState('');
  const [creating, setCreating] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const rows = await listFindings();
      setFindings(rows);
      setError(null);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to load findings';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const handleCreate = async () => {
    if (!draftText.trim()) return;
    setCreating(true);
    setError(null);
    try {
      await createFinding(draftText.trim(), {
        title: draftTitle.trim() || undefined,
        tags: draftTags.trim() || undefined,
      });
      setDraftTitle('');
      setDraftText('');
      setDraftTags('');
      await refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Create failed';
      setError(msg);
    } finally {
      setCreating(false);
    }
  };

  const handleEdit = async (f: ResearchFinding) => {
    const title = window.prompt('Edit title', f.title);
    if (title === null) return;
    const text = window.prompt('Edit body', f.text);
    if (text === null) return;
    const tags = window.prompt('Edit tags (comma-separated)', f.tags ?? '') ?? '';
    try {
      await updateFinding(f.id, {
        title: title.trim() || undefined,
        text,
        tags,
      });
      await refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Edit failed';
      setError(msg);
    }
  };

  const handleDelete = async (f: ResearchFinding) => {
    if (!window.confirm(`Delete finding "${f.title}"?`)) return;
    try {
      await deleteFinding(f.id);
      await refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Delete failed';
      setError(msg);
    }
  };

  const renderTags = (tags: string | null) => {
    if (!tags) return null;
    const items = tags.split(',').map((t) => t.trim()).filter(Boolean);
    if (items.length === 0) return null;
    return (
      <div className="flex flex-wrap gap-1.5 mt-2">
        {items.map((t) => (
          <span
            key={t}
            className="px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider bg-violet-50 text-violet-700 ring-1 ring-violet-200"
          >
            {t}
          </span>
        ))}
      </div>
    );
  };

  return (
    <motion.div variants={pageItem} className="space-y-6">
      <Panel
        title="New finding"
        subtitle="Capture a piece of curated knowledge. Citations can be attached by promoting a message from the Threads tab."
        icon={<Icon.Bolt className="w-5 h-5" />}
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input
            type="text"
            value={draftTitle}
            onChange={(e) => setDraftTitle(e.target.value)}
            placeholder="Title (optional)"
            className="md:col-span-2 px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 focus:outline-none text-sm"
          />
          <input
            type="text"
            value={draftTags}
            onChange={(e) => setDraftTags(e.target.value)}
            placeholder="Tags (comma-separated)"
            className="px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 focus:outline-none text-sm"
          />
        </div>
        <textarea
          value={draftText}
          onChange={(e) => setDraftText(e.target.value)}
          placeholder="Finding body…"
          rows={4}
          className="mt-3 w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 focus:outline-none text-sm"
        />
        <div className="mt-3 flex justify-end">
          <button
            type="button"
            onClick={() => void handleCreate()}
            disabled={creating || !draftText.trim()}
            className={`px-4 py-2 rounded-xl text-sm font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-lg hover:shadow-violet-500/30 transition disabled:opacity-50`}
          >
            {creating ? 'Saving…' : 'Save finding'}
          </button>
        </div>

        {error && (
          <div className="mt-4 px-4 py-3 rounded-xl bg-rose-50 ring-1 ring-rose-200 text-sm text-rose-700 flex items-center gap-2">
            <Icon.Alert className="w-4 h-4" />
            {error}
          </div>
        )}
      </Panel>

      <Panel
        title="Ledger"
        subtitle={loading ? 'Loading…' : `${findings.length} finding${findings.length === 1 ? '' : 's'}`}
        icon={<Icon.CheckCircle className="w-5 h-5" />}
      >
        {findings.length === 0 && !loading ? (
          <div className="py-10 text-center">
            <div className="mx-auto w-12 h-12 rounded-xl bg-slate-100 text-slate-400 flex items-center justify-center mb-3">
              <Icon.CheckCircle className="w-6 h-6" />
            </div>
            <div className="text-sm font-semibold text-slate-700">No findings yet</div>
            <div className="text-xs text-slate-500 mt-1">
              Promote an assistant message from the Threads tab, or author one directly above.
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            {findings.map((f) => (
              <div
                key={f.id}
                className="rounded-2xl ring-1 ring-slate-200 bg-white p-4 hover:shadow-md transition"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold text-slate-900">{f.title}</div>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      {formatDate(f.createdAt)}
                      {f.sourceThreadId && ' · from thread'}
                    </div>
                    <div className="text-sm text-slate-700 mt-2 whitespace-pre-wrap">{f.text}</div>
                    {renderTags(f.tags)}
                    {f.citations.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-slate-100 text-[11px] text-slate-500 space-y-1">
                        <div className="font-semibold uppercase tracking-wider text-slate-400">Sources · {f.citations.length}</div>
                        {f.citations.map((c) => (
                          <div key={c.index} className="flex items-start gap-2">
                            <span className={`flex-shrink-0 w-4 h-4 rounded-full text-[10px] font-bold text-white flex items-center justify-center bg-gradient-to-br ${theme.gradients.kpiA}`}>
                              {c.index}
                            </span>
                            <span className="truncate">
                              {c.source}{c.page ? ` · p.${c.page}` : ''}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="flex flex-col gap-2 flex-shrink-0">
                    <button
                      type="button"
                      onClick={() => void handleEdit(f)}
                      className="px-2.5 py-1 rounded-md text-xs font-semibold text-slate-700 bg-slate-50 ring-1 ring-slate-200 hover:bg-slate-100 transition"
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleDelete(f)}
                      className="px-2.5 py-1 rounded-md text-xs font-semibold text-rose-700 bg-rose-50 ring-1 ring-rose-200 hover:bg-rose-100 transition"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </motion.div>
  );
};

export default FindingsTab;
