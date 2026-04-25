import React, { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Icon, theme } from '../theme';
import { useBundles } from '../../contexts/BundleContext';
import { ResearchBundle } from '../../services/bundleService';

/**
 * Left-rail bundle switcher. Lives on every Research Studio tab so the
 * researcher can jump between parallel investigations without leaving
 * the current screen (Library, Threads, Findings, Vulns all honour the
 * active bundle via the axios X-Bundle-Id header).
 */

interface BundleSidebarProps {
  /** Width-respecting container; parent controls the flex layout. */
  className?: string;
}

const BundleSidebar: React.FC<BundleSidebarProps> = ({ className = '' }) => {
  const {
    bundles,
    activeBundleId,
    selectBundle,
    createBundle,
    loading,
    error,
  } = useBundles();

  const [tagFilter, setTagFilter] = useState('');
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [newTags, setNewTags] = useState('');
  const [submitError, setSubmitError] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const needle = tagFilter.trim().toLowerCase();
    if (!needle) return bundles;
    return bundles.filter(b =>
      (b.tags ?? '').toLowerCase().includes(needle) ||
      b.name.toLowerCase().includes(needle) ||
      b.slug.toLowerCase().includes(needle)
    );
  }, [bundles, tagFilter]);

  const handleCreate = async () => {
    if (!newName.trim()) return;
    setSubmitError(null);
    try {
      await createBundle({
        name: newName.trim(),
        tags: newTags.trim() || undefined,
      });
      setNewName('');
      setNewTags('');
      setCreating(false);
    } catch (e: unknown) {
      setSubmitError(e instanceof Error ? e.message : 'Create failed');
    }
  };

  return (
    <aside className={`bg-white rounded-2xl ring-1 ring-slate-200 shadow-sm p-4 flex flex-col gap-3 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            Bundles
          </div>
          <div className="text-sm font-bold text-slate-900">
            {loading ? 'Loading…' : `${bundles.length} workspace${bundles.length === 1 ? '' : 's'}`}
          </div>
        </div>
        <button
          type="button"
          onClick={() => setCreating(v => !v)}
          className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-md transition`}
        >
          {creating ? 'Cancel' : '+ New'}
        </button>
      </div>

      {/* Create form (inline, expands on click) */}
      {creating && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="space-y-2 rounded-xl bg-slate-50 ring-1 ring-slate-200 p-3"
        >
          <input
            autoFocus
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="Bundle name (e.g. Siemens S7-1500)"
            className="w-full px-2 py-1.5 rounded-lg ring-1 ring-slate-200 text-sm"
          />
          <input
            value={newTags}
            onChange={(e) => setNewTags(e.target.value)}
            placeholder="Tags (comma-separated)"
            className="w-full px-2 py-1.5 rounded-lg ring-1 ring-slate-200 text-sm"
          />
          {submitError && (
            <div className="text-[11px] text-rose-600">{submitError}</div>
          )}
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void handleCreate()}
              disabled={!newName.trim()}
              className={`flex-1 px-2.5 py-1.5 rounded-lg text-[11px] font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} disabled:opacity-50`}
            >
              Create
            </button>
            <button
              type="button"
              onClick={() => { setCreating(false); setNewName(''); setNewTags(''); }}
              className="px-2.5 py-1.5 rounded-lg text-[11px] font-semibold text-slate-600 bg-white ring-1 ring-slate-200"
            >
              Cancel
            </button>
          </div>
        </motion.div>
      )}

      {/* Tag filter */}
      <div>
        <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
          Filter by tag
        </label>
        <div className="relative mt-1">
          <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400">
            <Icon.Search className="w-3.5 h-3.5" />
          </span>
          <input
            value={tagFilter}
            onChange={(e) => setTagFilter(e.target.value)}
            placeholder="e.g. siemens"
            className="w-full pl-8 pr-2 py-1.5 rounded-lg ring-1 ring-slate-200 text-sm"
          />
        </div>
      </div>

      {error && (
        <div className="text-[11px] text-rose-600 bg-rose-50 ring-1 ring-rose-200 rounded-lg px-2.5 py-1.5">
          {error}
        </div>
      )}

      {/* Bundle list */}
      <div className="flex-1 overflow-y-auto space-y-1.5 -mx-1 px-1">
        {filtered.length === 0 && !loading && (
          <div className="text-xs text-slate-500 text-center py-6">
            {bundles.length === 0 ? 'No bundles yet.' : 'No matches.'}
          </div>
        )}
        {filtered.map(b => (
          <BundleRow
            key={b.id}
            bundle={b}
            active={b.id === activeBundleId}
            onSelect={() => selectBundle(b.id)}
          />
        ))}
      </div>
    </aside>
  );
};

const BundleRow: React.FC<{
  bundle: ResearchBundle;
  active: boolean;
  onSelect: () => void;
}> = ({ bundle, active, onSelect }) => {
  const tags = (bundle.tags ?? '').split(',').map(t => t.trim()).filter(Boolean);
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`w-full text-left px-3 py-2 rounded-xl transition ring-1 ${
        active
          ? 'bg-gradient-to-r from-violet-50 to-fuchsia-50 ring-violet-300'
          : 'bg-white ring-slate-200 hover:bg-slate-50'
      }`}
    >
      <div className="flex items-center gap-2">
        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${active ? 'bg-violet-500' : 'bg-slate-300'}`} />
        <div className="text-sm font-semibold text-slate-900 truncate flex-1">
          {bundle.name}
        </div>
      </div>
      {tags.length > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-1">
          {tags.slice(0, 3).map((t, i) => (
            <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600">
              {t}
            </span>
          ))}
        </div>
      )}
      <div className="mt-1 text-[10px] text-slate-500 flex items-center gap-2">
        <span>{bundle.documentCount} doc{bundle.documentCount === 1 ? '' : 's'}</span>
        <span className="text-slate-300">·</span>
        <span>{bundle.threadCount} thread{bundle.threadCount === 1 ? '' : 's'}</span>
        <span className="text-slate-300">·</span>
        <span>{bundle.vulnCount} vuln{bundle.vulnCount === 1 ? '' : 's'}</span>
      </div>
    </button>
  );
};

export default BundleSidebar;
