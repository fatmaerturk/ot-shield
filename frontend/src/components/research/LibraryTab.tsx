import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { KpiCard, Panel, Icon, pageItem, theme } from '../theme';
import {
  ResearchDocument,
  ResearchDiagnostics,
  ResearchSourceType,
  listDocuments,
  uploadDocument,
  deleteDocument,
  reingestDocument,
  fetchDiagnostics,
  setDocumentSourceType,
  reconcileKnowledgeBase,
} from '../../services/researchService';

/* ---------------------------------------------------------------------------
 * Research Studio — Library tab
 *
 * Extracted verbatim from the original ResearchLibrary.tsx so the new
 * tabbed workbench can host the upload flow alongside Threads and
 * Findings without rewriting the whole thing. The behaviour (polling,
 * drag-drop, KPI row, error surfacing) is unchanged - only the hero/
 * shell chrome has been hoisted up into ResearchStudio.tsx.
 * ------------------------------------------------------------------------ */

const POLL_INTERVAL_MS = 2500;

const statusStyle = (status: ResearchDocument['status']) => {
  switch (status) {
    case 'READY':
      return { badge: 'bg-emerald-100 text-emerald-700 ring-emerald-200', dot: 'bg-emerald-500' };
    case 'PROCESSING':
      return { badge: 'bg-violet-100 text-violet-700 ring-violet-200', dot: 'bg-violet-500' };
    case 'UPLOADED':
      return { badge: 'bg-sky-100 text-sky-700 ring-sky-200', dot: 'bg-sky-500' };
    case 'FAILED':
    default:
      return { badge: 'bg-rose-100 text-rose-700 ring-rose-200', dot: 'bg-rose-500' };
  }
};

const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

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

export interface LibraryTabProps {
  /** Fed upward to the shell hero so the stats row can reflect library size. */
  onStatsChange?: (stats: { total: number; ready: number; chunks: number; bytes: number }) => void;
}

const LibraryTab: React.FC<LibraryTabProps> = ({ onStatsChange }) => {
  const [documents, setDocuments] = useState<ResearchDocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [dragging, setDragging] = useState(false);
  const [productLabel, setProductLabel] = useState('');
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Operator diagnostics - surfaced in a banner above the upload panel
  // so "why is my upload stuck on UPLOADED" becomes a one-click question.
  const [diag, setDiag] = useState<ResearchDiagnostics | null>(null);
  const [diagLoading, setDiagLoading] = useState(false);
  const [diagError, setDiagError] = useState<string | null>(null);
  const [diagOpen, setDiagOpen] = useState(false);
  // "Rebuild knowledge base" state - flips to true while the POST is
  // in flight, resolves with a short-lived status chip so the user
  // sees something after clicking.
  const [rebuildBusy, setRebuildBusy] = useState(false);
  const [rebuildStatus, setRebuildStatus] = useState<string | null>(null);

  const handleRebuild = useCallback(async () => {
    if (rebuildBusy) return;
    setRebuildBusy(true);
    setRebuildStatus(null);
    try {
      const { chunksInStore } = await reconcileKnowledgeBase();
      setRebuildStatus(`Knowledge base rebuilt · ${chunksInStore} chunks`);
    } catch (e: unknown) {
      setRebuildStatus(e instanceof Error ? e.message : 'Rebuild failed');
    } finally {
      setRebuildBusy(false);
      // Auto-dismiss the toast-ish chip after a few seconds so it
      // doesn't linger forever on the panel.
      window.setTimeout(() => setRebuildStatus(null), 4000);
    }
  }, [rebuildBusy]);

  const runDiagnostics = useCallback(async () => {
    setDiagLoading(true);
    setDiagError(null);
    try {
      const d = await fetchDiagnostics();
      setDiag(d);
      setDiagOpen(true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Diagnostics request failed';
      setDiagError(msg);
      setDiagOpen(true);
    } finally {
      setDiagLoading(false);
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const rows = await listDocuments();
      setDocuments(rows);
      setError(null);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to load library';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Poll while anything is still in flight.
  useEffect(() => {
    const anyInFlight = documents.some(
      (d) => d.status === 'UPLOADED' || d.status === 'PROCESSING'
    );
    if (!anyInFlight) return;
    const id = window.setInterval(() => { void refresh(); }, POLL_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [documents, refresh]);

  const handleFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setUploading(true);
    setError(null);
    try {
      for (const f of Array.from(files)) {
        await uploadDocument(f, productLabel || undefined);
      }
      await refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Upload failed';
      setError(msg);
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm('Delete this document and all its indexed chunks?')) return;
    try {
      await deleteDocument(id);
      await refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Delete failed';
      setError(msg);
    }
  };

  const handleRetry = async (id: string) => {
    try {
      await reingestDocument(id);
      await refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Retry failed';
      setError(msg);
    }
  };

  const stats = useMemo(() => {
    const total = documents.length;
    const ready = documents.filter((d) => d.status === 'READY').length;
    const processing = documents.filter((d) => d.status === 'PROCESSING' || d.status === 'UPLOADED').length;
    const failed = documents.filter((d) => d.status === 'FAILED').length;
    const totalChunks = documents.reduce((a, b) => a + (b.chunkCount || 0), 0);
    const totalBytes = documents.reduce((a, b) => a + (b.sizeBytes || 0), 0);
    return { total, ready, processing, failed, totalChunks, totalBytes };
  }, [documents]);

  useEffect(() => {
    onStatsChange?.({
      total: stats.total,
      ready: stats.ready,
      chunks: stats.totalChunks,
      bytes: stats.totalBytes,
    });
  }, [stats, onStatsChange]);

  return (
    <>
      <motion.div
        variants={pageItem}
        className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6"
      >
        <KpiCard
          label="Total documents"
          value={stats.total}
          hint="Reference materials in the library"
          color="violet"
          icon={<Icon.Layers className="w-5 h-5" />}
        />
        <KpiCard
          label="Indexed chunks"
          value={stats.totalChunks}
          hint="Retrievable passages available to the copilot"
          color="fuchsia"
          icon={<Icon.Brain className="w-5 h-5" />}
        />
        <KpiCard
          label="Processing"
          value={stats.processing}
          hint="Still extracting or embedding"
          color="rose"
          icon={<Icon.Refresh className="w-5 h-5" />}
        />
        <KpiCard
          label="Failed"
          value={stats.failed}
          hint="Click a row to see the error"
          color="pink"
          icon={<Icon.Alert className="w-5 h-5" />}
        />
      </motion.div>

      <motion.div variants={pageItem} className="mb-6">
        <div className="rounded-2xl ring-1 ring-slate-200 bg-white">
          <div className="px-4 py-3 flex items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white flex items-center justify-center flex-shrink-0">
                <Icon.Alert className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <div className="text-sm font-semibold text-slate-900">
                  Ingest diagnostics
                </div>
                <div className="text-xs text-slate-500 truncate">
                  {diag
                    ? diag.verdict
                    : 'Upload stuck on UPLOADED? Run a one-shot check of Ollama + the embed pipeline.'}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              {diag && (
                <button
                  type="button"
                  onClick={() => setDiagOpen((v) => !v)}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-700 bg-slate-100 ring-1 ring-slate-200 hover:bg-slate-200 transition"
                >
                  {diagOpen ? 'Hide details' : 'Show details'}
                </button>
              )}
              <button
                type="button"
                onClick={() => void handleRebuild()}
                disabled={rebuildBusy}
                title="Resyncs the in-memory retriever with the chunk table. Use when RAG cites deleted documents."
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-700 bg-white ring-1 ring-slate-200 hover:bg-slate-100 transition disabled:opacity-60"
              >
                {rebuildBusy ? 'Rebuilding…' : 'Rebuild knowledge base'}
              </button>
              <button
                type="button"
                onClick={() => void runDiagnostics()}
                disabled={diagLoading}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-violet-500 to-fuchsia-500 hover:shadow-md hover:shadow-violet-500/30 transition disabled:opacity-60"
              >
                {diagLoading ? 'Checking…' : 'Run diagnostics'}
              </button>
            </div>
          </div>
          {rebuildStatus && (
            <div className="px-4 pb-3 text-[11px] text-emerald-700 bg-emerald-50 ring-1 ring-emerald-200 mx-4 -mt-1 mb-3 rounded-lg py-2 px-3">
              {rebuildStatus}
            </div>
          )}
          {diagOpen && (
            <div className="px-4 pb-4 border-t border-slate-100 pt-3 text-xs text-slate-700 space-y-2">
              {diagError && (
                <div className="px-3 py-2 rounded-lg bg-rose-50 ring-1 ring-rose-200 text-rose-700">
                  {diagError}
                </div>
              )}
              {diag && (
                <>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                    <div className="px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200">
                      <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">
                        Ollama
                      </div>
                      <div className="mt-1 text-slate-900">
                        <span
                          className={`inline-flex w-2 h-2 rounded-full mr-1.5 ${
                            diag.ollama.ping ? 'bg-emerald-500' : 'bg-rose-500'
                          }`}
                        />
                        {diag.ollama.ping ? 'reachable' : 'unreachable'} · {diag.ollama.baseUrl}
                      </div>
                    </div>
                    <div className="px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200">
                      <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">
                        Embedding model
                      </div>
                      <div className="mt-1 text-slate-900">
                        <span
                          className={`inline-flex w-2 h-2 rounded-full mr-1.5 ${
                            diag.ollama.embeddingModelInstalled ? 'bg-emerald-500' : 'bg-rose-500'
                          }`}
                        />
                        {diag.ollama.embeddingModel}
                      </div>
                    </div>
                    <div className="px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200">
                      <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">
                        Chat model
                      </div>
                      <div className="mt-1 text-slate-900">
                        <span
                          className={`inline-flex w-2 h-2 rounded-full mr-1.5 ${
                            diag.ollama.chatModelInstalled ? 'bg-emerald-500' : 'bg-rose-500'
                          }`}
                        />
                        {diag.ollama.chatModel}
                      </div>
                    </div>
                  </div>
                  <div className="px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200">
                    <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">
                      Embedding smoke test
                    </div>
                    {diag.embeddingSmokeTest.ok ? (
                      <div className="mt-1 text-slate-900">
                        <span className="inline-flex w-2 h-2 rounded-full bg-emerald-500 mr-1.5" />
                        {diag.embeddingSmokeTest.dimensions} dims ·{' '}
                        {diag.embeddingSmokeTest.latencyMs} ms · vector store ={' '}
                        {diag.vectorStore.chunks} chunks
                      </div>
                    ) : (
                      <div className="mt-1 text-rose-700">
                        <span className="inline-flex w-2 h-2 rounded-full bg-rose-500 mr-1.5" />
                        {diag.embeddingSmokeTest.error || 'Embed call failed'}
                      </div>
                    )}
                  </div>
                  {diag.ollama.availableModels.length > 0 && (
                    <div className="text-[11px] text-slate-500">
                      Installed models:{' '}
                      <span className="font-mono text-slate-700">
                        {diag.ollama.availableModels.join(', ')}
                      </span>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </motion.div>

      <motion.div variants={pageItem} className="mb-6">
        <Panel
          title="Upload reference material"
          subtitle="PDF, markdown, plain text, or CSV. Drop multiple files to ingest them in sequence."
          icon={<Icon.Bolt className="w-5 h-5" />}
        >
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                void handleFiles(e.dataTransfer.files);
              }}
              className={`lg:col-span-2 rounded-2xl border-2 border-dashed px-6 py-8 flex flex-col items-center justify-center text-center transition ${
                dragging
                  ? 'border-violet-400 bg-violet-50'
                  : 'border-slate-300 bg-slate-50 hover:bg-violet-50/40 hover:border-violet-300'
              }`}
            >
              <div
                className={`w-12 h-12 rounded-xl bg-gradient-to-br ${theme.gradients.kpiA} text-white flex items-center justify-center shadow-lg shadow-violet-500/30`}
              >
                <Icon.Layers className="w-6 h-6" />
              </div>
              <div className="mt-4 text-sm font-semibold text-slate-900">
                {uploading ? 'Uploading…' : dragging ? 'Release to upload' : 'Drag & drop documents here'}
              </div>
              <div className="mt-1 text-xs text-slate-500">
                or click to browse — everything stays on this machine
              </div>
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
                className={`mt-4 px-4 py-2 rounded-xl text-sm font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-lg hover:shadow-violet-500/30 transition disabled:opacity-60`}
              >
                Browse files
              </button>
              <input
                ref={fileInputRef}
                type="file"
                multiple
                accept=".pdf,.md,.txt,.csv"
                className="hidden"
                onChange={(e) => void handleFiles(e.target.files)}
              />
            </div>

            <div className="flex flex-col gap-3">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-500">
                Product label (optional)
              </label>
              <input
                type="text"
                value={productLabel}
                onChange={(e) => setProductLabel(e.target.value)}
                placeholder="e.g. Siemens S7-1500"
                className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 focus:outline-none text-sm"
              />
              <div className="text-xs text-slate-500 leading-relaxed">
                Tagging a document lets you group reference material by
                machine or vendor so you can filter the library later.
                Leave blank for general-purpose research notes.
              </div>
            </div>
          </div>

          {error && (
            <div className="mt-4 px-4 py-3 rounded-xl bg-rose-50 ring-1 ring-rose-200 text-sm text-rose-700 flex items-center gap-2">
              <Icon.Alert className="w-4 h-4" />
              {error}
            </div>
          )}
        </Panel>
      </motion.div>

      <motion.div variants={pageItem}>
        <Panel
          title="Library"
          subtitle={loading ? 'Loading…' : `${documents.length} document${documents.length === 1 ? '' : 's'}`}
          icon={<Icon.Server className="w-5 h-5" />}
        >
          {documents.length === 0 && !loading ? (
            <div className="py-10 text-center">
              <div className="mx-auto w-12 h-12 rounded-xl bg-slate-100 text-slate-400 flex items-center justify-center mb-3">
                <Icon.Layers className="w-6 h-6" />
              </div>
              <div className="text-sm font-semibold text-slate-700">No documents yet</div>
              <div className="text-xs text-slate-500 mt-1">
                Upload a manual or datasheet above to give the copilot something to cite.
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto -mx-2">
              <table className="min-w-full text-sm">
                <thead>
                  <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 border-b border-slate-200">
                    <th className="py-2 px-3">Document</th>
                    <th className="py-2 px-3">Source type</th>
                    <th className="py-2 px-3">Product</th>
                    <th className="py-2 px-3">Size</th>
                    <th className="py-2 px-3">Pages</th>
                    <th className="py-2 px-3">Chunks</th>
                    <th className="py-2 px-3">Status</th>
                    <th className="py-2 px-3">Uploaded</th>
                    <th className="py-2 px-3"></th>
                  </tr>
                </thead>
                <tbody>
                  {documents.map((doc) => {
                    const s = statusStyle(doc.status);
                    return (
                      <tr
                        key={doc.id}
                        className="border-b border-slate-100 hover:bg-violet-50/30 transition"
                      >
                        <td className="py-3 px-3">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white flex items-center justify-center flex-shrink-0">
                              <Icon.Layers className="w-4 h-4" />
                            </div>
                            <div className="min-w-0">
                              <div className="text-sm font-semibold text-slate-900 truncate max-w-xs">
                                {doc.fileName}
                              </div>
                              {doc.errorMessage && (
                                <div className="text-[11px] text-rose-600 mt-0.5 max-w-xs truncate">
                                  {doc.errorMessage}
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                        <td className="py-3 px-3">
                          <SourceTypeSelect doc={doc} onChanged={(updated) => {
                            setDocuments((prev) => prev.map((d) => d.id === updated.id ? updated : d));
                          }} />
                        </td>
                        <td className="py-3 px-3 text-slate-700">
                          {doc.productLabel || <span className="text-slate-400">—</span>}
                        </td>
                        <td className="py-3 px-3 text-slate-600">{formatBytes(doc.sizeBytes)}</td>
                        <td className="py-3 px-3 text-slate-600">
                          {doc.pageCount ?? <span className="text-slate-400">—</span>}
                        </td>
                        <td className="py-3 px-3 text-slate-600">{doc.chunkCount}</td>
                        <td className="py-3 px-3">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold ring-1 ${s.badge}`}
                          >
                            <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
                            {doc.status}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-slate-500 text-xs">
                          {formatRelative(doc.uploadedAt)}
                        </td>
                        <td className="py-3 px-3 text-right">
                          <div className="inline-flex items-center gap-2">
                            {(doc.status === 'UPLOADED' || doc.status === 'FAILED') && (
                              <button
                                onClick={() => void handleRetry(doc.id)}
                                className="px-2.5 py-1 rounded-md text-xs font-semibold text-violet-700 bg-violet-50 ring-1 ring-violet-200 hover:bg-violet-100 transition"
                              >
                                Retry
                              </button>
                            )}
                            <button
                              onClick={() => void handleDelete(doc.id)}
                              className="px-2.5 py-1 rounded-md text-xs font-semibold text-rose-700 bg-rose-50 ring-1 ring-rose-200 hover:bg-rose-100 transition"
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </motion.div>
    </>
  );
};

/* ------------------------------------------------------------------
 * SourceTypeSelect
 *
 * Inline <select> for reassigning a document's source-type class.
 * Optimistically updates the row in place and only re-renders on
 * error (when it reverts to the previous value). We deliberately
 * keep the dropdown tiny + unobtrusive: users mostly accept the
 * heuristic guess, and the override is a rare "oh the classifier
 * got this wrong" action.
 * ---------------------------------------------------------------- */
const SOURCE_TYPE_OPTIONS: Array<{ value: ResearchSourceType; label: string }> = [
  { value: 'VENDOR_MANUAL', label: 'Vendor manual' },
  { value: 'DATASHEET',     label: 'Datasheet' },
  { value: 'ACADEMIC',      label: 'Academic' },
  { value: 'FORUM',         label: 'Forum' },
  { value: 'CODE',          label: 'Code' },
  { value: 'UNKNOWN',       label: 'Unknown' },
];

const SOURCE_TYPE_ROW_COLOUR: Record<string, string> = {
  VENDOR_MANUAL: 'text-emerald-700',
  DATASHEET:     'text-sky-700',
  ACADEMIC:      'text-amber-700',
  FORUM:         'text-rose-700',
  CODE:          'text-slate-700',
  UNKNOWN:       'text-slate-400',
};

interface SourceTypeSelectProps {
  doc: ResearchDocument;
  onChanged: (updated: ResearchDocument) => void;
}
const SourceTypeSelect: React.FC<SourceTypeSelectProps> = ({ doc, onChanged }) => {
  const current: ResearchSourceType = (doc.sourceType as ResearchSourceType) || 'UNKNOWN';
  const [busy, setBusy] = useState(false);
  const handleChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
    const next = e.target.value as ResearchSourceType;
    if (next === current || busy) return;
    setBusy(true);
    try {
      const updated = await setDocumentSourceType(doc.id, next);
      onChanged(updated);
    } catch {
      // Swallow - the row reverts to the previous value automatically
      // because we never mutated local state until the await resolved.
    } finally {
      setBusy(false);
    }
  };
  const colour = SOURCE_TYPE_ROW_COLOUR[current] ?? SOURCE_TYPE_ROW_COLOUR.UNKNOWN;
  return (
    <select
      value={current}
      onChange={handleChange}
      disabled={busy}
      className={`text-xs font-semibold bg-transparent ring-1 ring-slate-200 rounded-md px-2 py-1 focus:ring-violet-300 focus:outline-none ${colour} disabled:opacity-60`}
      aria-label="Source type"
    >
      {SOURCE_TYPE_OPTIONS.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
};

export default LibraryTab;
