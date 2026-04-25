import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Panel, Icon, pageItem, theme } from '../theme';
import {
  InventoryItem,
  InventoryKind,
  DeepExtractionJob,
  ExtractionResult,
  listInventory,
  createInventory,
  updateInventory,
  deleteInventory,
  extractInventory,
  extractInventoryDeep,
  getDeepExtractionStatus,
} from '../../services/inventoryService';

/* ---------------------------------------------------------------------------
 * Reusable inventory table
 *
 * Used twice inside Research Studio: the Inventory tab filters to
 * COMPONENT + PROTOCOL, the Ports & Services tab filters to PORT +
 * SERVICE. Same CRUD, different filter + default-kind.
 * ------------------------------------------------------------------------ */

export interface InventoryTableProps {
  /** Kinds this surface is allowed to show and create. */
  allowedKinds: InventoryKind[];
  /** Default kind the "New item" form starts with. */
  defaultKind: InventoryKind;
  /** Panel title (e.g. "Inventory", "Ports & services"). */
  title: string;
  /** Human description under the title. */
  subtitle: string;
}

const InventoryTable: React.FC<InventoryTableProps> = ({
  allowedKinds,
  defaultKind,
  title,
  subtitle,
}) => {
  const [items, setItems] = useState<InventoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  // Extract-from-corpus state
  const [quickExtracting, setQuickExtracting] = useState(false);
  const [extractToast, setExtractToast] = useState<ExtractionResult | null>(null);
  const [deepJob, setDeepJob] = useState<DeepExtractionJob | null>(null);

  // Composer state (also reused for inline edit)
  const [kind, setKind] = useState<InventoryKind>(defaultKind);
  const [name, setName] = useState('');
  const [reference, setReference] = useState('');
  const [details, setDetails] = useState('');
  const [tags, setTags] = useState('');

  const refresh = useCallback(async () => {
    setError(null);
    try {
      const [rows, job] = await Promise.all([
        listInventory(allowedKinds),
        getDeepExtractionStatus().catch(() => null),
      ]);
      setItems(rows);
      if (job) setDeepJob(job);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load inventory');
    } finally {
      setLoading(false);
    }
  }, [allowedKinds]);

  useEffect(() => { void refresh(); }, [refresh]);

  // Poll while a deep extract is in flight. Stops automatically once
  // the job row leaves GENERATING. Re-fetches the inventory list once
  // the job finishes so newly-written rows show up without a manual
  // reload.
  const deepRunning = deepJob?.status === 'GENERATING';
  useEffect(() => {
    if (!deepRunning) return;
    const h = window.setInterval(() => { void refresh(); }, 3000);
    return () => window.clearInterval(h);
  }, [deepRunning, refresh]);

  const resetComposer = () => {
    setKind(defaultKind);
    setName('');
    setReference('');
    setDetails('');
    setTags('');
    setCreating(false);
    setEditingId(null);
  };

  const startEdit = (it: InventoryItem) => {
    setEditingId(it.id);
    setCreating(true); // same form
    setKind(it.kind);
    setName(it.name);
    setReference(it.reference ?? '');
    setDetails(it.details ?? '');
    setTags(it.tags ?? '');
  };

  const submit = async () => {
    if (!name.trim()) return;
    try {
      if (editingId) {
        await updateInventory(editingId, {
          kind,
          name: name.trim(),
          details: details.trim() || undefined,
          reference: reference.trim() || undefined,
          tags: tags.trim() || undefined,
        });
      } else {
        await createInventory({
          kind,
          name: name.trim(),
          details: details.trim() || undefined,
          reference: reference.trim() || undefined,
          tags: tags.trim() || undefined,
          source: 'analyst:manual',
        });
      }
      resetComposer();
      await refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Save failed');
    }
  };

  const remove = async (id: string) => {
    if (!window.confirm('Delete this entry?')) return;
    try {
      await deleteInventory(id);
      await refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Delete failed');
    }
  };

  const counts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const it of items) out[it.kind] = (out[it.kind] ?? 0) + 1;
    return out;
  }, [items]);

  const handleQuickExtract = async () => {
    setError(null);
    setExtractToast(null);
    setQuickExtracting(true);
    try {
      const result = await extractInventory();
      setExtractToast(result);
      await refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Extraction failed');
    } finally {
      setQuickExtracting(false);
    }
  };

  const handleDeepExtract = async () => {
    setError(null);
    try {
      const job = await extractInventoryDeep();
      setDeepJob(job);
      // Polling effect takes over from here.
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Deep extract failed to start');
    }
  };

  return (
    <motion.div variants={pageItem} className="space-y-6">
      <Panel
        title={title}
        subtitle={subtitle}
        icon={<Icon.Server className="w-5 h-5" />}
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void handleQuickExtract()}
              disabled={quickExtracting || deepRunning}
              title="Scan this bundle's documents for well-known ports, protocols and services using regex."
              className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-700 bg-slate-100 ring-1 ring-slate-200 hover:bg-slate-200 transition inline-flex items-center gap-1.5 disabled:opacity-50"
            >
              <Icon.Refresh className={`w-3.5 h-3.5 ${quickExtracting ? 'animate-spin' : ''}`} />
              {quickExtracting ? 'Extracting…' : 'Extract from corpus'}
            </button>
            <button
              type="button"
              onClick={() => void handleDeepExtract()}
              disabled={quickExtracting || deepRunning}
              title="Use the local LLM for a slower, richer pass. Runs in the background."
              className="px-3 py-1.5 rounded-lg text-xs font-semibold text-violet-700 bg-violet-50 ring-1 ring-violet-200 hover:bg-violet-100 transition inline-flex items-center gap-1.5 disabled:opacity-50"
            >
              <Icon.Bolt className="w-3.5 h-3.5" />
              Deep extract
            </button>
            <button
              type="button"
              onClick={() => { resetComposer(); setCreating(true); }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-md transition`}
            >
              + New entry
            </button>
          </div>
        }
      >
        {/* Kind roll-up pills */}
        {items.length > 0 && (
          <div className="mb-4 flex flex-wrap gap-2">
            {allowedKinds.map(k => (
              <span
                key={k}
                className="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 ring-1 ring-slate-200"
              >
                {k.toLowerCase()}: <b>{counts[k] ?? 0}</b>
              </span>
            ))}
          </div>
        )}

        {error && (
          <div className="mb-3 px-3 py-2 rounded-lg bg-rose-50 ring-1 ring-rose-200 text-xs text-rose-700 flex items-center gap-2">
            <Icon.Alert className="w-3.5 h-3.5" />
            {error}
          </div>
        )}

        {/* Quick-extract toast - green on success, grey if nothing new was found */}
        {extractToast && (
          <div className={`mb-3 px-3 py-2 rounded-lg text-xs ring-1 flex items-start gap-2 ${
            extractToast.itemsCreated > 0
              ? 'bg-emerald-50 ring-emerald-200 text-emerald-800'
              : 'bg-slate-50 ring-slate-200 text-slate-600'
          }`}>
            <Icon.CheckCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <div className="font-semibold">
                {extractToast.itemsCreated > 0
                  ? `Regex extract added ${extractToast.itemsCreated} new item(s)`
                  : 'Regex extract found nothing new'}
              </div>
              <div className="text-[11px] mt-0.5 opacity-80">
                Scanned {extractToast.chunksScanned} chunk(s) across {extractToast.documentsScanned} document(s)
                {extractToast.itemsCreated > 0 && (
                  <> · {extractToast.portsCreated} port(s), {extractToast.protocolsCreated} protocol(s), {extractToast.servicesCreated} service(s)</>
                )}
              </div>
            </div>
            <button
              onClick={() => setExtractToast(null)}
              className="text-[11px] font-semibold opacity-70 hover:opacity-100"
            >
              dismiss
            </button>
          </div>
        )}

        {/* Deep extract status banner */}
        {deepJob && deepJob.status === 'GENERATING' && (
          <div className="mb-3 px-3 py-2 rounded-lg bg-violet-50 ring-1 ring-violet-200 text-xs text-violet-800 flex items-center gap-2">
            <Icon.Refresh className="w-3.5 h-3.5 animate-spin flex-shrink-0" />
            <div className="flex-1">
              <div className="font-semibold">Deep extract running…</div>
              <div className="text-[11px] mt-0.5 opacity-80">
                Local LLM is reading the corpus. This can take a minute or more on CPU-only hosts; you can navigate away and come back.
              </div>
            </div>
          </div>
        )}
        {deepJob && deepJob.status === 'READY' && deepJob.finishedAt && (
          <div className="mb-3 px-3 py-2 rounded-lg bg-emerald-50 ring-1 ring-emerald-200 text-xs text-emerald-800 flex items-start gap-2">
            <Icon.CheckCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <div className="font-semibold">Deep extract complete</div>
              <div className="text-[11px] mt-0.5 opacity-80">{deepJob.message}</div>
            </div>
            <button
              onClick={() => setDeepJob({ ...deepJob, status: 'IDLE' })}
              className="text-[11px] font-semibold opacity-70 hover:opacity-100"
            >
              dismiss
            </button>
          </div>
        )}
        {deepJob && deepJob.status === 'FAILED' && (
          <div className="mb-3 px-3 py-2 rounded-lg bg-rose-50 ring-1 ring-rose-200 text-xs text-rose-700 flex items-start gap-2">
            <Icon.Alert className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <div className="font-semibold">Deep extract failed</div>
              <div className="text-[11px] mt-0.5 opacity-80">{deepJob.message}</div>
            </div>
            <button
              onClick={() => setDeepJob({ ...deepJob, status: 'IDLE' })}
              className="text-[11px] font-semibold opacity-70 hover:opacity-100"
            >
              dismiss
            </button>
          </div>
        )}

        {/* Composer (create + edit share this) */}
        {creating && (
          <div className="mb-4 rounded-xl bg-slate-50 ring-1 ring-slate-200 p-3 space-y-2">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
              <Labelled label="Kind">
                <select
                  value={kind}
                  onChange={(e) => setKind(e.target.value as InventoryKind)}
                  className="w-full px-2 py-1.5 rounded-lg ring-1 ring-slate-200 text-sm bg-white"
                >
                  {allowedKinds.map(k => (
                    <option key={k} value={k}>{k.toLowerCase()}</option>
                  ))}
                </select>
              </Labelled>
              <Labelled label="Name *">
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={placeholderFor(kind, 'name')}
                  className="w-full px-2 py-1.5 rounded-lg ring-1 ring-slate-200 text-sm"
                />
              </Labelled>
              <Labelled label="Reference">
                <input
                  value={reference}
                  onChange={(e) => setReference(e.target.value)}
                  placeholder={placeholderFor(kind, 'reference')}
                  className="w-full px-2 py-1.5 rounded-lg ring-1 ring-slate-200 text-sm font-mono"
                />
              </Labelled>
              <Labelled label="Tags">
                <input
                  value={tags}
                  onChange={(e) => setTags(e.target.value)}
                  placeholder="comma,separated"
                  className="w-full px-2 py-1.5 rounded-lg ring-1 ring-slate-200 text-sm"
                />
              </Labelled>
            </div>
            <Labelled label="Details">
              <textarea
                rows={2}
                value={details}
                onChange={(e) => setDetails(e.target.value)}
                placeholder="Datasheet excerpts, config notes, anything worth keeping."
                className="w-full px-2 py-1.5 rounded-lg ring-1 ring-slate-200 text-sm"
              />
            </Labelled>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => void submit()}
                disabled={!name.trim()}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} disabled:opacity-50`}
              >
                {editingId ? 'Save changes' : 'Add entry'}
              </button>
              <button
                type="button"
                onClick={resetComposer}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-700 bg-white ring-1 ring-slate-200"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* List */}
        {items.length === 0 && !loading ? (
          <div className="py-10 text-center">
            <div className="mx-auto w-12 h-12 rounded-xl bg-slate-100 text-slate-400 flex items-center justify-center mb-3">
              <Icon.Server className="w-6 h-6" />
            </div>
            <div className="text-sm font-semibold text-slate-700">Nothing inventoried yet</div>
            <div className="text-xs text-slate-500 mt-1">
              Click "New entry" above to capture a {allowedKinds.map(k => k.toLowerCase()).join(' / ')}.
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto -mx-2">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 border-b border-slate-200">
                  <th className="py-2 px-3">Name</th>
                  <th className="py-2 px-3">Kind</th>
                  <th className="py-2 px-3">Reference</th>
                  <th className="py-2 px-3">Tags</th>
                  <th className="py-2 px-3">Updated</th>
                  <th className="py-2 px-3"></th>
                </tr>
              </thead>
              <tbody>
                {items.map(it => (
                  <tr key={it.id} className="border-b border-slate-100 hover:bg-violet-50/30 transition align-top">
                    <td className="py-3 px-3">
                      <div className="text-sm font-semibold text-slate-900">{it.name}</div>
                      {it.details && (
                        <div className="text-[11px] text-slate-600 mt-0.5 whitespace-pre-wrap max-w-lg">
                          {it.details}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-violet-50 text-violet-700 ring-1 ring-violet-200">
                        {it.kind.toLowerCase()}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-xs text-slate-700 font-mono">
                      {it.reference ?? <span className="text-slate-400 font-sans">—</span>}
                    </td>
                    <td className="py-3 px-3 text-xs text-slate-600">
                      {it.tags
                        ? it.tags.split(',').map((t, i) =>
                            <span key={i} className="inline-block mr-1 mb-0.5 px-1.5 py-0.5 rounded bg-slate-100 text-slate-600">{t.trim()}</span>
                          )
                        : <span className="text-slate-400">—</span>}
                    </td>
                    <td className="py-3 px-3 text-xs text-slate-500">
                      {formatRelative(it.updatedAt)}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <div className="inline-flex items-center gap-2">
                        <button
                          onClick={() => startEdit(it)}
                          className="px-2 py-1 rounded-md text-xs font-semibold text-violet-700 bg-violet-50 ring-1 ring-violet-200 hover:bg-violet-100 transition"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => void remove(it.id)}
                          className="px-2 py-1 rounded-md text-xs font-semibold text-rose-700 bg-rose-50 ring-1 ring-rose-200 hover:bg-rose-100 transition"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </motion.div>
  );
};

const Labelled: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className="flex flex-col gap-1">
    <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
      {label}
    </label>
    {children}
  </div>
);

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

function placeholderFor(kind: InventoryKind, field: 'name' | 'reference'): string {
  if (field === 'name') {
    switch (kind) {
      case 'COMPONENT': return 'e.g. STM32F407 microcontroller';
      case 'PROTOCOL':  return 'e.g. Modbus TCP';
      case 'PORT':      return 'e.g. Port 502/TCP';
      case 'SERVICE':   return 'e.g. Web UI (admin)';
    }
  }
  switch (kind) {
    case 'COMPONENT': return 'U4, CN1 pin 3, …';
    case 'PROTOCOL':  return 'IEC 60870-5-104';
    case 'PORT':      return 'eth0, MGMT, RJ45-1';
    case 'SERVICE':   return 'systemd unit, port';
  }
}

export default InventoryTable;
