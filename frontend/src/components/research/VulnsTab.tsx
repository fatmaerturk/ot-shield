import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { KpiCard, Panel, Icon, pageItem, theme } from '../theme';
import {
  VulnObservation,
  VulnStatus,
  VulnSeverity,
  VulnConfidence,
  VulnComponentType,
  VulnEvent,
  VulnKpi,
  VulnTransitions,
  listVulns,
  getVuln,
  getVulnEvents,
  getVulnTransitions,
  getVulnKpi,
  createVuln,
  updateVuln,
  transitionVuln,
  deleteVuln,
  scanVulnSignals,
  SignalScanResult,
} from '../../services/vulnService';

/* ---------------------------------------------------------------------------
 * Research Studio - Vulnerability Observations tab
 *
 * HMGCC Co-Creation "Smart personal assistant for security researchers":
 * a researcher-authored hypothesis ledger with an explicit lifecycle
 * (DRAFT -> UNDER_REVIEW -> VERIFIED -> MITIGATED), confidence grades,
 * alternative theories, and an append-only audit timeline so every
 * decision is attributable. Offline-first - no CVE feed lookups.
 * ------------------------------------------------------------------------ */

const SEVERITY_ORDER: VulnSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const STATUS_ORDER: VulnStatus[] = [
  'DRAFT', 'UNDER_REVIEW', 'VERIFIED', 'MITIGATED', 'DISMISSED', 'FALSE_POSITIVE',
];
const COMPONENT_ORDER: VulnComponentType[] = [
  'PROTOCOL', 'INTERFACE', 'FIRMWARE', 'SOFTWARE',
  'HARDWARE_COMPONENT', 'CONFIGURATION', 'SUPPLY_CHAIN', 'OTHER',
];
const CONFIDENCE_ORDER: VulnConfidence[] = ['HIGH', 'MEDIUM', 'LOW'];

const severityStyle = (s: VulnSeverity) => {
  switch (s) {
    case 'CRITICAL': return { badge: 'bg-rose-100 text-rose-700 ring-rose-200',        dot: 'bg-rose-600' };
    case 'HIGH':     return { badge: 'bg-orange-100 text-orange-700 ring-orange-200',  dot: 'bg-orange-500' };
    case 'MEDIUM':   return { badge: 'bg-amber-100 text-amber-700 ring-amber-200',     dot: 'bg-amber-500' };
    case 'LOW':      return { badge: 'bg-sky-100 text-sky-700 ring-sky-200',           dot: 'bg-sky-500' };
    case 'INFO':
    default:         return { badge: 'bg-slate-100 text-slate-700 ring-slate-200',     dot: 'bg-slate-400' };
  }
};

const statusStyle = (s: VulnStatus) => {
  switch (s) {
    case 'DRAFT':          return { badge: 'bg-slate-100 text-slate-700 ring-slate-200',   dot: 'bg-slate-400' };
    case 'UNDER_REVIEW':   return { badge: 'bg-violet-100 text-violet-700 ring-violet-200', dot: 'bg-violet-500' };
    case 'VERIFIED':       return { badge: 'bg-emerald-100 text-emerald-700 ring-emerald-200', dot: 'bg-emerald-500' };
    case 'MITIGATED':      return { badge: 'bg-teal-100 text-teal-700 ring-teal-200',      dot: 'bg-teal-500' };
    case 'DISMISSED':      return { badge: 'bg-stone-100 text-stone-700 ring-stone-200',   dot: 'bg-stone-400' };
    case 'FALSE_POSITIVE': return { badge: 'bg-rose-50 text-rose-700 ring-rose-200',       dot: 'bg-rose-400' };
    default:               return { badge: 'bg-slate-100 text-slate-700 ring-slate-200',   dot: 'bg-slate-400' };
  }
};

const confidenceStyle = (c: VulnConfidence) => {
  switch (c) {
    case 'HIGH':   return 'text-emerald-600';
    case 'MEDIUM': return 'text-amber-600';
    case 'LOW':
    default:       return 'text-rose-600';
  }
};

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

// ---------------------------------------------------------------------------
// Main tab component
// ---------------------------------------------------------------------------

const VulnsTab: React.FC = () => {
  const [kpi, setKpi] = useState<VulnKpi | null>(null);
  const [rows, setRows] = useState<VulnObservation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [fStatus, setFStatus] = useState<VulnStatus | ''>('');
  const [fSeverity, setFSeverity] = useState<VulnSeverity | ''>('');
  const [fComponent, setFComponent] = useState<VulnComponentType | ''>('');
  const [fNeedsMore, setFNeedsMore] = useState<boolean | null>(null);

  // Drawer + modal state
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showNewModal, setShowNewModal] = useState(false);

  // Signal scan state
  const [scanning, setScanning] = useState(false);
  const [scanToast, setScanToast] = useState<SignalScanResult | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [k, list] = await Promise.all([
        getVulnKpi(),
        listVulns({
          status: fStatus || undefined,
          severity: fSeverity || undefined,
          componentType: fComponent || undefined,
          needsMoreSources: fNeedsMore === null ? undefined : fNeedsMore,
        }),
      ]);
      setKpi(k);
      setRows(list);
      setError(null);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to load observations';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [fStatus, fSeverity, fComponent, fNeedsMore]);

  useEffect(() => { void refresh(); }, [refresh]);

  const clearFilters = () => {
    setFStatus(''); setFSeverity(''); setFComponent(''); setFNeedsMore(null);
  };

  const handleScan = async () => {
    setScanning(true);
    setScanToast(null);
    setError(null);
    try {
      const result = await scanVulnSignals();
      setScanToast(result);
      await refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const anyFilter = fStatus || fSeverity || fComponent || fNeedsMore !== null;

  return (
    <>
      {/* KPI row */}
      <motion.div
        variants={pageItem}
        className="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-6"
      >
        <KpiCard
          label="Open"
          value={kpi?.openCount ?? 0}
          hint="Not yet mitigated or dismissed"
          color="violet"
          icon={<Icon.Shield className="w-5 h-5" />}
        />
        <KpiCard
          label="Needs sources"
          value={kpi?.needsMoreSourcesCount ?? 0}
          hint="Flagged for more evidence"
          color="rose"
          icon={<Icon.Search className="w-5 h-5" />}
        />
        <KpiCard
          label="Under review"
          value={kpi?.underReviewCount ?? 0}
          hint="Awaiting verification"
          color="fuchsia"
          icon={<Icon.Clock className="w-5 h-5" />}
        />
        <KpiCard
          label="Verified · high"
          value={kpi?.verifiedHighOrCriticalCount ?? 0}
          hint="Confirmed HIGH / CRITICAL items"
          color="pink"
          icon={<Icon.Alert className="w-5 h-5" />}
        />
        <KpiCard
          label="Mitigated"
          value={kpi?.mitigatedCount ?? 0}
          hint="Closed out as fixed"
          color="violet"
          icon={<Icon.CheckCircle className="w-5 h-5" />}
        />
      </motion.div>

      {/* Filter + actions bar */}
      <motion.div variants={pageItem} className="mb-6">
        <Panel
          title="Filter observations"
          subtitle="Narrow the table by status, severity, component type, or the 'needs more sources' flag."
          icon={<Icon.Filter className="w-5 h-5" />}
          actions={
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => void handleScan()}
                disabled={scanning}
                title="Regex-scan the bundle's documents for common security signals. Produces DRAFT observations you can verify."
                className="px-4 py-2 rounded-xl text-sm font-semibold text-slate-700 bg-slate-100 ring-1 ring-slate-200 hover:bg-slate-200 transition inline-flex items-center gap-1.5 disabled:opacity-50"
              >
                <Icon.Search className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
                {scanning ? 'Scanning…' : 'Scan for signals'}
              </button>
              <button
                type="button"
                onClick={() => setShowNewModal(true)}
                className={`px-4 py-2 rounded-xl text-sm font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-lg hover:shadow-violet-500/30 transition`}
              >
                + New observation
              </button>
            </div>
          }
        >
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <Select
              label="Status"
              value={fStatus}
              onChange={(v) => setFStatus(v as VulnStatus | '')}
              options={['', ...STATUS_ORDER]}
              emptyLabel="Any status"
            />
            <Select
              label="Severity"
              value={fSeverity}
              onChange={(v) => setFSeverity(v as VulnSeverity | '')}
              options={['', ...SEVERITY_ORDER]}
              emptyLabel="Any severity"
            />
            <Select
              label="Component"
              value={fComponent}
              onChange={(v) => setFComponent(v as VulnComponentType | '')}
              options={['', ...COMPONENT_ORDER]}
              emptyLabel="Any component"
            />
            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Needs more sources
              </label>
              <div className="flex gap-2">
                {[
                  { label: 'Any',   v: null },
                  { label: 'Yes',   v: true },
                  { label: 'No',    v: false },
                ].map(opt => (
                  <button
                    key={opt.label}
                    type="button"
                    onClick={() => setFNeedsMore(opt.v as boolean | null)}
                    className={`flex-1 px-2 py-1.5 rounded-lg text-xs font-semibold ring-1 transition ${
                      fNeedsMore === opt.v
                        ? 'bg-violet-100 text-violet-700 ring-violet-300'
                        : 'bg-white text-slate-600 ring-slate-200 hover:bg-slate-50'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
          {anyFilter && (
            <div className="mt-3">
              <button
                type="button"
                onClick={clearFilters}
                className="text-xs font-semibold text-violet-600 hover:text-violet-800 transition"
              >
                Clear filters
              </button>
            </div>
          )}
        </Panel>
      </motion.div>

      {/* Table */}
      <motion.div variants={pageItem}>
        <Panel
          title="Observations"
          subtitle={loading
            ? 'Loading…'
            : `${rows.length} observation${rows.length === 1 ? '' : 's'}${anyFilter ? ' matching filters' : ''}`}
          icon={<Icon.Shield className="w-5 h-5" />}
        >
          {error && (
            <div className="mb-4 px-4 py-3 rounded-xl bg-rose-50 ring-1 ring-rose-200 text-sm text-rose-700 flex items-center gap-2">
              <Icon.Alert className="w-4 h-4" />
              {error}
            </div>
          )}

          {scanToast && (
            <div className={`mb-4 px-4 py-3 rounded-xl ring-1 flex items-start gap-2 text-sm ${
              scanToast.draftsCreated > 0
                ? 'bg-emerald-50 ring-emerald-200 text-emerald-800'
                : 'bg-slate-50 ring-slate-200 text-slate-700'
            }`}>
              <Icon.CheckCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <div className="font-semibold">
                  {scanToast.draftsCreated > 0
                    ? `Signal scan drafted ${scanToast.draftsCreated} new observation(s)`
                    : 'Signal scan found nothing new'}
                </div>
                <div className="text-[11px] mt-0.5 opacity-80">
                  Scanned {scanToast.chunksScanned} chunk(s) across {scanToast.documentsScanned} document(s).
                  {scanToast.draftsCreated > 0 && (
                    <>
                      {' '}Breakdown: {scanToast.insecureRemoteCount} insecure-remote
                      {' '}· {scanToast.weakAuthCount} weak-auth
                      {' '}· {scanToast.cryptoCount} crypto
                      {' '}· {scanToast.firmwareCount} firmware
                      {' '}· {scanToast.cveCount} CVE mention(s).
                      {' '}All land as <b>DRAFT</b> with low confidence - verify before trusting.
                    </>
                  )}
                </div>
              </div>
              <button
                onClick={() => setScanToast(null)}
                className="text-[11px] font-semibold opacity-70 hover:opacity-100"
              >
                dismiss
              </button>
            </div>
          )}
          {rows.length === 0 && !loading ? (
            <div className="py-10 text-center">
              <div className="mx-auto w-12 h-12 rounded-xl bg-slate-100 text-slate-400 flex items-center justify-center mb-3">
                <Icon.Shield className="w-6 h-6" />
              </div>
              <div className="text-sm font-semibold text-slate-700">No observations yet</div>
              <div className="text-xs text-slate-500 mt-1">
                Promote an answer from the Threads tab, or click "New observation" above.
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto -mx-2">
              <table className="min-w-full text-sm">
                <thead>
                  <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 border-b border-slate-200">
                    <th className="py-2 px-3">Title</th>
                    <th className="py-2 px-3">Severity</th>
                    <th className="py-2 px-3">Status</th>
                    <th className="py-2 px-3">Confidence</th>
                    <th className="py-2 px-3">Component</th>
                    <th className="py-2 px-3">Sources</th>
                    <th className="py-2 px-3">Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(v => {
                    const sv = severityStyle(v.severity);
                    const st = statusStyle(v.status);
                    return (
                      <tr
                        key={v.id}
                        onClick={() => setSelectedId(v.id)}
                        className="border-b border-slate-100 hover:bg-violet-50/30 transition cursor-pointer"
                      >
                        <td className="py-3 px-3">
                          <div className="flex items-start gap-3">
                            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white flex items-center justify-center flex-shrink-0">
                              <Icon.Shield className="w-4 h-4" />
                            </div>
                            <div className="min-w-0">
                              <div className="text-sm font-semibold text-slate-900 truncate max-w-md">
                                {v.title}
                              </div>
                              {v.componentRef && (
                                <div className="text-[11px] text-slate-500 truncate max-w-md">
                                  {v.componentRef}
                                </div>
                              )}
                              {v.needsMoreSources && (
                                <div className="mt-1 inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-rose-50 text-rose-600 ring-1 ring-rose-200">
                                  needs more sources
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                        <td className="py-3 px-3">
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold ring-1 ${sv.badge}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${sv.dot}`} />
                            {v.severity}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold ring-1 ${st.badge}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${st.dot}`} />
                            {v.status.replace('_', ' ')}
                          </span>
                        </td>
                        <td className={`py-3 px-3 text-xs font-semibold ${confidenceStyle(v.confidence)}`}>
                          {v.confidence}
                        </td>
                        <td className="py-3 px-3 text-slate-700 text-xs">
                          {v.componentType.replace('_', ' ').toLowerCase()}
                        </td>
                        <td className="py-3 px-3 text-slate-600 text-xs">
                          {v.citations.length > 0
                            ? `${v.citations.length} cited`
                            : <span className="text-slate-400">-</span>}
                        </td>
                        <td className="py-3 px-3 text-slate-500 text-xs">
                          {formatRelative(v.updatedAt)}
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

      {/* Drawer */}
      <AnimatePresence>
        {selectedId && (
          <VulnDetailDrawer
            id={selectedId}
            onClose={() => { setSelectedId(null); void refresh(); }}
          />
        )}
      </AnimatePresence>

      {/* New modal */}
      <AnimatePresence>
        {showNewModal && (
          <NewVulnModal
            onClose={() => setShowNewModal(false)}
            onCreated={() => { setShowNewModal(false); void refresh(); }}
          />
        )}
      </AnimatePresence>
    </>
  );
};

// ---------------------------------------------------------------------------
// Select - compact dropdown used in the filter bar
// ---------------------------------------------------------------------------

interface SelectProps {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: string[];
  emptyLabel?: string;
}
const Select: React.FC<SelectProps> = ({ label, value, onChange, options, emptyLabel }) => (
  <div className="flex flex-col gap-1">
    <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
      {label}
    </label>
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 focus:outline-none text-sm bg-white"
    >
      {options.map(opt => (
        <option key={opt} value={opt}>
          {opt === '' ? (emptyLabel ?? 'Any') : opt.replace('_', ' ')}
        </option>
      ))}
    </select>
  </div>
);

// ---------------------------------------------------------------------------
// VulnDetailDrawer - right-side slide-over
// ---------------------------------------------------------------------------

interface VulnDetailDrawerProps {
  id: string;
  onClose: () => void;
}
const VulnDetailDrawer: React.FC<VulnDetailDrawerProps> = ({ id, onClose }) => {
  const [vuln, setVuln] = useState<VulnObservation | null>(null);
  const [events, setEvents] = useState<VulnEvent[]>([]);
  const [transitions, setTransitions] = useState<VulnTransitions | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [transitioning, setTransitioning] = useState<VulnStatus | null>(null);
  const [comment, setComment] = useState('');

  // Edit form state (mirrors the observation fields we allow editing)
  const [editDraft, setEditDraft] = useState<Partial<VulnObservation>>({});

  const load = useCallback(async () => {
    try {
      const [v, ev, tr] = await Promise.all([
        getVuln(id),
        getVulnEvents(id),
        getVulnTransitions(id),
      ]);
      setVuln(v);
      setEvents(ev);
      setTransitions(tr);
      setEditDraft(v);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  const saveEdit = async () => {
    if (!vuln) return;
    try {
      await updateVuln(vuln.id, {
        title: editDraft.title,
        summary: editDraft.summary ?? undefined,
        componentType: editDraft.componentType,
        componentRef: editDraft.componentRef ?? undefined,
        affectedProduct: editDraft.affectedProduct ?? undefined,
        severity: editDraft.severity,
        cveId: editDraft.cveId ?? undefined,
        cvssV31: editDraft.cvssV31 ?? undefined,
        confidence: editDraft.confidence,
        needsMoreSources: editDraft.needsMoreSources,
        mitigationSummary: editDraft.mitigationSummary ?? undefined,
        alternativeHypotheses: editDraft.alternativeHypotheses ?? undefined,
        tags: editDraft.tags ?? undefined,
      });
      setEditing(false);
      void load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Update failed');
    }
  };

  const runTransition = async (to: VulnStatus) => {
    if (!vuln) return;
    try {
      await transitionVuln(vuln.id, {
        toStatus: to,
        comment: comment.trim() || undefined,
        actor: undefined,
      });
      setTransitioning(null);
      setComment('');
      void load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Transition failed');
    }
  };

  const handleDelete = async () => {
    if (!vuln) return;
    if (!window.confirm('Delete this observation and its full event log?')) return;
    try {
      await deleteVuln(vuln.id);
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Delete failed');
    }
  };

  return (
    <>
      {/* Backdrop */}
      <motion.div
        className="fixed inset-0 bg-slate-900/20 backdrop-blur-sm z-40"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
      />
      {/* Panel */}
      <motion.aside
        className="fixed inset-y-0 right-0 w-full max-w-2xl bg-white shadow-2xl z-50 overflow-y-auto"
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'tween', duration: 0.25 }}
      >
        <div className="p-6">
          {loading && <div className="text-sm text-slate-500">Loading…</div>}
          {error && (
            <div className="mb-4 px-4 py-3 rounded-xl bg-rose-50 ring-1 ring-rose-200 text-sm text-rose-700 flex items-center gap-2">
              <Icon.Alert className="w-4 h-4" />
              {error}
            </div>
          )}
          {vuln && !loading && (
            <>
              {/* Header */}
              <div className="flex items-start justify-between gap-4 mb-4">
                <div className="min-w-0">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-1">
                    Vulnerability observation
                  </div>
                  {editing ? (
                    <input
                      value={editDraft.title ?? ''}
                      onChange={(e) => setEditDraft({ ...editDraft, title: e.target.value })}
                      className="w-full text-xl font-bold text-slate-900 px-2 py-1 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 focus:outline-none"
                    />
                  ) : (
                    <h2 className="text-xl font-bold text-slate-900">{vuln.title}</h2>
                  )}
                </div>
                <button
                  onClick={onClose}
                  className="p-2 rounded-lg text-slate-500 hover:bg-slate-100 transition flex-shrink-0"
                  aria-label="Close"
                >
                  ✕
                </button>
              </div>

              {/* Badges */}
              <div className="flex flex-wrap items-center gap-2 mb-5">
                <Badge kind="severity" value={vuln.severity} />
                <Badge kind="status"   value={vuln.status} />
                <span className={`text-xs font-semibold ${confidenceStyle(vuln.confidence)}`}>
                  confidence: {vuln.confidence}
                </span>
                {vuln.needsMoreSources && (
                  <span className="text-[11px] font-semibold bg-rose-50 text-rose-600 ring-1 ring-rose-200 px-2 py-0.5 rounded-full">
                    needs more sources
                  </span>
                )}
              </div>

              {/* Edit / Save / Delete row */}
              <div className="flex items-center gap-2 mb-6">
                {editing ? (
                  <>
                    <button
                      onClick={saveEdit}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-violet-500 to-fuchsia-500"
                    >
                      Save
                    </button>
                    <button
                      onClick={() => { setEditing(false); setEditDraft(vuln); }}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-700 bg-slate-100 ring-1 ring-slate-200"
                    >
                      Cancel
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      onClick={() => setEditing(true)}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold text-violet-700 bg-violet-50 ring-1 ring-violet-200 hover:bg-violet-100 transition"
                    >
                      Edit
                    </button>
                    <button
                      onClick={handleDelete}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold text-rose-700 bg-rose-50 ring-1 ring-rose-200 hover:bg-rose-100 transition"
                    >
                      Delete
                    </button>
                  </>
                )}
              </div>

              {/* Fields grid */}
              <div className="grid grid-cols-2 gap-4 text-sm mb-6">
                <Field label="Component type">
                  {editing ? (
                    <select
                      value={editDraft.componentType ?? 'OTHER'}
                      onChange={(e) => setEditDraft({ ...editDraft, componentType: e.target.value as VulnComponentType })}
                      className="w-full px-2 py-1 rounded-lg ring-1 ring-slate-200 text-sm bg-white"
                    >
                      {COMPONENT_ORDER.map(c => <option key={c} value={c}>{c.replace('_', ' ')}</option>)}
                    </select>
                  ) : vuln.componentType.replace('_', ' ').toLowerCase()}
                </Field>
                <Field label="Component ref">
                  {editing ? (
                    <input
                      value={editDraft.componentRef ?? ''}
                      onChange={(e) => setEditDraft({ ...editDraft, componentRef: e.target.value })}
                      className="w-full px-2 py-1 rounded-lg ring-1 ring-slate-200 text-sm"
                    />
                  ) : (vuln.componentRef ?? <span className="text-slate-400">-</span>)}
                </Field>
                <Field label="Affected product">
                  {editing ? (
                    <input
                      value={editDraft.affectedProduct ?? ''}
                      onChange={(e) => setEditDraft({ ...editDraft, affectedProduct: e.target.value })}
                      className="w-full px-2 py-1 rounded-lg ring-1 ring-slate-200 text-sm"
                    />
                  ) : (vuln.affectedProduct ?? <span className="text-slate-400">-</span>)}
                </Field>
                <Field label="Severity">
                  {editing ? (
                    <select
                      value={editDraft.severity ?? 'INFO'}
                      onChange={(e) => setEditDraft({ ...editDraft, severity: e.target.value as VulnSeverity })}
                      className="w-full px-2 py-1 rounded-lg ring-1 ring-slate-200 text-sm bg-white"
                    >
                      {SEVERITY_ORDER.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  ) : vuln.severity}
                </Field>
                <Field label="CVE ID">
                  {editing ? (
                    <input
                      value={editDraft.cveId ?? ''}
                      placeholder="CVE-2024-0000"
                      onChange={(e) => setEditDraft({ ...editDraft, cveId: e.target.value })}
                      className="w-full px-2 py-1 rounded-lg ring-1 ring-slate-200 text-sm font-mono"
                    />
                  ) : (vuln.cveId ?? <span className="text-slate-400">-</span>)}
                </Field>
                <Field label="CVSS v3.1">
                  {editing ? (
                    <input
                      value={editDraft.cvssV31 ?? ''}
                      placeholder="7.5 or vector string"
                      onChange={(e) => setEditDraft({ ...editDraft, cvssV31: e.target.value })}
                      className="w-full px-2 py-1 rounded-lg ring-1 ring-slate-200 text-sm font-mono"
                    />
                  ) : (vuln.cvssV31 ?? <span className="text-slate-400">-</span>)}
                </Field>
                <Field label="Confidence">
                  {editing ? (
                    <select
                      value={editDraft.confidence ?? 'LOW'}
                      onChange={(e) => setEditDraft({ ...editDraft, confidence: e.target.value as VulnConfidence })}
                      className="w-full px-2 py-1 rounded-lg ring-1 ring-slate-200 text-sm bg-white"
                    >
                      {CONFIDENCE_ORDER.map(c => <option key={c} value={c}>{c}</option>)}
                    </select>
                  ) : vuln.confidence}
                </Field>
                <Field label="Needs more sources">
                  {editing ? (
                    <label className="inline-flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={editDraft.needsMoreSources ?? false}
                        onChange={(e) => setEditDraft({ ...editDraft, needsMoreSources: e.target.checked })}
                      />
                      <span className="text-sm">Yes</span>
                    </label>
                  ) : (vuln.needsMoreSources ? 'Yes' : 'No')}
                </Field>
              </div>

              {/* Summary */}
              <div className="mb-5">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Summary</div>
                {editing ? (
                  <textarea
                    rows={5}
                    value={editDraft.summary ?? ''}
                    onChange={(e) => setEditDraft({ ...editDraft, summary: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                  />
                ) : (
                  <div className="whitespace-pre-wrap text-sm text-slate-800 bg-slate-50 rounded-lg p-3 ring-1 ring-slate-100">
                    {vuln.summary || <span className="text-slate-400">-</span>}
                  </div>
                )}
              </div>

              {/* Alternative hypotheses */}
              <div className="mb-5">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
                  Alternative hypotheses
                </div>
                {editing ? (
                  <textarea
                    rows={3}
                    value={editDraft.alternativeHypotheses ?? ''}
                    placeholder="- Alt theory 1&#10;- Alt theory 2"
                    onChange={(e) => setEditDraft({ ...editDraft, alternativeHypotheses: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                  />
                ) : (
                  <div className="whitespace-pre-wrap text-sm text-slate-800 bg-amber-50/40 rounded-lg p-3 ring-1 ring-amber-200/60">
                    {vuln.alternativeHypotheses || <span className="text-slate-400">-</span>}
                  </div>
                )}
              </div>

              {/* Mitigation (only meaningful post-VERIFIED) */}
              {(vuln.status === 'VERIFIED' || vuln.status === 'MITIGATED' || editing) && (
                <div className="mb-5">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
                    Mitigation summary
                  </div>
                  {editing ? (
                    <textarea
                      rows={3}
                      value={editDraft.mitigationSummary ?? ''}
                      onChange={(e) => setEditDraft({ ...editDraft, mitigationSummary: e.target.value })}
                      className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                    />
                  ) : (
                    <div className="whitespace-pre-wrap text-sm text-slate-800 bg-emerald-50/40 rounded-lg p-3 ring-1 ring-emerald-200/60">
                      {vuln.mitigationSummary || <span className="text-slate-400">-</span>}
                    </div>
                  )}
                </div>
              )}

              {/* Citations */}
              {vuln.citations.length > 0 && (
                <div className="mb-5">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
                    Citations ({vuln.citations.length})
                  </div>
                  <ul className="space-y-2">
                    {vuln.citations.map(c => (
                      <li key={c.index} className="rounded-lg ring-1 ring-slate-200 bg-white px-3 py-2 text-xs">
                        <div className="font-semibold text-slate-800">
                          [{c.index}] {c.source}
                          {c.page && <span className="text-slate-500 font-normal"> · p. {c.page}</span>}
                          <span className="ml-2 text-slate-400 font-normal">score {c.score.toFixed(2)}</span>
                        </div>
                        {c.snippet && (
                          <div className="mt-1 text-slate-600 italic">"{c.snippet}"</div>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Status transitions */}
              {!editing && transitions && transitions.next.length > 0 && (
                <div className="mb-6">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
                    Advance this observation
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {transitions.next.map(next => {
                      const st = statusStyle(next);
                      return (
                        <button
                          key={next}
                          type="button"
                          onClick={() => setTransitioning(next)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-semibold ring-1 ${st.badge} hover:opacity-80 transition`}
                        >
                          → {next.replace('_', ' ')}
                        </button>
                      );
                    })}
                  </div>
                  {transitioning && (
                    <div className="mt-3 p-3 rounded-lg bg-slate-50 ring-1 ring-slate-200">
                      <div className="text-xs font-semibold text-slate-700 mb-2">
                        Transition to <span className="text-violet-700">{transitioning.replace('_', ' ')}</span>
                      </div>
                      <textarea
                        rows={2}
                        placeholder="Optional comment for the audit log…"
                        value={comment}
                        onChange={(e) => setComment(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm mb-2"
                      />
                      <div className="flex gap-2">
                        <button
                          onClick={() => runTransition(transitioning)}
                          className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-violet-500 to-fuchsia-500"
                        >
                          Confirm transition
                        </button>
                        <button
                          onClick={() => { setTransitioning(null); setComment(''); }}
                          className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-700 bg-white ring-1 ring-slate-200"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Audit timeline */}
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
                  Audit timeline ({events.length} event{events.length === 1 ? '' : 's'})
                </div>
                <ol className="relative border-l-2 border-slate-200 pl-4 space-y-3">
                  {events.map(e => (
                    <li key={e.id} className="relative">
                      <span className="absolute -left-[1.37rem] top-1 w-3 h-3 rounded-full bg-violet-400 ring-4 ring-white" />
                      <div className="text-xs font-semibold text-slate-700">
                        {e.kind}
                        {e.fromStatus && e.toStatus && (
                          <span className="font-normal text-slate-500">
                            {' '}· {e.fromStatus.replace('_', ' ')} → {e.toStatus.replace('_', ' ')}
                          </span>
                        )}
                      </div>
                      {e.comment && (
                        <div className="text-xs text-slate-600 mt-0.5 italic">"{e.comment}"</div>
                      )}
                      <div className="text-[10px] text-slate-400 mt-0.5">
                        {e.actor ?? 'system'} · {formatRelative(e.createdAt)}
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            </>
          )}
        </div>
      </motion.aside>
    </>
  );
};

// Small field helper for the drawer grid
const Field: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div>
    <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-1">{label}</div>
    <div className="text-sm text-slate-800">{children}</div>
  </div>
);

// Small badge helper used in the drawer header
interface BadgeProps {
  kind: 'severity' | 'status';
  value: string;
}
const Badge: React.FC<BadgeProps> = ({ kind, value }) => {
  const s = kind === 'severity'
    ? severityStyle(value as VulnSeverity)
    : statusStyle(value as VulnStatus);
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold ring-1 ${s.badge}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {value.replace('_', ' ')}
    </span>
  );
};

// ---------------------------------------------------------------------------
// NewVulnModal - manual create
// ---------------------------------------------------------------------------

interface NewVulnModalProps {
  onClose: () => void;
  onCreated: () => void;
}
const NewVulnModal: React.FC<NewVulnModalProps> = ({ onClose, onCreated }) => {
  const [title, setTitle] = useState('');
  const [summary, setSummary] = useState('');
  const [componentType, setComponentType] = useState<VulnComponentType>('PROTOCOL');
  const [componentRef, setComponentRef] = useState('');
  const [affectedProduct, setAffectedProduct] = useState('');
  const [severity, setSeverity] = useState<VulnSeverity>('MEDIUM');
  const [confidence, setConfidence] = useState<VulnConfidence>('MEDIUM');
  const [cveId, setCveId] = useState('');
  const [cvssV31, setCvssV31] = useState('');
  const [needsMoreSources, setNeedsMoreSources] = useState(false);
  const [alternativeHypotheses, setAlternativeHypotheses] = useState('');
  const [tags, setTags] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = title.trim().length > 0 && !submitting;

  const submit = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      await createVuln({
        title: title.trim(),
        summary: summary || undefined,
        componentType,
        componentRef: componentRef || undefined,
        affectedProduct: affectedProduct || undefined,
        severity,
        confidence,
        cveId: cveId || undefined,
        cvssV31: cvssV31 || undefined,
        needsMoreSources,
        alternativeHypotheses: alternativeHypotheses || undefined,
        tags: tags || undefined,
      });
      onCreated();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Create failed');
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
        <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
          <div className="p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  New observation
                </div>
                <h2 className="text-xl font-bold text-slate-900">Record a vulnerability observation</h2>
                <div className="text-xs text-slate-500 mt-1">
                  Starts in DRAFT. Advance it through the lifecycle after peer review.
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
              <Labelled label="Title *">
                <input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="Short, action-oriented headline"
                  className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-400 focus:outline-none text-sm"
                />
              </Labelled>

              <div className="grid grid-cols-2 gap-3">
                <Labelled label="Component type">
                  <select
                    value={componentType}
                    onChange={(e) => setComponentType(e.target.value as VulnComponentType)}
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm bg-white"
                  >
                    {COMPONENT_ORDER.map(c => <option key={c} value={c}>{c.replace('_', ' ')}</option>)}
                  </select>
                </Labelled>
                <Labelled label="Component ref">
                  <input
                    value={componentRef}
                    onChange={(e) => setComponentRef(e.target.value)}
                    placeholder="Port 23 on mgmt NIC"
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                  />
                </Labelled>
                <Labelled label="Affected product">
                  <input
                    value={affectedProduct}
                    onChange={(e) => setAffectedProduct(e.target.value)}
                    placeholder="SamplePLC-7800"
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                  />
                </Labelled>
                <Labelled label="Tags">
                  <input
                    value={tags}
                    onChange={(e) => setTags(e.target.value)}
                    placeholder="comma,separated"
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                  />
                </Labelled>
                <Labelled label="Severity">
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as VulnSeverity)}
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm bg-white"
                  >
                    {SEVERITY_ORDER.map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </Labelled>
                <Labelled label="Confidence">
                  <select
                    value={confidence}
                    onChange={(e) => setConfidence(e.target.value as VulnConfidence)}
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm bg-white"
                  >
                    {CONFIDENCE_ORDER.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </Labelled>
                <Labelled label="CVE ID (optional)">
                  <input
                    value={cveId}
                    onChange={(e) => setCveId(e.target.value)}
                    placeholder="CVE-2024-0000"
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm font-mono"
                  />
                </Labelled>
                <Labelled label="CVSS v3.1 (optional)">
                  <input
                    value={cvssV31}
                    onChange={(e) => setCvssV31(e.target.value)}
                    placeholder="7.5 or vector string"
                    className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm font-mono"
                  />
                </Labelled>
              </div>

              <Labelled label="Summary">
                <textarea
                  rows={3}
                  value={summary}
                  onChange={(e) => setSummary(e.target.value)}
                  placeholder="What's the observation? What made you flag it?"
                  className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                />
              </Labelled>

              <Labelled label="Alternative hypotheses">
                <textarea
                  rows={2}
                  value={alternativeHypotheses}
                  onChange={(e) => setAlternativeHypotheses(e.target.value)}
                  placeholder={"- Could also be...\n- Or alternatively..."}
                  className="w-full px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm"
                />
              </Labelled>

              <label className="inline-flex items-center gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={needsMoreSources}
                  onChange={(e) => setNeedsMoreSources(e.target.checked)}
                />
                Needs more sources (keep visible in the "Needs sources" KPI)
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
                disabled={!canSubmit}
                className={`px-4 py-2 rounded-xl text-sm font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} disabled:opacity-60 hover:shadow-lg hover:shadow-violet-500/30 transition`}
              >
                {submitting ? 'Creating…' : 'Create observation'}
              </button>
            </div>
          </div>
        </div>
      </motion.div>
    </>
  );
};

const Labelled: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className="flex flex-col gap-1">
    <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</label>
    {children}
  </div>
);

export default VulnsTab;
