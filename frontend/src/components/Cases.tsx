import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  caseService, CaseDTO, CaseStats, CaseStatus, CasePriority,
  statusTone, priorityTone, severityDot, formatDuration, ageSince,
  CreateCaseRequest, CaseCategory,
} from '../services/caseService';
import { PageHero, KpiCard, Panel, Icon, pageContainer, pageItem, theme } from './theme';
import CaseDetailDrawer from './cases/CaseDetailDrawer';

const STATUS_OPTIONS: Array<CaseStatus | 'ALL'> = [
  'ALL', 'NEW', 'TRIAGING', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'CLOSED',
];
const PRIORITY_OPTIONS: Array<CasePriority | 'ALL'> = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const Cases: React.FC = () => {
  const [cases, setCases] = useState<CaseDTO[]>([]);
  const [stats, setStats] = useState<CaseStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState<CaseStatus | 'ALL'>('ALL');
  const [priorityFilter, setPriorityFilter] = useState<CasePriority | 'ALL'>('ALL');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [size] = useState(25);
  const [totalElements, setTotalElements] = useState(0);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showNew, setShowNew] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [list, st] = await Promise.all([
        caseService.list({
          status: statusFilter === 'ALL' ? undefined : statusFilter,
          priority: priorityFilter === 'ALL' ? undefined : priorityFilter,
          search: search || undefined,
          page,
          size,
          sortBy: 'createdAt',
          sortDir: 'desc',
        }),
        caseService.stats(),
      ]);
      setCases(list.content);
      setTotalElements(list.totalElements);
      setStats(st);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to load cases';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, priorityFilter, search, page, size]);

  useEffect(() => { void refresh(); }, [refresh]);

  const onCreate = async (req: CreateCaseRequest) => {
    const created = await caseService.create(req);
    setShowNew(false);
    setSelectedId(created.id);
    void refresh();
  };

  const onCaseChanged = () => { void refresh(); };

  const totalPages = Math.max(1, Math.ceil(totalElements / size));

  const kpis = useMemo(() => {
    if (!stats) return [];
    return [
      { label: 'Open', value: stats.open, hint: `${stats.inProgress} in progress`, color: 'violet' as const, icon: <Icon.Layers className="w-5 h-5" /> },
      { label: 'Critical', value: stats.critical, hint: 'Across all statuses', color: 'rose' as const, icon: <Icon.Alert className="w-5 h-5" /> },
      { label: 'Resolved (7d)', value: stats.resolved7d, hint: `${stats.falsePositive7d} marked FP`, color: 'fuchsia' as const, icon: <Icon.CheckCircle className="w-5 h-5" /> },
      {
        label: 'Avg MTTR (7d)',
        value: formatDuration(stats.avgMttResolveSeconds7d),
        hint: `MTT-Ack ${formatDuration(stats.avgMttAcknowledgeSeconds7d)}`,
        color: 'pink' as const,
        icon: <Icon.Clock className="w-5 h-5" />,
      },
    ];
  }, [stats]);

  return (
    <motion.div
      className="min-h-screen p-6 md:p-8"
      style={{ background: theme.pageBackground }}
      variants={pageContainer} initial="hidden" animate="visible"
    >
      <PageHero
        eyebrow="SOC Workbench"
        icon={<Icon.Layers className="w-4 h-4" />}
        title="Incident & Case Management"
        subtitle="Every correlated alert, IOC, and response action - one investigation file. Track MTTR, keep timelines, close the loop."
        actions={
          <div className="flex gap-3">
            <button
              onClick={() => void refresh()}
              className="px-4 py-2 rounded-xl bg-white/10 hover:bg-white/20 ring-1 ring-white/20 text-sm font-medium backdrop-blur-sm flex items-center gap-2 transition"
            >
              <Icon.Refresh className="w-4 h-4" /> Refresh
            </button>
            <button
              onClick={() => setShowNew(true)}
              className="px-4 py-2 rounded-xl bg-white text-violet-700 hover:bg-violet-50 text-sm font-semibold flex items-center gap-2 shadow-lg transition"
            >
              <Icon.Bolt className="w-4 h-4" /> New Case
            </button>
          </div>
        }
        stats={stats ? [
          { label: 'Total cases', value: stats.total },
          { label: 'Open now', value: stats.open },
          { label: 'Contained', value: stats.contained },
        ] : undefined}
      />

      {/* KPI ribbon */}
      <motion.div variants={pageItem} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {kpis.map((k, i) => (
          <KpiCard key={i} label={k.label} value={k.value} hint={k.hint} color={k.color} icon={k.icon} />
        ))}
      </motion.div>

      {/* Filters + search */}
      <motion.div variants={pageItem}>
        <Panel className="mb-6">
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap gap-2">
              {STATUS_OPTIONS.map(s => {
                const active = statusFilter === s;
                return (
                  <button
                    key={s}
                    onClick={() => { setStatusFilter(s); setPage(0); }}
                    className={`px-3 py-1.5 rounded-full text-xs font-semibold transition ring-1 ${
                      active
                        ? 'bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white ring-violet-500 shadow'
                        : 'bg-white text-slate-600 ring-slate-200 hover:ring-violet-300 hover:text-violet-700'
                    }`}
                  >
                    {s === 'ALL' ? 'All statuses' : s.replace('_', ' ')}
                    {stats && s !== 'ALL' && (
                      <span className={`ml-1.5 text-[10px] ${active ? 'text-violet-100' : 'text-slate-400'}`}>
                        {stats.statusDistribution[s] ?? 0}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            <div className="flex flex-wrap gap-2 items-center">
              {PRIORITY_OPTIONS.map(p => {
                const active = priorityFilter === p;
                return (
                  <button
                    key={p}
                    onClick={() => { setPriorityFilter(p); setPage(0); }}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-bold uppercase tracking-wide transition ring-1 ${
                      active
                        ? 'bg-slate-900 text-white ring-slate-900'
                        : 'bg-slate-50 text-slate-600 ring-slate-200 hover:bg-slate-100'
                    }`}
                  >
                    {p === 'ALL' ? 'Any priority' : p}
                  </button>
                );
              })}

              <div className="relative ml-auto w-full sm:w-80">
                <Icon.Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={search}
                  onChange={e => { setSearch(e.target.value); setPage(0); }}
                  placeholder="Search case # / title / description…"
                  className="w-full pl-9 pr-3 py-2 text-sm rounded-xl ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-500 outline-none bg-white"
                />
              </div>
            </div>
          </div>
        </Panel>
      </motion.div>

      {/* Table */}
      <motion.div variants={pageItem}>
        <Panel
          title="Cases"
          subtitle={totalElements > 0 ? `${totalElements} match${totalElements === 1 ? '' : 'es'}` : 'No matching cases'}
          icon={<Icon.Layers className="w-5 h-5" />}
        >
          {error && (
            <div className="mb-4 p-3 rounded-lg bg-rose-50 ring-1 ring-rose-200 text-sm text-rose-700">
              {error}
            </div>
          )}

          <div className="overflow-x-auto -mx-6 px-6">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wider text-slate-500 border-b border-slate-200">
                  <th className="py-2 pr-3">Case</th>
                  <th className="py-2 pr-3">Title</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Priority</th>
                  <th className="py-2 pr-3">Assignee</th>
                  <th className="py-2 pr-3">Age</th>
                  <th className="py-2 pr-3">Linked</th>
                  <th className="py-2 pr-0 text-right">MTTR</th>
                </tr>
              </thead>
              <tbody>
                {loading && cases.length === 0 && (
                  <tr><td colSpan={8} className="py-10 text-center text-slate-400">Loading cases…</td></tr>
                )}
                {!loading && cases.length === 0 && (
                  <tr><td colSpan={8} className="py-10 text-center text-slate-400">No cases match the current filters.</td></tr>
                )}
                {cases.map(c => (
                  <tr
                    key={c.id}
                    onClick={() => setSelectedId(c.id)}
                    className="border-b border-slate-100 hover:bg-violet-50/40 cursor-pointer transition"
                  >
                    <td className="py-3 pr-3 font-mono text-xs text-slate-500">{c.caseNumber}</td>
                    <td className="py-3 pr-3">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${severityDot(c.severity)}`} />
                        <span className="font-medium text-slate-900 line-clamp-1">{c.title}</span>
                      </div>
                      {c.tags && c.tags.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {c.tags.slice(0, 3).map(t => (
                            <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600">
                              #{t}
                            </span>
                          ))}
                          {c.tags.length > 3 && (
                            <span className="text-[10px] text-slate-400">+{c.tags.length - 3}</span>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="py-3 pr-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold ring-1 ${statusTone(c.status)}`}>
                        {c.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="py-3 pr-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide ring-1 ${priorityTone(c.priority)}`}>
                        {c.priority}
                      </span>
                    </td>
                    <td className="py-3 pr-3">
                      {c.assigneeName ? (
                        <span className="inline-flex items-center gap-2">
                          <span className="w-6 h-6 rounded-full bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white text-[10px] flex items-center justify-center font-bold">
                            {initials(c.assigneeName)}
                          </span>
                          <span className="text-slate-700">{c.assigneeName}</span>
                        </span>
                      ) : (
                        <span className="text-slate-400 italic text-xs">Unassigned</span>
                      )}
                    </td>
                    <td className="py-3 pr-3 text-slate-500 font-mono text-xs">{ageSince(c.createdAt)}</td>
                    <td className="py-3 pr-3">
                      <span className="text-xs text-slate-600">
                        {c.linkedAlertCount ?? 0} alerts · {c.artifactCount ?? 0} IOCs
                      </span>
                    </td>
                    <td className="py-3 pr-0 text-right text-xs font-mono text-slate-600">
                      {formatDuration(c.mttResolveSeconds)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="mt-4 flex items-center justify-between text-xs text-slate-500">
              <div>Page {page + 1} of {totalPages}</div>
              <div className="flex gap-1">
                <button
                  onClick={() => setPage(0)}
                  disabled={page === 0}
                  className="px-2 py-1 rounded-md ring-1 ring-slate-200 bg-white hover:bg-slate-50 disabled:opacity-40"
                >First</button>
                <button
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="px-2 py-1 rounded-md ring-1 ring-slate-200 bg-white hover:bg-slate-50 disabled:opacity-40"
                >Prev</button>
                <span className="px-3 py-1 rounded-md bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white font-semibold">
                  {page + 1}
                </span>
                <button
                  onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                  className="px-2 py-1 rounded-md ring-1 ring-slate-200 bg-white hover:bg-slate-50 disabled:opacity-40"
                >Next</button>
                <button
                  onClick={() => setPage(totalPages - 1)}
                  disabled={page >= totalPages - 1}
                  className="px-2 py-1 rounded-md ring-1 ring-slate-200 bg-white hover:bg-slate-50 disabled:opacity-40"
                >Last</button>
              </div>
            </div>
          )}
        </Panel>
      </motion.div>

      {/* New case modal */}
      {showNew && <NewCaseModal onClose={() => setShowNew(false)} onCreate={onCreate} />}

      {/* Detail drawer */}
      {selectedId && (
        <CaseDetailDrawer
          caseId={selectedId}
          onClose={() => setSelectedId(null)}
          onChanged={onCaseChanged}
        />
      )}
    </motion.div>
  );
};

// ---------- New Case modal ----------
const NewCaseModal: React.FC<{
  onClose: () => void;
  onCreate: (req: CreateCaseRequest) => Promise<void>;
}> = ({ onClose, onCreate }) => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState<CasePriority>('MEDIUM');
  const [category, setCategory] = useState<CaseCategory>('OTHER');
  const [assignee, setAssignee] = useState('');
  const [tags, setTags] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const submit = async () => {
    if (!title.trim()) return;
    setSubmitting(true);
    try {
      await onCreate({
        title: title.trim(),
        description: description.trim() || undefined,
        priority,
        category,
        assigneeName: assignee.trim() || undefined,
        assigneeId: assignee.trim() || undefined,
        reporterName: 'analyst',
        tags: tags.split(',').map(t => t.trim()).filter(Boolean),
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm">
      <div className="bg-white rounded-2xl w-full max-w-lg ring-1 ring-slate-200 shadow-2xl overflow-hidden">
        <div
          className="px-6 py-4 text-white"
          style={{ background: theme.gradients.hero }}
        >
          <div className="text-xs uppercase tracking-wider text-violet-200">New investigation</div>
          <div className="text-lg font-bold">Open a case</div>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">Title</label>
            <input
              value={title}
              onChange={e => setTitle(e.target.value)}
              placeholder="Short summary - e.g. 'Suspicious MODBUS write to PLC-04'"
              className="w-full mt-1 px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-500 outline-none text-sm"
            />
          </div>
          <div>
            <label className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">Description</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              rows={3}
              placeholder="What do you know so far? Add context - sources, timestamps, impacted assets."
              className="w-full mt-1 px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-500 outline-none text-sm"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">Priority</label>
              <select
                value={priority}
                onChange={e => setPriority(e.target.value as CasePriority)}
                className="w-full mt-1 px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-500 outline-none text-sm bg-white"
              >
                {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(p => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">Category</label>
              <select
                value={category}
                onChange={e => setCategory(e.target.value as CaseCategory)}
                className="w-full mt-1 px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-500 outline-none text-sm bg-white"
              >
                {(['MALWARE', 'UNAUTHORIZED_ACCESS', 'POLICY_VIOLATION', 'ANOMALY', 'RECON',
                   'LATERAL_MOVEMENT', 'OT_DISRUPTION', 'DATA_EXFIL', 'INSIDER_THREAT', 'OTHER'] as const).map(c => (
                  <option key={c} value={c}>{c.replace(/_/g, ' ')}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">Assignee</label>
            <input
              value={assignee}
              onChange={e => setAssignee(e.target.value)}
              placeholder="Analyst name (leave blank for unassigned)"
              className="w-full mt-1 px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-500 outline-none text-sm"
            />
          </div>
          <div>
            <label className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">Tags</label>
            <input
              value={tags}
              onChange={e => setTags(e.target.value)}
              placeholder="comma, separated, tags"
              className="w-full mt-1 px-3 py-2 rounded-lg ring-1 ring-slate-200 focus:ring-2 focus:ring-violet-500 outline-none text-sm"
            />
          </div>
        </div>
        <div className="px-6 py-4 bg-slate-50 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm rounded-lg ring-1 ring-slate-200 bg-white hover:bg-slate-100"
          >Cancel</button>
          <button
            onClick={submit}
            disabled={submitting || !title.trim()}
            className="px-4 py-2 text-sm rounded-lg text-white font-semibold bg-gradient-to-r from-violet-600 to-fuchsia-600 hover:from-violet-700 hover:to-fuchsia-700 disabled:opacity-50"
          >{submitting ? 'Creating…' : 'Open case'}</button>
        </div>
      </div>
    </div>
  );
};

// ---------- helpers ----------
function initials(name?: string | null) {
  if (!name) return '?';
  return name.split(/\s+/).slice(0, 2).map(s => s[0]?.toUpperCase() ?? '').join('');
}

export default Cases;
