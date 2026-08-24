import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  iec62443Service, IecPosture, IecFR, IecRequirement, IecStatus,
} from '../services/iec62443Service';
import { PageHero, KpiCard, Panel, Icon, pageContainer, pageItem } from './theme';

// ---------- status visuals ----------
const STATUS_TONE: Record<IecStatus, string> = {
  COMPLIANT: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  PARTIAL: 'bg-amber-50 text-amber-700 ring-amber-200',
  NON_COMPLIANT: 'bg-rose-50 text-rose-700 ring-rose-200',
  NOT_ASSESSED: 'bg-slate-100 text-slate-500 ring-slate-200',
};
const STATUS_LABEL: Record<IecStatus, string> = {
  COMPLIANT: 'Compliant',
  PARTIAL: 'Partial',
  NON_COMPLIANT: 'Non-compliant',
  NOT_ASSESSED: 'Not assessed',
};
const STATUS_DOT: Record<IecStatus, string> = {
  COMPLIANT: 'bg-emerald-500',
  PARTIAL: 'bg-amber-500',
  NON_COMPLIANT: 'bg-rose-500',
  NOT_ASSESSED: 'bg-slate-300',
};

const StatusBadge: React.FC<{ status: IecStatus }> = ({ status }) => (
  <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold ring-1 ${STATUS_TONE[status]}`}>
    <span className={`w-1.5 h-1.5 rounded-full ${STATUS_DOT[status]}`} />
    {STATUS_LABEL[status]}
  </span>
);

/** The 62443 SL vector cell: achieved vs target for one FR. */
const SlDial: React.FC<{ achieved: number; target: number; label: string; sub: string }> = ({ achieved, target, label, sub }) => {
  const met = achieved >= target;
  return (
    <div className="rounded-xl ring-1 ring-slate-200 bg-white p-3 text-center">
      <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{label}</div>
      <div className="mt-1 flex items-baseline justify-center gap-1">
        <span className={`text-2xl font-bold ${met ? 'text-emerald-600' : achieved > 0 ? 'text-amber-600' : 'text-slate-400'}`}>SL {achieved}</span>
        <span className="text-xs text-slate-400">/ {target}</span>
      </div>
      <div className="mt-0.5 text-[10px] text-slate-500 truncate" title={sub}>{sub}</div>
    </div>
  );
};

const IEC62443Compliance: React.FC = () => {
  const [posture, setPosture] = useState<IecPosture | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>('FR1');
  const [statusFilter, setStatusFilter] = useState<IecStatus | 'ALL'>('ALL');

  const refresh = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      setPosture(await iec62443Service.getPosture());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load IEC 62443 posture');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const slVectorText = useMemo(() => {
    if (!posture) return '';
    return posture.foundationalRequirements.map((f) => f.achievedSL).join(' ');
  }, [posture]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-violet-200 border-t-violet-600" />
      </div>
    );
  }
  if (error || !posture) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="rounded-xl bg-rose-50 ring-1 ring-rose-200 text-rose-700 px-6 py-4 font-medium">
          {error || 'No data'}
        </div>
      </div>
    );
  }

  const o = posture.overall;

  return (
    <motion.div variants={pageContainer} initial="hidden" animate="visible" className="space-y-6">
      <PageHero
        eyebrow="GOVERN · IACS SECURITY"
        title="ISA/IEC 62443-3-3 Compliance"
        subtitle={`System security requirements & security levels for ${posture.organization.name} · ${posture.organization.sector}. Status is derived live from real platform telemetry - requirements with no telemetry basis are shown as "not assessed", never assumed.`}
        icon={<Icon.Lock className="w-6 h-6" />}
        stats={[
          { label: 'Achieved SL (min)', value: `SL ${o.achievedSL}`, sub: `Target SL ${o.targetSL}` },
          { label: 'Coverage', value: `${o.coveragePct}%`, sub: o.classification },
          { label: 'Compliant', value: `${o.compliant}/${o.totalRequirements}`, sub: `${o.partial} partial · ${o.notAssessed} n/a` },
          { label: 'SL vector', value: slVectorText, sub: 'FR1 → FR7' },
        ]}
      />

      {/* SL vector: achieved vs target per Foundational Requirement */}
      <motion.div variants={pageItem}>
        <Panel title="Security Level vector" subtitle="Achieved SL-A vs target SL-T per Foundational Requirement (the weakest FR sets the overall SL)" icon={<Icon.Target className="w-4 h-4" />}>
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
            {posture.foundationalRequirements.map((f) => (
              <SlDial key={f.fr} achieved={f.achievedSL} target={f.targetSL} label={f.fr} sub={f.code} />
            ))}
          </div>
        </Panel>
      </motion.div>

      {/* Zones (real, from asset Purdue levels) */}
      {posture.zones.length > 0 && (
        <motion.div variants={pageItem}>
          <Panel title="Zones & conduits" subtitle="Derived from discovered assets grouped by Purdue level (62443-3-2)" icon={<Icon.Network className="w-4 h-4" />}>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {posture.zones.map((z) => (
                <div key={z.level} className="rounded-xl ring-1 ring-slate-200 bg-white p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold text-slate-800">{z.name}</span>
                    <span className="text-[10px] font-bold text-violet-600">SL-T {z.suggestedTargetSL}</span>
                  </div>
                  <div className="mt-1 text-xs text-slate-500">{z.assetCount} asset(s) · {z.backedUp} backed up</div>
                </div>
              ))}
            </div>
          </Panel>
        </motion.div>
      )}

      {/* Foundational Requirements - expandable full SR catalogue */}
      <motion.div variants={pageItem} className="space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <h2 className="text-lg font-bold text-slate-800">Foundational Requirements</h2>
          <div className="flex gap-1 p-1 bg-slate-100 rounded-xl ring-1 ring-slate-200">
            {(['ALL', 'COMPLIANT', 'PARTIAL', 'NOT_ASSESSED'] as const).map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition ${
                  statusFilter === s ? 'bg-white text-violet-700 shadow' : 'text-slate-500 hover:text-slate-700'
                }`}
              >
                {s === 'ALL' ? 'All' : STATUS_LABEL[s as IecStatus]}
              </button>
            ))}
          </div>
        </div>

        {posture.foundationalRequirements.map((f) => (
          <FrCard key={f.fr} fr={f} expanded={expanded === f.fr} onToggle={() => setExpanded(expanded === f.fr ? null : f.fr)} statusFilter={statusFilter} />
        ))}
      </motion.div>

      {/* Reference: SL model + standard parts */}
      <motion.div variants={pageItem} className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Panel title="Security levels (SL 0-4)" subtitle="Protection against increasing adversary capability" icon={<Icon.Shield className="w-4 h-4" />}>
          <div className="space-y-2">
            {posture.securityLevels.map((sl) => (
              <div key={sl.sl} className="flex gap-3 items-start">
                <span className="flex-shrink-0 mt-0.5 inline-flex items-center justify-center w-9 h-6 rounded-md bg-violet-50 text-violet-700 ring-1 ring-violet-200 text-xs font-bold">SL{sl.sl}</span>
                <div>
                  <div className="text-sm font-semibold text-slate-800">{sl.name}</div>
                  <div className="text-xs text-slate-500">{sl.description}</div>
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="The IEC 62443 family" subtitle="This page assesses part 3-3 (highlighted)" icon={<Icon.Layers className="w-4 h-4" />}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
            {posture.standardParts.map((p) => (
              <div key={p.part} className={`flex gap-2 items-center px-2.5 py-1.5 rounded-lg text-xs ${p.focus ? 'bg-violet-50 ring-1 ring-violet-200' : ''}`}>
                <span className={`font-mono font-bold ${p.focus ? 'text-violet-700' : 'text-slate-400'}`}>{p.part}</span>
                <span className={p.focus ? 'text-violet-900 font-semibold' : 'text-slate-600'}>{p.title}</span>
              </div>
            ))}
          </div>
        </Panel>
      </motion.div>
    </motion.div>
  );
};

const FrCard: React.FC<{ fr: IecFR; expanded: boolean; onToggle: () => void; statusFilter: IecStatus | 'ALL' }> = ({ fr, expanded, onToggle, statusFilter }) => {
  const met = fr.achievedSL >= fr.targetSL;
  const reqs = statusFilter === 'ALL' ? fr.requirements : fr.requirements.filter((r) => r.status === statusFilter);
  return (
    <div className="rounded-2xl ring-1 ring-slate-200 bg-white overflow-hidden">
      <button onClick={onToggle} className="w-full flex items-center gap-4 p-4 text-left hover:bg-slate-50 transition">
        <span className="flex-shrink-0 inline-flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white font-bold text-sm">{fr.fr}</span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold text-slate-800">{fr.name} <span className="text-slate-400 font-normal">({fr.code})</span></div>
          <div className="text-xs text-slate-500 truncate">{fr.description}</div>
        </div>
        <div className="hidden sm:flex items-center gap-4 flex-shrink-0">
          <div className="text-center">
            <div className={`text-lg font-bold ${met ? 'text-emerald-600' : fr.achievedSL > 0 ? 'text-amber-600' : 'text-slate-400'}`}>SL {fr.achievedSL}</div>
            <div className="text-[10px] text-slate-400">of {fr.targetSL}</div>
          </div>
          <div className="w-28">
            <div className="flex justify-between text-[10px] text-slate-500 mb-0.5"><span>{fr.coveragePct}%</span><span>{fr.compliant}/{fr.total}</span></div>
            <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
              <div className="h-full bg-gradient-to-r from-violet-500 to-fuchsia-500 rounded-full" style={{ width: `${fr.coveragePct}%` }} />
            </div>
          </div>
        </div>
        <span className={`flex-shrink-0 text-slate-400 transition-transform ${expanded ? 'rotate-90' : ''}`}>›</span>
      </button>

      {expanded && (
        <div className="border-t border-slate-100 divide-y divide-slate-100">
          {reqs.length === 0 ? (
            <div className="p-4 text-xs text-slate-400 text-center">No requirements match the filter.</div>
          ) : reqs.map((r) => <SrRow key={r.id} req={r} />)}
        </div>
      )}
    </div>
  );
};

const SrRow: React.FC<{ req: IecRequirement }> = ({ req }) => (
  <div className="p-4">
    <div className="flex items-start justify-between gap-3 flex-wrap">
      <div className="min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-xs font-bold text-violet-700">{req.id}</span>
          <span className="text-sm font-semibold text-slate-800">{req.title}</span>
          <span className="text-[10px] font-semibold text-slate-400 ring-1 ring-slate-200 rounded px-1.5 py-0.5">SL ≥ {req.appliesFrom}</span>
        </div>
        <div className="mt-1 text-xs text-slate-500">{req.evidence}</div>
        {req.enhancements.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {req.enhancements.map((e) => (
              <span key={e.id} className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] ring-1 ${STATUS_TONE[e.status]}`} title={e.title}>
                <span className="font-mono font-bold">{e.id}</span>
                <span className="text-[9px] opacity-70">SL{e.sl}</span>
                <span className="truncate max-w-[140px]">{e.title}</span>
              </span>
            ))}
          </div>
        )}
      </div>
      <StatusBadge status={req.status} />
    </div>
  </div>
);

export default IEC62443Compliance;
