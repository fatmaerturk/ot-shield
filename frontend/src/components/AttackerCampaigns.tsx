import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  attackerService, AttackerSummary, AttackerTimeline, TimelineEvent,
  KillChainPhase, TimelineSource,
  KILL_CHAIN_ORDER, PHASE_LABEL,
} from '../services/attackerService';
import { PageHero, KpiCard, Panel, Icon, pageContainer, pageItem } from './theme';

// ---------- small visual helpers ----------

const PHASE_TONE: Record<KillChainPhase, string> = {
  RECON: 'bg-slate-100 text-slate-700 ring-slate-200',
  INITIAL_ACCESS: 'bg-sky-50 text-sky-700 ring-sky-200',
  DISCOVERY: 'bg-violet-50 text-violet-700 ring-violet-200',
  LATERAL_MOVEMENT: 'bg-amber-50 text-amber-700 ring-amber-200',
  EXECUTION: 'bg-orange-50 text-orange-700 ring-orange-200',
  IMPACT: 'bg-rose-50 text-rose-700 ring-rose-200',
};
const PHASE_DOT: Record<KillChainPhase, string> = {
  RECON: 'bg-slate-400',
  INITIAL_ACCESS: 'bg-sky-500',
  DISCOVERY: 'bg-violet-500',
  LATERAL_MOVEMENT: 'bg-amber-500',
  EXECUTION: 'bg-orange-500',
  IMPACT: 'bg-rose-500',
};
const SEV_TONE: Record<string, string> = {
  CRITICAL: 'bg-rose-100 text-rose-700 ring-rose-200',
  HIGH: 'bg-orange-100 text-orange-700 ring-orange-200',
  MEDIUM: 'bg-amber-100 text-amber-700 ring-amber-200',
  LOW: 'bg-emerald-100 text-emerald-700 ring-emerald-200',
  INFO: 'bg-slate-100 text-slate-600 ring-slate-200',
};

const SOURCE_ICON: Record<TimelineSource, React.ReactNode> = {
  HONEYPOT: <Icon.Eye className="w-3.5 h-3.5" />,
  TWIN: <Icon.Layers className="w-3.5 h-3.5" />,
  DPI: <Icon.Activity className="w-3.5 h-3.5" />,
  ANOMALY: <Icon.Brain className="w-3.5 h-3.5" />,
  CASE: <Icon.Alert className="w-3.5 h-3.5" />,
};
const SOURCE_LABEL: Record<TimelineSource, string> = {
  HONEYPOT: 'Internet-exposed decoy',
  TWIN: 'Decoy twin',
  DPI: 'Captured traffic',
  ANOMALY: 'Anomaly engine',
  CASE: 'Case',
};

function fmt(ts: string | null): string {
  if (!ts) return '-';
  const d = new Date(ts);
  return isNaN(d.getTime()) ? '-' : d.toLocaleString();
}

/** The 6-phase kill-chain rail; reached phases are lit and connected. */
const KillChainRail: React.FC<{ reached: KillChainPhase[]; compact?: boolean }> = ({ reached, compact }) => {
  const set = new Set(reached);
  return (
    <div className="flex items-center gap-1">
      {KILL_CHAIN_ORDER.map((p, i) => {
        const on = set.has(p);
        return (
          <React.Fragment key={p}>
            {i > 0 && (
              <div className={`h-0.5 ${compact ? 'w-3' : 'w-5'} rounded ${on && set.has(KILL_CHAIN_ORDER[i - 1]) ? PHASE_DOT[p] : 'bg-slate-200'}`} />
            )}
            <div
              title={PHASE_LABEL[p]}
              className={`rounded-full ring-2 ring-white shadow-sm ${compact ? 'w-2.5 h-2.5' : 'w-3.5 h-3.5'} ${on ? PHASE_DOT[p] : 'bg-slate-200'}`}
            />
          </React.Fragment>
        );
      })}
    </div>
  );
};

// ---------- page ----------

const AttackerCampaigns: React.FC = () => {
  const [attackers, setAttackers] = useState<AttackerSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [timeline, setTimeline] = useState<AttackerTimeline | null>(null);
  const [timelineLoading, setTimelineLoading] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const list = await attackerService.listAttackers(50);
      setAttackers(list);
      if (list.length && !selectedIp) setSelectedIp(list[0].ip);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load attackers');
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  useEffect(() => {
    if (!selectedIp) { setTimeline(null); return; }
    let cancelled = false;
    (async () => {
      setTimelineLoading(true);
      try {
        const t = await attackerService.getTimeline(selectedIp);
        if (!cancelled) setTimeline(t);
      } catch {
        if (!cancelled) setTimeline(null);
      } finally {
        if (!cancelled) setTimelineLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [selectedIp]);

  const breachedCount = useMemo(() => attackers.filter((a) => a.breached).length, [attackers]);
  const deepest = useMemo(() => {
    let best = 0;
    attackers.forEach((a) => { best = Math.max(best, a.reachedPhases?.length ?? 0); });
    return best;
  }, [attackers]);

  return (
    <motion.div variants={pageContainer} initial="hidden" animate="visible" className="space-y-6">
      <PageHero
        eyebrow="Attribution"
        title="Attack Campaigns"
        subtitle="Every real signal we hold for one attacker - internet-exposed decoy hits, decoy-twin trips, captured traffic, anomalies and cases - stitched into a single kill-chain, mapped to MITRE ATT&CK for ICS."
        icon={<Icon.Target className="w-6 h-6" />}
        stats={[
          { label: 'Attackers', value: attackers.length },
          { label: 'Reached impact', value: breachedCount },
          { label: 'Deepest chain', value: `${deepest}/6` },
        ]}
      />

      {error && (
        <div className="rounded-xl ring-1 ring-rose-200 bg-rose-50 text-rose-700 text-sm p-4">{error}</div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Left: ranked attacker list */}
        <div className="xl:col-span-1">
          <Panel title="Attackers" subtitle="Ranked by activity" icon={<Icon.Network className="w-4 h-4" />}>
            {loading ? (
              <div className="py-10 text-center text-sm text-slate-400">Loading attackers...</div>
            ) : attackers.length === 0 ? (
              <div className="py-10 text-center text-sm text-slate-400">
                No attacker activity yet. Upload a capture or expose a decoy to populate this view.
              </div>
            ) : (
              <div className="space-y-2 max-h-[70vh] overflow-y-auto pr-1">
                {attackers.map((a) => {
                  const active = a.ip === selectedIp;
                  return (
                    <button
                      key={a.ip}
                      onClick={() => setSelectedIp(a.ip)}
                      className={`w-full text-left rounded-xl p-3 ring-1 transition ${
                        active ? 'ring-violet-300 bg-violet-50' : 'ring-slate-200 bg-white hover:bg-slate-50'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-sm font-semibold text-slate-800 truncate">{a.ip}</span>
                        {a.breached && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-100 text-rose-700 ring-1 ring-rose-200">
                            BREACH
                          </span>
                        )}
                      </div>
                      <div className="mt-2"><KillChainRail reached={a.reachedPhases ?? []} compact /></div>
                      <div className="mt-2 flex items-center gap-3 text-[11px] text-slate-500">
                        <span>{a.eventCount} events</span>
                        <span>{a.targetedAssetCount} targets</span>
                        {a.country && <span>{a.country}</span>}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </Panel>
        </div>

        {/* Right: selected attacker timeline */}
        <div className="xl:col-span-2 space-y-6">
          {!selectedIp ? (
            <Panel><div className="py-16 text-center text-sm text-slate-400">Select an attacker to see its kill-chain.</div></Panel>
          ) : timelineLoading ? (
            <Panel><div className="py-16 text-center text-sm text-slate-400">Building timeline for {selectedIp}...</div></Panel>
          ) : !timeline ? (
            <Panel><div className="py-16 text-center text-sm text-slate-400">No timeline for {selectedIp}.</div></Panel>
          ) : (
            <>
              {/* summary */}
              <motion.div variants={pageItem} className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <KpiCard label="Events" value={timeline.totalEvents} icon={<Icon.Activity className="w-4 h-4" />} color="violet" />
                <KpiCard label="Phases reached" value={`${timeline.reachedPhases.length}/6`} icon={<Icon.Target className="w-4 h-4" />} color="fuchsia" />
                <KpiCard label="Targets" value={timeline.targetedAssets.length} icon={<Icon.Server className="w-4 h-4" />} color="violet" />
                <KpiCard label="Severity" value={timeline.highestSeverity ?? '-'} icon={<Icon.Alert className="w-4 h-4" />} color="rose" />
              </motion.div>

              {/* kill-chain rail + meta */}
              <Panel
                title={<span className="font-mono">{timeline.ip}</span>}
                subtitle={`First seen ${fmt(timeline.firstSeen)}  -  last seen ${fmt(timeline.lastSeen)}${timeline.country ? '  -  ' + timeline.country : ''}`}
                icon={<Icon.Target className="w-4 h-4" />}
              >
                <div className="flex flex-wrap items-center gap-4">
                  <KillChainRail reached={timeline.reachedPhases} />
                  <div className="flex flex-wrap gap-1.5">
                    {KILL_CHAIN_ORDER.filter((p) => timeline.reachedPhases.includes(p)).map((p) => (
                      <span key={p} className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold ring-1 ${PHASE_TONE[p]}`}>
                        {PHASE_LABEL[p]}
                      </span>
                    ))}
                  </div>
                </div>

                {timeline.targetedAssets.length > 0 && (
                  <div className="mt-4 pt-4 border-t border-slate-100">
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 mb-2">Targeted assets</div>
                    <div className="flex flex-wrap gap-2">
                      {timeline.targetedAssets.map((t) => (
                        <span key={t.ip} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs bg-slate-50 ring-1 ring-slate-200">
                          <Icon.Server className="w-3 h-3 text-slate-400" />
                          <span className="font-mono text-slate-700">{t.ip}</span>
                          {t.name && <span className="text-slate-500">{t.name}</span>}
                          {t.purdueLevel && <span className="text-[10px] text-violet-600 font-semibold">{t.purdueLevel.replace('LEVEL_', 'L')}</span>}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {timeline.caseNumbers.length > 0 && (
                  <div className="mt-3 text-xs text-slate-500">
                    Linked cases: {timeline.caseNumbers.map((c) => <span key={c} className="font-mono text-violet-700 mr-2">{c}</span>)}
                  </div>
                )}
              </Panel>

              {/* timeline */}
              <Panel
                title="Kill-chain timeline"
                subtitle={timeline.totalEvents > timeline.events.length
                  ? `Showing ${timeline.events.length} of ${timeline.totalEvents} events (most recent)`
                  : `${timeline.events.length} events, oldest first`}
                icon={<Icon.Clock className="w-4 h-4" />}
              >
                <Timeline events={timeline.events} />
              </Panel>
            </>
          )}
        </div>
      </div>
    </motion.div>
  );
};

const MAX_RENDER = 150; // guard: react-refresh walks siblings recursively; thousands of nodes overflow the stack

const Timeline: React.FC<{ events: TimelineEvent[] }> = ({ events }) => {
  if (!events.length) {
    return <div className="py-10 text-center text-sm text-slate-400">No events recorded for this attacker.</div>;
  }
  // Render only the most recent MAX_RENDER events (they arrive oldest-first).
  const shown = events.length > MAX_RENDER ? events.slice(events.length - MAX_RENDER) : events;
  return (
    <div className="relative pl-6">
      {shown.length < events.length && (
        <div className="mb-3 text-xs text-slate-400">
          Showing the {shown.length} most recent of {events.length} events.
        </div>
      )}
      <div className="absolute left-2 top-1 bottom-1 w-px bg-slate-200" />
      <div className="space-y-4">
        {shown.map((e, i) => (
          <div key={i} className="relative">
            <span className={`absolute -left-[18px] top-1.5 w-3 h-3 rounded-full ring-2 ring-white ${e.phase ? PHASE_DOT[e.phase] : 'bg-slate-300'}`} />
            <div className="rounded-xl ring-1 ring-slate-200 bg-white p-3">
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    {e.phase && (
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold ring-1 ${PHASE_TONE[e.phase]}`}>
                        {PHASE_LABEL[e.phase]}
                      </span>
                    )}
                    <span className="inline-flex items-center gap-1 text-[11px] text-slate-500">
                      {SOURCE_ICON[e.source]} {SOURCE_LABEL[e.source]}
                    </span>
                    {e.severity && (
                      <span className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-bold ring-1 ${SEV_TONE[e.severity] ?? SEV_TONE.INFO}`}>
                        {e.severity}
                      </span>
                    )}
                  </div>
                  <div className="mt-1.5 text-sm font-semibold text-slate-800">{e.title}</div>
                  {e.description && <div className="mt-0.5 text-xs text-slate-500 line-clamp-2">{e.description}</div>}
                  <div className="mt-1.5 flex items-center gap-3 text-[11px] text-slate-400 flex-wrap">
                    {e.protocol && <span>{e.protocol}</span>}
                    {e.functionCode && <span className="font-mono">{e.functionCode}</span>}
                    {e.targetIp && <span>-&gt; <span className="font-mono text-slate-500">{e.targetIp}</span></span>}
                    {e.mitreId && <span className="text-violet-600 font-semibold">{e.mitreId}</span>}
                  </div>
                </div>
                <span className="text-[11px] text-slate-400 whitespace-nowrap font-mono">{fmt(e.timestamp)}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default AttackerCampaigns;
