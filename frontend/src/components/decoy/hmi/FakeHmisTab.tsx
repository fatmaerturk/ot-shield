import React, { useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  fakeHmiService,
  subscribeFakeHmiStream,
  FakeHmiInstance,
  HmiMetric,
  HmiAlarm,
  HmiInteraction,
  HmiScenarioType,
  FakeHmiStats,
} from '../../../services/fakeHmiService';
import { Icon, Panel } from '../../theme';
import { FakeHmiPanel } from './FakeHmiPanel';
import TripwireAlarmsBanner from './TripwireAlarmsBanner';

const SCENARIO_LABEL: Record<HmiScenarioType, string> = {
  WATER_TREATMENT: 'Water Treatment',
  SUBSTATION:      'Substation',
  OIL_GAS:         'Oil & Gas',
  MANUFACTURING:   'Manufacturing',
};

const SCENARIO_COLOR: Record<HmiScenarioType, string> = {
  WATER_TREATMENT: 'bg-cyan-50 text-cyan-700 ring-cyan-200',
  SUBSTATION:      'bg-amber-50 text-amber-700 ring-amber-200',
  OIL_GAS:         'bg-orange-50 text-orange-700 ring-orange-200',
  MANUFACTURING:   'bg-violet-50 text-violet-700 ring-violet-200',
};

const VARIANT_BADGE: Record<string, string> = {
  SIEMENS:   'bg-teal-600 text-white',
  ROCKWELL:  'bg-red-700 text-white',
  SCHNEIDER: 'bg-emerald-600 text-white',
  GENERIC:   'bg-slate-700 text-white',
};

/**
 * FakeHmisTab - lists fake HMIs as cards with live metric previews,
 * opens full HMI mockup in a modal. WebSocket pushes metric/alarm/interaction
 * events so cards update without polling.
 */
const FakeHmisTab: React.FC = () => {
  const [hmis, setHmis] = useState<FakeHmiInstance[]>([]);
  const [stats, setStats] = useState<FakeHmiStats | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<FakeHmiInstance | null>(null);
  const [streamConnected, setStreamConnected] = useState(false);
  const [flashingHmi, setFlashingHmi] = useState<Set<string>>(new Set());
  const streamCloseRef = useRef<(() => void) | null>(null);

  // ---- Initial load ----
  const loadAll = async () => {
    try {
      const [list, st] = await Promise.all([
        fakeHmiService.list(),
        fakeHmiService.stats(),
      ]);
      setHmis(list);
      setStats(st);
    } catch (e) {
      /* ignore */
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  // ---- Live updates ----
  useEffect(() => {
    const close = subscribeFakeHmiStream((msg) => {
      if (msg.kind === 'CONNECTED') {
        setStreamConnected(true);
      } else if (msg.kind === 'METRIC_UPDATE') {
        setHmis(prev => prev.map(h => h.id === msg.hmiId ? { ...h, metrics: msg.metrics } : h));
        setDetail(prev => (prev && prev.id === msg.hmiId) ? { ...prev, metrics: msg.metrics } : prev);
      } else if (msg.kind === 'ALARM') {
        setHmis(prev => prev.map(h => h.id === msg.hmiId
          ? { ...h, alarms: [msg.alarm, ...h.alarms].slice(0, 20) }
          : h));
        setDetail(prev => (prev && prev.id === msg.hmiId)
          ? { ...prev, alarms: [msg.alarm, ...prev.alarms].slice(0, 20) }
          : prev);
        // briefly flash card
        setFlashingHmi(prev => new Set(prev).add(msg.hmiId));
        setTimeout(() => {
          setFlashingHmi(prev => { const s = new Set(prev); s.delete(msg.hmiId); return s; });
        }, 1600);
      } else if (msg.kind === 'INTERACTION') {
        setHmis(prev => prev.map(h => h.id === msg.hmiId
          ? { ...h, totalInteractions: (h.totalInteractions || 0) + 1, lastAccessedAt: msg.interaction.ts }
          : h));
        setDetail(prev => (prev && prev.id === msg.hmiId)
          ? {
              ...prev,
              totalInteractions: (prev.totalInteractions || 0) + 1,
              lastAccessedAt: msg.interaction.ts,
              recentInteractions: [msg.interaction, ...(prev.recentInteractions || [])].slice(0, 25),
            }
          : prev);
      }
    }, () => setStreamConnected(false));
    streamCloseRef.current = close;
    return () => { close(); };
  }, []);

  // ---- Detail load on select ----
  useEffect(() => {
    if (!selectedId) { setDetail(null); return; }
    let cancelled = false;
    fakeHmiService.get(selectedId).then(d => { if (!cancelled) setDetail(d); }).catch(() => {});
    return () => { cancelled = true; };
  }, [selectedId]);

  const totalAlarms = useMemo(() => hmis.reduce((acc, h) => acc + h.alarms.filter(a => !a.acknowledged).length, 0), [hmis]);

  return (
    <div className="space-y-5">
      {/* Tripwire alarms banner — sourced from real /api/honeypot/stats events
          where decoySource = "internal-decoy" (the docker-compose tripwire fleet) */}
      <TripwireAlarmsBanner />

      {/* Stats ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatChip label="HMIs running"       value={`${stats?.runningHmis ?? 0}/${stats?.totalHmis ?? 0}`} tone="emerald" />
        <StatChip label="Active alarms"      value={totalAlarms}          tone="rose" />
        <StatChip label="Interactions 24h"   value={stats?.interactions24h ?? 0} tone="violet" />
        <StatChip label="Distinct attackers" value={stats?.distinctAttackers24h ?? 0} tone="fuchsia" />
        <StatChip
          label="Stream"
          value={streamConnected ? 'Live' : 'Offline'}
          tone={streamConnected ? 'emerald' : 'slate'}
          pulse={streamConnected}
        />
      </div>

      {/* Grid of HMI cards */}
      <Panel
        title="Fake HMIs in production"
        subtitle="Each persona simulates a real OT control screen. Attacker interactions are logged to the SOC; writes are always rejected."
        icon={<Icon.Eye className="w-5 h-5" />}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-2 gap-4">
          {hmis.map(h => (
            <HmiCard
              key={h.id}
              hmi={h}
              flashing={flashingHmi.has(h.id)}
              onOpen={() => setSelectedId(h.id)}
            />
          ))}
          {hmis.length === 0 && (
            <div className="col-span-full p-8 text-center text-sm text-slate-500">
              No fake HMIs loaded yet. The deception layer may still be initialising.
            </div>
          )}
        </div>
      </Panel>

      {/* Detail modal */}
      <AnimatePresence>
        {detail && (
          <FakeHmiDetailModal
            hmi={detail}
            onClose={() => { setSelectedId(null); setDetail(null); }}
          />
        )}
      </AnimatePresence>
    </div>
  );
};

// ============================================================
// HMI card (grid item)
// ============================================================
const HmiCard: React.FC<{ hmi: FakeHmiInstance; flashing: boolean; onOpen: () => void }> = ({ hmi, flashing, onOpen }) => {
  const activeAlarms = hmi.alarms.filter(a => !a.acknowledged).length;
  const topMetrics = hmi.metrics.slice(0, 4);
  return (
    <motion.button
      onClick={onOpen}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -2 }}
      className={`relative text-left rounded-2xl bg-white ring-1 ring-slate-200 hover:ring-violet-300 hover:shadow-xl transition-all overflow-hidden ${
        flashing ? 'ring-2 ring-rose-400 shadow-rose-200/60 shadow-2xl' : ''
      }`}
    >
      {/* Flash overlay */}
      {flashing && <div className="absolute inset-0 bg-rose-500/10 pointer-events-none animate-pulse" />}

      {/* Header bar */}
      <div className="px-4 py-3 bg-gradient-to-r from-slate-900 to-slate-700 text-white flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <span className={`text-[10px] font-black uppercase tracking-wider px-2 py-0.5 rounded ${VARIANT_BADGE[hmi.variant]}`}>
            {hmi.variant}
          </span>
          <span className="text-xs font-semibold truncate">{hmi.name}</span>
        </div>
        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ring-1 ring-inset ${SCENARIO_COLOR[hmi.scenario]}`}>
          {SCENARIO_LABEL[hmi.scenario]}
        </span>
      </div>

      {/* Live mini-preview */}
      <div className="p-4 grid grid-cols-2 gap-3">
        {topMetrics.map(m => <MiniMetric key={m.key} metric={m} />)}
      </div>

      {/* Footer: rollups */}
      <div className="px-4 py-3 border-t border-slate-100 bg-slate-50 grid grid-cols-4 gap-2">
        <FooterStat label="Alarms"       value={activeAlarms}              tone={activeAlarms > 0 ? 'rose' : 'slate'} />
        <FooterStat label="Interactions" value={hmi.totalInteractions || 0} tone="violet" />
        <FooterStat label="Attackers"    value={hmi.distinctAttackers24h || 0} tone="fuchsia" />
        <FooterStat label="Threat"       value={`${hmi.threatScore || 0}`}  tone={(hmi.threatScore || 0) > 50 ? 'rose' : 'emerald'} />
      </div>

      <div className="px-4 py-2 bg-white border-t border-slate-100 flex items-center justify-between text-[10.5px] text-slate-500">
        <span className="font-mono" title={`Tripwire container @ ${hmi.facility}`}>
          {hmi.ipAddress}:{hmi.port}
          <span className="ml-1.5 text-slate-400">· {hmi.facility}</span>
        </span>
        <span className="text-violet-600 font-semibold">Open HMI →</span>
      </div>
    </motion.button>
  );
};

const MiniMetric: React.FC<{ metric: HmiMetric }> = ({ metric }) => {
  const pct = Math.max(0, Math.min(100, ((metric.value - metric.min) / Math.max(0.001, metric.max - metric.min)) * 100));
  return (
    <div>
      <div className="flex items-baseline justify-between mb-0.5">
        <span className="text-[9.5px] text-slate-500 truncate">{metric.name}</span>
        <span className={`text-[11px] font-bold font-mono tabular-nums ${metric.alarming ? 'text-rose-600' : 'text-slate-800'}`}>
          {metric.value}<span className="text-[8px] ml-0.5 text-slate-400">{metric.unit}</span>
        </span>
      </div>
      <div className="h-1 rounded-full bg-slate-100 overflow-hidden">
        <div
          className={`h-full transition-all ${metric.alarming ? 'bg-rose-500' : 'bg-gradient-to-r from-violet-500 to-fuchsia-500'}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
};

const StatChip: React.FC<{ label: string; value: React.ReactNode; tone: 'emerald' | 'rose' | 'violet' | 'fuchsia' | 'slate'; pulse?: boolean }> = ({ label, value, tone, pulse }) => {
  const tones: Record<string, string> = {
    emerald: 'from-emerald-500 to-teal-500',
    rose: 'from-rose-500 to-red-500',
    violet: 'from-violet-500 to-purple-500',
    fuchsia: 'from-fuchsia-500 to-pink-500',
    slate: 'from-slate-400 to-slate-500',
  };
  return (
    <div className="rounded-2xl bg-white ring-1 ring-slate-200 p-3">
      <div className="flex items-center gap-2">
        <span className={`w-2 h-2 rounded-full bg-gradient-to-r ${tones[tone]} ${pulse ? 'animate-pulse' : ''}`} />
        <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</span>
      </div>
      <div className="mt-1 text-xl font-bold text-slate-900">{value}</div>
    </div>
  );
};

const FooterStat: React.FC<{ label: string; value: React.ReactNode; tone: 'rose' | 'slate' | 'violet' | 'fuchsia' | 'emerald' }> = ({ label, value, tone }) => {
  const textTone: Record<string, string> = {
    rose: 'text-rose-700',
    slate: 'text-slate-700',
    violet: 'text-violet-700',
    fuchsia: 'text-fuchsia-700',
    emerald: 'text-emerald-700',
  };
  return (
    <div className="text-center">
      <div className={`text-sm font-bold tabular-nums ${textTone[tone]}`}>{value}</div>
      <div className="text-[9px] text-slate-500 uppercase tracking-wider">{label}</div>
    </div>
  );
};

// Map a fake-HMI persona to the wire protocol its tripwire container speaks.
// Mirrors the env vars in /decoys/docker-compose.yml so what the user sees in
// the Deception Metadata box matches what the real container is listening on.
const describeProtocol = (hmi: FakeHmiInstance): string => {
  switch (hmi.scenario) {
    case 'WATER_TREATMENT': return 'Modbus TCP (502)';
    case 'SUBSTATION':      return 'Modbus TCP (502)';
    case 'OIL_GAS':         return 'IEC 60870-5-104 (2404)';
    case 'MANUFACTURING':   return 'S7Comm (102)';
    default:                return `TCP/${hmi.port}`;
  }
};

// ============================================================
// Detail modal - full HMI mockup + interaction log + actions
// ============================================================
const FakeHmiDetailModal: React.FC<{ hmi: FakeHmiInstance; onClose: () => void }> = ({ hmi, onClose }) => {
  const [simulating, setSimulating] = useState(false);

  const simulateHit = async (type: HmiInteraction['type']) => {
    setSimulating(true);
    try {
      await fakeHmiService.interact(hmi.id, {
        type,
        target: type === 'CONTROL_WRITE' ? hmi.metrics[0]?.key : '/hmi/overview',
        payload: type === 'LOGIN_ATTEMPT' ? 'admin:password123' : type === 'CONTROL_WRITE' ? 'value=0' : undefined,
      });
    } catch (_) { /* ignore */ }
    setSimulating(false);
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 bg-slate-900/70 backdrop-blur-sm flex items-center justify-center p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.97, y: 8 }}
        animate={{ scale: 1, y: 0 }}
        exit={{ scale: 0.97, y: 8 }}
        onClick={e => e.stopPropagation()}
        className="w-full max-w-6xl max-h-[92vh] overflow-y-auto rounded-2xl bg-slate-100 shadow-2xl ring-1 ring-slate-200 flex flex-col"
      >
        {/* Modal chrome */}
        <div className="bg-gradient-to-r from-violet-700 to-fuchsia-700 text-white px-5 py-3 flex items-center justify-between">
          <div>
            <div className="text-[10px] uppercase tracking-[0.2em] text-white/70">DECEPTION · FAKE HMI</div>
            <div className="text-base font-bold">{hmi.name}</div>
          </div>
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg bg-white/10 ring-1 ring-white/20 hover:bg-white/20 text-sm font-semibold"
          >
            Close ✕
          </button>
        </div>

        {/* Body: HMI + side panel */}
        <div className="p-5 grid grid-cols-1 xl:grid-cols-3 gap-5">
          {/* HMI panel (2 cols) */}
          <div className="xl:col-span-2">
            <FakeHmiPanel hmi={hmi} />
          </div>

          {/* Side: interactions + actions */}
          <div className="space-y-4">
            <div className="rounded-2xl bg-white ring-1 ring-slate-200 p-4">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">SOC actions - simulate attacker</div>
              <div className="grid grid-cols-2 gap-2">
                {(['PAGE_VIEW', 'LOGIN_ATTEMPT', 'DATA_POLL', 'CONTROL_WRITE', 'ALARM_ACK', 'CONFIG_PROBE'] as const).map(t => (
                  <button
                    key={t}
                    disabled={simulating}
                    onClick={() => simulateHit(t)}
                    className="px-2 py-1.5 text-[10.5px] font-semibold rounded-lg ring-1 ring-violet-200 text-violet-700 hover:bg-violet-50 disabled:opacity-50"
                  >
                    {t.replace('_', ' ')}
                  </button>
                ))}
              </div>
              <div className="mt-3 text-[10px] text-slate-500 leading-relaxed">
                Control writes are always rejected on decoys. Each simulated hit appears in the interaction log below within ~1s.
              </div>
            </div>

            <div className="rounded-2xl bg-white ring-1 ring-slate-200 p-4">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center justify-between">
                <span>Recent interactions</span>
                <span className="text-slate-400">{(hmi.recentInteractions || []).length}</span>
              </div>
              <div className="space-y-1.5 max-h-80 overflow-y-auto">
                {(hmi.recentInteractions || []).length === 0 && (
                  <div className="text-[11px] text-slate-400 text-center py-3">No interactions yet</div>
                )}
                {(hmi.recentInteractions || []).map(ix => (
                  <InteractionRow key={ix.id} ix={ix} />
                ))}
              </div>
            </div>

            <div className="rounded-2xl bg-slate-900 text-white p-4 text-[11px]">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="uppercase text-[9px] tracking-wider text-emerald-300 font-bold">
                    Tripwire container · live
                  </span>
                </div>
                <span className="text-[8.5px] uppercase tracking-wider text-white/40">
                  /decoys/docker-compose.yml
                </span>
              </div>
              <div className="grid grid-cols-2 gap-y-1 gap-x-3 font-mono">
                <span className="text-white/50">Container IP</span>
                <span className="text-amber-200">{hmi.ipAddress}:{hmi.port}</span>
                <span className="text-white/50">Site tag</span>
                <span className="text-amber-200">{hmi.facility}</span>
                <span className="text-white/50">Protocol</span>
                <span>{describeProtocol(hmi)}</span>
                <span className="text-white/50">Vendor</span><span>{hmi.vendor}</span>
                <span className="text-white/50">Model</span><span className="truncate">{hmi.model}</span>
                <span className="text-white/50">FW</span><span>{hmi.firmware}</span>
                <span className="text-white/50">Purdue</span><span>L{hmi.purdueLevel}</span>
                <span className="text-white/50">Uptime</span><span>{Math.floor((hmi.uptimeSeconds||0) / 60)}m</span>
                <span className="text-white/50">Threat</span>
                <span className={(hmi.threatScore||0) > 50 ? 'text-rose-300' : 'text-emerald-300'}>
                  {hmi.threatScore || 0}/100
                </span>
              </div>
              <div className="mt-3 pt-2 border-t border-white/10 text-[9.5px] text-white/50 leading-relaxed">
                Real Docker tripwire — every TCP probe POSTs to
                <span className="text-emerald-300"> /api/honeypot/ingest</span> and lights up this card as a CRITICAL alarm.
              </div>
            </div>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
};

const InteractionRow: React.FC<{ ix: HmiInteraction }> = ({ ix }) => {
  const typeTone: Record<string, string> = {
    PAGE_VIEW:     'bg-slate-100 text-slate-600',
    LOGIN_ATTEMPT: 'bg-amber-100 text-amber-800',
    CONTROL_WRITE: 'bg-rose-100 text-rose-800',
    ALARM_ACK:     'bg-violet-100 text-violet-800',
    DATA_POLL:     'bg-blue-100 text-blue-800',
    CONFIG_PROBE:  'bg-fuchsia-100 text-fuchsia-800',
  };
  return (
    <div className="flex items-center gap-2 text-[10.5px] px-2 py-1.5 rounded hover:bg-slate-50">
      <span className="font-mono text-slate-400 w-12 shrink-0">
        {new Date(ix.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
      </span>
      <span className={`px-1.5 py-0.5 rounded font-bold ${typeTone[ix.type] || 'bg-slate-100 text-slate-700'}`}>
        {ix.type.replace('_', ' ')}
      </span>
      <span className="font-mono text-slate-700 truncate flex-1" title={ix.attackerIp}>
        {ix.attackerIp}
        {ix.attackerCountry && <span className="ml-1 text-slate-400">({ix.attackerCountry})</span>}
      </span>
      {ix.blocked && <span className="text-[9px] font-bold text-rose-600">BLOCKED</span>}
    </div>
  );
};

export default FakeHmisTab;
