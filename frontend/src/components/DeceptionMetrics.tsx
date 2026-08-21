import React, { useEffect, useMemo, useState } from 'react';
import { Icon, PageHero, Panel } from './theme';
import { deceptionMetricsService, DeceptionMetrics as Metrics, NameCount } from '../services/deceptionMetricsService';

/**
 * Deception Effectiveness
 * ============================================================
 * Does the deception actually work? Every figure is first-party: adversary
 * effort absorbed, engagement depth, intel harvested, decoy believability
 * (do attackers come back), and signal cleanliness (lure trips are
 * false-positive-free). No sampling assumptions, no seeded numbers.
 */

const fmtDuration = (s: number | null | undefined) => {
  if (s == null || s <= 0) return '-';
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${(s / 3600).toFixed(1)}h`;
  return `${(s / 86400).toFixed(1)}d`;
};

const fmtNum = (n: number) => n.toLocaleString();

const Tile: React.FC<{ label: string; value: React.ReactNode; sub?: React.ReactNode; accent?: string }> = ({
  label,
  value,
  sub,
  accent = 'text-slate-900',
}) => (
  <div className="rounded-2xl bg-white ring-1 ring-slate-200/70 shadow-sm p-4">
    <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</div>
    <div className={`text-2xl font-bold mt-1 ${accent}`}>{value}</div>
    {sub && <div className="text-xs text-slate-500 mt-0.5">{sub}</div>}
  </div>
);

const BarList: React.FC<{ items: NameCount[]; color: string }> = ({ items, color }) => {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <div className="space-y-2">
      {items.length === 0 && <div className="text-xs text-slate-400 py-2">No data yet.</div>}
      {items.map((i) => (
        <div key={i.name} className="flex items-center gap-2">
          <div className="w-28 shrink-0 text-xs text-slate-600 truncate" title={i.name}>{i.name}</div>
          <div className="flex-1 h-4 rounded-full bg-slate-100 overflow-hidden">
            <div className={`h-full ${color} rounded-full`} style={{ width: `${(i.count / max) * 100}%` }} />
          </div>
          <div className="w-12 shrink-0 text-right text-xs font-semibold text-slate-700">{fmtNum(i.count)}</div>
        </div>
      ))}
    </div>
  );
};

const Sparkline: React.FC<{ data: NameCount[] }> = ({ data }) => {
  const w = 640, h = 90, pad = 6;
  const max = Math.max(1, ...data.map((d) => d.count));
  const step = data.length > 1 ? (w - pad * 2) / (data.length - 1) : 0;
  const pts = data.map((d, i) => {
    const x = pad + i * step;
    const y = h - pad - (d.count / max) * (h - pad * 2);
    return [x, y];
  });
  const line = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
  const area = `${line} L${pts.length ? pts[pts.length - 1][0].toFixed(1) : 0},${h - pad} L${pad},${h - pad} Z`;
  return (
    <div>
      <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-24" preserveAspectRatio="none">
        <defs>
          <linearGradient id="dmGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgba(139,92,246,0.35)" />
            <stop offset="100%" stopColor="rgba(139,92,246,0)" />
          </linearGradient>
        </defs>
        <path d={area} fill="url(#dmGrad)" />
        <path d={line} fill="none" stroke="#8b5cf6" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
      </svg>
      <div className="flex justify-between text-[10px] text-slate-400 mt-1">
        <span>{data[0]?.name}</span>
        <span>{data[data.length - 1]?.name}</span>
      </div>
    </div>
  );
};

const DeceptionMetrics: React.FC = () => {
  const [m, setM] = useState<Metrics | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      setM(await deceptionMetricsService.get());
      setError(null);
    } catch {
      setError('Could not load deception metrics. Is the backend running?');
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);

  const h = m?.headline;
  const e = m?.engagement;

  return (
    <div className="space-y-6">
      <PageHero
        eyebrow="DECEPTION EFFECTIVENESS"
        icon={<Icon.TrendingUp className="w-3.5 h-3.5" />}
        title="Deception Effectiveness"
        subtitle="Does the deception work? Adversary effort absorbed, engagement depth, intel harvested and decoy believability - all measured from live first-party evidence."
        stats={h ? [
          { label: 'Effort absorbed', value: fmtNum(h.interactionsAbsorbed), sub: `${fmtNum(h.uniqueAttackers)} unique attackers` },
          { label: 'Intel harvested', value: fmtNum(h.credentialsHarvested), sub: 'credential attempts captured' },
          { label: 'Lure false-positive rate', value: `${h.lureFalsePositiveRate}%`, sub: `${h.luresTripped}/${h.luresPlanted} lures tripped` },
        ] : []}
        actions={
          <button
            onClick={load}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-white bg-white/10 hover:bg-white/20 ring-1 ring-white/20 backdrop-blur-sm"
          >
            <Icon.Refresh className="w-4 h-4" /> Refresh
          </button>
        }
      />

      {error && (
        <div className="p-4 rounded-2xl bg-rose-50 ring-1 ring-rose-200 text-rose-700 text-sm">{error}</div>
      )}

      {/* Headline KPI tiles */}
      {h && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Tile label="Interactions absorbed" value={fmtNum(h.interactionsAbsorbed)} sub="drawn away from real assets" accent="text-violet-600" />
          <Tile label="Unique attackers" value={fmtNum(h.uniqueAttackers)} sub={`${m?.coverage.countriesSeen ?? 0} countries`} />
          <Tile label="Credentials harvested" value={fmtNum(h.credentialsHarvested)} sub="attacker intel captured" accent="text-fuchsia-600" />
          <Tile label="Decoys active" value={h.decoysActive} sub={`${m?.coverage.protocolsCovered ?? 0} protocols covered`} />
          <Tile label="Lures tripped" value={`${h.luresTripped}/${h.luresPlanted}`} sub="planted honeytokens" />
          <Tile label="Cases from deception" value={h.casesFromDeception} sub="real incidents surfaced" accent="text-rose-600" />
          <Tile label="Lure false-positive rate" value={`${h.lureFalsePositiveRate}%`} sub="lures never fire on staff" accent="text-emerald-600" />
          <Tile label="Deepest engagement" value={e ? fmtNum(e.deepestEngagement) : '-'} sub="interactions, one attacker" />
        </div>
      )}

      {/* Engagement quality + trend */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Panel title="Engagement quality" subtitle="How deeply the fabric holds an intruder" icon={<Icon.Target className="w-5 h-5" />}>
          {e && (
            <div className="grid grid-cols-2 gap-3">
              <Tile label="Avg interactions / attacker" value={e.avgInteractionsPerAttacker} />
              <Tile label="Avg dwell time" value={fmtDuration(e.avgDwellSeconds)} />
              <Tile label="Returning attackers" value={fmtNum(e.returningAttackers)} sub="came back > 1h later" />
              <Tile label="Deepest engagement" value={fmtNum(e.deepestEngagement)} />
            </div>
          )}
        </Panel>

        <Panel title="Engagement trend" subtitle="Interactions absorbed, last 14 days" icon={<Icon.Activity className="w-5 h-5" />} className="lg:col-span-2">
          {m && <Sparkline data={m.trend} />}
        </Panel>
      </div>

      {/* Breakdowns */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Panel title="Top protocols probed" icon={<Icon.Layers className="w-5 h-5" />}>
          <BarList items={m?.breakdown.topProtocols ?? []} color="bg-violet-500" />
        </Panel>
        <Panel title="Top technique classes" icon={<Icon.Target className="w-5 h-5" />}>
          <BarList items={m?.breakdown.topAttackTypes ?? []} color="bg-fuchsia-500" />
        </Panel>
        <Panel title="Top attacker origins" icon={<Icon.Network className="w-5 h-5" />}>
          <BarList items={m?.breakdown.topCountries ?? []} color="bg-pink-500" />
        </Panel>
        <Panel title="Busiest decoys" subtitle="by lifetime engagements" icon={<Icon.Eye className="w-5 h-5" />}>
          <BarList items={m?.breakdown.topDecoys ?? []} color="bg-sky-500" />
        </Panel>
      </div>

      {/* Lures */}
      {m && (
        <Panel title="Lure performance" subtitle="Planted honeytokens - false-positive-free breach signals" icon={<Icon.Lock className="w-5 h-5" />}>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <Tile label="Planted" value={m.lures.planted} />
            <Tile label="Tripped" value={m.lures.tripped} sub={`${m.lures.tripRatePct}% trip rate`} accent="text-rose-600" />
            <Tile label="Beacon trips" value={fmtNum(m.lures.beaconTrips)} sub="opened in the wild" />
            <Tile label="Credential replays" value={fmtNum(m.lures.replayTrips)} sub="secret replayed" />
            <Tile label="Avg time-to-trip" value={fmtDuration(m.lures.avgTimeToTripSeconds)} sub="planted to opened" />
          </div>
        </Panel>
      )}

      {!m && !error && <div className="text-sm text-slate-500 py-10 text-center">Loading metrics…</div>}
    </div>
  );
};

export default DeceptionMetrics;
