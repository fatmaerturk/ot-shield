import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { Line, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, Filler, Tooltip, Legend,
} from 'chart.js';
import { ingestionService, IngestionSummary, IngestEvent } from '../services/ingestionService';
import DecodedPacketsPanel from './DecodedPacketsPanel';
import { PageHero, Panel, Icon, pageContainer, pageItem } from './theme';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, Filler, Tooltip, Legend);

// House palette, matching the dashboard charts (violet/fuchsia hero gradient
// plus high-contrast accents). Grey is reserved for chart chrome, not data.
const PAL = {
  violet: '#8B5CF6', fuchsia: '#D946EF', rose: '#F43F5E', amber: '#F59E0B',
  emerald: '#10B981', sky: '#0EA5E9', grid: '#EEF2F7', tick: '#94A3B8',
} as const;

// Shared dark tooltip so Chart.js defaults don't clash with the light surface.
const tooltipStyle = {
  backgroundColor: '#0F172A', titleColor: '#FFFFFF', bodyColor: '#E2E8F0',
  borderColor: PAL.violet, borderWidth: 1, cornerRadius: 8, padding: 10,
  titleFont: { weight: 'bold' as const, size: 12 }, bodyFont: { size: 12 },
};

/** Card shell for a chart: title, fixed height, loading + empty states. Kept at
 *  module scope so the 5s poll re-renders don't remount the chart canvas. */
const ChartCard: React.FC<{ title: string; hint: string; loading: boolean; ready: boolean; children: React.ReactNode }> = ({ title, hint, loading, ready, children }) => (
  <div className="rounded-xl ring-1 ring-slate-200 bg-white p-4">
    <div className="flex items-baseline justify-between gap-2">
      <h4 className="text-sm font-semibold text-slate-700">{title}</h4>
      <span className="text-[11px] text-slate-400">{hint}</span>
    </div>
    <div className="mt-3 h-[220px]">
      {loading ? (
        <div className="h-full w-full rounded-lg bg-slate-100 animate-pulse" />
      ) : ready ? (
        children
      ) : (
        <div className="h-full w-full flex items-center justify-center text-xs text-slate-400 text-center px-4">
          No captures yet. Ingest a pcap and the chart fills in.
        </div>
      )}
    </div>
  </div>
);

/** Small protocol pill. Protocol names come straight from the DPI pipeline. */
const ProtoChips: React.FC<{ protocols?: string[]; max?: number }> = ({ protocols, max = 8 }) => {
  const list = protocols ?? [];
  if (list.length === 0) return <span className="text-slate-400">-</span>;
  const shown = list.slice(0, max);
  const extra = list.length - shown.length;
  return (
    <span className="inline-flex flex-wrap gap-1 align-middle">
      {shown.map((p) => (
        <span key={p} className="inline-flex px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 ring-1 ring-slate-200 text-[10px] font-mono font-medium">
          {p}
        </span>
      ))}
      {extra > 0 && <span className="text-[10px] text-slate-400 font-medium self-center">+{extra}</span>}
    </span>
  );
};

function fmtBytes(b: number): string {
  if (!b || b < 1) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = b, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

function relTime(ts: number): string {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

/**
 * Live-ingestion monitor. Shows which sensors are feeding OTShield and how much,
 * all from real {@code /api/upload/pcap} uploads (a SPAN sensor tags each upload
 * with X-Sensor-Id; manual browser uploads appear as "manual-upload"). Capture
 * happens at the edge (the sensor box on the mirror port); this page reflects it.
 */
const IngestionSensors: React.FC = () => {
  const [summary, setSummary] = useState<IngestionSummary | null>(null);
  const [events, setEvents] = useState<IngestEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const timer = useRef<number | null>(null);
  const navigate = useNavigate();

  const ingestUrl = `${window.location.origin}/api/upload/pcap`;

  const refresh = useCallback(async () => {
    try {
      const [s, e] = await Promise.all([
        ingestionService.getSummary(),
        ingestionService.getRecent(60),
      ]);
      setSummary(s);
      setEvents(e);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load ingestion status');
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial load + silent poll every 5s (no skeleton flash after the first paint).
  useEffect(() => {
    void refresh();
    timer.current = window.setInterval(() => { void refresh(); }, 5000);
    return () => { if (timer.current) window.clearInterval(timer.current); };
  }, [refresh]);

  const copy = async (text: string, key: string) => {
    try { await navigator.clipboard.writeText(text); setCopied(key); setTimeout(() => setCopied(null), 1500); } catch { /* ignore */ }
  };

  // Pulsing skeleton in place of a value while the first fetch is in flight.
  const lv = (node: React.ReactNode, w = 'w-10') =>
    loading
      ? <span className={`inline-block align-middle rounded bg-white/30 animate-pulse h-[0.9em] ${w}`} aria-hidden="true" />
      : <>{node}</>;

  const sensors = summary?.sensors ?? [];

  // Captures oldest->newest, trimmed to keep the x-axis readable. Every point is
  // one real uploaded capture; nothing here is synthesized.
  const ordered = useMemo(
    () => [...events].sort((a, b) => a.ts - b.ts).slice(-40),
    [events],
  );
  const timeLabels = useMemo(
    () => ordered.map((e) => new Date(e.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })),
    [ordered],
  );

  // 1) Ingest throughput: packets analyzed per capture over time.
  const throughputData = useMemo(() => ({
    labels: timeLabels,
    datasets: [{
      label: 'Packets',
      data: ordered.map((e) => e.packets),
      borderColor: PAL.violet,
      backgroundColor: 'rgba(139,92,246,0.14)',
      fill: true, tension: 0.35, pointRadius: ordered.length > 20 ? 0 : 3,
      pointBackgroundColor: PAL.violet, borderWidth: 2,
    }],
  }), [timeLabels, ordered]);

  // 2) What each capture produced: new assets + anomalies, stacked.
  const findingsData = useMemo(() => ({
    labels: timeLabels,
    datasets: [
      { label: 'New assets', data: ordered.map((e) => e.newAssets), backgroundColor: PAL.violet, borderRadius: 4, maxBarThickness: 22, stack: 'f' },
      { label: 'Anomalies', data: ordered.map((e) => e.newAnomalies), backgroundColor: PAL.rose, borderRadius: 4, maxBarThickness: 22, stack: 'f' },
    ],
  }), [timeLabels, ordered]);

  // 3) Protocol coverage: how many captures carried each protocol (real presence
  // count; per-protocol packet volume isn't tracked, so we never imply it).
  const protocolData = useMemo(() => {
    const counts: Record<string, number> = {};
    events.forEach((e) => (e.protocols ?? []).forEach((p) => { counts[p] = (counts[p] || 0) + 1; }));
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const ramp = [PAL.violet, PAL.fuchsia, PAL.rose, PAL.amber, PAL.emerald, PAL.sky];
    return {
      count: top.length,
      data: {
        labels: top.map((t) => t[0]),
        datasets: [{
          label: 'Captures', data: top.map((t) => t[1]),
          backgroundColor: top.map((_, i) => ramp[i % ramp.length]),
          borderRadius: 4, maxBarThickness: 18,
        }],
      },
    };
  }, [events]);

  const lineOpts = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: tooltipStyle },
    scales: {
      x: { grid: { display: false }, ticks: { color: PAL.tick, font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 6 } },
      y: { beginAtZero: true, grid: { color: PAL.grid }, ticks: { color: PAL.tick, font: { size: 10 }, precision: 0 } },
    },
  } as const;

  const stackedOpts = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: true, position: 'bottom' as const, labels: { color: '#475569', boxWidth: 10, font: { size: 11 } } }, tooltip: tooltipStyle },
    scales: {
      x: { stacked: true, grid: { display: false }, ticks: { color: PAL.tick, font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 6 } },
      y: { stacked: true, beginAtZero: true, grid: { color: PAL.grid }, ticks: { color: PAL.tick, font: { size: 10 }, precision: 0 } },
    },
  } as const;

  const barYOpts = {
    indexAxis: 'y' as const, responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: tooltipStyle },
    scales: {
      x: { beginAtZero: true, grid: { color: PAL.grid }, ticks: { color: PAL.tick, font: { size: 10 }, precision: 0 } },
      y: { grid: { display: false }, ticks: { color: '#475569', font: { size: 11 } } },
    },
  } as const;

  const hasCaptures = !loading && ordered.length > 0;

  return (
    <motion.div variants={pageContainer} initial="hidden" animate="visible" className="space-y-6">
      <PageHero
        eyebrow="OPERATE · LIVE INGESTION"
        title="Live Traffic Ingestion"
        subtitle="Sensors on your SPAN/mirror ports stream OT traffic into OTShield as rolling captures. Every capture runs the full pipeline - asset discovery, DPI and anomaly detection. This page shows which sensors are feeding the platform right now and how much."
        icon={<Icon.Activity className="w-6 h-6" />}
        stats={[
          { label: 'Active sensors', value: lv(`${summary?.onlineSensors ?? 0}/${summary?.totalSensors ?? 0}`, 'w-12') },
          { label: 'Packets / min', value: lv((summary?.packetsPerMin ?? 0).toLocaleString()) },
          { label: 'Ingested (window)', value: lv(fmtBytes(summary?.windowBytes ?? 0), 'w-16') },
          { label: 'Captures (window)', value: lv((summary?.windowEvents ?? 0).toLocaleString()) },
        ]}
      />

      {error && (
        <motion.div variants={pageItem} className="rounded-xl bg-amber-50 ring-1 ring-amber-200 text-amber-800 px-4 py-3 text-sm">
          Ingestion status unavailable: {error}. Sensors will appear here once they start uploading.
        </motion.div>
      )}

      {/* What the pipeline found in the ingested traffic (real, deep-linked) */}
      <motion.div variants={pageItem}>
        <Panel
          title="What we found in this traffic"
          subtitle="Results the analysis pipeline produced from the SPAN-ingested captures in the current window. Open any card for the full detail."
          icon={<Icon.Shield className="w-4 h-4" />}
        >
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <button
              onClick={() => navigate('/assets')}
              className="group text-left rounded-xl ring-1 ring-slate-200 bg-white hover:ring-violet-300 hover:bg-violet-50/40 transition px-4 py-3"
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] uppercase tracking-wide text-slate-400">Assets discovered</span>
                <Icon.Server className="w-4 h-4 text-slate-300 group-hover:text-violet-500" />
              </div>
              <div className="mt-1 text-2xl font-bold text-slate-800 tabular-nums">
                {lv((summary?.windowAssets ?? 0).toLocaleString(), 'w-10')}
              </div>
              <span className="text-[11px] font-semibold text-violet-700 group-hover:text-violet-900">Open asset inventory →</span>
            </button>

            <button
              onClick={() => navigate('/anomalies')}
              className="group text-left rounded-xl ring-1 ring-slate-200 bg-white hover:ring-rose-300 hover:bg-rose-50/40 transition px-4 py-3"
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] uppercase tracking-wide text-slate-400">Anomalies raised</span>
                <Icon.Activity className="w-4 h-4 text-slate-300 group-hover:text-rose-500" />
              </div>
              <div className="mt-1 text-2xl font-bold text-slate-800 tabular-nums">
                {lv((summary?.windowAnomalies ?? 0).toLocaleString(), 'w-10')}
              </div>
              <span className="text-[11px] font-semibold text-rose-700 group-hover:text-rose-900">Open anomalies →</span>
            </button>

            <button
              onClick={() => navigate('/network-topology')}
              className="group text-left rounded-xl ring-1 ring-slate-200 bg-white hover:ring-sky-300 hover:bg-sky-50/40 transition px-4 py-3"
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] uppercase tracking-wide text-slate-400">Protocols observed</span>
                <Icon.Network className="w-4 h-4 text-slate-300 group-hover:text-sky-500" />
              </div>
              <div className="mt-1 text-2xl font-bold text-slate-800 tabular-nums">
                {lv((summary?.protocols?.length ?? 0).toLocaleString(), 'w-10')}
              </div>
              <span className="text-[11px] font-semibold text-sky-700 group-hover:text-sky-900">Open network map →</span>
            </button>
          </div>

          {!loading && (summary?.protocols?.length ?? 0) > 0 && (
            <div className="mt-3 pt-3 border-t border-slate-100">
              <span className="text-[11px] uppercase tracking-wide text-slate-400 mr-2">Protocols</span>
              <ProtoChips protocols={summary?.protocols} max={24} />
            </div>
          )}
        </Panel>
      </motion.div>

      {/* Ingestion analytics (all from real captures) */}
      <motion.div variants={pageItem}>
        <Panel
          title="Ingestion analytics"
          subtitle="Trends across the captures this window retained. Every point is a real upload that ran the pipeline."
          icon={<Icon.Activity className="w-4 h-4" />}
        >
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <ChartCard title="Ingest throughput" hint="packets / capture" loading={loading} ready={hasCaptures}>
              <Line data={throughputData} options={lineOpts} />
            </ChartCard>
            <ChartCard title="Findings per capture" hint="new assets + anomalies" loading={loading} ready={hasCaptures}>
              <Bar data={findingsData} options={stackedOpts} />
            </ChartCard>
            <ChartCard title="Protocol coverage" hint="captures carrying each protocol" loading={loading} ready={!loading && protocolData.count > 0}>
              <Bar data={protocolData.data} options={barYOpts} />
            </ChartCard>
            <ChartCard title="Per-sensor volume" hint="total packets by sensor" loading={loading} ready={!loading && sensors.length > 0}>
              <Bar
                data={{
                  labels: sensors.map((s) => s.sensorId),
                  datasets: [{
                    label: 'Packets', data: sensors.map((s) => s.packets),
                    backgroundColor: PAL.fuchsia, hoverBackgroundColor: PAL.violet,
                    borderRadius: 4, maxBarThickness: 18,
                  }],
                }}
                options={barYOpts}
              />
            </ChartCard>
          </div>
        </Panel>
      </motion.div>

      {/* Connect a sensor */}
      <motion.div variants={pageItem}>
        <Panel
          title="Connect a sensor"
          subtitle="Run the SPAN sensor on a box cabled to the mirror port; it uploads rolling pcaps to the pipeline."
          icon={<Icon.Network className="w-4 h-4" />}
        >
          <div className="space-y-3">
            <div className="flex items-center gap-2 rounded-lg ring-1 ring-slate-200 bg-slate-50 px-3 py-2 text-xs font-mono text-slate-600 min-w-0">
              <span className="text-[10px] uppercase tracking-wider text-slate-400 flex-shrink-0">Ingest URL</span>
              <span className="truncate">{ingestUrl}</span>
              <button onClick={() => copy(ingestUrl, 'url')} className="flex-shrink-0 text-violet-700 font-semibold hover:text-violet-900">
                {copied === 'url' ? 'Copied' : 'Copy'}
              </button>
            </div>
            <div className="flex items-center gap-2 rounded-lg ring-1 ring-slate-200 bg-slate-900 px-3 py-2 text-xs font-mono text-slate-100 min-w-0">
              <span className="truncate">OTSHIELD_URL={window.location.origin} python3 span_sensor.py --iface &lt;NIC&gt;</span>
              <button
                onClick={() => copy(`OTSHIELD_URL=${window.location.origin} python3 span_sensor.py --iface <NIC>`, 'cmd')}
                className="flex-shrink-0 text-violet-300 font-semibold hover:text-violet-100"
              >
                {copied === 'cmd' ? 'Copied' : 'Copy'}
              </button>
            </div>
            <p className="text-xs text-slate-500">
              The sensor lives in <span className="font-mono">sensor/span_sensor.py</span>. List interfaces with
              <span className="font-mono"> --list</span>; smoke-test the pipeline with <span className="font-mono">--once &lt;file.pcap&gt;</span>.
              Mirror the ICS segment (Modbus / S7 / IEC-104 ...) for best coverage.
            </p>
          </div>
        </Panel>
      </motion.div>

      {/* Sensors */}
      <motion.div variants={pageItem}>
        <Panel
          title="Sensors"
          subtitle={loading ? 'Loading sensors…' : `${sensors.length} sensor${sensors.length === 1 ? '' : 's'} seen in the recent window`}
          icon={<Icon.Server className="w-4 h-4" />}
        >
          <div className="overflow-x-auto rounded-lg ring-1 ring-slate-100">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wide text-slate-400 border-b border-slate-200">
                  <th className="py-2 pr-4 pl-3">Sensor</th>
                  <th className="py-2 pr-4">Host / interface</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Packets/min</th>
                  <th className="py-2 pr-4">Total packets</th>
                  <th className="py-2 pr-4">Protocols / found</th>
                  <th className="py-2 pr-4">Last upload</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {loading ? (
                  Array.from({ length: 3 }).map((_, i) => (
                    <tr key={`s-skel-${i}`}>
                      {Array.from({ length: 7 }).map((__, c) => (
                        <td key={c} className={`py-2.5 pr-4 ${c === 0 ? 'pl-3' : ''}`}>
                          <div className="h-3 w-full max-w-[120px] rounded bg-slate-200 animate-pulse" />
                        </td>
                      ))}
                    </tr>
                  ))
                ) : sensors.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-10 text-center text-sm text-slate-400">
                      No sensors feeding yet. Start the SPAN sensor (or upload a pcap) and it appears here within a rotation window.
                    </td>
                  </tr>
                ) : (
                  sensors.map((s) => (
                    <tr key={s.sensorId} className="hover:bg-slate-50">
                      <td className="py-2.5 pr-4 pl-3 font-semibold text-slate-800">{s.sensorId}</td>
                      <td className="py-2.5 pr-4 text-slate-600">
                        {s.host || '-'}{s.iface ? <span className="text-slate-400"> · {s.iface}</span> : null}
                        {s.remoteIp ? <div className="text-[11px] text-slate-400 font-mono">{s.remoteIp}</div> : null}
                      </td>
                      <td className="py-2.5 pr-4">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                          s.online ? 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200' : 'bg-slate-100 text-slate-500 ring-1 ring-slate-200'
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${s.online ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`} />
                          {s.online ? 'Online' : 'Idle'}
                        </span>
                      </td>
                      <td className="py-2.5 pr-4 font-semibold text-slate-800 tabular-nums">{s.packetsLastMin.toLocaleString()}</td>
                      <td className="py-2.5 pr-4 text-slate-600 tabular-nums">
                        {s.packets.toLocaleString()}
                        <span className="text-[11px] text-slate-400"> · {fmtBytes(s.bytes)}</span>
                      </td>
                      <td className="py-2.5 pr-4">
                        <ProtoChips protocols={s.protocols} max={5} />
                        {(s.newAssets > 0 || s.newAnomalies > 0) && (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {s.newAssets > 0 && (
                              <span className="inline-flex px-1.5 py-0.5 rounded bg-violet-50 text-violet-700 ring-1 ring-violet-200 text-[10px] font-semibold">
                                +{s.newAssets} asset{s.newAssets === 1 ? '' : 's'}
                              </span>
                            )}
                            {s.newAnomalies > 0 && (
                              <span className="inline-flex px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 ring-1 ring-rose-200 text-[10px] font-semibold">
                                +{s.newAnomalies} anomal{s.newAnomalies === 1 ? 'y' : 'ies'}
                              </span>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="py-2.5 pr-4 text-slate-500 whitespace-nowrap">
                        {relTime(s.lastSeen)}
                        <span className="text-[11px] text-slate-400"> · {s.lastPackets.toLocaleString()} pkt</span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Panel>
      </motion.div>

      {/* Decoded packet inspector (Wireshark-style, from real dpi_events) */}
      <motion.div variants={pageItem}>
        <DecodedPacketsPanel />
      </motion.div>

      {/* Recent ingest feed */}
      <motion.div variants={pageItem}>
        <Panel
          title="Recent captures"
          subtitle={loading ? 'Loading feed…' : 'Each row is one uploaded capture that ran the pipeline'}
          icon={<Icon.Activity className="w-4 h-4" />}
        >
          <div className="overflow-y-auto max-h-[50vh] rounded-lg ring-1 ring-slate-100">
            <table className="min-w-full text-sm">
              <thead className="sticky top-0 z-10 bg-white">
                <tr className="text-left text-[11px] uppercase tracking-wide text-slate-400 border-b border-slate-200">
                  <th className="py-2 pr-4 pl-3">Time</th>
                  <th className="py-2 pr-4">Sensor</th>
                  <th className="py-2 pr-4">Capture</th>
                  <th className="py-2 pr-4">Packets</th>
                  <th className="py-2 pr-4">Protocols</th>
                  <th className="py-2 pr-4">Found</th>
                  <th className="py-2 pr-4">Pipeline</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {loading ? (
                  Array.from({ length: 6 }).map((_, i) => (
                    <tr key={`e-skel-${i}`}>
                      {Array.from({ length: 7 }).map((__, c) => (
                        <td key={c} className={`py-2 pr-4 ${c === 0 ? 'pl-3' : ''}`}>
                          <div className="h-3 w-full max-w-[110px] rounded bg-slate-200 animate-pulse" />
                        </td>
                      ))}
                    </tr>
                  ))
                ) : events.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-10 text-center text-sm text-slate-400">No captures ingested yet.</td>
                  </tr>
                ) : (
                  events.map((e, i) => (
                    <tr key={`${e.ts}-${i}`} className="hover:bg-slate-50">
                      <td className="py-2 pr-4 pl-3 text-slate-500 whitespace-nowrap">{relTime(e.ts)}</td>
                      <td className="py-2 pr-4 text-slate-700 font-medium">{e.sensorId}</td>
                      <td className="py-2 pr-4 text-slate-600 font-mono text-xs truncate max-w-[220px]">{e.filename || '-'}</td>
                      <td className="py-2 pr-4 text-slate-600 tabular-nums">{e.packets.toLocaleString()}</td>
                      <td className="py-2 pr-4"><ProtoChips protocols={e.protocols} max={5} /></td>
                      <td className="py-2 pr-4 whitespace-nowrap">
                        {e.newAssets > 0 && (
                          <button onClick={() => navigate('/assets')} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-violet-50 text-violet-700 ring-1 ring-violet-200 text-[10px] font-semibold hover:bg-violet-100 mr-1">
                            +{e.newAssets} asset{e.newAssets === 1 ? '' : 's'}
                          </button>
                        )}
                        {e.newAnomalies > 0 && (
                          <button onClick={() => navigate('/anomalies')} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 ring-1 ring-rose-200 text-[10px] font-semibold hover:bg-rose-100">
                            +{e.newAnomalies} anomal{e.newAnomalies === 1 ? 'y' : 'ies'}
                          </button>
                        )}
                        {e.newAssets === 0 && e.newAnomalies === 0 && <span className="text-slate-400 text-[11px]">-</span>}
                      </td>
                      <td className="py-2 pr-4">
                        <span className={`inline-flex px-2 py-0.5 rounded-md text-[11px] font-semibold ${
                          e.parsed ? 'bg-violet-50 text-violet-700 ring-1 ring-violet-200' : 'bg-slate-100 text-slate-500 ring-1 ring-slate-200'
                        }`}>
                          {e.parsed ? 'Analyzed' : 'No packets'}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Panel>
      </motion.div>
    </motion.div>
  );
};

export default IngestionSensors;
