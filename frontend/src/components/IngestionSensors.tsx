import React, { useCallback, useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { ingestionService, IngestionSummary, IngestEvent } from '../services/ingestionService';
import { PageHero, Panel, Icon, pageContainer, pageItem } from './theme';

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
                  <th className="py-2 pr-4">Data</th>
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
                      <td className="py-2.5 pr-4 text-slate-600 tabular-nums">{s.packets.toLocaleString()}</td>
                      <td className="py-2.5 pr-4 text-slate-600 tabular-nums">{fmtBytes(s.bytes)}</td>
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
                  <th className="py-2 pr-4">Size</th>
                  <th className="py-2 pr-4">Pipeline</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {loading ? (
                  Array.from({ length: 6 }).map((_, i) => (
                    <tr key={`e-skel-${i}`}>
                      {Array.from({ length: 6 }).map((__, c) => (
                        <td key={c} className={`py-2 pr-4 ${c === 0 ? 'pl-3' : ''}`}>
                          <div className="h-3 w-full max-w-[110px] rounded bg-slate-200 animate-pulse" />
                        </td>
                      ))}
                    </tr>
                  ))
                ) : events.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-10 text-center text-sm text-slate-400">No captures ingested yet.</td>
                  </tr>
                ) : (
                  events.map((e, i) => (
                    <tr key={`${e.ts}-${i}`} className="hover:bg-slate-50">
                      <td className="py-2 pr-4 pl-3 text-slate-500 whitespace-nowrap">{relTime(e.ts)}</td>
                      <td className="py-2 pr-4 text-slate-700 font-medium">{e.sensorId}</td>
                      <td className="py-2 pr-4 text-slate-600 font-mono text-xs truncate max-w-[220px]">{e.filename || '-'}</td>
                      <td className="py-2 pr-4 text-slate-600 tabular-nums">{e.packets.toLocaleString()}</td>
                      <td className="py-2 pr-4 text-slate-600 tabular-nums">{fmtBytes(e.bytes)}</td>
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
