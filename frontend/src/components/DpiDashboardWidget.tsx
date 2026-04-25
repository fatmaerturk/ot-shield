import React, { useEffect, useMemo, useState } from 'react';
import dpiService, { DpiEvent, FunctionCodeStat } from '../services/dpiService';
import DpiEventModal, { DpiModalScope } from './DpiEventModal';

/**
 * Compact Dashboard widget summarising recent Deep-Packet-Inspection activity:
 * global function-code distribution, write/exception counters and the last
 * few suspicious PDUs. Click-through opens the global {@link DpiEventModal}.
 *
 * This is designed as a drop-in card - the container sizing is up to the
 * Dashboard layout so it can sit next to KPIs or spans the full width.
 */
interface Props {
  /** Number of recent events to summarise. Defaults to 50. */
  recentLimit?: number;
  /** Extra class names so the Dashboard can tune padding / grid span. */
  className?: string;
}

const DpiDashboardWidget: React.FC<Props> = ({ recentLimit = 50, className = '' }) => {
  const [events, setEvents] = useState<DpiEvent[]>([]);
  const [stats, setStats] = useState<FunctionCodeStat[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [modalScope, setModalScope] = useState<DpiModalScope | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([
      dpiService.search({ size: recentLimit }).then((p) => p.content).catch(() => [] as DpiEvent[]),
      dpiService.functionStats({}).catch(() => [] as FunctionCodeStat[]),
    ])
      .then(([ev, st]) => {
        if (cancelled) return;
        setEvents(ev);
        setStats(st);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e?.message || 'Failed to load DPI data');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [recentLimit]);

  // Counters across the loaded events (not the whole DB - global counts come
  // from stats totals instead).
  const counters = useMemo(() => {
    let writes = 0;
    let reads = 0;
    let exceptions = 0;
    const protocols = new Set<string>();
    const peers = new Set<string>();
    for (const e of events) {
      if (e.isWrite) writes++;
      else if (e.pduKind === 'read') reads++;
      if (e.isException) exceptions++;
      if (e.protocol) protocols.add(e.protocol);
      if (e.sourceIp) peers.add(e.sourceIp);
      if (e.destinationIp) peers.add(e.destinationIp);
    }
    return {
      writes,
      reads,
      exceptions,
      protocolCount: protocols.size,
      peerCount: peers.size,
      total: events.length,
    };
  }, [events]);

  const totalPdu = useMemo(() => stats.reduce((s, r) => s + r.count, 0), [stats]);
  const topStats = useMemo(() => stats.slice(0, 6), [stats]);
  const recentWrites = useMemo(() => events.filter((e) => e.isWrite).slice(0, 5), [events]);

  return (
    <>
      <div className={`bg-white rounded-lg shadow-sm border border-gray-200 p-4 ${className}`}>
        <div className="flex items-start justify-between mb-3">
          <div>
            <div className="text-[11px] uppercase tracking-wide text-gray-500">
              Deep Packet Inspection
            </div>
            <div className="text-base font-semibold text-gray-900">ICS protocol activity</div>
          </div>
          <button
            type="button"
            className="text-xs text-blue-600 hover:text-blue-800 whitespace-nowrap"
            onClick={() => setModalScope({ kind: 'global', title: 'DPI · Global' })}
          >
            View all →
          </button>
        </div>

        {loading && <div className="text-sm text-gray-500">Loading…</div>}
        {error && <div className="text-sm text-red-600">{error}</div>}

        {!loading && !error && (
          <>
            {/* KPI row */}
            <div className="grid grid-cols-4 gap-2 text-center text-xs mb-3">
              <Kpi label="Writes" value={counters.writes} tone="amber" />
              <Kpi label="Reads" value={counters.reads} tone="green" />
              <Kpi label="Exceptions" value={counters.exceptions} tone="red" />
              <Kpi label="Protocols" value={counters.protocolCount} tone="blue" />
            </div>

            {/* Histogram */}
            {topStats.length > 0 ? (
              <div className="mb-3">
                <div className="text-[10px] uppercase text-gray-400 mb-1">
                  Top function codes · {totalPdu.toLocaleString()} PDU
                </div>
                <ul className="space-y-1">
                  {topStats.map((s, idx) => {
                    const pct = totalPdu > 0 ? (s.count / totalPdu) * 100 : 0;
                    return (
                      <li key={`${s.protocol}-${s.functionCode}-${idx}`} className="flex items-center gap-2 text-xs">
                        <span className="w-14 text-gray-500 uppercase text-[10px]">{s.protocol}</span>
                        <span className="w-12 font-mono text-gray-700">{s.functionCode}</span>
                        <span className="flex-1 min-w-0 truncate text-gray-800">{s.functionName || '-'}</span>
                        <span className="w-20 bg-gray-100 rounded h-1.5 overflow-hidden">
                          <span
                            className="block h-full bg-blue-500"
                            style={{ width: `${Math.max(2, pct)}%` }}
                          />
                        </span>
                        <span className="w-12 text-right tabular-nums text-gray-500">{s.count}</span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ) : (
              <div className="text-xs text-gray-400 italic mb-3">
                No DPI data yet. Upload a .pcap with Modbus or S7 traffic to populate.
              </div>
            )}

            {/* Recent writes, these are the higher-signal PDUs */}
            {recentWrites.length > 0 && (
              <div>
                <div className="text-[10px] uppercase text-gray-400 mb-1">Recent write PDUs</div>
                <ul className="space-y-1">
                  {recentWrites.map((e) => (
                    <li
                      key={e.id}
                      className="flex items-center gap-2 text-xs border-t border-gray-100 pt-1"
                    >
                      <span className="w-14 text-gray-500 uppercase text-[10px]">{e.protocol}</span>
                      <span className="flex-1 min-w-0 truncate text-gray-800" title={e.summary || ''}>
                        {e.functionName || e.functionCode || 'Write'}
                        {e.registerAddress ? ` @ ${e.registerAddress}` : ''}
                        {e.value ? ` = ${e.value}` : ''}
                      </span>
                      <span className="text-gray-400 text-[10px] truncate max-w-[110px]">
                        {e.sourceIp} → {e.destinationIp}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </div>

      <DpiEventModal
        open={modalScope !== null}
        scope={modalScope}
        onClose={() => setModalScope(null)}
      />
    </>
  );
};

const Kpi: React.FC<{ label: string; value: number; tone: 'amber' | 'green' | 'red' | 'blue' }> = ({
  label,
  value,
  tone,
}) => {
  const toneMap: Record<string, string> = {
    amber: 'bg-amber-50 text-amber-800 border-amber-200',
    green: 'bg-green-50 text-green-800 border-green-200',
    red: 'bg-red-50 text-red-800 border-red-200',
    blue: 'bg-blue-50 text-blue-800 border-blue-200',
  };
  return (
    <div className={`rounded border px-2 py-1 ${toneMap[tone]}`}>
      <div className="text-base font-semibold tabular-nums">{value}</div>
      <div className="text-[10px] uppercase tracking-wide">{label}</div>
    </div>
  );
};

export default DpiDashboardWidget;
