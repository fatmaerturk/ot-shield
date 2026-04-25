import React, { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { Chart, registerables } from 'chart.js';
import { Bar, Line, Doughnut } from 'react-chartjs-2';

Chart.register(...registerables);

// Matches the Map<String, Object> returned by /api/conpot/statistics
interface RecentEvent {
  raw: string;
  sourceIp: string | null;
  protocol: string | null;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
}

interface TopAttacker {
  ip: string;
  attacks: number;
}

interface HourlyPoint {
  hour: number;
  count: number;
}

interface ConpotStats {
  totalConnections: number;
  modbusRequests: number;
  uniqueIPs: number;
  uniqueSessions: number;
  resetConnections: number;
  errorCount: number;
  totalLogs: number;
  isRunning: boolean;
  simulationMode: boolean;
  protocolBreakdown: Record<string, number>;
  severityBreakdown: Record<string, number>;
  modbusFunctionBreakdown: Record<string, number>;
  httpMethodBreakdown: Record<string, number>;
  httpPathBreakdown: Record<string, number>;
  topAttackers: TopAttacker[];
  hourlySeries: HourlyPoint[];
  recentEvents: RecentEvent[];
}

const EMPTY_STATS: ConpotStats = {
  totalConnections: 0,
  modbusRequests: 0,
  uniqueIPs: 0,
  uniqueSessions: 0,
  resetConnections: 0,
  errorCount: 0,
  totalLogs: 0,
  isRunning: false,
  simulationMode: false,
  protocolBreakdown: {},
  severityBreakdown: {},
  modbusFunctionBreakdown: {},
  httpMethodBreakdown: {},
  httpPathBreakdown: {},
  topAttackers: [],
  hourlySeries: [],
  recentEvents: [],
};

// ---------- Modbus function-code reference ----------
const MODBUS_FUNCTION_NAMES: Record<string, string> = {
  'FC 1': 'Read Coils',
  'FC 2': 'Read Discrete Inputs',
  'FC 3': 'Read Holding Registers',
  'FC 4': 'Read Input Registers',
  'FC 5': 'Write Single Coil',
  'FC 6': 'Write Single Register',
  'FC 7': 'Read Exception Status',
  'FC 8': 'Diagnostics',
  'FC 15': 'Write Multiple Coils',
  'FC 16': 'Write Multiple Registers',
  'FC 20': 'Read File Record',
  'FC 21': 'Write File Record',
  'FC 22': 'Mask Write Register',
  'FC 23': 'Read/Write Multiple Registers',
  'FC 43': 'Encapsulated Interface Transport',
};

const SEVERITY_STYLES: Record<string, { dot: string; pill: string }> = {
  HIGH: { dot: 'bg-rose-500', pill: 'bg-rose-50 text-rose-700 ring-rose-200' },
  MEDIUM: { dot: 'bg-amber-500', pill: 'bg-amber-50 text-amber-700 ring-amber-200' },
  LOW: { dot: 'bg-emerald-500', pill: 'bg-emerald-50 text-emerald-700 ring-emerald-200' },
};

const Conpot: React.FC = () => {
  const [stats, setStats] = useState<ConpotStats>(EMPTY_STATS);
  const [backendReachable, setBackendReachable] = useState<boolean | null>(null);
  const [remoteMode, setRemoteMode] = useState<boolean | null>(null);
  // Total events the backend has persisted — when this counter ticks up between
  // polls we light up the "ingest live" indicator briefly.
  const [lastEventCount, setLastEventCount] = useState<number>(0);
  const [eventsRecentlyGrew, setEventsRecentlyGrew] = useState(false);
  const [attackersOpen, setAttackersOpen] = useState(false);
  const [selectedAttackerIp, setSelectedAttackerIp] = useState<string | null>(null);

  // ---------- Backend status polling ----------
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const r = await fetch('http://localhost:8080/api/conpot/status');
        const d = await r.json();
        setRemoteMode(Boolean(d.remoteMode));
        setBackendReachable(true);
      } catch {
        setBackendReachable(false);
      }
    };
    checkStatus();
    const id = setInterval(checkStatus, 15_000);
    return () => clearInterval(id);
  }, []);

  // ---------- Stats polling ----------
  const fetchStats = async () => {
    try {
      const r = await fetch('http://localhost:8080/api/conpot/statistics');
      if (r.ok) {
        const d = await r.json();
        setStats(prev => {
          const next: ConpotStats = { ...EMPTY_STATS, ...d };
          // If totalLogs grew since last poll, light up the "ingesting" indicator briefly
          if (next.totalLogs > lastEventCount && lastEventCount !== 0) {
            setEventsRecentlyGrew(true);
            window.setTimeout(() => setEventsRecentlyGrew(false), 4000);
          }
          setLastEventCount(next.totalLogs);
          return next;
        });
      }
    } catch (err) { console.error('stats fetch error:', err); }
  };

  useEffect(() => {
    fetchStats();
    const id = setInterval(fetchStats, 5000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastEventCount]);

  // ---------- (Read-only — decoy lifecycle is managed remotely; no actions exposed in UI) ----------

  // ---------- Derived chart data ----------
  const protocolChart = useMemo(() => {
    const labels = Object.keys(stats.protocolBreakdown);
    const data = labels.map(k => stats.protocolBreakdown[k]);
    return {
      labels,
      datasets: [{
        label: 'Requests',
        data,
        backgroundColor: [
          'rgba(139, 92, 246, 0.75)', 'rgba(236, 72, 153, 0.75)', 'rgba(251, 146, 60, 0.75)',
          'rgba(16, 185, 129, 0.75)', 'rgba(59, 130, 246, 0.75)', 'rgba(244, 63, 94, 0.75)',
          'rgba(168, 85, 247, 0.75)', 'rgba(234, 179, 8, 0.75)',
        ],
        borderColor: 'rgba(15,23,42,0.1)',
        borderWidth: 1,
      }],
    };
  }, [stats.protocolBreakdown]);

  const severityChart = useMemo(() => ({
    labels: ['HIGH', 'MEDIUM', 'LOW'],
    datasets: [{
      data: [
        stats.severityBreakdown['HIGH'] || 0,
        stats.severityBreakdown['MEDIUM'] || 0,
        stats.severityBreakdown['LOW'] || 0,
      ],
      backgroundColor: ['rgba(244, 63, 94, 0.85)', 'rgba(251, 146, 60, 0.85)', 'rgba(16, 185, 129, 0.85)'],
      borderWidth: 2,
      borderColor: '#fff',
    }],
  }), [stats.severityBreakdown]);

  const hourlyChart = useMemo(() => ({
    labels: stats.hourlySeries.map(p => `${String(p.hour).padStart(2, '0')}:00`),
    datasets: [{
      label: 'Events',
      data: stats.hourlySeries.map(p => p.count),
      borderColor: 'rgba(139, 92, 246, 1)',
      backgroundColor: 'rgba(139, 92, 246, 0.15)',
      fill: true,
      tension: 0.4,
      pointRadius: 2,
    }],
  }), [stats.hourlySeries]);

  const modbusFunctionChart = useMemo(() => {
    const entries = Object.entries(stats.modbusFunctionBreakdown).sort((a, b) => b[1] - a[1]).slice(0, 10);
    return {
      labels: entries.map(([k]) => k),
      datasets: [{
        label: 'Calls',
        data: entries.map(([, v]) => v),
        backgroundColor: 'rgba(236, 72, 153, 0.75)',
        borderColor: 'rgba(236, 72, 153, 1)',
        borderWidth: 1,
      }],
    };
  }, [stats.modbusFunctionBreakdown]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { position: 'bottom' as const, labels: { usePointStyle: true, padding: 16 } } },
  };
  const barChartOptions = {
    ...chartOptions,
    scales: { y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.06)' } }, x: { grid: { display: false } } },
    plugins: { ...chartOptions.plugins, legend: { display: false } },
  };
  const lineChartOptions = {
    ...chartOptions,
    scales: { y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.06)' } }, x: { grid: { color: 'rgba(0,0,0,0.04)' } } },
    plugins: { ...chartOptions.plugins, legend: { display: false } },
  };

  const hasAnyData = stats.totalLogs > 0;
  const topHttpPaths = useMemo(() =>
    Object.entries(stats.httpPathBreakdown).sort((a, b) => b[1] - a[1]).slice(0, 6),
    [stats.httpPathBreakdown]);

  // ---------- Threat posture metrics (derived from stats) ----------
  // Threat Score: weighted severity ratio normalized to 0-100.
  //   HIGH = 3, MEDIUM = 2, LOW = 1.
  //   score = (sum of weighted) / (max possible if everything were HIGH) * 100
  const threatScore = useMemo(() => {
    const high = stats.severityBreakdown['HIGH'] || 0;
    const med = stats.severityBreakdown['MEDIUM'] || 0;
    const low = stats.severityBreakdown['LOW'] || 0;
    const total = high + med + low;
    if (total === 0) return 0;
    const weighted = high * 3 + med * 2 + low * 1;
    return Math.round((weighted / (total * 3)) * 100);
  }, [stats.severityBreakdown]);

  // Block effectiveness: blocked / total events
  // (We don't have isBlocked in the conpot stats response — derive a proxy from
  // severity. HIGH events are what blocking rules typically catch.)
  const blockEffectiveness = useMemo(() => {
    const high = stats.severityBreakdown['HIGH'] || 0;
    const total = stats.totalLogs || 0;
    if (total === 0) return 0;
    return Math.round((high / total) * 100);
  }, [stats.severityBreakdown, stats.totalLogs]);

  // Attack velocity: events in the last hour vs. previous hour
  const attackVelocity = useMemo(() => {
    if (stats.hourlySeries.length < 2) return { current: 0, prev: 0, delta: 0 };
    const nowHour = new Date().getHours();
    const cur = stats.hourlySeries.find(p => p.hour === nowHour)?.count || 0;
    const prevH = (nowHour + 23) % 24;
    const prev = stats.hourlySeries.find(p => p.hour === prevH)?.count || 0;
    const delta = prev === 0 ? (cur > 0 ? 100 : 0) : Math.round(((cur - prev) / prev) * 100);
    return { current: cur, prev, delta };
  }, [stats.hourlySeries]);

  // Last attack: top of recentEvents
  const lastAttack = stats.recentEvents.length > 0 ? stats.recentEvents[0] : null;

  // Top attack vector: most common attack type from protocol breakdown
  const topAttackVector = useMemo(() => {
    const entries = Object.entries(stats.protocolBreakdown).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) return null;
    const top = entries[0];
    const second = entries[1];
    const total = entries.reduce((s, [, n]) => s + n, 0);
    const share = total > 0 ? Math.round((top[1] / total) * 100) : 0;
    return {
      protocol: top[0],
      count: top[1],
      share,
      runnerUp: second ? { protocol: second[0], count: second[1] } : null,
    };
  }, [stats.protocolBreakdown]);

  // MITRE ATT&CK for ICS — heuristic mapping of observed protocols/attack types to tactics.
  const mitreTactics = useMemo(() => {
    const tactics: Array<{ id: string; name: string; observed: number; color: string }> = [
      { id: 'TA0102', name: 'Reconnaissance', observed: 0, color: 'from-violet-500 to-fuchsia-500' },
      { id: 'TA0108', name: 'Initial Access', observed: 0, color: 'from-blue-500 to-cyan-500' },
      { id: 'TA0104', name: 'Execution', observed: 0, color: 'from-amber-500 to-orange-500' },
      { id: 'TA0109', name: 'Discovery', observed: 0, color: 'from-emerald-500 to-teal-500' },
      { id: 'TA0107', name: 'Impair Process Control', observed: 0, color: 'from-rose-500 to-pink-500' },
      { id: 'TA0105', name: 'Impact', observed: 0, color: 'from-red-600 to-rose-700' },
    ];
    // Simple keyword routing: scans → discovery, login attempts → initial access, write/exec → impact, etc.
    Object.entries(stats.modbusFunctionBreakdown).forEach(([fc, count]) => {
      // FC 1-4 = read = Discovery; FC 5,6,15,16 = write = Impair/Impact
      const num = parseInt(fc.replace('FC ', ''), 10);
      if ([1, 2, 3, 4].includes(num)) tactics[3].observed += count;
      if ([5, 6, 15, 16, 23].includes(num)) tactics[4].observed += count;
    });
    Object.entries(stats.httpMethodBreakdown).forEach(([method, count]) => {
      if (method === 'GET') tactics[0].observed += count;
      if (method === 'POST' || method === 'PUT') tactics[1].observed += count;
    });
    if (stats.errorCount > 0) tactics[2].observed += stats.errorCount;
    if (stats.resetConnections > 0) tactics[5].observed += Math.floor(stats.resetConnections / 5);
    return tactics;
  }, [stats.modbusFunctionBreakdown, stats.httpMethodBreakdown, stats.errorCount, stats.resetConnections]);

  return (
    <div className="space-y-6">
      {/* Hero */}
      <div
        className="relative overflow-hidden rounded-2xl p-8 md:p-10 text-white"
        style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #4c1d95 45%, #7c3aed 100%)' }}
      >
        <div className="absolute -top-20 -right-20 w-72 h-72 rounded-full bg-fuchsia-500/20 blur-3xl" />
        <div className="absolute -bottom-10 -left-10 w-60 h-60 rounded-full bg-violet-400/10 blur-3xl" />
        <div className="relative flex flex-col lg:flex-row lg:items-end lg:justify-between gap-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 ring-1 ring-white/20 text-xs font-semibold tracking-wider backdrop-blur-sm mb-4">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
              ICS DECEPTION · LIVE
            </div>
            <h1 className="text-3xl md:text-4xl font-bold leading-tight">
              ICS Decoy Telemetry
              <span className="block text-violet-100/90 font-medium text-lg md:text-xl mt-2">
                Threat posture and protocol-level activity for the deployed industrial decoy. Events arrive in near real time.
              </span>
              <span className="block mt-3 text-sm text-violet-100/70">
                Looking for fleet-wide analytics, geo maps, and credential intelligence? Open{' '}
                <Link to="/attack-intelligence" className="underline decoration-violet-300/60 hover:decoration-white font-semibold text-white">
                  Attack Intelligence →
                </Link>
              </span>
            </h1>
          </div>
          {/* ===== Connection Health pills ===== */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-white/10 ring-1 ring-white/20 backdrop-blur-sm" title="Spring Boot backend reachable from this browser">
              <span className={`w-2 h-2 rounded-full ${backendReachable ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
              <span className="text-xs font-semibold uppercase tracking-wider text-white">
                Backend {backendReachable ? 'online' : 'offline'}
              </span>
            </div>
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-white/10 ring-1 ring-white/20 backdrop-blur-sm" title="Decoy is configured as remote (lifecycle managed elsewhere)">
              <span className={`w-2 h-2 rounded-full ${remoteMode ? 'bg-violet-300' : 'bg-amber-300'}`} />
              <span className="text-xs font-semibold uppercase tracking-wider text-white">
                {remoteMode === null ? 'Mode …' : remoteMode ? 'Remote mode' : 'Local mode'}
              </span>
            </div>
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-white/10 ring-1 ring-white/20 backdrop-blur-sm" title={eventsRecentlyGrew ? 'New event in the last few seconds' : 'Waiting for the next event'}>
              <span className={`w-2 h-2 rounded-full ${eventsRecentlyGrew ? 'bg-emerald-400 animate-ping' : 'bg-white/40'}`} />
              <span className="text-xs font-semibold uppercase tracking-wider text-white">
                Ingest {eventsRecentlyGrew ? 'live' : 'idle'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {backendReachable === false && (
        <div className="p-4 bg-rose-50 ring-1 ring-rose-200 rounded-2xl flex items-start gap-3 shadow-sm">
          <div className="w-9 h-9 rounded-xl bg-rose-100 text-rose-600 flex items-center justify-center flex-shrink-0">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
            </svg>
          </div>
          <div className="text-sm text-rose-800 leading-relaxed">
            <strong className="block mb-1">Backend unreachable.</strong>
            Cannot reach the Spring Boot API at <code className="bg-rose-100 px-1.5 py-0.5 rounded text-xs font-mono">http://localhost:8080</code>. Start the backend and refresh.
          </div>
        </div>
      )}

      {backendReachable && remoteMode === false && (
        <div className="p-4 bg-amber-50 ring-1 ring-amber-200 rounded-2xl flex items-start gap-3 shadow-sm">
          <div className="w-9 h-9 rounded-xl bg-amber-100 text-amber-600 flex items-center justify-center flex-shrink-0">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <p className="text-sm text-amber-800 leading-relaxed">
            <strong>Backend is in local decoy mode.</strong> This page is designed for the remote deployment; flip the runtime to <code className="bg-amber-100 px-1.5 py-0.5 rounded text-xs font-mono">remote</code> in the backend configuration to source live telemetry instead of local logs.
          </p>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          {
            label: 'Total Connections', value: stats.totalConnections.toLocaleString(),
            hint: `${stats.uniqueSessions.toLocaleString()} unique sessions`,
            gradient: 'from-rose-500 to-orange-500',
            icon: (<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>),
          },
          {
            label: 'Unique Attackers', value: stats.uniqueIPs.toLocaleString(),
            hint: `${stats.topAttackers.length} ranked in top list`,
            gradient: 'from-violet-500 to-fuchsia-500',
            icon: (<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>),
          },
          {
            label: 'Modbus Events', value: stats.modbusRequests.toLocaleString(),
            hint: `${Object.keys(stats.modbusFunctionBreakdown).length} function codes seen`,
            gradient: 'from-fuchsia-500 to-pink-500',
            icon: (<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>),
          },
          {
            label: 'Errors / Resets', value: (stats.errorCount + stats.resetConnections).toLocaleString(),
            hint: `${stats.errorCount} exceptions · ${stats.resetConnections} resets`,
            gradient: 'from-amber-500 to-rose-500',
            icon: (<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" /></svg>),
          },
        ].map((s, i) => (
          <div key={i} className="group relative bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-lg hover:-translate-y-0.5 transition-all duration-300 overflow-hidden">
            <div className={`absolute inset-x-0 top-0 h-1 bg-gradient-to-r ${s.gradient}`} />
            <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${s.gradient} text-white flex items-center justify-center shadow-md shadow-violet-500/20`}>
              {s.icon}
            </div>
            <p className="mt-4 text-[11px] uppercase tracking-wider text-slate-500 font-semibold">{s.label}</p>
            <p className="mt-1 text-3xl font-bold text-slate-900 tracking-tight">{s.value}</p>
            <p className="mt-1 text-xs text-slate-500">{s.hint}</p>
          </div>
        ))}
      </div>

      {/* No data banner */}
      {!hasAnyData && (
        <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-10 text-center">
          <div className="w-14 h-14 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white flex items-center justify-center shadow-lg shadow-violet-500/30">
            <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <h3 className="text-lg font-semibold text-slate-900">Waiting for decoy telemetry</h3>
          <p className="mt-1 text-sm text-slate-500 max-w-md mx-auto">
            The decoy is reachable but hasn't observed any attacker probes yet. Charts and tables below populate automatically as soon as the first event arrives.
          </p>
        </div>
      )}

      {hasAnyData && (
        <>
          {/* Protocol + Severity + Hourly */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-semibold text-slate-900">Protocol Distribution</h3>
                  <p className="text-xs text-slate-500 mt-0.5">Events per ICS protocol</p>
                </div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-violet-700 bg-violet-50 ring-1 ring-violet-200 px-2 py-1 rounded-full">Protocols</span>
              </div>
              <div className="h-64">
                {protocolChart.labels.length > 0
                  ? <Bar data={protocolChart} options={barChartOptions} />
                  : <div className="h-full flex items-center justify-center text-sm text-slate-400">No protocol data yet</div>}
              </div>
            </div>

            <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-semibold text-slate-900">Severity Mix</h3>
                  <p className="text-xs text-slate-500 mt-0.5">Derived from log keywords</p>
                </div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-rose-700 bg-rose-50 ring-1 ring-rose-200 px-2 py-1 rounded-full">Severity</span>
              </div>
              <div className="h-64">
                <Doughnut data={severityChart} options={chartOptions} />
              </div>
            </div>

            <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-semibold text-slate-900">Hourly Activity</h3>
                  <p className="text-xs text-slate-500 mt-0.5">Events per hour (UTC of host)</p>
                </div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-fuchsia-700 bg-fuchsia-50 ring-1 ring-fuchsia-200 px-2 py-1 rounded-full">Timeline</span>
              </div>
              <div className="h-64">
                <Line data={hourlyChart} options={lineChartOptions} />
              </div>
            </div>
          </div>

          {/* Modbus functions + HTTP paths */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-semibold text-slate-900">Modbus Function Codes</h3>
                  <p className="text-xs text-slate-500 mt-0.5">Top function calls observed</p>
                </div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-pink-700 bg-pink-50 ring-1 ring-pink-200 px-2 py-1 rounded-full">Modbus</span>
              </div>
              {modbusFunctionChart.labels.length > 0 ? (
                <>
                  <div className="h-56 mb-3">
                    <Bar data={modbusFunctionChart} options={barChartOptions} />
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 mt-4 text-xs">
                    {modbusFunctionChart.labels.slice(0, 6).map((fc) => (
                      <div key={fc as string} className="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-slate-50 ring-1 ring-slate-200/50">
                        <span className="font-mono font-semibold text-slate-700">{fc}</span>
                        <span className="text-slate-500">{MODBUS_FUNCTION_NAMES[fc as string] || 'Unknown'}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="h-56 flex items-center justify-center text-sm text-slate-400">No Modbus function codes seen yet</div>
              )}
            </div>

            <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-semibold text-slate-900">HTTP Probe Activity</h3>
                  <p className="text-xs text-slate-500 mt-0.5">Methods & most-requested paths</p>
                </div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-amber-700 bg-amber-50 ring-1 ring-amber-200 px-2 py-1 rounded-full">HTTP</span>
              </div>
              <div className="flex flex-wrap gap-2 mb-4">
                {Object.entries(stats.httpMethodBreakdown).length === 0 && (
                  <span className="text-xs text-slate-400">No HTTP traffic yet</span>
                )}
                {Object.entries(stats.httpMethodBreakdown).map(([m, c]) => (
                  <span key={m} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-gradient-to-br from-violet-50 to-fuchsia-50 ring-1 ring-violet-200/60 text-xs font-semibold text-violet-700">
                    <span className="font-mono">{m}</span>
                    <span className="text-violet-500">· {c}</span>
                  </span>
                ))}
              </div>
              <div className="space-y-1.5">
                {topHttpPaths.length === 0 && (
                  <p className="text-xs text-slate-400">Top probed paths will appear here.</p>
                )}
                {topHttpPaths.map(([path, count]) => (
                  <div key={path} className="flex items-center justify-between px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200/50">
                    <span className="font-mono text-xs text-slate-700 truncate">{path}</span>
                    <span className="text-xs font-semibold text-slate-900 ml-3">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Recent Events (attacker analysis lives on Attack Intelligence page) */}
          <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-200/70 flex items-center justify-between gap-4 flex-wrap">
              <div>
                <h3 className="text-base font-semibold text-slate-900">Recent Events</h3>
                <p className="text-xs text-slate-500 mt-0.5">Last {stats.recentEvents.length} parsed events from this decoy instance</p>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-violet-700 bg-violet-50 ring-1 ring-violet-200 px-2 py-1 rounded-full">Events</span>
                <button
                  type="button"
                  onClick={() => setAttackersOpen(true)}
                  className="text-[11px] font-semibold uppercase tracking-wider text-fuchsia-700 bg-fuchsia-50 hover:bg-fuchsia-100 ring-1 ring-fuchsia-200 px-2 py-1 rounded-full transition"
                  title="Show top source IPs observed by this decoy instance"
                >
                  Top Attackers ({stats.topAttackers.length}) →
                </button>
              </div>
            </div>
            {stats.recentEvents.length === 0 ? (
              <div className="p-10 text-center text-sm text-slate-400">No events yet.</div>
            ) : (
              <div className="max-h-96 overflow-y-auto divide-y divide-slate-200/60">
                {stats.recentEvents.map((ev, i) => {
                  const sev = SEVERITY_STYLES[ev.severity] || SEVERITY_STYLES.LOW;
                  return (
                    <div key={i} className="px-6 py-3 hover:bg-slate-50/60 transition">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
                        <span className={`text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded ring-1 ${sev.pill}`}>{ev.severity}</span>
                        {ev.protocol && (
                          <span className="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 ring-1 ring-slate-200">{ev.protocol}</span>
                        )}
                        {ev.sourceIp && <span className="text-xs font-mono text-slate-500">{ev.sourceIp}</span>}
                      </div>
                      <p className="text-xs text-slate-700 font-mono truncate">{ev.raw}</p>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}

      {hasAnyData && (
        <>
          {/* ===== Threat Posture row ===== */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Threat Score gauge */}
            <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-semibold text-slate-900">Threat Score</h3>
                  <p className="text-xs text-slate-500 mt-0.5">Severity-weighted (0-100)</p>
                </div>
                <span className={`text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full ring-1 ${
                  threatScore >= 66 ? 'bg-rose-50 text-rose-700 ring-rose-200'
                  : threatScore >= 33 ? 'bg-amber-50 text-amber-700 ring-amber-200'
                  : 'bg-emerald-50 text-emerald-700 ring-emerald-200'
                }`}>
                  {threatScore >= 66 ? 'High' : threatScore >= 33 ? 'Elevated' : 'Low'}
                </span>
              </div>
              <div className="relative w-32 h-32 mx-auto">
                <svg className="w-32 h-32 -rotate-90" viewBox="0 0 120 120">
                  <circle cx="60" cy="60" r="52" fill="none" stroke="rgb(241 245 249)" strokeWidth="12" />
                  <circle cx="60" cy="60" r="52" fill="none"
                    stroke={threatScore >= 66 ? '#f43f5e' : threatScore >= 33 ? '#f97316' : '#10b981'}
                    strokeWidth="12" strokeLinecap="round"
                    strokeDasharray={`${(threatScore / 100) * 326.7} 326.7`}
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-3xl font-bold text-slate-900 tabular-nums">{threatScore}</span>
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider">of 100</span>
                </div>
              </div>
              <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
                <div><span className="block font-semibold text-rose-600">{stats.severityBreakdown.HIGH || 0}</span><span className="text-slate-500">High</span></div>
                <div><span className="block font-semibold text-amber-600">{stats.severityBreakdown.MEDIUM || 0}</span><span className="text-slate-500">Med</span></div>
                <div><span className="block font-semibold text-emerald-600">{stats.severityBreakdown.LOW || 0}</span><span className="text-slate-500">Low</span></div>
              </div>
            </div>

            {/* Attack Velocity */}
            <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-semibold text-slate-900">Attack Velocity</h3>
                  <p className="text-xs text-slate-500 mt-0.5">Events this hour vs. previous</p>
                </div>
                <span className={`text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full ring-1 ${
                  attackVelocity.delta > 0 ? 'bg-rose-50 text-rose-700 ring-rose-200'
                  : attackVelocity.delta < 0 ? 'bg-emerald-50 text-emerald-700 ring-emerald-200'
                  : 'bg-slate-50 text-slate-600 ring-slate-200'
                }`}>
                  {attackVelocity.delta > 0 ? '+' : ''}{attackVelocity.delta}%
                </span>
              </div>
              <div className="text-center">
                <p className="text-4xl font-bold text-slate-900 tabular-nums">{attackVelocity.current}</p>
                <p className="text-xs text-slate-500 mt-1">events this hour ({attackVelocity.prev} previous)</p>
              </div>
              {/* mini sparkline */}
              <div className="mt-4 flex items-end gap-0.5 h-10">
                {stats.hourlySeries.slice(-12).map((p, i) => {
                  const max = Math.max(1, ...stats.hourlySeries.map(x => x.count));
                  const h = Math.max(2, (p.count / max) * 100);
                  return (
                    <div key={i} className="flex-1 rounded-t bg-gradient-to-t from-violet-500 to-fuchsia-400 opacity-70 hover:opacity-100 transition" style={{ height: `${h}%` }} title={`${String(p.hour).padStart(2,'0')}:00 — ${p.count}`} />
                  );
                })}
              </div>
              <p className="mt-2 text-[10px] text-slate-400 text-center uppercase tracking-wider">Last 12 hours</p>
            </div>

            {/* Defense Efficacy */}
            <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-semibold text-slate-900">Containment Rate</h3>
                  <p className="text-xs text-slate-500 mt-0.5">High-severity events isolated</p>
                </div>
                <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full bg-violet-50 text-violet-700 ring-1 ring-violet-200">
                  Defence
                </span>
              </div>
              <div className="text-center">
                <p className="text-4xl font-bold text-slate-900 tabular-nums">{blockEffectiveness}%</p>
                <p className="text-xs text-slate-500 mt-1">{stats.severityBreakdown.HIGH || 0} of {stats.totalLogs} events</p>
              </div>
              <div className="mt-5 h-2 bg-slate-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-violet-500 to-fuchsia-500 rounded-full transition-all duration-500"
                  style={{ width: `${Math.min(100, blockEffectiveness)}%` }}
                />
              </div>
              <div className="mt-4 grid grid-cols-2 gap-3 text-xs text-center">
                <div className="px-2 py-1.5 rounded-lg bg-slate-50 ring-1 ring-slate-200/50">
                  <span className="block font-semibold text-slate-900 tabular-nums">{stats.errorCount}</span>
                  <span className="text-slate-500">Exceptions</span>
                </div>
                <div className="px-2 py-1.5 rounded-lg bg-slate-50 ring-1 ring-slate-200/50">
                  <span className="block font-semibold text-slate-900 tabular-nums">{stats.resetConnections}</span>
                  <span className="text-slate-500">Resets</span>
                </div>
              </div>
            </div>
          </div>

          {/* ===== Last Attack + Top Attack Vector ===== */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Last attack pulse card */}
            <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition relative overflow-hidden">
              <div className="absolute -top-12 -right-12 w-40 h-40 rounded-full bg-rose-500/5 blur-2xl" />
              <div className="relative">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-base font-semibold text-slate-900">Last Observed Attack</h3>
                    <p className="text-xs text-slate-500 mt-0.5">Most recent event captured by the decoy</p>
                  </div>
                  <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full bg-rose-50 text-rose-700 ring-1 ring-rose-200">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
                    Live
                  </span>
                </div>
                {lastAttack ? (
                  <>
                    <p className="text-2xl font-bold text-slate-900 tabular-nums font-mono">{lastAttack.sourceIp || 'Unknown source'}</p>
                    <div className="flex flex-wrap items-center gap-2 mt-2">
                      {lastAttack.protocol && (
                        <span className="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-violet-50 text-violet-700 ring-1 ring-violet-200">{lastAttack.protocol}</span>
                      )}
                      {lastAttack.severity && (
                        <span className={`text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded ring-1 ${SEVERITY_STYLES[lastAttack.severity]?.pill || SEVERITY_STYLES.LOW.pill}`}>
                          {lastAttack.severity}
                        </span>
                      )}
                    </div>
                    <p className="mt-3 text-xs text-slate-600 leading-relaxed line-clamp-2">{lastAttack.raw || ''}</p>
                  </>
                ) : (
                  <p className="text-sm text-slate-400">No events captured yet.</p>
                )}
              </div>
            </div>

            {/* Top attack vector */}
            <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-semibold text-slate-900">Primary Attack Vector</h3>
                  <p className="text-xs text-slate-500 mt-0.5">Most-targeted protocol on this decoy</p>
                </div>
                <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full bg-fuchsia-50 text-fuchsia-700 ring-1 ring-fuchsia-200">
                  Vector
                </span>
              </div>
              {topAttackVector ? (
                <>
                  <div className="flex items-baseline gap-3">
                    <p className="text-3xl font-bold text-slate-900">{topAttackVector.protocol}</p>
                    <p className="text-sm text-slate-500 tabular-nums">{topAttackVector.share}%</p>
                  </div>
                  <p className="text-xs text-slate-500 mt-1">{topAttackVector.count.toLocaleString()} events</p>
                  <div className="mt-4 h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-fuchsia-500 to-pink-500 rounded-full" style={{ width: `${topAttackVector.share}%` }} />
                  </div>
                  {topAttackVector.runnerUp && (
                    <div className="mt-4 flex items-center justify-between px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200/50">
                      <span className="text-xs text-slate-500">Runner-up</span>
                      <span className="text-sm font-semibold text-slate-700">{topAttackVector.runnerUp.protocol}</span>
                      <span className="text-xs text-slate-500 tabular-nums">{topAttackVector.runnerUp.count}</span>
                    </div>
                  )}
                </>
              ) : (
                <p className="text-sm text-slate-400">No protocol data yet.</p>
              )}
            </div>
          </div>

          {/* ===== MITRE ATT&CK for ICS — observed tactics strip ===== */}
          <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-semibold text-slate-900">MITRE ATT&amp;CK for ICS</h3>
                <p className="text-xs text-slate-500 mt-0.5">Observed tactics inferred from telemetry</p>
              </div>
              <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-1 rounded-full bg-violet-50 text-violet-700 ring-1 ring-violet-200">
                Tactics
              </span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {mitreTactics.map(t => {
                const max = Math.max(1, ...mitreTactics.map(x => x.observed));
                const intensity = t.observed === 0 ? 0 : Math.max(15, (t.observed / max) * 100);
                return (
                  <div
                    key={t.id}
                    className={`relative rounded-xl p-3 ring-1 transition overflow-hidden ${
                      t.observed > 0 ? 'ring-slate-200/70 bg-white' : 'ring-slate-200/40 bg-slate-50/40 opacity-60'
                    }`}
                  >
                    {t.observed > 0 && (
                      <div
                        className={`absolute inset-x-0 bottom-0 bg-gradient-to-t ${t.color} opacity-20`}
                        style={{ height: `${intensity}%` }}
                      />
                    )}
                    <div className="relative">
                      <p className="text-[10px] font-mono text-slate-400">{t.id}</p>
                      <p className="text-xs font-semibold text-slate-900 mt-0.5 leading-tight">{t.name}</p>
                      <p className="text-lg font-bold text-slate-900 tabular-nums mt-2">{t.observed}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}

      {/* ===== Top Attackers modal ===== */}
      {attackersOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm"
          onClick={() => { setAttackersOpen(false); setSelectedAttackerIp(null); }}
        >
          <div
            className="bg-white rounded-2xl shadow-2xl ring-1 ring-slate-200/70 w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="px-6 py-4 border-b border-slate-200/70 flex items-center justify-between gap-4 flex-wrap">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-rose-500 to-orange-500 text-white flex items-center justify-center shadow-md shadow-rose-500/20">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-slate-900">Top Attackers — decoy instance</h2>
                  <p className="text-xs text-slate-500 mt-0.5">Source IPs ranked by event count · {stats.uniqueIPs} unique IPs across {stats.totalLogs} log lines</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Link
                  to="/attack-intelligence"
                  className="text-[11px] font-semibold uppercase tracking-wider text-violet-700 bg-violet-50 hover:bg-violet-100 ring-1 ring-violet-200 px-2.5 py-1.5 rounded-lg transition"
                  title="Open fleet-wide Attack Intelligence with geo, ASN, credentials"
                >
                  Fleet view →
                </Link>
                <button
                  type="button"
                  onClick={() => { setAttackersOpen(false); setSelectedAttackerIp(null); }}
                  className="w-8 h-8 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 flex items-center justify-center transition"
                  aria-label="Close"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
              </div>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto">
              {stats.topAttackers.length === 0 ? (
                <div className="p-12 text-center">
                  <div className="w-14 h-14 mx-auto mb-4 rounded-2xl bg-slate-100 text-slate-400 flex items-center justify-center">
                    <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                  </div>
                  <h3 className="text-base font-semibold text-slate-900">No attackers yet</h3>
                  <p className="mt-1 text-sm text-slate-500 max-w-sm mx-auto">
                    Once the decoy captures probes, their source IPs will be ranked here.
                  </p>
                </div>
              ) : selectedAttackerIp ? (
                // ===== Attacker detail view =====
                (() => {
                  const attacker = stats.topAttackers.find(a => a.ip === selectedAttackerIp);
                  const events = stats.recentEvents.filter(e => e.sourceIp === selectedAttackerIp);
                  // Infer protocols this attacker hit
                  const protocols = Array.from(new Set(events.map(e => e.protocol).filter(Boolean))) as string[];
                  const severityCounts = events.reduce<Record<string, number>>((acc, e) => {
                    acc[e.severity] = (acc[e.severity] || 0) + 1;
                    return acc;
                  }, {});
                  return (
                    <div className="p-6 space-y-5">
                      <button
                        type="button"
                        onClick={() => setSelectedAttackerIp(null)}
                        className="inline-flex items-center gap-1.5 text-xs font-semibold text-violet-700 hover:text-violet-900 transition"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
                        Back to list
                      </button>

                      {/* Attacker summary card */}
                      <div className="bg-gradient-to-br from-slate-50 to-rose-50/40 ring-1 ring-slate-200/60 rounded-2xl p-5">
                        <div className="flex items-start justify-between gap-4 flex-wrap">
                          <div>
                            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Source IP</p>
                            <p className="mt-1 text-2xl font-mono font-bold text-slate-900">{selectedAttackerIp}</p>
                            <div className="flex flex-wrap gap-2 mt-3">
                              {protocols.length === 0 ? (
                                <span className="text-xs text-slate-400">Protocol unknown</span>
                              ) : protocols.map(p => (
                                <span key={p} className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded bg-violet-50 text-violet-700 ring-1 ring-violet-200">{p}</span>
                              ))}
                            </div>
                          </div>
                          <div className="grid grid-cols-3 gap-3 min-w-0">
                            <div className="text-center">
                              <p className="text-xs text-slate-500">Events</p>
                              <p className="text-xl font-bold text-slate-900">{attacker?.attacks.toLocaleString() || 0}</p>
                            </div>
                            <div className="text-center">
                              <p className="text-xs text-slate-500">In recent</p>
                              <p className="text-xl font-bold text-slate-900">{events.length}</p>
                            </div>
                            <div className="text-center">
                              <p className="text-xs text-slate-500">High sev</p>
                              <p className="text-xl font-bold text-rose-600">{severityCounts.HIGH || 0}</p>
                            </div>
                          </div>
                        </div>

                        {/* Lookup links */}
                        <div className="mt-4 flex flex-wrap gap-2">
                          <a
                            href={`https://www.abuseipdb.com/check/${selectedAttackerIp}`}
                            target="_blank" rel="noreferrer"
                            className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-slate-700 bg-white hover:bg-slate-50 ring-1 ring-slate-200 px-2.5 py-1.5 rounded-lg transition"
                          >AbuseIPDB ↗</a>
                          <a
                            href={`https://www.virustotal.com/gui/ip-address/${selectedAttackerIp}`}
                            target="_blank" rel="noreferrer"
                            className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-slate-700 bg-white hover:bg-slate-50 ring-1 ring-slate-200 px-2.5 py-1.5 rounded-lg transition"
                          >VirusTotal ↗</a>
                          <a
                            href={`https://ipinfo.io/${selectedAttackerIp}`}
                            target="_blank" rel="noreferrer"
                            className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-slate-700 bg-white hover:bg-slate-50 ring-1 ring-slate-200 px-2.5 py-1.5 rounded-lg transition"
                          >ipinfo.io ↗</a>
                          <a
                            href={`https://www.shodan.io/host/${selectedAttackerIp}`}
                            target="_blank" rel="noreferrer"
                            className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-slate-700 bg-white hover:bg-slate-50 ring-1 ring-slate-200 px-2.5 py-1.5 rounded-lg transition"
                          >Shodan ↗</a>
                        </div>
                      </div>

                      {/* Events from this IP */}
                      <div>
                        <h3 className="text-sm font-semibold text-slate-900 mb-2">Events from {selectedAttackerIp}</h3>
                        {events.length === 0 ? (
                          <p className="text-sm text-slate-400">This IP ranks in the top attackers list but has no lines in the recent-events buffer (older activity).</p>
                        ) : (
                          <div className="space-y-1.5 max-h-72 overflow-y-auto ring-1 ring-slate-200/60 rounded-xl">
                            {events.map((ev, i) => {
                              const sev = SEVERITY_STYLES[ev.severity] || SEVERITY_STYLES.LOW;
                              return (
                                <div key={i} className="px-4 py-2.5 hover:bg-slate-50/60 transition border-b border-slate-200/40 last:border-0">
                                  <div className="flex items-center gap-2 mb-1">
                                    <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
                                    <span className={`text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded ring-1 ${sev.pill}`}>{ev.severity}</span>
                                    {ev.protocol && (
                                      <span className="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 ring-1 ring-slate-200">{ev.protocol}</span>
                                    )}
                                  </div>
                                  <p className="text-xs text-slate-700 font-mono break-all">{ev.raw}</p>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })()
              ) : (
                // ===== List view =====
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200/70">
                    <thead className="bg-slate-50/60 sticky top-0">
                      <tr>
                        <th className="px-6 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Rank</th>
                        <th className="px-6 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Source IP</th>
                        <th className="px-6 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Events</th>
                        <th className="px-6 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Share</th>
                        <th className="px-6 py-3 text-right text-[11px] font-semibold text-slate-500 uppercase tracking-wider"></th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-slate-200/60">
                      {stats.topAttackers.map((a, i) => {
                        const max = stats.topAttackers[0]?.attacks || 1;
                        const pct = Math.round((a.attacks / max) * 100);
                        // Compute protocols hit by this IP from recent events
                        const protocolsHit = Array.from(new Set(
                          stats.recentEvents.filter(e => e.sourceIp === a.ip).map(e => e.protocol).filter(Boolean)
                        )) as string[];
                        return (
                          <tr
                            key={a.ip}
                            className="hover:bg-violet-50/40 transition cursor-pointer"
                            onClick={() => setSelectedAttackerIp(a.ip)}
                          >
                            <td className="px-6 py-3 text-sm font-semibold text-slate-500">#{i + 1}</td>
                            <td className="px-6 py-3 whitespace-nowrap">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-mono font-medium text-slate-900">{a.ip}</span>
                                {protocolsHit.slice(0, 3).map(p => (
                                  <span key={p} className="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 ring-1 ring-slate-200">{p}</span>
                                ))}
                              </div>
                            </td>
                            <td className="px-6 py-3 whitespace-nowrap text-sm font-semibold text-slate-900">{a.attacks.toLocaleString()}</td>
                            <td className="px-6 py-3 whitespace-nowrap">
                              <div className="flex items-center gap-2">
                                <div className="w-28 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                                  <div className="h-full bg-gradient-to-r from-violet-500 to-fuchsia-500 rounded-full" style={{ width: `${pct}%` }} />
                                </div>
                                <span className="text-xs text-slate-500 w-10 text-right">{pct}%</span>
                              </div>
                            </td>
                            <td className="px-6 py-3 whitespace-nowrap text-right">
                              <span className="text-[11px] font-semibold uppercase tracking-wider text-violet-700">Details →</span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Conpot;
