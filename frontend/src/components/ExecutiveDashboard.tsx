import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Line, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Filler,
} from 'chart.js';

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Filler
);

/* ------------------------------------------------------------------ */
/*  Inline SVG icon set - no external AI-generated icon packs          */
/* ------------------------------------------------------------------ */
const Icon = {
  Shield: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2l8 3v7c0 4.97-3.58 9.16-8 10-4.42-.84-8-5.03-8-10V5l8-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  ),
  Eye: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  ),
  Brain: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 3a3 3 0 0 0-3 3v1a3 3 0 0 0-3 3v2a3 3 0 0 0 1.5 2.6A3 3 0 0 0 6 19a3 3 0 0 0 3 3 3 3 0 0 0 3-3V6a3 3 0 0 0-3-3z" />
      <path d="M15 3a3 3 0 0 1 3 3v1a3 3 0 0 1 3 3v2a3 3 0 0 1-1.5 2.6A3 3 0 0 1 18 19a3 3 0 0 1-3 3 3 3 0 0 1-3-3V6a3 3 0 0 1 3-3z" />
    </svg>
  ),
  Target: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <circle cx="12" cy="12" r="6" />
      <circle cx="12" cy="12" r="2" />
    </svg>
  ),
  Alert: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  Clock: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <polyline points="12 6 12 12 16 14" />
    </svg>
  ),
  Activity: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  ),
  Network: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="5" r="2" />
      <circle cx="5" cy="19" r="2" />
      <circle cx="19" cy="19" r="2" />
      <path d="M12 7v4M12 11l-7 6M12 11l7 6" />
    </svg>
  ),
  CheckCircle: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
  ),
  Bolt: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  ),
  Layers: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="12 2 2 7 12 12 22 7 12 2" />
      <polyline points="2 17 12 22 22 17" />
      <polyline points="2 12 12 17 22 12" />
    </svg>
  ),
  Server: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="20" height="8" rx="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" />
      <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  ),
  Lock: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  ),
  TrendingUp: ({ className = 'w-4 h-4' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="23 6 13.5 15.5 8.5 10.5 1 18" />
      <polyline points="17 6 23 6 23 12" />
    </svg>
  ),
  TrendingDown: ({ className = 'w-4 h-4' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="23 18 13.5 8.5 8.5 13.5 1 6" />
      <polyline points="17 18 23 18 23 12" />
    </svg>
  ),
  Arrow: ({ className = 'w-4 h-4' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="5" y1="12" x2="19" y2="12" />
      <polyline points="12 5 19 12 12 19" />
    </svg>
  ),
};

const ExecutiveDashboard: React.FC = () => {
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('7d');

  /* ---------- CISO-facing KPIs ---------- */
  const [metrics] = useState({
    // Posture
    postureScore: 82,           // 0-100, composite risk-adjusted posture
    postureDelta: +4,           // vs last period
    residualRisk: 'MODERATE',   // HIGH | MODERATE | LOW
    // Operational performance
    mttd: 6.4,                  // mean time to detect (minutes)
    mttdBenchmark: 197,         // industry avg (days → shown as 197d)
    mttr: 42,                   // mean time to respond (minutes)
    mttrDelta: -31,             // % reduction vs baseline
    dwellTime: 11,              // minutes (deception reduces this drastically)
    dwellBenchmark: 84,         // days industry avg
    // Risk / exposure
    criticalAssetsAtRisk: 3,
    totalCrownJewels: 47,
    highConfidenceAlerts: 28,   // last period
    noiseReduction: 92,         // % noise cut vs SIEM-only
    // Business impact
    estimatedLossAvoided: 2.4,  // £M
    insurancePremiumImpact: -12,// % estimated reduction
    complianceReadiness: 91,    // overall composite %
    // Coverage
    coverageLevel0: 78,
    coverageLevel1: 92,
    coverageLevel2: 74,
    coverageLevel3: 65,
  });

  /* ---------- Weekly incident trend: confirmed vs noise ---------- */
  const [threatTrends] = useState([
    { day: 'Mon', confirmed: 3, investigated: 18, noise: 142 },
    { day: 'Tue', confirmed: 2, investigated: 14, noise: 128 },
    { day: 'Wed', confirmed: 5, investigated: 22, noise: 156 },
    { day: 'Thu', confirmed: 4, investigated: 19, noise: 134 },
    { day: 'Fri', confirmed: 6, investigated: 26, noise: 168 },
    { day: 'Sat', confirmed: 1, investigated: 9, noise: 88 },
    { day: 'Sun', confirmed: 2, investigated: 11, noise: 96 },
  ]);

  /* ---------- MITRE ATT&CK for ICS: tactic coverage ---------- */
  const [mitreTactics] = useState([
    { id: 'TA0108', name: 'Initial Access', observed: 14, coverage: 92 },
    { id: 'TA0109', name: 'Execution', observed: 8, coverage: 88 },
    { id: 'TA0102', name: 'Discovery', observed: 31, coverage: 96 },
    { id: 'TA0111', name: 'Lateral Movement', observed: 11, coverage: 84 },
    { id: 'TA0103', name: 'Collection', observed: 6, coverage: 78 },
    { id: 'TA0105', name: 'Impair Process Control', observed: 3, coverage: 71 },
  ]);

  /* ---------- Crown-jewel assets & current risk state ---------- */
  const [crownJewels] = useState([
    { asset: 'Substation PLC Cluster · North', zone: 'Level 1', risk: 'CRITICAL', trend: '+2', detail: 'Active recon on decoy RTU' },
    { asset: 'SCADA Historian · Primary', zone: 'Level 3', risk: 'HIGH',     trend: '·',  detail: 'Credential spraying blocked' },
    { asset: 'Engineering Workstation · HMI-7', zone: 'Level 2', risk: 'HIGH',     trend: '+1', detail: 'Lateral movement attempt' },
    { asset: 'Safety Instrumented System', zone: 'Level 1', risk: 'MEDIUM',   trend: '-1', detail: 'No anomalous interaction' },
    { asset: 'Remote Maintenance VPN',     zone: 'Level 3', risk: 'LOW',      trend: '-2', detail: 'Posture improved' },
  ]);

  /* ---------- Compliance gap (what's missing, not what's done) ---------- */
  const [complianceStatus] = useState([
    { name: 'NIS2',      value: 94, gap: 'Incident reporting automation pending' },
    { name: 'IEC 62443', value: 88, gap: '2 zones below SL-2 target' },
    { name: 'CAF',       value: 76, gap: 'Supply-chain monitoring partial' },
    { name: 'GDPR',      value: 92, gap: 'Data flow mapping for OT↔IT' },
  ]);

  /* ---------- Executive-grade alerts ---------- */
  const [recentAlerts] = useState([
    { id: 1, title: 'Unauthorised access attempt on decoy RTU',      severity: 'CRITICAL', time: '12m ago', source: 'North Substation',        impact: 'Could target real PLC cluster' },
    { id: 2, title: 'Credential spraying against SCADA historian',   severity: 'HIGH',     time: '1h ago',   source: 'Primary Data Centre',      impact: 'Blocked, no real asset exposed'},
    { id: 3, title: 'Modbus protocol anomaly from engineering host', severity: 'HIGH',     time: '3h ago',   source: 'HMI Workstation 07',       impact: 'Potential insider activity' },
    { id: 4, title: 'Repeated scanning from segmented IT subnet',    severity: 'MEDIUM',   time: '6h ago',   source: '10.42.0.0/16',             impact: 'IT/OT boundary pressure' },
  ]);

  /* ---------- Chart datasets ---------- */
  const threatTrendData = {
    labels: threatTrends.map((t) => t.day),
    datasets: [
      {
        type: 'bar' as const,
        label: 'Noise filtered',
        data: threatTrends.map((t) => t.noise),
        backgroundColor: 'rgba(148,163,184,0.35)',
        borderRadius: 6,
        stack: 'events',
        order: 3,
      },
      {
        type: 'bar' as const,
        label: 'Investigated',
        data: threatTrends.map((t) => t.investigated),
        backgroundColor: 'rgba(168,85,247,0.55)',
        borderRadius: 6,
        stack: 'events',
        order: 2,
      },
      {
        type: 'line' as const,
        label: 'Confirmed incidents',
        data: threatTrends.map((t) => t.confirmed),
        borderColor: '#ec4899',
        backgroundColor: 'rgba(236,72,153,0.15)',
        tension: 0.35,
        fill: false,
        pointBackgroundColor: '#ec4899',
        pointBorderColor: '#fff',
        pointRadius: 5,
        pointHoverRadius: 7,
        borderWidth: 3,
        yAxisID: 'y1',
        order: 1,
      },
    ],
  };

  /* ---------- Coverage across OT levels (Purdue) ---------- */
  const deploymentData = {
    labels: ['Level 0 (Field)', 'Level 1 (Control)', 'Level 2 (Supervisory)', 'Level 3 (Operations)'],
    datasets: [
      {
        label: 'Coverage %',
        data: [metrics.coverageLevel0, metrics.coverageLevel1, metrics.coverageLevel2, metrics.coverageLevel3],
        backgroundColor: ['#7c3aed', '#a855f7', '#c026d3', '#ec4899'],
        borderRadius: 8,
        borderSkipped: false,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#475569', font: { size: 12, weight: 500 }, usePointStyle: true, pointStyle: 'circle' },
        position: 'top' as const,
        align: 'end' as const,
      },
      tooltip: {
        backgroundColor: 'rgba(17, 24, 39, 0.95)',
        titleColor: '#fff',
        bodyColor: '#e5e7eb',
        padding: 12,
        borderColor: 'rgba(168,85,247,0.3)',
        borderWidth: 1,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: { color: 'rgba(226, 232, 240, 0.6)' },
        ticks: { color: '#94a3b8' },
        title: { display: true, text: 'Events volume', color: '#94a3b8', font: { size: 11 } },
      },
      y1: {
        beginAtZero: true,
        position: 'right' as const,
        grid: { display: false },
        ticks: { color: '#ec4899' },
        title: { display: true, text: 'Confirmed incidents', color: '#ec4899', font: { size: 11 } },
      },
      x: {
        stacked: true,
        grid: { display: false },
        ticks: { color: '#94a3b8' },
      },
    },
  };

  /* ---------- Helpers ---------- */
  const severityStyle = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return { badge: 'bg-rose-100 text-rose-700 ring-rose-200', dot: 'bg-rose-500', bar: 'bg-rose-500' };
      case 'HIGH':
        return { badge: 'bg-orange-100 text-orange-700 ring-orange-200', dot: 'bg-orange-500', bar: 'bg-orange-500' };
      case 'MEDIUM':
        return { badge: 'bg-amber-100 text-amber-700 ring-amber-200', dot: 'bg-amber-500', bar: 'bg-amber-500' };
      default:
        return { badge: 'bg-emerald-100 text-emerald-700 ring-emerald-200', dot: 'bg-emerald-500', bar: 'bg-emerald-500' };
    }
  };

  const container = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.05 } },
  };
  const item = {
    hidden: { opacity: 0, y: 12 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.35 } },
  };

  /* ---------- Render ---------- */
  return (
    <motion.div
      className="relative"
      variants={container}
      initial="hidden"
      animate="visible"
    >
        {/* ====== HERO - Security Posture ====== */}
        <motion.div variants={item} className="mb-8">
          <div
            className="relative overflow-hidden rounded-2xl p-8 md:p-10 text-white"
            style={{
              background:
                'linear-gradient(135deg, #1e1b4b 0%, #4c1d95 45%, #7c3aed 100%)',
            }}
          >
            <div className="absolute -top-20 -right-20 w-80 h-80 rounded-full" style={{ background: 'radial-gradient(closest-side, rgba(236,72,153,0.35), transparent)' }} />
            <div className="absolute -bottom-24 -left-10 w-72 h-72 rounded-full" style={{ background: 'radial-gradient(closest-side, rgba(168,85,247,0.35), transparent)' }} />

            <div className="relative flex flex-col lg:flex-row lg:items-start lg:justify-between gap-8">
              {/* Left: title + narrative */}
              <div className="max-w-2xl">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 backdrop-blur-sm ring-1 ring-white/20 text-xs font-medium tracking-wide">
                  <Icon.Shield className="w-4 h-4 text-pink-300" />
                  CISO EXECUTIVE SUMMARY &nbsp;·&nbsp; WEEK OF 20 APR 2026
                </div>
                <h1 className="mt-4 text-3xl md:text-4xl font-bold leading-tight">
                  OT environment is
                  <span className="text-emerald-300"> stable</span>.
                  <span className="block text-violet-100/95 font-medium text-xl md:text-2xl mt-2">
                    3 crown-jewel assets under active attacker interest, all contained at decoy layer.
                  </span>
                </h1>

                <div className="mt-5 grid grid-cols-3 gap-3">
                  <div className="p-3 rounded-xl bg-white/10 ring-1 ring-white/15 backdrop-blur-sm">
                    <div className="text-[10px] uppercase tracking-wider text-violet-200/80">Confirmed incidents</div>
                    <div className="mt-1 text-2xl font-bold">23</div>
                    <div className="text-[11px] text-emerald-300">↓ 18% vs last week</div>
                  </div>
                  <div className="p-3 rounded-xl bg-white/10 ring-1 ring-white/15 backdrop-blur-sm">
                    <div className="text-[10px] uppercase tracking-wider text-violet-200/80">Noise cut</div>
                    <div className="mt-1 text-2xl font-bold">{metrics.noiseReduction}%</div>
                    <div className="text-[11px] text-violet-200/80">vs SIEM baseline</div>
                  </div>
                  <div className="p-3 rounded-xl bg-white/10 ring-1 ring-white/15 backdrop-blur-sm">
                    <div className="text-[10px] uppercase tracking-wider text-violet-200/80">Loss avoided</div>
                    <div className="mt-1 text-2xl font-bold">£{metrics.estimatedLossAvoided}M</div>
                    <div className="text-[11px] text-violet-200/80">estimated, YTD</div>
                  </div>
                </div>
              </div>

              {/* Right: posture score gauge + time range */}
              <div className="flex flex-col items-center gap-4">
                <div className="relative w-44 h-44">
                  <svg className="transform -rotate-90 w-44 h-44">
                    <circle cx="88" cy="88" r="76" stroke="rgba(255,255,255,0.15)" strokeWidth="12" fill="none" />
                    <circle
                      cx="88" cy="88" r="76"
                      stroke="url(#postureGrad)"
                      strokeWidth="12"
                      fill="none"
                      strokeLinecap="round"
                      strokeDasharray={2 * Math.PI * 76}
                      strokeDashoffset={2 * Math.PI * 76 * (1 - metrics.postureScore / 100)}
                    />
                    <defs>
                      <linearGradient id="postureGrad" x1="0" y1="0" x2="1" y2="1">
                        <stop offset="0%" stopColor="#f0abfc" />
                        <stop offset="100%" stopColor="#fb7185" />
                      </linearGradient>
                    </defs>
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-[10px] uppercase tracking-widest text-violet-200/80">Posture</span>
                    <span className="text-4xl font-bold">{metrics.postureScore}</span>
                    <span className="text-xs text-emerald-300 font-semibold mt-1">
                      ▲ {metrics.postureDelta} pts · {metrics.residualRisk}
                    </span>
                  </div>
                </div>

                <div className="flex gap-1 p-1 bg-white/10 backdrop-blur-sm rounded-xl ring-1 ring-white/15">
                  {(['24h', '7d', '30d'] as const).map((range) => (
                    <button
                      key={range}
                      onClick={() => setTimeRange(range)}
                      className={`px-4 py-1.5 rounded-lg text-sm font-medium transition ${
                        timeRange === range
                          ? 'bg-white text-violet-700 shadow'
                          : 'text-violet-100 hover:text-white'
                      }`}
                    >
                      {range}
                    </button>
                  ))}
                </div>
                <div className="flex items-center gap-2 text-xs text-violet-200/80">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-300 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400"></span>
                  </span>
                  Live · updated 2 min ago
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* ====== OPERATIONAL KPIs - vs industry benchmark ====== */}
        <motion.div variants={item} className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          {[
            {
              icon: <Icon.Clock className="w-5 h-5" />,
              label: 'Mean Time to Detect',
              value: `${metrics.mttd} min`,
              benchmark: `${metrics.mttdBenchmark} days industry avg`,
              delta: '44,000× faster',
              deltaGood: true,
              from: 'from-violet-500',
              to: 'to-fuchsia-500',
            },
            {
              icon: <Icon.Bolt className="w-5 h-5" />,
              label: 'Mean Time to Respond',
              value: `${metrics.mttr} min`,
              benchmark: 'Target SLA: 60 min',
              delta: `${metrics.mttrDelta}% vs baseline`,
              deltaGood: true,
              from: 'from-fuchsia-500',
              to: 'to-pink-500',
            },
            {
              icon: <Icon.Eye className="w-5 h-5" />,
              label: 'Attacker Dwell Time',
              value: `${metrics.dwellTime} min`,
              benchmark: `${metrics.dwellBenchmark} days industry avg`,
              delta: 'Contained at decoy layer',
              deltaGood: true,
              from: 'from-pink-500',
              to: 'to-rose-500',
            },
          ].map((p, i) => (
            <div
              key={i}
              className="group relative bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-lg hover:-translate-y-0.5 transition-all duration-300 overflow-hidden"
            >
              <div className={`absolute inset-x-0 top-0 h-1 bg-gradient-to-r ${p.from} ${p.to}`} />
              <div className="flex items-start justify-between">
                <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${p.from} ${p.to} text-white flex items-center justify-center shadow-md shadow-violet-500/20`}>
                  {p.icon}
                </div>
                <span className={`text-[11px] font-semibold px-2 py-1 rounded-full ${
                  p.deltaGood ? 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200' : 'bg-rose-50 text-rose-700 ring-1 ring-rose-200'
                }`}>
                  {p.delta}
                </span>
              </div>
              <p className="mt-4 text-[11px] uppercase tracking-wider text-slate-500 font-semibold">{p.label}</p>
              <p className="mt-1 text-3xl font-bold text-slate-900 tracking-tight">{p.value}</p>
              <p className="mt-1 text-xs text-slate-500">{p.benchmark}</p>
            </div>
          ))}
        </motion.div>

        {/* ====== RISK EXPOSURE ROW ====== */}
        <motion.div variants={item} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {[
            {
              label: 'Crown Jewels at Risk',
              value: `${metrics.criticalAssetsAtRisk} / ${metrics.totalCrownJewels}`,
              hint: 'High-value OT assets under active probing',
              icon: <Icon.Lock className="w-5 h-5" />,
              color: 'rose',
              progress: (metrics.criticalAssetsAtRisk / metrics.totalCrownJewels) * 100,
            },
            {
              label: 'High-Confidence Alerts',
              value: metrics.highConfidenceAlerts,
              hint: `Only ${metrics.highConfidenceAlerts} needed review · ${metrics.noiseReduction}% noise cut`,
              icon: <Icon.Alert className="w-5 h-5" />,
              color: 'violet',
              progress: 72,
            },
            {
              label: 'Compliance Readiness',
              value: `${metrics.complianceReadiness}%`,
              hint: 'NIS2, IEC 62443, CAF composite',
              icon: <Icon.CheckCircle className="w-5 h-5" />,
              color: 'fuchsia',
              progress: metrics.complianceReadiness,
            },
            {
              label: 'Cyber Insurance Impact',
              value: `${metrics.insurancePremiumImpact}%`,
              hint: 'Projected premium reduction at renewal',
              icon: <Icon.Shield className="w-5 h-5" />,
              color: 'pink',
              progress: Math.abs(metrics.insurancePremiumImpact) * 5,
            },
          ].map((kpi, i) => {
            const gradient: Record<string, string> = {
              violet: 'from-violet-500 to-fuchsia-500',
              fuchsia: 'from-fuchsia-500 to-pink-500',
              rose: 'from-rose-500 to-orange-500',
              pink: 'from-pink-500 to-rose-500',
            };
            return (
              <div
                key={i}
                className="relative bg-white rounded-2xl p-5 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition"
              >
                <div className="flex items-center justify-between mb-3">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    {kpi.label}
                  </span>
                  <div
                    className={`w-9 h-9 rounded-lg bg-gradient-to-br ${gradient[kpi.color]} text-white flex items-center justify-center`}
                  >
                    {kpi.icon}
                  </div>
                </div>
                <div className="text-3xl font-bold text-slate-900 tracking-tight">{kpi.value}</div>
                <p className="mt-1 text-xs text-slate-500">{kpi.hint}</p>
                <div className="mt-4 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className={`h-full bg-gradient-to-r ${gradient[kpi.color]} rounded-full`}
                    style={{ width: `${kpi.progress}%` }}
                  />
                </div>
              </div>
            );
          })}
        </motion.div>

        {/* ====== INCIDENT TREND + SOC EFFICIENCY ====== */}
        <motion.div variants={item} className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Weekly incident trend */}
          <div className="lg:col-span-2 bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm">
            <div className="flex items-start justify-between mb-5">
              <div>
                <h3 className="text-base font-semibold text-slate-900">Alert Funnel · Last 7 Days</h3>
                <p className="text-xs text-slate-500 mt-1">
                  From raw events to confirmed incidents. Analyst review time is spent only on the pink line.
                </p>
              </div>
              <div className="flex items-center gap-3 text-xs">
                <span className="flex items-center gap-1.5 text-slate-600">
                  <span className="w-2.5 h-2.5 rounded-sm bg-slate-400/60" /> Noise
                </span>
                <span className="flex items-center gap-1.5 text-slate-600">
                  <span className="w-2.5 h-2.5 rounded-sm bg-violet-500/70" /> Reviewed
                </span>
                <span className="flex items-center gap-1.5 text-slate-600">
                  <span className="w-2.5 h-2.5 rounded-full bg-pink-500" /> Confirmed
                </span>
              </div>
            </div>
            <div style={{ height: '340px' }}>
              <Line data={threatTrendData as any} options={chartOptions as any} />
            </div>
          </div>

          {/* SOC Efficiency panel */}
          <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-base font-semibold text-slate-900">SOC Efficiency</h3>
                <p className="text-xs text-slate-500 mt-1">What the deception layer removed from the analyst queue</p>
              </div>
              <Icon.Activity className="w-5 h-5 text-fuchsia-500" />
            </div>

            {/* Noise reduction big number */}
            <div className="mt-5 p-4 rounded-xl bg-gradient-to-br from-violet-50 to-pink-50 ring-1 ring-violet-100">
              <div className="text-[11px] uppercase tracking-wider text-violet-700 font-semibold">Noise reduction vs. SIEM-only</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-4xl font-bold bg-gradient-to-r from-violet-600 to-pink-600 bg-clip-text text-transparent">
                  {metrics.noiseReduction}%
                </span>
                <span className="text-xs text-slate-500">fewer alerts to triage</span>
              </div>
            </div>

            {/* Analyst hours + false positives */}
            <div className="mt-4 space-y-3">
              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 ring-1 ring-slate-200/60">
                <div>
                  <p className="text-sm font-semibold text-slate-900">Analyst hours returned</p>
                  <p className="text-xs text-slate-500">vs last quarter</p>
                </div>
                <span className="text-lg font-bold text-emerald-600">+312 h</span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 ring-1 ring-slate-200/60">
                <div>
                  <p className="text-sm font-semibold text-slate-900">False-positive rate</p>
                  <p className="text-xs text-slate-500">Deception hits are binary</p>
                </div>
                <span className="text-lg font-bold text-emerald-600">&lt; 2%</span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 ring-1 ring-slate-200/60">
                <div>
                  <p className="text-sm font-semibold text-slate-900">Tickets auto-enriched</p>
                  <p className="text-xs text-slate-500">MITRE + threat intel</p>
                </div>
                <span className="text-lg font-bold text-violet-600">94%</span>
              </div>
            </div>
          </div>
        </motion.div>

        {/* ====== COMPLIANCE GAP + PURDUE COVERAGE ====== */}
        <motion.div variants={item} className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Compliance with gap narrative */}
          <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-base font-semibold text-slate-900">Compliance Posture & Gaps</h3>
                <p className="text-xs text-slate-500 mt-1">Audit-ready scores with the remaining work identified</p>
              </div>
              <Icon.CheckCircle className="w-5 h-5 text-violet-500" />
            </div>
            <div className="space-y-4">
              {complianceStatus.map((c) => (
                <div key={c.name} className="p-3 rounded-xl bg-slate-50/60 ring-1 ring-slate-200/50">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm font-semibold text-slate-800">{c.name}</span>
                    <span className={`text-sm font-bold ${c.value >= 90 ? 'text-emerald-600' : c.value >= 80 ? 'text-violet-600' : 'text-orange-600'}`}>
                      {c.value}%
                    </span>
                  </div>
                  <div className="h-2 bg-white rounded-full overflow-hidden ring-1 ring-slate-200/60 mb-2">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-violet-500 via-fuchsia-500 to-pink-500"
                      style={{ width: `${c.value}%` }}
                    />
                  </div>
                  <p className="text-[11px] text-slate-500">
                    <span className="font-medium text-slate-600">Gap: </span>{c.gap}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Purdue coverage */}
          <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-base font-semibold text-slate-900">Visibility Coverage · Purdue Levels</h3>
                <p className="text-xs text-slate-500 mt-1">Where we can see attackers, and where we can't</p>
              </div>
              <Icon.Layers className="w-5 h-5 text-fuchsia-500" />
            </div>
            <div style={{ height: '260px' }}>
              <Bar
                data={deploymentData}
                options={{
                  indexAxis: 'y',
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: { display: false },
                    tooltip: {
                      backgroundColor: 'rgba(17,24,39,0.95)',
                      padding: 12,
                      borderColor: 'rgba(168,85,247,0.3)',
                      borderWidth: 1,
                    },
                  },
                  scales: {
                    x: { grid: { color: 'rgba(226,232,240,0.6)' }, ticks: { color: '#94a3b8' } },
                    y: { grid: { display: false }, ticks: { color: '#475569', font: { size: 12, weight: 500 } } },
                  },
                }}
              />
            </div>
          </div>
        </motion.div>

        {/* ====== MITRE ATT&CK (ICS) + RESIDUAL RISK ====== */}
        <motion.div variants={item} className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* MITRE ATT&CK for ICS */}
          <div className="lg:col-span-2 bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-base font-semibold text-slate-900">MITRE ATT&amp;CK for ICS · Observed Tactics</h3>
                <p className="text-xs text-slate-500 mt-1">Where adversaries are probing this week and how well we see it</p>
              </div>
              <Icon.Network className="w-5 h-5 text-violet-500" />
            </div>
            <div className="space-y-3">
              {mitreTactics.map((t) => (
                <div
                  key={t.id}
                  className="p-4 rounded-xl bg-gradient-to-r from-slate-50 to-violet-50/30 ring-1 ring-slate-200/50"
                >
                  <div className="flex justify-between items-center mb-2">
                    <div className="flex items-baseline gap-2">
                      <span className="text-sm font-semibold text-slate-800">{t.name}</span>
                      <span className="text-[10px] font-mono text-slate-400">{t.id}</span>
                    </div>
                    <div className="flex items-center gap-3 text-xs">
                      <span className="text-slate-500">
                        <span className="font-semibold text-slate-800">{t.observed}</span> events
                      </span>
                      <span className={`font-semibold ${t.coverage >= 90 ? 'text-emerald-600' : t.coverage >= 80 ? 'text-violet-600' : 'text-orange-600'}`}>
                        {t.coverage}% coverage
                      </span>
                    </div>
                  </div>
                  <div className="h-2 bg-white rounded-full overflow-hidden ring-1 ring-slate-200/60">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-violet-500 to-pink-500"
                      style={{ width: `${t.coverage}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Residual risk panel */}
          <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-base font-semibold text-slate-900">Residual Risk</h3>
                <p className="text-xs text-slate-500 mt-1">Board-level risk posture</p>
              </div>
              <Icon.Target className="w-5 h-5 text-pink-500" />
            </div>

            <div className="text-center mb-6">
              <div className="relative inline-flex items-center justify-center w-36 h-36">
                <svg className="transform -rotate-90 w-36 h-36">
                  <circle cx="72" cy="72" r="62" stroke="#f1f5f9" strokeWidth="12" fill="none" />
                  <circle
                    cx="72" cy="72" r="62"
                    stroke="url(#riskGrad)"
                    strokeWidth="12"
                    fill="none"
                    strokeLinecap="round"
                    strokeDasharray={2 * Math.PI * 62}
                    strokeDashoffset={2 * Math.PI * 62 * (1 - 0.37)}
                  />
                  <defs>
                    <linearGradient id="riskGrad" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#a855f7" />
                      <stop offset="100%" stopColor="#ec4899" />
                    </linearGradient>
                  </defs>
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-[10px] uppercase tracking-widest text-slate-500">Residual</span>
                  <span className="text-3xl font-bold text-slate-900">3.7</span>
                  <span className="text-[11px] text-violet-600 font-semibold">/ 10</span>
                </div>
              </div>
              <p className="mt-2 text-xs font-semibold text-emerald-600">Within board-approved tolerance (&lt; 5)</p>
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 rounded-lg bg-rose-50 ring-1 ring-rose-100">
                <span className="text-xs text-slate-700">Ransomware exposure</span>
                <span className="text-xs font-bold text-rose-700">HIGH · contained</span>
              </div>
              <div className="flex items-center justify-between p-3 rounded-lg bg-amber-50 ring-1 ring-amber-100">
                <span className="text-xs text-slate-700">Insider / 3rd-party</span>
                <span className="text-xs font-bold text-amber-700">MEDIUM</span>
              </div>
              <div className="flex items-center justify-between p-3 rounded-lg bg-emerald-50 ring-1 ring-emerald-100">
                <span className="text-xs text-slate-700">Nation-state recon</span>
                <span className="text-xs font-bold text-emerald-700">LOW · decoyed</span>
              </div>
            </div>
          </div>
        </motion.div>

        {/* ====== CROWN-JEWEL RISK REGISTER + EXECUTIVE ALERTS ====== */}
        <motion.div variants={item} className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Crown Jewel Risk Register */}
          <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-base font-semibold text-slate-900">Crown-Jewel Risk Register</h3>
                <p className="text-xs text-slate-500 mt-1">Highest-value OT assets ranked by current attacker interest</p>
              </div>
              <Icon.Lock className="w-5 h-5 text-violet-500" />
            </div>
            <div className="space-y-3">
              {crownJewels.map((cj, idx) => {
                const s = severityStyle(cj.risk);
                const trendColor =
                  cj.trend.startsWith('+') ? 'text-rose-600' :
                  cj.trend.startsWith('-') ? 'text-emerald-600' : 'text-slate-400';
                return (
                  <div
                    key={idx}
                    className="p-4 rounded-xl bg-gradient-to-r from-slate-50 to-fuchsia-50/30 ring-1 ring-slate-200/50 hover:ring-violet-300/60 transition"
                  >
                    <div className="flex justify-between items-start">
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-slate-900 truncate">{cj.asset}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">{cj.zone} · {cj.detail}</p>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                        <span className={`text-[11px] font-bold tabular-nums ${trendColor}`}>{cj.trend}</span>
                        <span className={`text-[10px] font-bold px-2.5 py-1 rounded-full ring-1 ${s.badge}`}>
                          {cj.risk}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Executive alerts */}
          <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-base font-semibold text-slate-900">Incidents Requiring Board Awareness</h3>
                <p className="text-xs text-slate-500 mt-1">Only confirmed, high-impact events. No alert fatigue.</p>
              </div>
              <Icon.Alert className="w-5 h-5 text-rose-500" />
            </div>
            <div className="space-y-2.5">
              {recentAlerts.map((alert) => {
                const s = severityStyle(alert.severity);
                return (
                  <div
                    key={alert.id}
                    className="group flex items-start gap-3 p-4 rounded-xl bg-slate-50 hover:bg-white ring-1 ring-slate-200/60 hover:ring-violet-300/60 hover:shadow-sm transition"
                  >
                    <span className={`mt-1 flex-shrink-0 w-2.5 h-2.5 rounded-full ${s.dot} ring-4 ring-white`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-sm font-semibold text-slate-900 truncate">{alert.title}</p>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ring-1 ${s.badge} flex-shrink-0`}>
                          {alert.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 mt-1">{alert.impact}</p>
                      <div className="flex items-center justify-between mt-1.5">
                        <p className="text-[11px] text-slate-400 truncate">{alert.source}</p>
                        <span className="text-[11px] text-slate-400">{alert.time}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </motion.div>

        {/* ====== BOTTOM - ACTION ITEMS FOR THE CISO ====== */}
        <motion.div variants={item} className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {[
            { value: '3', label: 'Decisions pending CISO sign-off', icon: <Icon.CheckCircle className="w-4 h-4" /> },
            { value: '2', label: 'Zones below IEC 62443 SL-2 target', icon: <Icon.Alert className="w-4 h-4" /> },
            { value: '14d', label: 'Until next NIS2 reporting window', icon: <Icon.Clock className="w-4 h-4" /> },
            { value: 'On track', label: 'FY quarterly risk-reduction target', icon: <Icon.TrendingUp className="w-4 h-4" /> },
          ].map((s, i) => (
            <div
              key={i}
              className="relative overflow-hidden bg-white rounded-2xl p-5 ring-1 ring-slate-200/70 shadow-sm"
            >
              <div className="absolute -right-4 -top-4 w-20 h-20 rounded-full bg-gradient-to-br from-violet-500/10 to-pink-500/10" />
              <div className="relative flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                <span className="text-violet-500">{s.icon}</span>
                {s.label}
              </div>
              <p className="relative text-3xl font-bold text-slate-900 mt-2 tracking-tight">{s.value}</p>
            </div>
          ))}
        </motion.div>

        {/* ====== BOARD TALKING POINTS ====== */}
        <motion.div variants={item} className="mb-8">
          <div
            className="relative overflow-hidden rounded-2xl p-6 md:p-8 text-white"
            style={{
              background:
                'linear-gradient(120deg, #3b0764 0%, #6d28d9 50%, #be185d 100%)',
            }}
          >
            <div className="absolute -bottom-10 -right-10 w-64 h-64 rounded-full" style={{ background: 'radial-gradient(closest-side, rgba(255,255,255,0.12), transparent)' }} />

            <div className="relative grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div>
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 ring-1 ring-white/20 text-xs font-medium">
                  <Icon.Shield className="w-4 h-4 text-pink-300" />
                  BOARD TALKING POINTS
                </div>
                <h3 className="mt-3 text-2xl font-bold">Three lines for the next risk-committee meeting</h3>
                <p className="mt-2 text-sm text-violet-100/90 leading-relaxed">
                  Each card translates this week's OT security telemetry into a financial or regulatory
                  outcome the board can action.
                </p>
              </div>

              <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-3 gap-3">
                {[
                  {
                    stat: `£${metrics.estimatedLossAvoided}M`,
                    head: 'Loss Avoided · YTD',
                    body: 'Based on 6 interventions that would otherwise have required production stoppage under IEC 62443 safety controls.',
                  },
                  {
                    stat: `${metrics.insurancePremiumImpact}%`,
                    head: 'Cyber Insurance',
                    body: 'Evidence pack prepared for renewal in Q3. Broker indicates premium reduction contingent on SL-2 closure.',
                  },
                  {
                    stat: '0',
                    head: 'Reportable NIS2 Incidents',
                    body: 'No Article 23 notification required this quarter. Two near-misses contained at the deception layer.',
                  },
                ].map((c, i) => (
                  <div key={i} className="p-4 rounded-xl bg-white/10 backdrop-blur-sm ring-1 ring-white/15">
                    <div className="text-3xl font-bold bg-gradient-to-r from-pink-200 to-white bg-clip-text text-transparent">
                      {c.stat}
                    </div>
                    <p className="mt-1 text-sm font-semibold text-violet-50">{c.head}</p>
                    <p className="mt-1.5 text-xs text-violet-100/80 leading-relaxed">{c.body}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>

        {/* ====== FOOTER ====== */}
        <motion.div variants={item} className="flex flex-col sm:flex-row items-center justify-between gap-2 pt-4 border-t border-slate-200/70">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Icon.Shield className="w-4 h-4 text-violet-500" />
            CISO Executive Summary · OTShield Platform
          </div>
          <p className="text-xs text-slate-400">
            Confidential · Board &amp; Risk Committee distribution &nbsp;•&nbsp; Live · auto-refresh 60s
          </p>
        </motion.div>
    </motion.div>
  );
};

export default ExecutiveDashboard;
