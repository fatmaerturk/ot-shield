import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bar, Doughnut, Line, PolarArea } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  PointElement,
  LineElement,
  RadialLinearScale,
  Filler,
} from 'chart.js';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  PointElement,
  LineElement,
  RadialLinearScale,
  Filler
);

// =====================================================================
//   Types — match /api/honeypot/stats response
// =====================================================================

interface HourlyPoint {
  hour: number;
  label: string;
  total: number;
  high: number;
  medium: number;
  low: number;
}

interface DailyPoint {
  date: string;
  count: number;
}

interface TopAttacker {
  ip: string;
  count: number;
  country: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  topProtocol: string | null;
  highestSeverity: string | null;
  lastSeen: string | null;
  blocked: boolean;
}

interface TopPort {
  port: number;
  count: number;
  service: string;
}

interface OwaspEntry {
  category: string;
  count: number;
}

interface RecentEvent {
  id: number;
  timestamp: string | null;
  sourceIp: string | null;
  sourcePort: number | null;
  destinationPort: number | null;
  protocol: string | null;
  attackType: string | null;
  severity: string | null;
  description: string | null;
  country: string | null;
  city: string | null;
  usernameAttempt: string | null;
  passwordAttempt: string | null;
  isBlocked: boolean;
}

interface HoneypotStats {
  totalAttacks: number;
  uniqueIPs: number;
  uniqueSessions: number;
  attacksByProtocol: Record<string, number>;
  attacksBySeverity: Record<string, number>;
  attacksByType: Record<string, number>;
  topSourceIps: TopAttacker[];
  countryBreakdown: Record<string, number>;
  cityBreakdown: Record<string, number>;
  topUsernames: Record<string, number>;
  topPasswords: Record<string, number>;
  topAttackedPorts: TopPort[];
  hourlySeries: HourlyPoint[];
  dailySeries: DailyPoint[];
  owaspMapping: { breakdown: OwaspEntry[]; total: number };
  recentAttacks24h: number;
  blockedAttacks: number;
  recentEvents: RecentEvent[];
  geoIpAvailable: boolean;
}

const EMPTY_STATS: HoneypotStats = {
  totalAttacks: 0,
  uniqueIPs: 0,
  uniqueSessions: 0,
  attacksByProtocol: {},
  attacksBySeverity: {},
  attacksByType: {},
  topSourceIps: [],
  countryBreakdown: {},
  cityBreakdown: {},
  topUsernames: {},
  topPasswords: {},
  topAttackedPorts: [],
  hourlySeries: [],
  dailySeries: [],
  owaspMapping: { breakdown: [], total: 0 },
  recentAttacks24h: 0,
  blockedAttacks: 0,
  recentEvents: [],
  geoIpAvailable: false,
};

// =====================================================================
//   Icons (inline SVG — consistent stroke-based style)
// =====================================================================

const Icon = {
  Shield: (p: React.SVGProps<SVGSVGElement>) => (
    <svg {...p} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  ),
  Zap: (p: React.SVGProps<SVGSVGElement>) => (
    <svg {...p} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
  ),
  Users: (p: React.SVGProps<SVGSVGElement>) => (
    <svg {...p} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
  ),
  Globe: (p: React.SVGProps<SVGSVGElement>) => (
    <svg {...p} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
  ),
  Lock: (p: React.SVGProps<SVGSVGElement>) => (
    <svg {...p} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
  ),
  User: (p: React.SVGProps<SVGSVGElement>) => (
    <svg {...p} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
  ),
  Chart: (p: React.SVGProps<SVGSVGElement>) => (
    <svg {...p} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>
  ),
  Clock: (p: React.SVGProps<SVGSVGElement>) => (
    <svg {...p} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
  ),
  Map: (p: React.SVGProps<SVGSVGElement>) => (
    <svg {...p} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" /></svg>
  ),
  Server: (p: React.SVGProps<SVGSVGElement>) => (
    <svg {...p} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" /></svg>
  ),
  Ban: (p: React.SVGProps<SVGSVGElement>) => (
    <svg {...p} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
  ),
};

// =====================================================================
//   Helpers
// =====================================================================

const SEVERITY_PILL: Record<string, string> = {
  HIGH: 'bg-rose-50 text-rose-700 ring-rose-200',
  CRITICAL: 'bg-rose-50 text-rose-700 ring-rose-200',
  MEDIUM: 'bg-amber-50 text-amber-700 ring-amber-200',
  LOW: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
};
const SEVERITY_DOT: Record<string, string> = {
  HIGH: 'bg-rose-500', CRITICAL: 'bg-rose-500', MEDIUM: 'bg-amber-500', LOW: 'bg-emerald-500',
};

const PROTO_COLORS = [
  'rgba(139, 92, 246, 0.8)',
  'rgba(236, 72, 153, 0.8)',
  'rgba(251, 146, 60, 0.8)',
  'rgba(16, 185, 129, 0.8)',
  'rgba(59, 130, 246, 0.8)',
  'rgba(244, 63, 94, 0.8)',
  'rgba(168, 85, 247, 0.8)',
  'rgba(234, 179, 8, 0.8)',
  'rgba(20, 184, 166, 0.8)',
];

const formatRelative = (iso: string | null): string => {
  if (!iso) return '-';
  const t = new Date(iso).getTime();
  if (isNaN(t)) return '-';
  const diff = Math.max(0, Date.now() - t);
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
};

// Fix default Leaflet marker icon paths (bundlers strip them)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});
// Decoy location (Ankara) — destination for the attack arcs
const DECOY_POS: L.LatLngTuple = [39.9334, 32.8597];

// --------- Custom Leaflet divIcons for animated markers -----------
// Leaflet's divIcon applies `className` to the wrapper div it creates, so the
// inner HTML is rendered INSIDE .attacker-pulse automatically. We put data-sev
// on the wrapper directly via the html payload's first child using an outer
// span we're sure is positioned, then rely on the parent's .pulse-dot /
// .pulse-ring descendants.
const attackerIcon = (severity: string | null) => L.divIcon({
  className: `attacker-pulse-wrap`, // wrapper around our inner styled span
  html: `<span class="attacker-pulse" data-sev="${severity || 'LOW'}" style="position:absolute;inset:0;display:block;">
      <span class="pulse-ring"></span>
      <span class="pulse-dot"></span>
    </span>`,
  iconSize: [22, 22],
  iconAnchor: [11, 11],
});

const decoyIcon = L.divIcon({
  className: 'decoy-pulse-wrap',
  html: `<span class="decoy-pulse" style="position:absolute;inset:0;display:block;">
      <span class="decoy-ring-outer"></span>
      <span class="decoy-ring-inner"></span>
      <span class="decoy-core"></span>
    </span>`,
  iconSize: [60, 60],
  iconAnchor: [30, 30],
});

// Severity → stroke color for the attack arc + projectile
const sevColor = (sev: string | null): string => {
  if (sev === 'HIGH' || sev === 'CRITICAL') return '#e11d48';
  if (sev === 'MEDIUM') return '#fb923c';
  if (sev === 'LOW') return '#10b981';
  return '#a855f7';
};
// Canned coordinates for common country labels (simple fallback when we only know the country)
const COUNTRY_COORDS: Record<string, L.LatLngTuple> = {
  'Russia': [55.7558, 37.6176],
  'China': [39.9042, 116.4074],
  'United States': [38.9072, -77.0369],
  'Germany': [52.52, 13.405],
  'Netherlands': [52.3676, 4.9041],
  'United Kingdom': [51.5074, -0.1278],
  'France': [48.8566, 2.3522],
  'India': [28.6139, 77.2090],
  'Brazil': [-15.7939, -47.8828],
  'Turkey': [39.9334, 32.8597],
  'Ukraine': [50.4501, 30.5234],
  'Iran': [35.6892, 51.389],
  'Korea, Republic of': [37.5665, 126.978],
  'Japan': [35.6762, 139.6503],
};

// =====================================================================

const Honeypot: React.FC = () => {
  const [stats, setStats] = useState<HoneypotStats>(EMPTY_STATS);
  const [logs, setLogs] = useState<RecentEvent[]>([]);
  const [backendReachable, setBackendReachable] = useState<boolean | null>(null);
  const [logPage, setLogPage] = useState(0);
  const [logSize] = useState(20);
  const [logFilter, setLogFilter] = useState('');
  const [logProtocol, setLogProtocol] = useState('');
  const [reportTab, setReportTab] = useState<'threat-intel' | 'geographic' | 'time-analytics' | 'owasp' | 'event-distribution'>('threat-intel');
  const [selectedAttacker, setSelectedAttacker] = useState<TopAttacker | null>(null);
  // Impact flash state — increments on each projectile hit so we can rotate keys
  const [impactFlash, setImpactFlash] = useState<{ id: number; color: string } | null>(null);
  const impactCounter = useRef(0);
  const triggerImpact = (color: string) => {
    impactCounter.current += 1;
    setImpactFlash({ id: impactCounter.current, color });
  };

  // -------- data fetching --------
  const fetchStats = async () => {
    try {
      const r = await fetch('http://localhost:8080/api/honeypot/stats');
      if (r.ok) {
        const d = await r.json();
        setStats({ ...EMPTY_STATS, ...d });
        setBackendReachable(true);
      }
    } catch {
      setBackendReachable(false);
    }
  };

  const fetchLogs = async () => {
    try {
      const params = new URLSearchParams();
      params.set('page', String(logPage));
      params.set('size', String(logSize));
      if (logFilter) params.set('sourceIp', logFilter);
      if (logProtocol) params.set('protocol', logProtocol);
      const r = await fetch(`http://localhost:8080/api/honeypot/logs?${params}`);
      if (r.ok) {
        const d = await r.json();
        setLogs(Array.isArray(d) ? d : []);
      }
    } catch { /* backend banner will show */ }
  };

  useEffect(() => {
    fetchStats();
    fetchLogs();
    const id = setInterval(() => { fetchStats(); fetchLogs(); }, 10_000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [logPage, logFilter, logProtocol]);

  // -------- derived chart data --------
  const protocolBarChart = useMemo(() => {
    const entries = Object.entries(stats.attacksByProtocol).sort((a, b) => b[1] - a[1]);
    return {
      labels: entries.map(([k]) => k),
      datasets: [{
        label: 'Attacks',
        data: entries.map(([, v]) => v),
        backgroundColor: entries.map((_, i) => PROTO_COLORS[i % PROTO_COLORS.length]),
        borderWidth: 0,
      }],
    };
  }, [stats.attacksByProtocol]);

  const severityDoughnut = useMemo(() => ({
    labels: ['HIGH', 'MEDIUM', 'LOW'],
    datasets: [{
      data: [
        stats.attacksBySeverity.HIGH || 0,
        stats.attacksBySeverity.MEDIUM || 0,
        stats.attacksBySeverity.LOW || 0,
      ],
      backgroundColor: ['rgba(244, 63, 94, 0.85)', 'rgba(251, 146, 60, 0.85)', 'rgba(16, 185, 129, 0.85)'],
      borderWidth: 2, borderColor: '#fff',
    }],
  }), [stats.attacksBySeverity]);

  const hourlyLineChart = useMemo(() => ({
    labels: stats.hourlySeries.map(p => p.label),
    datasets: [
      {
        label: 'Total',
        data: stats.hourlySeries.map(p => p.total),
        borderColor: 'rgba(139, 92, 246, 1)',
        backgroundColor: 'rgba(139, 92, 246, 0.15)',
        fill: true, tension: 0.4, pointRadius: 2,
      },
      {
        label: 'High severity',
        data: stats.hourlySeries.map(p => p.high),
        borderColor: 'rgba(244, 63, 94, 1)',
        backgroundColor: 'rgba(244, 63, 94, 0.1)',
        tension: 0.4, pointRadius: 0,
      },
    ],
  }), [stats.hourlySeries]);

  const dailyBar = useMemo(() => ({
    labels: stats.dailySeries.map(p => p.date.slice(5)),
    datasets: [{
      label: 'Daily attacks',
      data: stats.dailySeries.map(p => p.count),
      backgroundColor: 'rgba(139, 92, 246, 0.7)',
      borderColor: 'rgba(139, 92, 246, 1)', borderWidth: 1,
    }],
  }), [stats.dailySeries]);

  const countryPolar = useMemo(() => {
    const entries = Object.entries(stats.countryBreakdown).slice(0, 8);
    return {
      labels: entries.map(([k]) => k),
      datasets: [{
        data: entries.map(([, v]) => v),
        backgroundColor: entries.map((_, i) => PROTO_COLORS[i % PROTO_COLORS.length]),
        borderWidth: 2, borderColor: '#fff',
      }],
    };
  }, [stats.countryBreakdown]);

  const eventTypeDoughnut = useMemo(() => {
    const entries = Object.entries(stats.attacksByType).sort((a, b) => b[1] - a[1]).slice(0, 10);
    return {
      labels: entries.map(([k]) => k),
      datasets: [{
        data: entries.map(([, v]) => v),
        backgroundColor: entries.map((_, i) => PROTO_COLORS[i % PROTO_COLORS.length]),
        borderWidth: 2, borderColor: '#fff',
      }],
    };
  }, [stats.attacksByType]);

  const owaspBar = useMemo(() => ({
    labels: stats.owaspMapping.breakdown.map(e => e.category.slice(0, 25)),
    datasets: [{
      label: 'Events',
      data: stats.owaspMapping.breakdown.map(e => e.count),
      backgroundColor: 'rgba(139, 92, 246, 0.7)',
      borderColor: 'rgba(139, 92, 246, 1)', borderWidth: 1,
    }],
  }), [stats.owaspMapping]);

  const hasData = stats.totalAttacks > 0;

  // Markers for the map. Resolution order:
  //   1. Backend-provided lat/lon (from MaxMind) — most accurate
  //   2. Canned country capital coords — fallback when city resolution fails
  // Entries with no usable coords are skipped.
  const attackerMarkers = useMemo(() => {
    return stats.topSourceIps
      .map(a => {
        let coords: L.LatLngTuple | undefined;
        if (typeof a.lat === 'number' && typeof a.lon === 'number') {
          coords = [a.lat, a.lon];
        } else if (a.country && COUNTRY_COORDS[a.country]) {
          coords = COUNTRY_COORDS[a.country];
        }
        if (!coords) return null;
        return { ...a, pos: coords };
      })
      .filter((x): x is (TopAttacker & { pos: L.LatLngTuple }) => x !== null)
      .slice(0, 15);
  }, [stats.topSourceIps]);

  const chartOptions = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { position: 'bottom' as const, labels: { usePointStyle: true, padding: 14, font: { size: 11 } } } },
  };
  const barOpts = {
    ...chartOptions,
    scales: { y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.06)' } }, x: { grid: { display: false } } },
    plugins: { ...chartOptions.plugins, legend: { display: false } },
  };
  const lineOpts = {
    ...chartOptions,
    scales: { y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.06)' } }, x: { grid: { color: 'rgba(0,0,0,0.04)' } } },
  };

  return (
    <div className="space-y-6">
      {/* Hero */}
      <div className="relative overflow-hidden rounded-2xl p-8 md:p-10 text-white"
        style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #4c1d95 45%, #7c3aed 100%)' }}>
        <div className="absolute -top-20 -right-20 w-72 h-72 rounded-full bg-fuchsia-500/20 blur-3xl" />
        <div className="absolute -bottom-10 -left-10 w-60 h-60 rounded-full bg-violet-400/10 blur-3xl" />
        <div className="relative flex flex-col lg:flex-row lg:items-end lg:justify-between gap-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 ring-1 ring-white/20 text-xs font-semibold tracking-wider backdrop-blur-sm mb-4">
              <Icon.Shield className="w-4 h-4" />
              ATTACK INTELLIGENCE
            </div>
            <h1 className="text-3xl md:text-4xl font-bold leading-tight">
              Fleet-wide Honeypot Analytics
              <span className="block text-violet-100/90 font-medium text-lg md:text-xl mt-2">
                Who's attacking, from where, how, and with which credentials, aggregated across all decoys.
              </span>
              <span className="block mt-3 text-sm text-violet-100/70">
                Want to inspect a single decoy's threat posture and Modbus telemetry? Open{' '}
                <Link to="/integrations/ics-decoy" className="underline decoration-violet-300/60 hover:decoration-white font-semibold text-white">
                  ICS Decoy →
                </Link>
              </span>
            </h1>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-white/10 ring-1 ring-white/20 backdrop-blur-sm">
              <span className={`w-2 h-2 rounded-full ${backendReachable ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
              <span className="text-xs font-semibold uppercase tracking-wider text-white">
                {backendReachable ? 'Live' : 'Offline'}
              </span>
            </div>
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-white/10 ring-1 ring-white/20 backdrop-blur-sm">
              <Icon.Globe className="w-4 h-4" />
              <span className="text-xs font-semibold uppercase tracking-wider text-white">
                GeoIP {stats.geoIpAvailable ? 'ready' : 'disabled'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {backendReachable === false && (
        <div className="p-4 bg-rose-50 ring-1 ring-rose-200 rounded-2xl flex items-start gap-3 shadow-sm">
          <div className="w-9 h-9 rounded-xl bg-rose-100 text-rose-600 flex items-center justify-center flex-shrink-0">
            <Icon.Ban className="w-5 h-5" />
          </div>
          <div className="text-sm text-rose-800 leading-relaxed">
            <strong className="block mb-1">Backend unreachable.</strong>
            Cannot reach the Spring Boot API at <code className="bg-rose-100 px-1.5 py-0.5 rounded text-xs font-mono">http://localhost:8080</code>. Start the backend and refresh.
          </div>
        </div>
      )}

      {backendReachable && !stats.geoIpAvailable && (
        <div className="p-4 bg-amber-50 ring-1 ring-amber-200 rounded-2xl flex items-start gap-3 shadow-sm">
          <div className="w-9 h-9 rounded-xl bg-amber-100 text-amber-600 flex items-center justify-center flex-shrink-0">
            <Icon.Globe className="w-5 h-5" />
          </div>
          <div className="text-sm text-amber-800 leading-relaxed">
            <strong>GeoIP database not loaded.</strong> Country / city / map data will stay empty until
            {' '}<code className="bg-amber-100 px-1.5 py-0.5 rounded text-xs font-mono">backend/geoip/GeoLite2-City.mmdb</code>{' '}
            is placed on disk. See <code className="bg-amber-100 px-1.5 py-0.5 rounded text-xs font-mono">backend/geoip/README.md</code>.
          </div>
        </div>
      )}

      {/* KPI cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Attacks', value: stats.totalAttacks.toLocaleString(), hint: `${stats.recentAttacks24h.toLocaleString()} in last 24h`, gradient: 'from-rose-500 to-orange-500', icon: <Icon.Zap className="w-5 h-5" /> },
          { label: 'Unique Attackers', value: stats.uniqueIPs.toLocaleString(), hint: `${stats.topSourceIps.length} in top list`, gradient: 'from-violet-500 to-fuchsia-500', icon: <Icon.Users className="w-5 h-5" /> },
          { label: 'Countries', value: Object.keys(stats.countryBreakdown).length.toLocaleString(), hint: stats.geoIpAvailable ? 'Geo-resolved via MaxMind' : 'GeoIP DB required', gradient: 'from-emerald-500 to-teal-500', icon: <Icon.Globe className="w-5 h-5" /> },
          { label: 'Blocked', value: stats.blockedAttacks.toLocaleString(), hint: `${stats.uniqueSessions.toLocaleString()} sessions tracked`, gradient: 'from-fuchsia-500 to-pink-500', icon: <Icon.Ban className="w-5 h-5" /> },
        ].map((k, i) => (
          <div key={i} className="group relative bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-lg hover:-translate-y-0.5 transition-all duration-300 overflow-hidden">
            <div className={`absolute inset-x-0 top-0 h-1 bg-gradient-to-r ${k.gradient}`} />
            <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${k.gradient} text-white flex items-center justify-center shadow-md shadow-violet-500/20`}>
              {k.icon}
            </div>
            <p className="mt-4 text-[11px] uppercase tracking-wider text-slate-500 font-semibold">{k.label}</p>
            <p className="mt-1 text-3xl font-bold text-slate-900 tracking-tight">{k.value}</p>
            <p className="mt-1 text-xs text-slate-500">{k.hint}</p>
          </div>
        ))}
      </div>

      {!hasData && backendReachable && (
        <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm p-10 text-center">
          <div className="w-14 h-14 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white flex items-center justify-center shadow-lg shadow-violet-500/30">
            <Icon.Zap className="w-7 h-7" />
          </div>
          <h3 className="text-lg font-semibold text-slate-900">Waiting for attack telemetry</h3>
          <p className="mt-1 text-sm text-slate-500 max-w-md mx-auto">
            All metrics populate from live honeypot data. Start the honeypot agent (or any honeypot that writes to <code>/api/honeypot/logs</code>) and attacker probes will appear here automatically.
          </p>
          <div className="mt-4">
            <Link to="/integrations/ics-decoy" className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white font-semibold text-sm hover:shadow-lg hover:shadow-violet-500/30 transition">
              Go to ICS Decoy →
            </Link>
          </div>
        </div>
      )}

      {hasData && (
        <>
          {/* Attack map */}
          <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-200/70 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white flex items-center justify-center shadow-md shadow-violet-500/20">
                  <Icon.Map className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-semibold text-slate-900">Global Attack Map</h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {attackerMarkers.length} geolocated attackers · animated arcs converge on the decoy · severity-coloured
                  </p>
                </div>
              </div>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-violet-700 bg-violet-50 ring-1 ring-violet-200 px-2 py-1 rounded-full">Geo</span>
            </div>
            <div className="relative" style={{ height: '480px', width: '100%' }}>
              <MapContainer center={[25, 15]} zoom={2} scrollWheelZoom={false} style={{ height: '100%', width: '100%' }}>
                <TileLayer url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png" attribution='&copy; <a href="https://carto.com/">CARTO</a>' />

                {/* Decoy marker — pulsing target */}
                <Marker position={DECOY_POS} icon={decoyIcon}>
                  <Popup>
                    <div className="text-xs">
                      <div className="font-semibold">Decoy (Ankara)</div>
                      <div className="text-slate-500">Honeypot target · attack arcs converge here</div>
                    </div>
                  </Popup>
                </Marker>

                {/* Attacker markers (pulsing divIcons) */}
                {attackerMarkers.map((a, i) => {
                  const color = sevColor(a.highestSeverity);
                  return (
                    <Marker key={`${a.ip}-${i}`} position={a.pos} icon={attackerIcon(a.highestSeverity)}>
                      <Popup>
                        <div className="text-xs">
                          <div className="font-mono font-semibold">{a.ip}</div>
                          <div>{a.country || 'Unknown'}{a.city ? ` · ${a.city}` : ''}</div>
                          <div>{a.count.toLocaleString()} events · {a.topProtocol || 'N/A'}</div>
                          {a.highestSeverity && (
                            <div className="mt-1">Severity: <span className="font-semibold" style={{ color }}>{a.highestSeverity}</span></div>
                          )}
                        </div>
                      </Popup>
                    </Marker>
                  );
                })}

                {/* SVG overlay — arcs, packets, impact ripples, country flashes */}
                <AttackArcLayer attackers={attackerMarkers} decoy={DECOY_POS} onImpact={triggerImpact} />
              </MapContainer>

              {/* Impact flash overlay — centred over map, triggered on projectile hit */}
              {impactFlash && (
                <div
                  key={impactFlash.id}
                  className="impact-flash pointer-events-none"
                  style={{
                    color: impactFlash.color,
                    background: `radial-gradient(circle, ${impactFlash.color}dd 0%, ${impactFlash.color}44 40%, transparent 70%)`,
                  }}
                  onAnimationEnd={() => setImpactFlash(null)}
                />
              )}

              {/* Legend overlay — bottom left, above Leaflet attribution */}
              <div className="absolute left-3 bottom-8 z-[500] bg-slate-900/85 backdrop-blur-sm ring-1 ring-white/10 rounded-xl px-3 py-2.5 shadow-lg text-xs text-white">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-white/60 mb-1.5">Severity</p>
                <div className="flex items-center gap-2 mb-1">
                  <span className="w-2 h-2 rounded-full" style={{ background: '#f43f5e', boxShadow: '0 0 6px #f43f5e' }} />
                  <span>High · critical events</span>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="w-2 h-2 rounded-full" style={{ background: '#f97316', boxShadow: '0 0 6px #f97316' }} />
                  <span>Medium</span>
                </div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="w-2 h-2 rounded-full" style={{ background: '#a855f7', boxShadow: '0 0 6px #a855f7' }} />
                  <span>Low · reconnaissance</span>
                </div>
                <div className="flex items-center gap-2 pt-2 border-t border-white/10">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ background: 'radial-gradient(circle, #ec4899, #8b5cf6)', boxShadow: '0 0 8px #ec4899' }} />
                  <span>Decoy target</span>
                </div>
              </div>

              {/* Live counter pill — top right of map */}
              <div className="absolute right-3 top-3 z-[500] bg-slate-900/85 backdrop-blur-sm ring-1 ring-white/10 rounded-xl px-3 py-2 shadow-lg text-xs text-white flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500"></span>
                </span>
                <span className="font-semibold tabular-nums">{stats.totalAttacks.toLocaleString()}</span>
                <span className="text-white/60">events · {attackerMarkers.length} live sources</span>
              </div>
            </div>
          </div>

          {/* Protocol + Severity + Hourly */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <PanelCard title="Protocol Distribution" subtitle="Events per target protocol" badge="Protocols" badgeTone="violet">
              <div className="h-64">{protocolBarChart.labels.length ? <Bar data={protocolBarChart} options={barOpts} /> : <Empty />}</div>
            </PanelCard>
            <PanelCard title="Severity Mix" subtitle="Attack severity distribution" badge="Severity" badgeTone="rose">
              <div className="h-64"><Doughnut data={severityDoughnut} options={chartOptions} /></div>
            </PanelCard>
            <PanelCard title="24-hour Activity" subtitle="Events per hour · high severity overlay" badge="Timeline" badgeTone="fuchsia">
              <div className="h-64"><Line data={hourlyLineChart} options={lineOpts} /></div>
            </PanelCard>
          </div>

          {/* Top attackers + Top ports */}
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
            <div className="lg:col-span-3 bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-200/70 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-rose-500 to-orange-500 text-white flex items-center justify-center">
                    <Icon.Users className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-semibold text-slate-900">Top Attackers</h3>
                    <p className="text-xs text-slate-500 mt-0.5">Most active source IPs · click a row for drilldown</p>
                  </div>
                </div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-rose-700 bg-rose-50 ring-1 ring-rose-200 px-2 py-1 rounded-full">IPs</span>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-200/70">
                  <thead className="bg-slate-50/60">
                    <tr>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">#</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">IP</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Country</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Protocol</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Severity</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Events</th>
                      <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Last seen</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-slate-200/60">
                    {stats.topSourceIps.map((a, i) => (
                      <tr key={a.ip} className="hover:bg-violet-50/40 transition cursor-pointer" onClick={() => setSelectedAttacker(a)}>
                        <td className="px-4 py-2.5 text-sm font-semibold text-slate-500">#{i + 1}</td>
                        <td className="px-4 py-2.5 text-sm font-mono font-medium text-slate-900">{a.ip}</td>
                        <td className="px-4 py-2.5 text-sm text-slate-600">{a.country || '-'}{a.city ? <span className="text-slate-400"> · {a.city}</span> : ''}</td>
                        <td className="px-4 py-2.5 text-sm">{a.topProtocol ? <span className="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 ring-1 ring-slate-200">{a.topProtocol}</span> : '-'}</td>
                        <td className="px-4 py-2.5 text-sm">{a.highestSeverity ? (
                          <span className={`inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded ring-1 ${SEVERITY_PILL[a.highestSeverity] || SEVERITY_PILL.LOW}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${SEVERITY_DOT[a.highestSeverity] || SEVERITY_DOT.LOW}`} />{a.highestSeverity}
                          </span>
                        ) : '-'}</td>
                        <td className="px-4 py-2.5 text-sm font-semibold text-slate-900">{a.count.toLocaleString()}</td>
                        <td className="px-4 py-2.5 text-sm text-slate-500">{formatRelative(a.lastSeen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="lg:col-span-2 bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-fuchsia-500 to-pink-500 text-white flex items-center justify-center">
                    <Icon.Server className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-semibold text-slate-900">Top Attacked Ports</h3>
                    <p className="text-xs text-slate-500 mt-0.5">Destination ports targeted most</p>
                  </div>
                </div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-pink-700 bg-pink-50 ring-1 ring-pink-200 px-2 py-1 rounded-full">Ports</span>
              </div>
              {stats.topAttackedPorts.length === 0 ? <Empty /> : (
                <div className="space-y-1.5">
                  {stats.topAttackedPorts.map(p => {
                    const max = stats.topAttackedPorts[0]?.count || 1;
                    const pct = Math.round((p.count / max) * 100);
                    return (
                      <div key={p.port} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200/50">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-baseline gap-2">
                            <span className="font-mono font-semibold text-slate-900">{p.port}</span>
                            <span className="text-xs text-slate-500 truncate">{p.service}</span>
                          </div>
                          <div className="mt-1 h-1.5 bg-white rounded-full overflow-hidden ring-1 ring-slate-200/60">
                            <div className="h-full bg-gradient-to-r from-fuchsia-500 to-pink-500 rounded-full" style={{ width: `${pct}%` }} />
                          </div>
                        </div>
                        <span className="text-sm font-semibold text-slate-900 ml-2">{p.count.toLocaleString()}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Credentials */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <CredCard title="Top Usernames" subtitle="Credentials attackers tried" tone="violet" icon={<Icon.User className="w-5 h-5" />} data={stats.topUsernames} badge="Usernames" emptyHint="The HTTP decoy logs Basic-auth attempts. Once any attacker tries a username, it'll show here." />
            <CredCard title="Top Passwords" subtitle="Credentials attackers tried" tone="fuchsia" icon={<Icon.Lock className="w-5 h-5" />} data={stats.topPasswords} badge="Passwords" emptyHint="Same source as usernames. Decoded from Basic-auth or extracted from form-encoded POSTs." />
          </div>

          {/* Reports tabs */}
          <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-200/70">
              <h3 className="text-base font-semibold text-slate-900">Security Reports</h3>
              <p className="text-xs text-slate-500 mt-0.5">Drill into geography, time trends, OWASP mapping, and event distribution</p>
            </div>
            <div className="flex border-b border-slate-200/70 overflow-x-auto">
              {([
                { id: 'threat-intel', label: 'Threat Intel', icon: <Icon.Shield className="w-4 h-4" /> },
                { id: 'geographic', label: 'Geographic', icon: <Icon.Globe className="w-4 h-4" /> },
                { id: 'time-analytics', label: 'Time Analytics', icon: <Icon.Clock className="w-4 h-4" /> },
                { id: 'owasp', label: 'OWASP Top 10', icon: <Icon.Lock className="w-4 h-4" /> },
                { id: 'event-distribution', label: 'Event Distribution', icon: <Icon.Chart className="w-4 h-4" /> },
              ] as const).map(t => (
                <button key={t.id} onClick={() => setReportTab(t.id)}
                  className={`flex items-center gap-2 px-5 py-3 text-sm font-semibold transition whitespace-nowrap border-b-2 ${
                    reportTab === t.id ? 'border-violet-500 text-violet-700 bg-violet-50/40' : 'border-transparent text-slate-500 hover:text-slate-900 hover:bg-slate-50'
                  }`}
                >
                  {t.icon}{t.label}
                </button>
              ))}
            </div>
            <div className="p-6">
              {reportTab === 'threat-intel' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <PanelCard title="Attack Types" subtitle="Frequency of observed attack categories" badge="Types" badgeTone="violet">
                    <div className="h-72">{Object.keys(stats.attacksByType).length ? <Doughnut data={eventTypeDoughnut} options={chartOptions} /> : <Empty />}</div>
                  </PanelCard>
                  <PanelCard title="Recent High-Severity Events" subtitle="Last HIGH-tagged events across all attackers" badge="Recent" badgeTone="rose">
                    {stats.recentEvents.filter(e => e.severity === 'HIGH').length === 0 ? <Empty /> : (
                      <div className="space-y-1.5 max-h-72 overflow-y-auto">
                        {stats.recentEvents.filter(e => e.severity === 'HIGH').slice(0, 10).map(e => (
                          <div key={e.id} className="px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200/50">
                            <div className="flex items-center gap-2 mb-0.5">
                              <span className={`w-1.5 h-1.5 rounded-full ${SEVERITY_DOT.HIGH}`} />
                              <span className="text-xs font-mono font-semibold text-slate-900">{e.sourceIp}</span>
                              {e.country && <span className="text-[10px] text-slate-500">{e.country}</span>}
                              <span className="ml-auto text-[10px] text-slate-400">{formatRelative(e.timestamp)}</span>
                            </div>
                            <p className="text-xs text-slate-600 truncate">{e.attackType} · {e.protocol}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </PanelCard>
                </div>
              )}

              {reportTab === 'geographic' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <PanelCard title="Top Countries" subtitle="Countries sending the most probes" badge="Countries" badgeTone="emerald">
                    {Object.keys(stats.countryBreakdown).length === 0 ? <Empty hint={!stats.geoIpAvailable ? 'Install GeoIP DB to enable' : 'No geolocated traffic yet'} /> : (
                      <div className="space-y-1.5">
                        {Object.entries(stats.countryBreakdown).slice(0, 10).map(([c, n], i) => {
                          const values = Object.values(stats.countryBreakdown);
                          const max = values.length > 0 ? Math.max(...values) : 1;
                          const pct = Math.round((n / max) * 100);
                          return (
                            <div key={c} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200/50">
                              <span className="text-xs font-semibold text-slate-500 w-5">#{i + 1}</span>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-sm font-medium text-slate-900 truncate">{c}</span>
                                  <span className="text-sm font-semibold text-slate-900">{n}</span>
                                </div>
                                <div className="h-1.5 bg-white rounded-full overflow-hidden ring-1 ring-slate-200/60">
                                  <div className="h-full bg-gradient-to-r from-emerald-500 to-teal-500 rounded-full" style={{ width: `${pct}%` }} />
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </PanelCard>
                  <PanelCard title="Country Distribution" subtitle="Polar-area view of source geography" badge="Distribution" badgeTone="emerald">
                    <div className="h-72">{Object.keys(stats.countryBreakdown).length ? <PolarArea data={countryPolar} options={chartOptions} /> : <Empty />}</div>
                  </PanelCard>
                </div>
              )}

              {reportTab === 'time-analytics' && (
                <div className="grid grid-cols-1 gap-6">
                  <PanelCard title="Hourly Attacks (last 24h)" subtitle="Total events vs. high-severity overlay" badge="24h" badgeTone="violet">
                    <div className="h-64">{stats.hourlySeries.length ? <Line data={hourlyLineChart} options={lineOpts} /> : <Empty />}</div>
                  </PanelCard>
                  <PanelCard title="Daily Attacks (last 30 days)" subtitle="Day-by-day trend" badge="30d" badgeTone="fuchsia">
                    <div className="h-64">{stats.dailySeries.length ? <Bar data={dailyBar} options={barOpts} /> : <Empty />}</div>
                  </PanelCard>
                </div>
              )}

              {reportTab === 'owasp' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <PanelCard title="OWASP Top 10 Mapping" subtitle="Events classified into OWASP 2021 categories" badge="OWASP" badgeTone="violet">
                    <div className="h-80">{stats.owaspMapping.breakdown.length && stats.owaspMapping.total > 0 ? <Bar data={owaspBar} options={barOpts} /> : <Empty />}</div>
                  </PanelCard>
                  <PanelCard title="Breakdown" subtitle={`${stats.owaspMapping.total.toLocaleString()} events matched`} badge="Detail" badgeTone="violet">
                    <div className="space-y-1.5">
                      {stats.owaspMapping.breakdown.map(e => (
                        <div key={e.category} className="flex items-center justify-between px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200/50">
                          <span className="text-xs text-slate-700 truncate">{e.category}</span>
                          <span className="text-xs font-semibold text-slate-900 ml-2">{e.count}</span>
                        </div>
                      ))}
                    </div>
                  </PanelCard>
                </div>
              )}

              {reportTab === 'event-distribution' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <PanelCard title="Attack Type Distribution" subtitle="Top 10 attack types observed" badge="Types" badgeTone="violet">
                    <div className="h-80">{Object.keys(stats.attacksByType).length ? <Doughnut data={eventTypeDoughnut} options={chartOptions} /> : <Empty />}</div>
                  </PanelCard>
                  <PanelCard title="Full Type Breakdown" subtitle="Sorted by frequency" badge="All" badgeTone="violet">
                    <div className="max-h-80 overflow-y-auto space-y-1">
                      {Object.entries(stats.attacksByType).sort((a, b) => b[1] - a[1]).map(([t, n]) => (
                        <div key={t} className="flex items-center justify-between px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200/50">
                          <span className="text-xs text-slate-700 truncate">{t}</span>
                          <span className="text-xs font-semibold text-slate-900 ml-2">{n}</span>
                        </div>
                      ))}
                    </div>
                  </PanelCard>
                </div>
              )}
            </div>
          </div>

          {/* Honeypot Logs table */}
          <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-200/70 flex items-center justify-between gap-3 flex-wrap">
              <div>
                <h3 className="text-base font-semibold text-slate-900">Attack Log</h3>
                <p className="text-xs text-slate-500 mt-0.5">Full-text view of persisted honeypot events · filter by IP or protocol</p>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <input
                  value={logFilter}
                  onChange={e => { setLogFilter(e.target.value); setLogPage(0); }}
                  placeholder="Filter by IP…"
                  className="px-3 py-1.5 text-sm rounded-lg ring-1 ring-slate-200 bg-white focus:ring-2 focus:ring-violet-400 focus:outline-none font-mono"
                />
                <select
                  value={logProtocol}
                  onChange={e => { setLogProtocol(e.target.value); setLogPage(0); }}
                  className="px-3 py-1.5 text-sm rounded-lg ring-1 ring-slate-200 bg-white focus:ring-2 focus:ring-violet-400 focus:outline-none"
                >
                  <option value="">All protocols</option>
                  {Object.keys(stats.attacksByProtocol).map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200/70">
                <thead className="bg-slate-50/60">
                  <tr>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">When</th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Source</th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Protocol</th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Attack Type</th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Severity</th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Status</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-slate-200/60">
                  {logs.length === 0 ? (
                    <tr><td colSpan={6} className="px-4 py-10 text-center text-sm text-slate-400">No logs match the current filter.</td></tr>
                  ) : logs.map(l => (
                    <tr key={l.id} className="hover:bg-slate-50/60 transition">
                      <td className="px-4 py-2.5 text-xs text-slate-500 whitespace-nowrap">{formatRelative(l.timestamp)}</td>
                      <td className="px-4 py-2.5 text-sm">
                        <div className="font-mono text-slate-900">{l.sourceIp}</div>
                        {l.country && <div className="text-[10px] text-slate-500">{l.country}{l.city ? ` · ${l.city}` : ''}</div>}
                      </td>
                      <td className="px-4 py-2.5 text-sm">{l.protocol && <span className="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 ring-1 ring-slate-200">{l.protocol}</span>}</td>
                      <td className="px-4 py-2.5 text-sm text-slate-700">{l.attackType || '-'}</td>
                      <td className="px-4 py-2.5 text-sm">{l.severity && (
                        <span className={`inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded ring-1 ${SEVERITY_PILL[l.severity] || SEVERITY_PILL.LOW}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${SEVERITY_DOT[l.severity] || SEVERITY_DOT.LOW}`} />{l.severity}
                        </span>
                      )}</td>
                      <td className="px-4 py-2.5 text-sm">
                        {l.isBlocked
                          ? <span className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 ring-1 ring-rose-200">Blocked</span>
                          : <span className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-50 text-slate-500 ring-1 ring-slate-200">Allowed</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="px-6 py-3 border-t border-slate-200/70 flex items-center justify-between">
              <span className="text-xs text-slate-500">Page {logPage + 1} · {logs.length} rows on this page</span>
              <div className="flex gap-2">
                <button disabled={logPage === 0} onClick={() => setLogPage(p => Math.max(0, p - 1))}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition">Previous</button>
                <button disabled={logs.length < logSize} onClick={() => setLogPage(p => p + 1)}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition">Next</button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Attacker drilldown modal */}
      {selectedAttacker && (
        <AttackerModal attacker={selectedAttacker} events={stats.recentEvents.filter(e => e.sourceIp === selectedAttacker.ip)} onClose={() => setSelectedAttacker(null)} />
      )}
    </div>
  );
};

// =====================================================================
//   Sub-components
// =====================================================================

/**
 * SVG-based attack-arc overlay (ported from Decoy Layer's WorldAttackerMap).
 *
 * For each spawn: draws a curved arc from attacker → decoy with a leading
 * stroke-reveal, glowing packet head, impact ripple at the decoy, and a
 * flash ring over the source country. Uses Leaflet's map projection so
 * everything stays registered to geographic coordinates during pan/zoom.
 */
interface AnimArc {
  id: number;
  from: L.LatLngTuple;
  to: L.LatLngTuple;
  severity: string | null;
  ip: string;
  bornAt: number;
  duration: number;
}

const AttackArcLayer: React.FC<{
  attackers: Array<TopAttacker & { pos: L.LatLngTuple }>;
  decoy: L.LatLngTuple;
  onImpact?: (color: string) => void;
}> = ({ attackers, decoy, onImpact }) => {
  const map = useMap();
  const [arcs, setArcs] = useState<AnimArc[]>([]);
  const [impacts, setImpacts] = useState<Array<{ id: number; bornAt: number; color: string }>>([]);
  const [flashes, setFlashes] = useState<Array<{ id: number; pos: L.LatLngTuple; bornAt: number; color: string }>>([]);
  const arcSeq = useRef(1);
  const attackersRef = useRef(attackers);
  useEffect(() => { attackersRef.current = attackers; }, [attackers]);
  const onImpactRef = useRef(onImpact);
  useEffect(() => { onImpactRef.current = onImpact; }, [onImpact]);

  const spawnAttack = React.useCallback((attacker: TopAttacker & { pos: L.LatLngTuple }) => {
    const now = Date.now();
    const id = arcSeq.current++;
    const duration = 1800;
    const color = sevColor(attacker.highestSeverity);
    const arc: AnimArc = {
      id, from: attacker.pos, to: decoy,
      severity: attacker.highestSeverity,
      ip: attacker.ip,
      bornAt: now, duration,
    };
    setArcs(prev => [...prev, arc]);
    setFlashes(prev => [...prev, { id, pos: attacker.pos, bornAt: now, color }]);
    window.setTimeout(() => {
      setImpacts(prev => [...prev, { id, bornAt: Date.now(), color }]);
      onImpactRef.current?.(color);
    }, duration - 150);
    window.setTimeout(() => {
      setArcs(prev => prev.filter(x => x.id !== id));
      setFlashes(prev => prev.filter(x => x.id !== id));
    }, duration + 400);
    window.setTimeout(() => {
      setImpacts(prev => prev.filter(x => x.id !== id));
    }, duration + 1200);
  }, [decoy]);

  // Ambient storm — fires an arc every 600-1500ms using the current attacker set
  useEffect(() => {
    if (attackers.length === 0) return;
    let cancelled = false;
    let timer: number | null = null;
    const loop = () => {
      if (cancelled) return;
      const pool = attackersRef.current;
      if (pool.length > 0) {
        const pick = pool[Math.floor(Math.random() * pool.length)];
        if (pick) spawnAttack(pick);
      }
      const delay = 600 + Math.random() * 900;
      timer = window.setTimeout(loop, delay);
    };
    timer = window.setTimeout(loop, 400);
    return () => { cancelled = true; if (timer) window.clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attackers.length > 0]);

  // rAF tick for smooth packet interpolation
  const [, setTick] = useState(0);
  useEffect(() => {
    let raf = 0;
    const loop = () => {
      setTick(t => (t + 1) % 1_000_000);
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, []);

  // Re-render on pan/zoom (map projection changes)
  useEffect(() => {
    const bump = () => setTick(t => t + 1);
    map.on('move', bump);
    map.on('zoom', bump);
    return () => { map.off('move', bump); map.off('zoom', bump); };
  }, [map]);

  const toPx = (lat: number, lon: number) => {
    const p = map.latLngToContainerPoint([lat, lon]);
    return { x: p.x, y: p.y };
  };

  const arcGeometry = (from: L.LatLngTuple, to: L.LatLngTuple) => {
    const a = toPx(from[0], from[1]);
    const b = toPx(to[0], to[1]);
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const len = Math.sqrt(dx * dx + dy * dy);
    const lift = Math.min(180, Math.max(50, len * 0.35));
    const cx = mx;
    const cy = my - lift;
    const path = `M${a.x},${a.y} Q${cx},${cy} ${b.x},${b.y}`;
    const sample = (t: number) => {
      const u = 1 - t;
      return { x: u * u * a.x + 2 * u * t * cx + t * t * b.x, y: u * u * a.y + 2 * u * t * cy + t * t * b.y };
    };
    return { path, sample, a, b, len };
  };

  const size = map.getSize();
  const now = Date.now();

  return (
    <div className="pointer-events-none absolute inset-0 z-[400]" style={{ width: size.x, height: size.y }}>
      <svg width={size.x} height={size.y} className="pointer-events-none">
        <defs>
          <radialGradient id="hp-packet-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#fde68a" stopOpacity="1" />
            <stop offset="60%" stopColor="#f472b6" stopOpacity="0.6" />
            <stop offset="100%" stopColor="#ec4899" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="hp-impact-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#fecaca" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#e11d48" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Live attack arcs + travelling packets */}
        {arcs.map(a => {
          const age = now - a.bornAt;
          const t = Math.min(1, Math.max(0, age / a.duration));
          const g = arcGeometry(a.from, a.to);
          const pkt = g.sample(t);
          const color = sevColor(a.severity);
          const dashLen = g.len + 60;
          return (
            <g key={a.id}>
              {/* Dim full-length arc in the background */}
              <path d={g.path} fill="none" stroke={color} strokeWidth={1} strokeOpacity={0.25} />
              {/* Leading stroke reveal */}
              <path
                d={g.path} fill="none" stroke={color} strokeWidth={2.5}
                strokeOpacity={0.9} strokeLinecap="round"
                strokeDasharray={`${dashLen * t}, ${dashLen}`}
              />
              {/* Packet head */}
              {t < 1 && (
                <>
                  <circle cx={pkt.x} cy={pkt.y} r={10} fill="url(#hp-packet-glow)" />
                  <circle cx={pkt.x} cy={pkt.y} r={3.2} fill="#fff" />
                </>
              )}
            </g>
          );
        })}

        {/* Impact ripples at the decoy */}
        {impacts.map(imp => {
          const p = toPx(decoy[0], decoy[1]);
          const age = now - imp.bornAt;
          const life = Math.min(1, age / 1000);
          const r = 8 + life * 34;
          const opacity = 1 - life;
          return (
            <g key={`imp-${imp.id}`}>
              <circle cx={p.x} cy={p.y} r={r} fill="none" stroke={imp.color} strokeWidth={2} opacity={opacity * 0.8} />
              <circle cx={p.x} cy={p.y} r={r * 0.55} fill="url(#hp-impact-glow)" opacity={opacity} />
            </g>
          );
        })}

        {/* Country flash ring over the attacker source */}
        {flashes.map(cf => {
          const p = toPx(cf.pos[0], cf.pos[1]);
          const age = now - cf.bornAt;
          const life = Math.min(1, age / 800);
          const r = 12 + life * 26;
          const opacity = (1 - life) * 0.9;
          return (
            <circle key={`flash-${cf.id}`} cx={p.x} cy={p.y} r={r} fill="none" stroke={cf.color} strokeWidth={1.5} opacity={opacity} />
          );
        })}
      </svg>
    </div>
  );
};

const Empty: React.FC<{ hint?: string }> = ({ hint = 'No data yet' }) => (
  <div className="h-full flex items-center justify-center text-sm text-slate-400">{hint}</div>
);

const BADGE_TONES: Record<string, string> = {
  violet: 'text-violet-700 bg-violet-50 ring-violet-200',
  rose: 'text-rose-700 bg-rose-50 ring-rose-200',
  fuchsia: 'text-fuchsia-700 bg-fuchsia-50 ring-fuchsia-200',
  emerald: 'text-emerald-700 bg-emerald-50 ring-emerald-200',
  pink: 'text-pink-700 bg-pink-50 ring-pink-200',
  amber: 'text-amber-700 bg-amber-50 ring-amber-200',
};

const PanelCard: React.FC<{ title: string; subtitle: string; badge: string; badgeTone: string; children: React.ReactNode }> = ({ title, subtitle, badge, badgeTone, children }) => (
  <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
    <div className="flex items-center justify-between mb-4">
      <div>
        <h3 className="text-base font-semibold text-slate-900">{title}</h3>
        <p className="text-xs text-slate-500 mt-0.5">{subtitle}</p>
      </div>
      <span className={`text-[11px] font-semibold uppercase tracking-wider ring-1 px-2 py-1 rounded-full ${BADGE_TONES[badgeTone] || BADGE_TONES.violet}`}>{badge}</span>
    </div>
    {children}
  </div>
);

const CredCard: React.FC<{
  title: string; subtitle: string; tone: string; icon: React.ReactNode;
  data: Record<string, number>; badge: string; emptyHint: string;
}> = ({ title, subtitle, tone, icon, data, badge, emptyHint }) => {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const max = entries[0]?.[1] || 1;
  return (
    <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`w-9 h-9 rounded-xl text-white flex items-center justify-center shadow-md bg-gradient-to-br ${tone === 'violet' ? 'from-violet-500 to-fuchsia-500' : 'from-fuchsia-500 to-pink-500'}`}>
            {icon}
          </div>
          <div>
            <h3 className="text-base font-semibold text-slate-900">{title}</h3>
            <p className="text-xs text-slate-500 mt-0.5">{subtitle}</p>
          </div>
        </div>
        <span className={`text-[11px] font-semibold uppercase tracking-wider ring-1 px-2 py-1 rounded-full ${BADGE_TONES[tone] || BADGE_TONES.violet}`}>{badge}</span>
      </div>
      {entries.length === 0 ? (
        <div className="py-8 text-center">
          <p className="text-sm text-slate-400">{emptyHint}</p>
        </div>
      ) : (
        <div className="space-y-1.5">
          {entries.map(([val, count], i) => {
            const pct = Math.round((count / max) * 100);
            return (
              <div key={val} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-slate-50 ring-1 ring-slate-200/50">
                <span className="text-xs font-semibold text-slate-500 w-5">#{i + 1}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-mono text-slate-900 truncate">{val}</span>
                    <span className="text-sm font-semibold text-slate-900">{count}</span>
                  </div>
                  <div className="h-1.5 bg-white rounded-full overflow-hidden ring-1 ring-slate-200/60">
                    <div className={`h-full rounded-full bg-gradient-to-r ${tone === 'violet' ? 'from-violet-500 to-fuchsia-500' : 'from-fuchsia-500 to-pink-500'}`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

const AttackerModal: React.FC<{ attacker: TopAttacker; events: RecentEvent[]; onClose: () => void }> = ({ attacker, events, onClose }) => (
  <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm" onClick={onClose}>
    <div className="bg-white rounded-2xl shadow-2xl ring-1 ring-slate-200/70 w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col" onClick={e => e.stopPropagation()}>
      <div className="px-6 py-4 border-b border-slate-200/70 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-rose-500 to-orange-500 text-white flex items-center justify-center shadow-md">
            <Icon.Users className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-900 font-mono">{attacker.ip}</h2>
            <p className="text-xs text-slate-500 mt-0.5">{attacker.country || 'Unknown country'}{attacker.city ? ` · ${attacker.city}` : ''} · {attacker.count.toLocaleString()} events</p>
          </div>
        </div>
        <button onClick={onClose} className="w-8 h-8 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 flex items-center justify-center transition" aria-label="Close">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      <div className="p-6 space-y-4 overflow-y-auto">
        <div className="flex flex-wrap gap-2">
          <a href={`https://www.abuseipdb.com/check/${attacker.ip}`} target="_blank" rel="noreferrer" className="text-[11px] font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 ring-1 ring-slate-200 px-2.5 py-1.5 rounded-lg transition">AbuseIPDB ↗</a>
          <a href={`https://www.virustotal.com/gui/ip-address/${attacker.ip}`} target="_blank" rel="noreferrer" className="text-[11px] font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 ring-1 ring-slate-200 px-2.5 py-1.5 rounded-lg transition">VirusTotal ↗</a>
          <a href={`https://www.shodan.io/host/${attacker.ip}`} target="_blank" rel="noreferrer" className="text-[11px] font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 ring-1 ring-slate-200 px-2.5 py-1.5 rounded-lg transition">Shodan ↗</a>
          <a href={`https://ipinfo.io/${attacker.ip}`} target="_blank" rel="noreferrer" className="text-[11px] font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 ring-1 ring-slate-200 px-2.5 py-1.5 rounded-lg transition">ipinfo.io ↗</a>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Stat label="Top protocol" value={attacker.topProtocol || '-'} />
          <Stat label="Highest severity" value={attacker.highestSeverity || '-'} />
          <Stat label="Last seen" value={formatRelative(attacker.lastSeen)} />
          <Stat label="Blocked" value={attacker.blocked ? 'Yes' : 'No'} />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-900 mb-2">Recent events from this attacker</h3>
          {events.length === 0 ? (
            <p className="text-sm text-slate-400">This IP has older activity that's no longer in the 30-event buffer.</p>
          ) : (
            <div className="space-y-1 ring-1 ring-slate-200/60 rounded-xl overflow-hidden">
              {events.map(e => (
                <div key={e.id} className="px-4 py-2.5 border-b border-slate-200/40 last:border-0 hover:bg-slate-50/60">
                  <div className="flex items-center gap-2 mb-0.5">
                    {e.severity && (
                      <span className={`inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded ring-1 ${SEVERITY_PILL[e.severity] || SEVERITY_PILL.LOW}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${SEVERITY_DOT[e.severity] || SEVERITY_DOT.LOW}`} />{e.severity}
                      </span>
                    )}
                    {e.protocol && <span className="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 ring-1 ring-slate-200">{e.protocol}</span>}
                    <span className="text-xs text-slate-500 ml-auto">{formatRelative(e.timestamp)}</span>
                  </div>
                  <p className="text-xs text-slate-700">{e.attackType || '-'}{e.description ? ` · ${e.description}` : ''}</p>
                  {(e.usernameAttempt || e.passwordAttempt) && (
                    <p className="text-xs font-mono text-slate-500 mt-0.5">
                      {e.usernameAttempt && <>u: <span className="text-slate-700">{e.usernameAttempt}</span> </>}
                      {e.passwordAttempt && <>p: <span className="text-slate-700">{e.passwordAttempt}</span></>}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  </div>
);

const Stat: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="bg-slate-50 ring-1 ring-slate-200/50 rounded-xl p-3">
    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
    <p className="mt-0.5 text-sm font-semibold text-slate-900 truncate">{value}</p>
  </div>
);

export default Honeypot;
