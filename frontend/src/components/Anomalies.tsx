import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  PointElement,
  LineElement,
  Filler,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';

import { User } from '../types/user';
import api from '../services/api';
import anomalyService, { Anomaly, AnomalyStatistics } from '../services/anomalyService';
import dpiService from '../services/dpiService';
import { PageShell, PageHero, Panel, KpiCard, Icon, theme } from './theme';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  PointElement,
  LineElement,
  Filler,
  Title,
  Tooltip,
  Legend
);

/*
 * This page is a LIVE VIEW over the anomaly store - everything shown here is
 * derived from real backend data. No hardcoded placeholders.
 *
 * Data sources, in order of importance:
 *  - /api/anomalies                   → paginated list (table + all derived stats)
 *  - /api/anomalies/stats             → pre-computed severity / status counts
 *  - /api/anomalies/stats/by-type     → anomaly-type distribution (pie)
 *  - /api/assets                      → asset inventory (Purdue-level breakdown)
 *  - /api/dpi/events                  → recent DPI events (write/read counts,
 *                                       "operations" sparkline)
 *
 * The `timeRange` selector filters anomalies by `detectedAt`; asset inventory
 * is time-independent (assets are long-lived) and DPI event totals use the
 * same window.
 *
 * When the backend returns an empty result the UI shows an explicit
 * "No data yet - upload a pcap" state instead of silently falling back to
 * fabricated numbers.
 */

interface AnomalyApiResponse {
  content?: Anomaly[];
  totalElements?: number;
  totalPages?: number;
  size?: number;
  number?: number;
}

interface AssetSummary {
  id: string;
  ipAddress?: string;
  purdueLevel?: string;
  assetType?: string;
  assetCategory?: string;
}

interface AssetApiResponse {
  content?: AssetSummary[];
  totalElements?: number;
}

type TimeRange = '24h' | '7d' | '30d' | '90d';

const TIME_RANGE_HOURS: Record<TimeRange, number> = {
  '24h': 24,
  '7d': 24 * 7,
  '30d': 24 * 30,
  '90d': 24 * 90,
};

/** ISO-8601 local-date-time (no timezone) - matches Spring's `LocalDateTime` binding. */
function isoLocal(d: Date): string {
  // 2024-04-21T10:45:00 (drop the Z / offset)
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function rangeStart(range: TimeRange): Date {
  const now = new Date();
  const h = TIME_RANGE_HOURS[range];
  return new Date(now.getTime() - h * 3600 * 1000);
}

/** Map Asset.PurdueLevel enum name ("LEVEL_3") to numeric 3. */
function parsePurdueLevel(name?: string): number | null {
  if (!name) return null;
  const m = /(\d+)/.exec(name);
  return m ? parseInt(m[1], 10) : null;
}

const Anomalies: React.FC = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState<User | null>(null);
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');

  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [anomalyStats, setAnomalyStats] = useState<AnomalyStatistics | null>(null);
  const [typeCounts, setTypeCounts] = useState<Record<string, number>>({});
  const [assets, setAssets] = useState<AssetSummary[]>([]);
  const [dpiWriteCount, setDpiWriteCount] = useState(0);
  const [dpiReadCount, setDpiReadCount] = useState(0);
  /** Daily anomaly counts over the selected window, oldest → newest. */
  const [activitySeries, setActivitySeries] = useState<{ labels: string[]; data: number[] }>({
    labels: [],
    data: [],
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  /** true when every source returned zero rows - show the "upload a pcap" hint. */
  const [allEmpty, setAllEmpty] = useState(false);

  // ------------------------------------------------------------------------
  // Data fetch. Re-runs on time-range change because anomaly filtering, DPI
  // activity, and the sparkline all depend on the window.
  // ------------------------------------------------------------------------
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        // User from localStorage (unchanged contract).
        const userData = localStorage.getItem('user');
        if (userData) {
          try { setUser(JSON.parse(userData)); } catch { /* ignore */ }
        }

        const since = rangeStart(timeRange);
        const until = new Date();

        // Fire everything in parallel. Each branch has its own fallback so a
        // single failing endpoint doesn't blank out the whole page.
        const [
          anomaliesRes,
          statsRes,
          typeCountsRes,
          assetsRes,
          dpiPage,
        ] = await Promise.allSettled([
          anomalyService.getAnomalies({
            page: 0,
            size: 200,
            sortBy: 'detectedAt',
            sortDir: 'desc',
          }),
          anomalyService.getAnomalyStatistics(),
          anomalyService.getAnomalyCountsByType(),
          api.get<AssetApiResponse>('/api/assets', { params: { page: 0, size: 500 } }),
          dpiService.search({
            from: isoLocal(since),
            to: isoLocal(until),
            size: 1000,
          }),
        ]);

        // Anomalies list (filter client-side by detectedAt so the sparkline /
        // KPI counts honour the selected window - the backend stats endpoint
        // returns lifetime totals).
        let anomalyList: Anomaly[] = [];
        if (anomaliesRes.status === 'fulfilled') {
          const raw = anomaliesRes.value as AnomalyApiResponse | Anomaly[];
          anomalyList = Array.isArray(raw) ? raw : (raw.content ?? []);
        }
        const windowed = anomalyList.filter((a) => {
          if (!a.detectedAt) return false;
          const t = new Date(a.detectedAt).getTime();
          return t >= since.getTime() && t <= until.getTime();
        });
        setAnomalies(windowed);

        if (statsRes.status === 'fulfilled') {
          setAnomalyStats(statsRes.value as AnomalyStatistics);
        } else {
          setAnomalyStats(null);
        }

        if (typeCountsRes.status === 'fulfilled' && typeCountsRes.value) {
          // Backend returns Map<displayName, count>; coerce to plain record.
          const raw = typeCountsRes.value as Record<string, number | string>;
          const coerced: Record<string, number> = {};
          for (const [k, v] of Object.entries(raw)) {
            const n = typeof v === 'number' ? v : Number(v);
            if (Number.isFinite(n)) coerced[k] = n;
          }
          setTypeCounts(coerced);
        } else {
          setTypeCounts({});
        }

        let assetList: AssetSummary[] = [];
        if (assetsRes.status === 'fulfilled') {
          const data = assetsRes.value.data;
          assetList = data?.content ?? [];
        }
        setAssets(assetList);

        let writes = 0;
        let reads = 0;
        if (dpiPage.status === 'fulfilled') {
          for (const ev of dpiPage.value.content) {
            if (ev.isWrite) writes++;
            else if (ev.pduKind === 'read') reads++;
          }
        }
        setDpiWriteCount(writes);
        setDpiReadCount(reads);

        // Build daily activity series from the windowed anomalies.
        const buckets = Math.max(1, Math.round(TIME_RANGE_HOURS[timeRange] / 24));
        const labels: string[] = [];
        const counts: number[] = new Array(buckets).fill(0);
        const startMs = since.getTime();
        const windowMs = until.getTime() - startMs;
        const bucketMs = windowMs / buckets;
        for (let i = 0; i < buckets; i++) {
          const d = new Date(startMs + bucketMs * (i + 0.5));
          labels.push(
            buckets <= 7
              ? d.toLocaleDateString(undefined, { weekday: 'short' })
              : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
          );
        }
        for (const a of windowed) {
          const t = new Date(a.detectedAt).getTime();
          const idx = Math.min(buckets - 1, Math.max(0, Math.floor((t - startMs) / bucketMs)));
          counts[idx] += 1;
        }
        setActivitySeries({ labels, data: counts });

        // Empty-state detection - explicit so the UI can tell the truth.
        const nothing = anomalyList.length === 0 && assetList.length === 0 &&
          (dpiPage.status !== 'fulfilled' || dpiPage.value.content.length === 0);
        setAllEmpty(nothing);
      } catch (err) {
        console.error('Error fetching anomalies data:', err);
        setError('Failed to load anomalies data');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [timeRange]);

  // ------------------------------------------------------------------------
  // Derived data (memoised - they recompute only when their inputs change).
  // ------------------------------------------------------------------------

  /** Count of anomalies per originating assetType (or "Unknown"), top 6. */
  const topAlertedZones = useMemo(() => {
    const bucket = new Map<string, { zone: string; alerts: number; worst: Anomaly['severity'] }>();
    const sevRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
    for (const a of anomalies) {
      const key = a.assetType || a.hostname || a.destinationIp || 'Unknown';
      const existing = bucket.get(key);
      if (existing) {
        existing.alerts += 1;
        if ((sevRank[a.severity] ?? 0) > (sevRank[existing.worst] ?? 0)) existing.worst = a.severity;
      } else {
        bucket.set(key, { zone: key, alerts: 1, worst: a.severity });
      }
    }
    return Array.from(bucket.values())
      .sort((a, b) => b.alerts - a.alerts)
      .slice(0, 6);
  }, [anomalies]);

  /** Assets grouped by Purdue level (L0..L5). */
  const assetsByPurdue = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of assets) {
      const lvl = parsePurdueLevel(a.purdueLevel);
      const label = lvl != null ? `L${lvl}` : 'Unknown';
      counts[label] = (counts[label] ?? 0) + 1;
    }
    return counts;
  }, [assets]);

  /** Assets grouped by assetType (PLC, HMI, …), top 6 + "Other". */
  const assetsByType = useMemo(() => {
    const counts = new Map<string, number>();
    for (const a of assets) {
      const key = a.assetType || 'Unknown';
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const sorted = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
    const top = sorted.slice(0, 6);
    const rest = sorted.slice(6).reduce((acc, [, v]) => acc + v, 0);
    const obj: Record<string, number> = {};
    for (const [k, v] of top) obj[k] = v;
    if (rest > 0) obj['Other'] = rest;
    return obj;
  }, [assets]);

  /**
   * Lightweight "hygiene" score derived from real data:
   *  start at 100, subtract
   *   -25 for any unresolved CRITICAL,
   *   -5  per unresolved HIGH,
   *   -1  per unresolved MEDIUM,
   *   clamp to 0–100.
   */
  const hygieneScore = useMemo(() => {
    let score = 100;
    for (const a of anomalies) {
      if (a.isResolved) continue;
      if (a.severity === 'CRITICAL') score -= 25;
      else if (a.severity === 'HIGH') score -= 5;
      else if (a.severity === 'MEDIUM') score -= 1;
    }
    return Math.max(0, Math.min(100, score));
  }, [anomalies]);

  // ------------------------------------------------------------------------
  // Handlers.
  // ------------------------------------------------------------------------

  const refreshAfterMutation = async () => {
    try {
      const [anomaliesResponse, statsResponse] = await Promise.all([
        anomalyService.getAnomalies({ page: 0, size: 200, sortBy: 'detectedAt', sortDir: 'desc' }),
        anomalyService.getAnomalyStatistics(),
      ]);
      const anomaliesData = anomaliesResponse as AnomalyApiResponse;
      const statsData = statsResponse as AnomalyStatistics;
      const anomalyList = anomaliesData.content || (Array.isArray(anomaliesData) ? anomaliesData as Anomaly[] : []);
      const since = rangeStart(timeRange);
      setAnomalies(anomalyList.filter((a) => new Date(a.detectedAt).getTime() >= since.getTime()));
      setAnomalyStats(statsData);
    } catch (err) {
      console.error('Error refreshing anomalies:', err);
    }
  };

  const handleAnomalyStatusChange = async (anomalyId: string, action: string, notes?: string) => {
    try {
      switch (action) {
        case 'acknowledge':
          await anomalyService.acknowledgeAnomaly(anomalyId);
          break;
        case 'escalate':
          await anomalyService.escalateAnomaly(anomalyId);
          break;
        case 'resolve':
          if (notes) await anomalyService.resolveAnomaly(anomalyId, notes);
          break;
        case 'false-positive':
          if (notes) await anomalyService.markAsFalsePositive(anomalyId, notes);
          break;
      }
      await refreshAfterMutation();
    } catch (err) {
      console.error('Error updating anomaly status:', err);
      setError('Failed to update anomaly status');
    }
  };

  // ------------------------------------------------------------------------
  // Chart configs - all driven by the derived memos above.
  // ------------------------------------------------------------------------

  // ------------------------------------------------------------------------
  // Chart palette.
  //
  // Hybrid scheme: violet/fuchsia/pink/rose tones where colour is
  // decorative or taxonomical (Purdue levels, asset types, activity
  // line); a narrower semantic band (rose/orange/amber/emerald) where
  // colour *must* telegraph risk (severity, hygiene, zone priority,
  // table badges). Keeping these two bands distinct means a design
  // refresh can't accidentally flatten critical vs low to the same hue.
  // ------------------------------------------------------------------------
  const chartPalette = {
    violet:   '#8B5CF6',
    fuchsia:  '#D946EF',
    pink:     '#EC4899',
    rose:     '#F43F5E',
    amber:    '#F59E0B',
    orange:   '#F97316',
    emerald:  '#10B981',
    slate200: '#E2E8F0',
    slate400: '#94A3B8',
    slate500: '#64748B',
    slate700: '#334155',
    // Semantic risk ramp (CRITICAL, HIGH, MEDIUM, LOW)
    sevCritical: '#E11D48', // rose-600
    sevHigh:     '#F97316', // orange-500
    sevMedium:   '#F59E0B', // amber-500
    sevLow:      '#10B981', // emerald-500
  } as const;

  /** Shared tooltip chrome so Chart.js defaults don't clash with the violet surface. */
  const chartChrome = {
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#0F172A',
        titleColor: '#FFFFFF',
        bodyColor: '#E2E8F0',
        borderColor: chartPalette.violet,
        borderWidth: 1,
        cornerRadius: 8,
        padding: 10,
        titleFont: { weight: 'bold' as const, size: 12 },
        bodyFont: { size: 12 },
      },
    },
  };

  const severityCounts = {
    critical: anomalyStats?.critical ?? anomalies.filter(a => a.severity === 'CRITICAL').length,
    high: anomalyStats?.high ?? anomalies.filter(a => a.severity === 'HIGH').length,
    medium: anomalyStats?.medium ?? anomalies.filter(a => a.severity === 'MEDIUM').length,
    low: anomalyStats?.low ?? anomalies.filter(a => a.severity === 'LOW').length,
  };

  // Severity stays semantic - red down to green - because this chart
  // is explicitly the "how bad is it" picture and analysts read it
  // by colour, not just by bar length.
  const severityChartData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      label: 'Anomalies',
      data: [severityCounts.critical, severityCounts.high, severityCounts.medium, severityCounts.low],
      backgroundColor: [
        chartPalette.sevCritical,
        chartPalette.sevHigh,
        chartPalette.sevMedium,
        chartPalette.sevLow,
      ],
      borderRadius: 6,
      borderSkipped: false as const,
      maxBarThickness: 22,
    }],
  };

  const severityChartOptions = {
    indexAxis: 'y' as const,
    responsive: true,
    maintainAspectRatio: false,
    ...chartChrome,
    scales: {
      x: {
        ticks: { color: chartPalette.slate500, font: { size: 11 } },
        grid: { color: chartPalette.slate200 },
        border: { display: false },
      },
      y: {
        ticks: { color: chartPalette.slate700, font: { size: 11, weight: 'bold' as const } },
        grid: { display: false },
        border: { display: false },
      },
    },
  };

  // Hygiene also stays semantic - emerald/amber/rose - for the same
  // reason. The remainder slice is a soft slate so it reads as "empty
  // space" rather than another data series.
  const hygieneChartData = {
    labels: ['Hygiene Score', 'Remaining'],
    datasets: [{
      label: 'Score',
      data: [hygieneScore, 100 - hygieneScore],
      backgroundColor: [
        hygieneScore >= 80 ? chartPalette.emerald :
        hygieneScore >= 60 ? chartPalette.amber : chartPalette.rose,
        '#F1F5F9', // slate-100
      ],
      borderWidth: 0,
    }],
  };

  const hygieneChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '72%',
    ...chartChrome,
  };

  // Purdue level is taxonomical, not risk - pivot to the theme spectrum.
  // L0 (field) starts violet and walks along the brand ramp up to L5
  // (enterprise); Unknown lands on slate so it visually drops out.
  const purdueLabels = ['L0', 'L1', 'L2', 'L3', 'L4', 'L5', 'Unknown']
    .filter(l => (assetsByPurdue[l] ?? 0) > 0);
  const PURDUE_PALETTE: Record<string, string> = {
    L0:      chartPalette.violet,
    L1:      chartPalette.fuchsia,
    L2:      chartPalette.pink,
    L3:      chartPalette.rose,
    L4:      chartPalette.amber,
    L5:      chartPalette.emerald,
    Unknown: chartPalette.slate400,
  };
  const assetsByPurdueChartData = {
    labels: purdueLabels,
    datasets: [{
      label: 'Assets',
      data: purdueLabels.map(l => assetsByPurdue[l] ?? 0),
      backgroundColor: purdueLabels.map(l => PURDUE_PALETTE[l] ?? chartPalette.slate400),
      borderColor: '#FFFFFF',
      borderWidth: 2,
      hoverOffset: 6,
    }],
  };

  // Asset types are also taxonomical - rotate through the theme ramp.
  const TYPE_PALETTE = [
    chartPalette.violet,
    chartPalette.fuchsia,
    chartPalette.pink,
    chartPalette.rose,
    chartPalette.amber,
    chartPalette.emerald,
    chartPalette.slate400,
  ];
  const assetsByTypeLabels = Object.keys(assetsByType);
  const assetsByTypeChartData = {
    labels: assetsByTypeLabels,
    datasets: [{
      label: 'Assets',
      data: assetsByTypeLabels.map(k => assetsByType[k]),
      backgroundColor: assetsByTypeLabels.map((_, i) => TYPE_PALETTE[i % TYPE_PALETTE.length]),
      borderRadius: 6,
      borderSkipped: false as const,
      maxBarThickness: 28,
    }],
  };

  // Single-series line chart - no semantic signal, pure brand.
  const activityChartData = {
    labels: activitySeries.labels,
    datasets: [{
      label: 'Anomalies detected',
      data: activitySeries.data,
      borderColor: chartPalette.violet,
      backgroundColor: 'rgba(139, 92, 246, 0.18)',
      pointBackgroundColor: chartPalette.fuchsia,
      pointBorderColor: '#FFFFFF',
      pointBorderWidth: 2,
      pointRadius: 3,
      pointHoverRadius: 5,
      tension: 0.35,
      fill: true,
    }],
  };

  const activityChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    ...chartChrome,
    scales: {
      x: {
        ticks: { color: chartPalette.slate500, font: { size: 11 } },
        grid: { display: false },
        border: { display: false },
      },
      y: {
        beginAtZero: true,
        ticks: { precision: 0, color: chartPalette.slate500, font: { size: 11 } },
        grid: { color: chartPalette.slate200 },
        border: { display: false },
      },
    },
  };

  const typeCountsLabels = Object.keys(typeCounts);

  // ------------------------------------------------------------------------
  // Render.
  // ------------------------------------------------------------------------

  if (loading) {
    return (
      <PageShell>
        <div className="flex items-center justify-center py-24">
          <div className="text-center">
            <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-violet-600 mx-auto" />
            <p className="mt-4 text-slate-600 text-sm">Loading anomaly data…</p>
          </div>
        </div>
      </PageShell>
    );
  }

  if (error) {
    return (
      <PageShell>
        <div className="flex items-center justify-center py-24">
          <div className="text-center max-w-md">
            <div className="mx-auto w-12 h-12 rounded-xl bg-rose-50 ring-1 ring-rose-200 text-rose-600 flex items-center justify-center mb-3">
              <Icon.Alert className="w-6 h-6" />
            </div>
            <div className="text-sm font-semibold text-slate-900 mb-1">Couldn't load anomalies</div>
            <p className="text-xs text-slate-600 mb-4">{error}</p>
            <button
              onClick={() => window.location.reload()}
              className={`px-4 py-2 rounded-lg text-sm font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA}`}
            >
              Retry
            </button>
          </div>
        </div>
      </PageShell>
    );
  }

  const totalAnomaliesInWindow = anomalies.length;
  const activeInWindow = anomalies.filter(a => a.isActive !== false && !a.isResolved).length;
  const resolvedInWindow = anomalies.filter(a => a.isResolved).length;
  const criticalInWindow = anomalies.filter(a => a.severity === 'CRITICAL').length;

  return (
    <PageShell>
      <PageHero
        eyebrow="ANOMALY DETECTION"
        icon={<Icon.Activity className="w-3.5 h-3.5" />}
        title={
          <span>
            Behavioural anomalies across OT
            <span className="block text-violet-100/90 font-medium text-lg md:text-xl mt-2">
              AI-driven baseline deviations correlated with deception-layer signals.
            </span>
          </span>
        }
        actions={
          <div className="flex gap-1 p-1 bg-white/10 backdrop-blur-sm rounded-xl ring-1 ring-white/15">
            {(['24h', '7d', '30d', '90d'] as TimeRange[]).map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                  timeRange === range
                    ? 'bg-white text-violet-700 shadow'
                    : 'text-violet-100 hover:text-white'
                }`}
              >
                {range}
              </button>
            ))}
          </div>
        }
      />

      {/* Live-data banner - same shape as on Network Topology so the user
          always knows whether what they're looking at comes from the backend. */}
      <div className="mb-6">
        {allEmpty ? (
          <div className="rounded-2xl ring-1 ring-amber-200 bg-amber-50 p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="h-2.5 w-2.5 rounded-full bg-amber-500 animate-pulse"></span>
              <div>
                <div className="text-sm font-semibold text-amber-900">No real data yet</div>
                <div className="text-xs text-amber-800">
                  Upload a pcap on the Dashboard or Network Topology page so the DPI rule engine can produce live anomalies.
                </div>
              </div>
            </div>
            <button
              onClick={() => navigate('/dashboard')}
              className={`px-3 py-1.5 text-xs font-semibold text-white rounded-lg bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-md transition`}
            >
              Upload pcap
            </button>
          </div>
        ) : (
          <div className="rounded-2xl ring-1 ring-emerald-200 bg-emerald-50 p-3 flex items-center gap-3">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
            <div className="text-sm font-semibold text-emerald-900">LIVE DATA</div>
            <div className="text-xs text-emerald-800">
              {anomalyStats?.total ?? 0} total anomalies · {totalAnomaliesInWindow} in the last {timeRange} · {assets.length} asset(s) · {dpiWriteCount + dpiReadCount} DPI events
            </div>
          </div>
        )}
      </div>

      {/* KPI strip - violet for neutral, rose for critical, pink/fuchsia
          for the other two so nothing falls outside the brand band. */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <KpiCard
          label="Total Anomalies"
          value={anomalyStats?.total ?? 0}
          hint={`${totalAnomaliesInWindow} in last ${timeRange}`}
          color="violet"
          icon={<Icon.Activity className="w-5 h-5" />}
        />
        <KpiCard
          label="Critical"
          value={anomalyStats?.critical ?? 0}
          hint={`${criticalInWindow} in last ${timeRange}`}
          color="rose"
          icon={<Icon.Alert className="w-5 h-5" />}
        />
        <KpiCard
          label="Active"
          value={anomalyStats?.active ?? activeInWindow}
          hint={`${activeInWindow} in last ${timeRange}`}
          color="fuchsia"
          icon={<Icon.Clock className="w-5 h-5" />}
        />
        <KpiCard
          label="Resolved"
          value={anomalyStats?.resolved ?? 0}
          hint={`${resolvedInWindow} in last ${timeRange}`}
          color="pink"
          icon={<Icon.CheckCircle className="w-5 h-5" />}
        />
      </div>

      {/* Main content grid: two-thirds of charts on the left, DPI + top
          zones on the right. */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mb-6">
        <div className="xl:col-span-2 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Panel
              title={`Severity (last ${timeRange})`}
              subtitle="Open anomalies by risk tier"
              icon={<Icon.Alert className="w-5 h-5" />}
            >
              <div className="h-48">
                {totalAnomaliesInWindow === 0 ? (
                  <EmptyChart hint="No anomalies in this window" />
                ) : (
                  <Bar data={severityChartData} options={severityChartOptions} />
                )}
              </div>
            </Panel>

            <Panel
              title="Hygiene Score"
              subtitle={`${hygieneScore}/100 · higher is healthier`}
              icon={<Icon.Shield className="w-5 h-5" />}
            >
              <div className="h-48 relative">
                <Doughnut data={hygieneChartData} options={hygieneChartOptions} />
                <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                  <div className="text-2xl font-bold text-slate-900 leading-none">{hygieneScore}</div>
                </div>
              </div>
              <p className="text-[11px] text-slate-500 mt-2 text-center">
                Starts at 100. Loses 25 per open CRITICAL, 5 per HIGH, 1 per MEDIUM.
              </p>
            </Panel>

            <Panel
              title="Assets by Purdue Level"
              subtitle="Inventory spread across L0-L5"
              icon={<Icon.Layers className="w-5 h-5" />}
            >
              <div className="h-48">
                {assets.length === 0 ? (
                  <EmptyChart hint="No assets discovered" />
                ) : (
                  <Doughnut
                    data={assetsByPurdueChartData}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      ...chartChrome,
                      plugins: {
                        ...chartChrome.plugins,
                        legend: {
                          display: true,
                          position: 'bottom' as const,
                          labels: {
                            boxWidth: 10,
                            boxHeight: 10,
                            font: { size: 10 },
                            color: chartPalette.slate700,
                            padding: 8,
                          },
                        },
                      },
                    }}
                  />
                )}
              </div>
            </Panel>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Panel
              title="Asset Distribution"
              subtitle="Inventory by asset type"
              icon={<Icon.Server className="w-5 h-5" />}
            >
              <div className="h-64">
                {assets.length === 0 ? (
                  <EmptyChart hint="No assets discovered" />
                ) : (
                  <Bar
                    data={assetsByTypeChartData}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      ...chartChrome,
                      scales: {
                        x: {
                          ticks: { color: chartPalette.slate500, font: { size: 11 } },
                          grid: { display: false },
                          border: { display: false },
                        },
                        y: {
                          ticks: { color: chartPalette.slate500, font: { size: 11 } },
                          grid: { color: chartPalette.slate200 },
                          border: { display: false },
                        },
                      },
                    }}
                  />
                )}
              </div>
            </Panel>

            <Panel
              title="Anomaly Activity"
              subtitle={`Detections trend (${timeRange})`}
              icon={<Icon.TrendingUp className="w-5 h-5" />}
            >
              <div className="h-64">
                {totalAnomaliesInWindow === 0 ? (
                  <EmptyChart hint="No anomalies in this window" />
                ) : (
                  <Line data={activityChartData} options={activityChartOptions} />
                )}
              </div>
            </Panel>
          </div>

          {typeCountsLabels.length > 0 && (
            <Panel
              title="Anomalies by Type"
              subtitle="All-time breakdown across detection rules"
              icon={<Icon.Filter className="w-5 h-5" />}
            >
              <div className="h-56">
                <Bar
                  data={{
                    labels: typeCountsLabels,
                    datasets: [{
                      label: 'Anomalies',
                      data: typeCountsLabels.map(k => typeCounts[k]),
                      backgroundColor: chartPalette.violet,
                      hoverBackgroundColor: chartPalette.fuchsia,
                      borderRadius: 6,
                      borderSkipped: false as const,
                      maxBarThickness: 32,
                    }],
                  }}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    ...chartChrome,
                    scales: {
                      x: {
                        ticks: { color: chartPalette.slate500, font: { size: 11 } },
                        grid: { display: false },
                        border: { display: false },
                      },
                      y: {
                        ticks: { color: chartPalette.slate500, font: { size: 11 } },
                        grid: { color: chartPalette.slate200 },
                        border: { display: false },
                      },
                    },
                  }}
                />
              </div>
            </Panel>
          )}
        </div>

        {/* Sidebar */}
        <div className="xl:col-span-1 space-y-4">
          <Panel
            title={`DPI Activity (last ${timeRange})`}
            subtitle="Deep-packet inspection telemetry"
            icon={<Icon.Bolt className="w-5 h-5" />}
          >
            <div className="space-y-3">
              <SidebarStat
                label="OT Assets"
                value={assets.length}
                tone="violet"
              />
              <SidebarStat
                label="Read Operations"
                value={dpiReadCount}
                tone="fuchsia"
              />
              <SidebarStat
                label="Write Operations"
                value={dpiWriteCount}
                tone="rose"
              />
            </div>
          </Panel>

          <Panel
            title="Top Alerted Zones"
            subtitle="Most-flagged segments in this window"
            icon={<Icon.Target className="w-5 h-5" />}
          >
            <div className="h-80 overflow-y-auto space-y-2 pr-1">
              {topAlertedZones.length === 0 && (
                <div className="text-sm text-slate-500 text-center pt-8">No anomalies in this window</div>
              )}
              {topAlertedZones.map((zone, index) => {
                const sevLabel =
                  zone.worst === 'CRITICAL' || zone.worst === 'HIGH' ? 'High' :
                  zone.worst === 'MEDIUM' ? 'Medium' : 'Low';
                const sevClass =
                  sevLabel === 'High'   ? 'text-rose-700 bg-rose-50 ring-rose-200' :
                  sevLabel === 'Medium' ? 'text-amber-700 bg-amber-50 ring-amber-200' :
                                          'text-emerald-700 bg-emerald-50 ring-emerald-200';
                return (
                  <div key={index} className="flex justify-between items-center p-2.5 rounded-xl bg-slate-50 ring-1 ring-slate-100">
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-semibold text-slate-900 truncate">{zone.zone}</div>
                      <span className={`mt-0.5 inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold ring-1 ${sevClass}`}>
                        {sevLabel} priority
                      </span>
                    </div>
                    <div className="flex items-baseline gap-1 flex-shrink-0 ml-2">
                      <span className="text-lg font-bold text-slate-900">{zone.alerts}</span>
                      <span className="text-[10px] text-slate-500">alerts</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </Panel>
        </div>
      </div>

      {/* Recent Anomalies Table */}
      <Panel
        title="Recent Anomalies"
        subtitle={`Showing ${Math.min(anomalies.length, 10)} of ${totalAnomaliesInWindow} in last ${timeRange}`}
        icon={<Icon.Search className="w-5 h-5" />}
      >
        <div className="overflow-x-auto overflow-y-auto max-h-96 -mx-2">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 border-b border-slate-200">
                <th className="py-2 px-3">Anomaly</th>
                <th className="py-2 px-3">Severity</th>
                <th className="py-2 px-3">Status</th>
                <th className="py-2 px-3">Source → Dest</th>
                <th className="py-2 px-3">Detected</th>
                <th className="py-2 px-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {anomalies.length === 0 && (
                <tr><td colSpan={6} className="px-3 py-8 text-center text-sm text-slate-500">No anomalies in this time window.</td></tr>
              )}
              {anomalies.slice(0, 10).map((anomaly) => {
                const sevBadge =
                  anomaly.severity === 'CRITICAL' ? 'bg-rose-100 text-rose-700 ring-rose-200' :
                  anomaly.severity === 'HIGH'     ? 'bg-orange-100 text-orange-700 ring-orange-200' :
                  anomaly.severity === 'MEDIUM'   ? 'bg-amber-100 text-amber-700 ring-amber-200' :
                                                    'bg-emerald-100 text-emerald-700 ring-emerald-200';
                // Status uses the theme for benign states (acknowledged /
                // investigating / resolved) but red for the "still open"
                // DETECTED state so it carries weight at a glance.
                const statusBadge =
                  anomaly.status === 'DETECTED'     ? 'bg-rose-100 text-rose-700 ring-rose-200' :
                  anomaly.status === 'ACKNOWLEDGED' ? 'bg-violet-100 text-violet-700 ring-violet-200' :
                  anomaly.status === 'INVESTIGATING'? 'bg-fuchsia-100 text-fuchsia-700 ring-fuchsia-200' :
                  anomaly.status === 'RESOLVED'     ? 'bg-emerald-100 text-emerald-700 ring-emerald-200' :
                                                      'bg-slate-100 text-slate-700 ring-slate-200';
                return (
                  <tr key={anomaly.id} className="border-b border-slate-100 hover:bg-violet-50/30 transition">
                    <td className="py-3 px-3">
                      <div className="text-sm font-semibold text-slate-900">{anomaly.title}</div>
                      <div className="text-[11px] text-slate-500">
                        {anomaly.anomalyType}
                        {anomaly.createdBy && ` · by ${anomaly.createdBy}`}
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`inline-flex px-2.5 py-0.5 text-[11px] font-semibold rounded-full ring-1 ${sevBadge}`}>
                        {anomaly.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`inline-flex px-2.5 py-0.5 text-[11px] font-semibold rounded-full ring-1 ${statusBadge}`}>
                        {anomaly.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-xs text-slate-700 font-mono">
                      {anomaly.sourceIp}
                      <span className="text-slate-400 mx-1">→</span>
                      {anomaly.destinationIp}
                    </td>
                    <td className="py-3 px-3 text-xs text-slate-500">
                      {anomaly.detectedAt ? new Date(anomaly.detectedAt).toLocaleString() : '-'}
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex gap-2">
                        {anomaly.status === 'DETECTED' && (
                          <>
                            <button
                              onClick={() => handleAnomalyStatusChange(anomaly.id, 'acknowledge')}
                              className={`px-2.5 py-1 text-[11px] font-semibold text-white rounded-md bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-md transition`}
                            >
                              Acknowledge
                            </button>
                            <button
                              onClick={() => handleAnomalyStatusChange(anomaly.id, 'escalate')}
                              className="px-2.5 py-1 text-[11px] font-semibold text-orange-700 bg-orange-50 ring-1 ring-orange-200 rounded-md hover:bg-orange-100 transition"
                            >
                              Escalate
                            </button>
                          </>
                        )}
                        {anomaly.status === 'ACKNOWLEDGED' && (
                          <button
                            onClick={() => {
                              const notes = prompt('Enter resolution notes:');
                              if (notes) handleAnomalyStatusChange(anomaly.id, 'resolve', notes);
                            }}
                            className="px-2.5 py-1 text-[11px] font-semibold text-emerald-700 bg-emerald-50 ring-1 ring-emerald-200 rounded-md hover:bg-emerald-100 transition"
                          >
                            Resolve
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>
    </PageShell>
  );
};

// ---------------------------------------------------------------------------
// Small sub-components kept local to the page so they can be tuned without
// polluting the shared theme.tsx.
// ---------------------------------------------------------------------------

/** One row in the DPI-activity sidebar panel. */
const SidebarStat: React.FC<{ label: string; value: number; tone: 'violet' | 'fuchsia' | 'rose' }> = ({ label, value, tone }) => {
  const toneClass =
    tone === 'violet'  ? 'bg-violet-50 ring-violet-200 text-violet-700' :
    tone === 'fuchsia' ? 'bg-fuchsia-50 ring-fuchsia-200 text-fuchsia-700' :
                         'bg-rose-50 ring-rose-200 text-rose-700';
  return (
    <div className={`flex justify-between items-center px-3 py-2 rounded-xl ring-1 ${toneClass}`}>
      <span className="text-xs font-semibold text-slate-700">{label}</span>
      <span className="text-xl font-bold">{value}</span>
    </div>
  );
};

/** Placeholder used when a chart has nothing to draw. */
const EmptyChart: React.FC<{ hint: string }> = ({ hint }) => (
  <div className="h-full flex items-center justify-center text-center">
    <div>
      <div className="mx-auto w-9 h-9 rounded-lg bg-gradient-to-br from-violet-100 to-fuchsia-100 text-violet-500 flex items-center justify-center mb-1.5">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2z" />
        </svg>
      </div>
      <p className="text-[11px] text-slate-500">{hint}</p>
    </div>
  </div>
);

export default Anomalies;
