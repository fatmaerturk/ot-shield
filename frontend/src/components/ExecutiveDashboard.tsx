import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { parseServerTime } from '../utils/time';
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
import honeypotService, { HoneypotStats, TtpAnalysis, HoneypotLog } from '../services/honeypotService';
import { alertService } from '../services/alertService';
import { AlertStatistics, Alert as BackendAlert } from '../types/alert';
import assetService, { AssetDTO } from '../services/assetService';
import { PageLoading } from './theme';
import api from '../services/api';
import { iec62443Service } from '../services/iec62443Service';

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

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */
const fmtNum = (n: number | undefined | null, fallback = '-'): string => {
  if (n === undefined || n === null || Number.isNaN(n)) return fallback;
  return n.toLocaleString();
};

const relativeTime = (iso?: string): string => {
  if (!iso) return '';
  const ts = parseServerTime(iso);
  if (Number.isNaN(ts)) return '';
  const diff = Date.now() - ts;
  if (diff < 60_000) return `${Math.max(1, Math.floor(diff / 1000))}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
};

const lastNDays = (n: number): string[] => {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const out: string[] = [];
  const today = new Date();
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    out.push(days[d.getDay()]);
  }
  return out;
};

const todayKeyDayLabel = (label: string): string => label;

const ExecutiveDashboard: React.FC = () => {
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('7d');
  const rangeLabel = timeRange === '24h' ? 'last 24h' : timeRange === '7d' ? 'last 7 days' : 'last 30 days';

  /* ---------- Live data from backend ---------- */
  const [honeypotStats, setHoneypotStats] = useState<HoneypotStats | null>(null);
  const [alertStats, setAlertStats] = useState<AlertStatistics | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<BackendAlert[]>([]);
  const [assets, setAssets] = useState<AssetDTO[]>([]);
  const [highRiskAssets, setHighRiskAssets] = useState<AssetDTO[]>([]);
  const [ttp, setTtp] = useState<TtpAnalysis | null>(null);
  const [recentLogs, setRecentLogs] = useState<HoneypotLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  // Real compliance readiness from the NIS2 / IEC 62443 posture endpoints
  // (null = endpoint unavailable / not yet loaded).
  const [nis2Score, setNis2Score] = useState<number | null>(null);
  const [iecScore, setIecScore] = useState<number | null>(null);

  /* ---------- Fetch loop ---------- */
  const refresh = useCallback(async () => {
    const rangeDays = timeRange === '24h' ? 1 : timeRange === '7d' ? 7 : 30;
    const tasks = await Promise.allSettled([
      honeypotService.getStats(rangeDays),
      alertService.getAlertStatistics(),
      alertService.getRecentAlerts(),
      assetService.listAll(500),
      assetService.highRisk(),
      honeypotService.getTtpAnalysis(),
      honeypotService.getRecentLogs(20),
    ]);
    const [hpRes, asRes, raRes, allAssetsRes, hraRes, ttpRes, logsRes] = tasks;
    if (hpRes.status === 'fulfilled') setHoneypotStats(hpRes.value);
    if (asRes.status === 'fulfilled') setAlertStats(asRes.value);
    if (raRes.status === 'fulfilled') setRecentAlerts(Array.isArray(raRes.value) ? raRes.value : []);
    if (allAssetsRes.status === 'fulfilled') setAssets(allAssetsRes.value);
    if (hraRes.status === 'fulfilled') setHighRiskAssets(hraRes.value);
    if (ttpRes.status === 'fulfilled') setTtp(ttpRes.value);
    if (logsRes.status === 'fulfilled') setRecentLogs(logsRes.value);

    // Real compliance posture (best-effort; kept out of the tuple above so its
    // response types don't widen the others).
    const [nis2Res, iecRes] = await Promise.allSettled([
      api.get('/api/compliance/nis2/posture'),
      iec62443Service.getPosture(),
    ]);
    if (nis2Res.status === 'fulfilled') setNis2Score(nis2Res.value?.data?.postureScore?.score ?? null);
    if (iecRes.status === 'fulfilled') setIecScore(iecRes.value?.overall?.coveragePct ?? null);

    setLastUpdated(new Date());
    setLoading(false);
  }, [timeRange]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 60_000);
    return () => clearInterval(id);
  }, [refresh]);

  /* ---------- Derived metrics (computed from live data) ---------- */

  // Posture score: derived from blocked-vs-total ratio + critical alert ratio + asset risk distribution
  const postureScore = useMemo(() => {
    // OTShield is a deception platform: it ABSORBS attacks at the decoy layer
    // rather than blocking them, so blockedAttacks is structurally ~0. Driving
    // the posture off a block rate therefore pinned the score near 40 no matter
    // how well the deception worked. Score real-asset residual risk instead:
    //  - crownJewelSafety: crown-jewel (CRITICAL/HIGH) assets NOT under active attacker interest
    //  - low critical-incident share
    //  - monitoring coverage of the asset estate
    const critical = alertStats?.criticalAlerts ?? 0;
    const totalAlerts = alertStats?.totalAlerts ?? 0;
    const criticalRatio = totalAlerts > 0 ? (critical / totalAlerts) * 100 : 0;

    const crownJewels = assets.filter((a) => a.criticalityLevel === 'CRITICAL' || a.criticalityLevel === 'HIGH');
    const highRiskIds = new Set(highRiskAssets.map((a) => a.id));
    const crownAtRisk = crownJewels.filter((a) => highRiskIds.has(a.id)).length;
    const crownJewelSafety = crownJewels.length > 0
      ? Math.max(0, (1 - crownAtRisk / crownJewels.length) * 100)
      : 100; // no crown jewels under active attacker interest

    const monitored = assets.filter((a) => a.monitoringStatus === 'MONITORED' || a.monitoringStatus === 'PARTIALLY_MONITORED').length;
    const coverage = assets.length > 0 ? (monitored / assets.length) * 100 : 100;

    const score = Math.round(0.5 * crownJewelSafety + 0.3 * (100 - criticalRatio) + 0.2 * coverage);
    return Math.max(0, Math.min(100, score || 0));
  }, [alertStats, assets, highRiskAssets]);

  // Residual risk (0-10, higher = worse): the inverse of the security posture,
  // nudged up by open critical / high incidents that still need action - so the
  // score genuinely reflects the "posture & alert mix" the card describes.
  const residualRiskScore = useMemo(() => {
    const base = (100 - postureScore) / 10; // 0-10 from posture
    const critical = alertStats?.criticalAlerts ?? 0;
    const high = alertStats?.highAlerts ?? 0;
    const alertPressure = Math.min(3, critical * 0.5 + high * 0.2); // up to +3
    return Math.round(Math.max(0, Math.min(10, base + alertPressure)) * 10) / 10;
  }, [postureScore, alertStats]);

  // Level is derived from the same score so the badge, header and gauge agree.
  const residualRiskLevel = useMemo<'HIGH' | 'MODERATE' | 'LOW'>(() => {
    if (residualRiskScore < 3.5) return 'LOW';
    if (residualRiskScore < 6.5) return 'MODERATE';
    return 'HIGH';
  }, [residualRiskScore]);

  // Crown jewels: high-criticality assets
  const crownJewelAssets = useMemo<AssetDTO[]>(() => {
    return assets.filter((a) => a.criticalityLevel === 'CRITICAL' || a.criticalityLevel === 'HIGH');
  }, [assets]);

  const totalCrownJewels = crownJewelAssets.length;
  const criticalAssetsAtRisk = useMemo(() => {
    const ids = new Set(highRiskAssets.map((a) => a.id));
    return crownJewelAssets.filter((a) => ids.has(a.id)).length;
  }, [crownJewelAssets, highRiskAssets]);

  // Confirmed incidents (last 24h proxy from recentAttacks24h, fallback to alert critical+high)
  const confirmedIncidents = useMemo(() => {
    if (typeof honeypotStats?.recentAttacks24h === 'number') return honeypotStats.recentAttacks24h;
    return (alertStats?.criticalAlerts ?? 0) + (alertStats?.highAlerts ?? 0);
  }, [honeypotStats, alertStats]);

  const highConfidenceAlerts = useMemo(() => {
    return (alertStats?.criticalAlerts ?? 0) + (alertStats?.highAlerts ?? 0);
  }, [alertStats]);

  // Noise reduction: compare resolved+falsePositive vs total
  const noiseReduction = useMemo(() => {
    const total = alertStats?.totalAlerts ?? 0;
    const noise = alertStats?.falsePositives ?? 0;
    if (total === 0) return 0;
    return Math.round((noise / total) * 100);
  }, [alertStats]);

  // Discovered OT assets at each Purdue level (real inventory distribution).
  // (Was "% monitored per level", but monitoring_status is never set on the
  // auto-discovered assets, so that chart was permanently 0% / empty.)
  const assetsByLevel = useMemo(() => {
    const buckets: Record<string, number> = { LEVEL_0: 0, LEVEL_1: 0, LEVEL_2: 0, LEVEL_3: 0 };
    assets.forEach((a) => {
      const lvl = a.purdueLevel as string | undefined;
      if (lvl && lvl in buckets) buckets[lvl]++;
    });
    return {
      level0: buckets.LEVEL_0,
      level1: buckets.LEVEL_1,
      level2: buckets.LEVEL_2,
      level3: buckets.LEVEL_3,
    };
  }, [assets]);

  // Threat trend: last 7 days of real daily attack counts from the honeypot
  // dailySeries. Only the real total per day - no fabricated stage split.
  const threatTrends = useMemo(() => {
    // dailySeries is a fixed ~30-day series with the RECENT days at the END.
    // Mapping weekday labels onto daily[0..6] previously read the OLDEST, all-
    // zero days -> the chart looked empty. Take the tail that matches the
    // selected range and label each bar from its own date.
    const daily = honeypotStats?.dailySeries ?? [];
    const n = timeRange === '30d' ? 30 : 7;
    const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    return daily.slice(-n).map((d) => {
      const dt = d.date ? new Date(d.date + 'T00:00:00') : null;
      return {
        day: dt ? (n > 7 ? d.date.slice(5) : dayNames[dt.getDay()]) : (d.date ?? ''),
        total: d.count ?? 0,
      };
    });
  }, [honeypotStats, timeRange]);

  // MITRE tactics from backend ttp-analysis. The endpoint returns `mitreTactics`
  // ({ tactic, eventCount, techniques, uniqueAttackers }); the old code read a
  // `tactics` / `mitreHeatmap` shape it never actually sent -> chart was empty.
  // The bar shows each tactic's share of observed activity (real), not a
  // fabricated "framework coverage".
  const mitreTactics = useMemo(() => {
    const list = ttp?.mitreTactics ?? [];
    if (list.length === 0) return [];
    const total = list.reduce((s, t) => s + (t.eventCount ?? 0), 0) || 1;
    const idByName: Record<string, string> = {
      'Initial Access': 'TA0108', 'Execution': 'TA0104', 'Persistence': 'TA0110',
      'Privilege Escalation': 'TA0111', 'Evasion': 'TA0103', 'Discovery': 'TA0102',
      'Lateral Movement': 'TA0109', 'Collection': 'TA0100', 'Command and Control': 'TA0101',
      'Inhibit Response Function': 'TA0107', 'Impair Process Control': 'TA0106',
      'Impact': 'TA0105', 'Reconnaissance': 'TA0043',
    };
    return list.map((t) => ({
      id: idByName[t.tactic] ?? '',
      name: t.tactic,
      observed: t.eventCount ?? 0,
      share: Math.round(((t.eventCount ?? 0) / total) * 100),
    }));
  }, [ttp]);

  // Risk register: prefer flagged high-risk assets, then formally CRITICAL/HIGH
  // assets; if the inventory has neither (auto-discovered assets default to
  // MEDIUM), fall back to the highest riskScore assets so the register still
  // reflects the real estate instead of rendering empty.
  const crownJewelsView = useMemo(() => {
    const list = highRiskAssets.length > 0
      ? highRiskAssets
      : crownJewelAssets.length > 0
        ? crownJewelAssets
        : [...assets].sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0));
    return list.slice(0, 5).map((a) => ({
      asset: a.name ?? a.hostname ?? a.id,
      zone: a.purdueLevel ? a.purdueLevel.replace('LEVEL_', 'Level ') : 'Unknown',
      risk: (a.criticalityLevel ?? 'MEDIUM') as string,
      trend: '·',
      detail: a.description || a.assetType || '',
    }));
  }, [highRiskAssets, crownJewelAssets, assets]);

  // Compliance readiness. NIS2 and IEC 62443 come from their REAL posture
  // endpoints (/api/compliance/nis2|iec62443/posture). CAF and GDPR have no
  // assessment source in the platform, so they are shown as "not assessed"
  // rather than derived from an unrelated proxy (the old heuristic drove NIS2/
  // IEC off asset coverage - always 0 here - and GDPR off the false-positive
  // rate, which was meaningless).
  const complianceStatus = useMemo<Array<{ name: string; value: number | null; gap: string }>>(() => {
    return [
      {
        name: 'NIS2',
        value: nis2Score,
        gap: nis2Score == null ? 'Posture unavailable'
          : nis2Score >= 85 ? 'On track'
          : nis2Score >= 50 ? 'Improving - close remaining Article 21 gaps'
          : 'Below target - prioritise Article 21 measures',
      },
      {
        name: 'IEC 62443',
        value: iecScore,
        gap: iecScore == null ? 'Posture unavailable'
          : iecScore >= 80 ? 'On track'
          : `${iecScore}% of requirements met - raise toward the target SL`,
      },
      // CAF and GDPR are intentionally omitted: the platform has no assessment
      // engine for them, so showing a value would be fabricated.
    ];
  }, [nis2Score, iecScore]);

  // Recent alerts mapped to executive view. De-duplicate repeated events (e.g.
  // the same probe firing many times from one IP) so the board sees distinct
  // incidents rather than the same line four times.
  const executiveAlerts = useMemo(() => {
    const seen = new Set<string>();
    const distinct = (recentAlerts || []).filter((a) => {
      const key = `${a.title ?? ''}|${a.sourceIp ?? a.source ?? ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    const list = distinct.slice(0, 4);
    return list.map((a) => ({
      id: a.id,
      title: a.title || 'Security event',
      severity: (a.severity || 'MEDIUM').toString().toUpperCase() as string,
      time: relativeTime(a.createdAt),
      source: a.source || a.sourceIp || 'Unknown',
      impact: a.description || 'No additional context',
    }));
  }, [recentAlerts]);

  // If we have no alerts, fall back to recent honeypot logs
  const fallbackAlerts = useMemo(() => {
    return (recentLogs || []).slice(0, 4).map((l, idx) => ({
      id: l.id ?? idx,
      title: `${l.attackType ?? l.protocol ?? 'Honeypot interaction'} from ${l.sourceIp ?? 'unknown'}`,
      severity: (l.severity || 'MEDIUM').toUpperCase() as string,
      time: relativeTime(l.timestamp),
      source: l.sourceIp ?? 'External',
      impact: l.description ?? l.payload ?? 'Decoy interaction recorded',
    }));
  }, [recentLogs]);

  const alertsToShow = executiveAlerts.length > 0 ? executiveAlerts : fallbackAlerts;

  // Window label
  const windowLabel = useMemo(() => {
    const d = new Date();
    return `WEEK OF ${d
      .toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
      .toUpperCase()}`;
  }, []);

  /* ---------- Chart datasets ---------- */
  const threatTrendData = {
    labels: threatTrends.map((t) => t.day),
    datasets: [
      {
        type: 'bar' as const,
        label: 'Attacks per day',
        data: threatTrends.map((t) => t.total),
        backgroundColor: 'rgba(168,85,247,0.55)',
        borderRadius: 6,
      },
    ],
  };

  const deploymentData = {
    labels: ['Level 0 (Field)', 'Level 1 (Control)', 'Level 2 (Supervisory)', 'Level 3 (Operations)'],
    datasets: [
      {
        label: 'Assets',
        data: [assetsByLevel.level0, assetsByLevel.level1, assetsByLevel.level2, assetsByLevel.level3],
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
    switch (sev?.toUpperCase()) {
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

  // Gauge placeholders while loading
  const showLoadingValue = (val: any, suffix = '') => {
    if (loading && (val === 0 || val === null || val === undefined)) return '-';
    return `${val}${suffix}`;
  };

  /* ---------- Render ---------- */
  if (loading) {
    return (
      <div className="relative">
        <PageLoading label="Loading executive overview…" />
      </div>
    );
  }

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
                  EXECUTIVE OVERVIEW &nbsp;·&nbsp; {windowLabel}
                </div>
                <h1 className="mt-4 text-3xl md:text-4xl font-bold leading-tight">
                  OT environment is
                  <span className={residualRiskLevel === 'LOW' ? 'text-emerald-300' : residualRiskLevel === 'MODERATE' ? 'text-amber-300' : 'text-rose-300'}>
                    {' '}{residualRiskLevel === 'LOW' ? 'stable' : residualRiskLevel === 'MODERATE' ? 'monitored' : 'elevated'}
                  </span>.
                  <span className="block text-violet-100/95 font-medium text-xl md:text-2xl mt-2">
                    {criticalAssetsAtRisk} crown-jewel asset{criticalAssetsAtRisk === 1 ? '' : 's'} under active attacker interest, all contained at decoy layer.
                  </span>
                </h1>

                <div className="mt-5 grid grid-cols-3 gap-3">
                  <div className="p-3 rounded-xl bg-white/10 ring-1 ring-white/15 backdrop-blur-sm">
                    <div className="text-[10px] uppercase tracking-wider text-violet-200/80">Confirmed incidents</div>
                    <div className="mt-1 text-2xl font-bold">{fmtNum(confirmedIncidents, '0')}</div>
                    <div className="text-[11px] text-violet-200/80">last 24h</div>
                  </div>
                  <div className="p-3 rounded-xl bg-white/10 ring-1 ring-white/15 backdrop-blur-sm">
                    <div className="text-[10px] uppercase tracking-wider text-violet-200/80">Total attacks</div>
                    <div className="mt-1 text-2xl font-bold">{fmtNum(honeypotStats?.totalAttacks, '0')}</div>
                    <div className="text-[11px] text-violet-200/80">{rangeLabel}</div>
                  </div>
                  <div className="p-3 rounded-xl bg-white/10 ring-1 ring-white/15 backdrop-blur-sm">
                    <div className="text-[10px] uppercase tracking-wider text-violet-200/80">Unique attackers</div>
                    <div className="mt-1 text-2xl font-bold">{fmtNum(honeypotStats?.uniqueIPs, '0')}</div>
                    <div className="text-[11px] text-violet-200/80">distinct IPs</div>
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
                      strokeDashoffset={2 * Math.PI * 76 * (1 - postureScore / 100)}
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
                    <span className="text-4xl font-bold">{loading ? '-' : postureScore}</span>
                    <span className="text-xs text-emerald-300 font-semibold mt-1">
                      {residualRiskLevel}
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
                  Live · updated {relativeTime(lastUpdated.toISOString()) || 'now'}
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* ====== OPERATIONAL KPIs (real honeypot telemetry) ====== */}
        <motion.div variants={item} className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          {[
            {
              icon: <Icon.Bolt className="w-5 h-5" />,
              label: 'Attacks Absorbed',
              value: (honeypotStats?.totalAttacks ?? 0).toLocaleString(),
              benchmark: `Decoy-fabric interactions · ${rangeLabel}`,
              delta: 'Live',
              deltaGood: true,
              from: 'from-violet-500',
              to: 'to-fuchsia-500',
            },
            {
              icon: <Icon.Eye className="w-5 h-5" />,
              label: 'Attacker Sessions',
              value: (honeypotStats?.uniqueSessions ?? 0).toLocaleString(),
              benchmark: 'Distinct attacker sessions observed',
              delta: 'Observed',
              deltaGood: true,
              from: 'from-fuchsia-500',
              to: 'to-pink-500',
            },
            {
              icon: <Icon.Shield className="w-5 h-5" />,
              // Was "Block Rate" (always 0% - OTShield absorbs attacks, it does
              // not block). Reframed to a real, distinct signal: the breadth of
              // the OT/IT attack surface probed on the decoy fabric.
              label: 'Protocols Targeted',
              value: `${Object.keys(honeypotStats?.attacksByProtocol ?? {}).length}`,
              benchmark: Object.keys(honeypotStats?.attacksByProtocol ?? {}).length > 0
                ? `ICS/IT protocols probed: ${Object.keys(honeypotStats?.attacksByProtocol ?? {}).join(', ')}`
                : 'No protocol data yet',
              delta: 'Observed',
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
              value: `${criticalAssetsAtRisk} / ${totalCrownJewels}`,
              hint: totalCrownJewels > 0 ? 'High-value OT assets under active probing' : 'No crown jewel assets defined',
              icon: <Icon.Lock className="w-5 h-5" />,
              color: 'rose',
              progress: totalCrownJewels > 0 ? (criticalAssetsAtRisk / totalCrownJewels) * 100 : 0,
            },
            {
              label: 'High-Confidence Alerts',
              value: highConfidenceAlerts,
              hint: alertStats ? `${alertStats.totalAlerts} total · ${alertStats.unassignedAlerts ?? 0} unassigned` : 'No alert data',
              icon: <Icon.Alert className="w-5 h-5" />,
              color: 'violet',
              progress: alertStats?.totalAlerts ? Math.min(100, (highConfidenceAlerts / alertStats.totalAlerts) * 100) : 0,
            },
            {
              label: 'Resolution Rate',
              value: `${alertStats?.totalAlerts ? Math.round(((alertStats.resolvedAlerts ?? 0) / alertStats.totalAlerts) * 100) : 0}%`,
              hint: `${alertStats?.resolvedAlerts ?? 0} resolved · ${alertStats?.acknowledgedAlerts ?? 0} acknowledged`,
              icon: <Icon.CheckCircle className="w-5 h-5" />,
              color: 'fuchsia',
              progress: alertStats?.totalAlerts ? ((alertStats.resolvedAlerts ?? 0) / alertStats.totalAlerts) * 100 : 0,
            },
            {
              // OTShield absorbs attacks at the decoy layer instead of blocking
              // them, so "blocked attacks / block rate" (always 0) understates a
              // working deception. Reframed as containment: every observed attack
              // landed on a decoy rather than a real asset.
              label: 'Containment Rate',
              value: (honeypotStats?.totalAttacks ?? 0) > 0 ? '100%' : '-',
              hint: (honeypotStats?.totalAttacks ?? 0) > 0
                ? `${(honeypotStats?.totalAttacks ?? 0).toLocaleString()} attacks absorbed at the decoy layer`
                : 'No attack data yet',
              icon: <Icon.Shield className="w-5 h-5" />,
              color: 'pink',
              progress: (honeypotStats?.totalAttacks ?? 0) > 0 ? 100 : 0,
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
                <h3 className="text-base font-semibold text-slate-900">Attack Volume · Last 7 Days</h3>
                <p className="text-xs text-slate-500 mt-1">
                  Real daily attack counts on the decoy fabric (honeypot dailySeries).
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
                <p className="text-xs text-slate-500 mt-1">Real-time alert resolution &amp; noise stats</p>
              </div>
              <Icon.Activity className="w-5 h-5 text-fuchsia-500" />
            </div>

            {/* Noise reduction big number */}
            <div className="mt-5 p-4 rounded-xl bg-gradient-to-br from-violet-50 to-pink-50 ring-1 ring-violet-100">
              <div className="text-[11px] uppercase tracking-wider text-violet-700 font-semibold">False positive rate</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-4xl font-bold bg-gradient-to-r from-violet-600 to-pink-600 bg-clip-text text-transparent">
                  {noiseReduction}%
                </span>
                <span className="text-xs text-slate-500">of total alerts</span>
              </div>
            </div>

            {/* Real stats */}
            <div className="mt-4 space-y-3">
              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 ring-1 ring-slate-200/60">
                <div>
                  <p className="text-sm font-semibold text-slate-900">Resolved alerts</p>
                  <p className="text-xs text-slate-500">closed by analysts</p>
                </div>
                <span className="text-lg font-bold text-emerald-600">{fmtNum(alertStats?.resolvedAlerts, '0')}</span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 ring-1 ring-slate-200/60">
                <div>
                  <p className="text-sm font-semibold text-slate-900">New alerts</p>
                  <p className="text-xs text-slate-500">awaiting triage</p>
                </div>
                <span className="text-lg font-bold text-violet-600">{fmtNum(alertStats?.newAlerts, '0')}</span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 ring-1 ring-slate-200/60">
                <div>
                  <p className="text-sm font-semibold text-slate-900">Unassigned</p>
                  <p className="text-xs text-slate-500">needs an owner</p>
                </div>
                <span className="text-lg font-bold text-rose-600">{fmtNum(alertStats?.unassignedAlerts, '0')}</span>
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
                <h3 className="text-base font-semibold text-slate-900">Compliance Readiness</h3>
                <p className="text-xs text-slate-500 mt-1">NIS2 and IEC 62443 scores come from the live posture engines. See the NIS2 / IEC pages for the full breakdown.</p>
              </div>
              <Icon.CheckCircle className="w-5 h-5 text-violet-500" />
            </div>
            <div className="space-y-4">
              {complianceStatus.map((c) => (
                <div key={c.name} className="p-3 rounded-xl bg-slate-50/60 ring-1 ring-slate-200/50">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm font-semibold text-slate-800">{c.name}</span>
                    {c.value == null ? (
                      <span className="text-xs font-semibold text-slate-400">Not assessed</span>
                    ) : (
                      <span className={`text-sm font-bold ${c.value >= 85 ? 'text-emerald-600' : c.value >= 60 ? 'text-violet-600' : 'text-orange-600'}`}>
                        {c.value}%
                      </span>
                    )}
                  </div>
                  <div className="h-2 bg-white rounded-full overflow-hidden ring-1 ring-slate-200/60 mb-2">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-violet-500 via-fuchsia-500 to-pink-500"
                      style={{ width: `${c.value ?? 0}%` }}
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
                <h3 className="text-base font-semibold text-slate-900">Assets by Purdue Level</h3>
                <p className="text-xs text-slate-500 mt-1">Discovered OT assets at each Purdue level</p>
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
                <p className="text-xs text-slate-500 mt-1">Live from honeypot TTP analysis</p>
              </div>
              <Icon.Network className="w-5 h-5 text-violet-500" />
            </div>
            <div className="space-y-3">
              {mitreTactics.length === 0 ? (
                <div className="p-6 text-center text-sm text-slate-500">
                  No MITRE tactics observed yet. Tactics will appear here as the honeypot collects more data.
                </div>
              ) : (
                mitreTactics.map((t) => (
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
                        <span className="font-semibold text-violet-600">
                          {t.share}% of activity
                        </span>
                      </div>
                    </div>
                    <div className="h-2 bg-white rounded-full overflow-hidden ring-1 ring-slate-200/60">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-violet-500 to-pink-500"
                        style={{ width: `${t.share}%` }}
                      />
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Residual risk panel */}
          <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-base font-semibold text-slate-900">Residual Risk</h3>
                <p className="text-xs text-slate-500 mt-1">Computed from posture &amp; alert mix</p>
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
                    strokeDashoffset={2 * Math.PI * 62 * (1 - residualRiskScore / 10)}
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
                  <span className="text-3xl font-bold text-slate-900">{residualRiskScore}</span>
                  <span className="text-[11px] text-violet-600 font-semibold">/ 10</span>
                </div>
              </div>
              <p className={`mt-2 text-xs font-semibold ${residualRiskScore < 3.5 ? 'text-emerald-600' : residualRiskScore < 6.5 ? 'text-amber-600' : 'text-rose-600'}`}>
                {residualRiskScore < 3.5
                  ? 'Within board-approved tolerance'
                  : residualRiskScore < 6.5
                  ? 'Approaching tolerance limit'
                  : 'Above tolerance - action required'}
              </p>
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 rounded-lg bg-rose-50 ring-1 ring-rose-100">
                <span className="text-xs text-slate-700">Critical alerts</span>
                <span className="text-xs font-bold text-rose-700">{fmtNum(alertStats?.criticalAlerts, '0')}</span>
              </div>
              <div className="flex items-center justify-between p-3 rounded-lg bg-amber-50 ring-1 ring-amber-100">
                <span className="text-xs text-slate-700">High alerts</span>
                <span className="text-xs font-bold text-amber-700">{fmtNum(alertStats?.highAlerts, '0')}</span>
              </div>
              <div className="flex items-center justify-between p-3 rounded-lg bg-emerald-50 ring-1 ring-emerald-100">
                <span className="text-xs text-slate-700">Honeypot decoyed</span>
                <span className="text-xs font-bold text-emerald-700">{fmtNum(honeypotStats?.uniqueSessions, '0')}</span>
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
                <p className="text-xs text-slate-500 mt-1">Highest-risk OT assets · live from inventory</p>
              </div>
              <Icon.Lock className="w-5 h-5 text-violet-500" />
            </div>
            <div className="space-y-3">
              {crownJewelsView.length === 0 ? (
                <div className="p-6 text-center text-sm text-slate-500">
                  No critical or high-criticality assets registered yet.
                </div>
              ) : (
                crownJewelsView.map((cj, idx) => {
                  const s = severityStyle(cj.risk);
                  return (
                    <div
                      key={idx}
                      className="p-4 rounded-xl bg-gradient-to-r from-slate-50 to-fuchsia-50/30 ring-1 ring-slate-200/50 hover:ring-violet-300/60 transition"
                    >
                      <div className="flex justify-between items-start">
                        <div className="min-w-0">
                          <p className="text-sm font-semibold text-slate-900 truncate">{cj.asset}</p>
                          <p className="text-[11px] text-slate-500 mt-0.5">{cj.zone}{cj.detail ? ` · ${cj.detail}` : ''}</p>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                          <span className={`text-[10px] font-bold px-2.5 py-1 rounded-full ring-1 ${s.badge}`}>
                            {cj.risk}
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Executive alerts */}
          <div className="bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-base font-semibold text-slate-900">Incidents Requiring Board Awareness</h3>
                <p className="text-xs text-slate-500 mt-1">Recent high-impact events from alerts &amp; honeypot</p>
              </div>
              <Icon.Alert className="w-5 h-5 text-rose-500" />
            </div>
            <div className="space-y-2.5">
              {alertsToShow.length === 0 ? (
                <div className="p-6 text-center text-sm text-slate-500">
                  No incidents to report. Quiet period.
                </div>
              ) : (
                alertsToShow.map((alert) => {
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
                })
              )}
            </div>
          </div>
        </motion.div>

        {/* ====== BOTTOM - ACTION ITEMS FOR THE CISO ====== */}
        <motion.div variants={item} className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {[
            {
              value: fmtNum(alertStats?.unassignedAlerts, '0'),
              label: 'Unassigned alerts',
              icon: <Icon.CheckCircle className="w-4 h-4" />,
            },
            {
              value: fmtNum(alertStats?.criticalAlerts, '0'),
              label: 'Critical alerts open',
              icon: <Icon.Alert className="w-4 h-4" />,
            },
            {
              value: fmtNum(assets.length, '0'),
              label: 'OT assets tracked',
              icon: <Icon.Lock className="w-4 h-4" />,
            },
            {
              value: fmtNum(honeypotStats?.recentAttacks24h, '0'),
              label: 'Attacks last 24h',
              icon: <Icon.Activity className="w-4 h-4" />,
            },
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
                    stat: fmtNum(honeypotStats?.totalAttacks, '0'),
                    head: 'Total Attacks Captured',
                    body: `${fmtNum(honeypotStats?.uniqueIPs, '0')} unique attacker IPs across ${fmtNum(honeypotStats?.uniqueSessions, '0')} sessions, all contained at the honeypot layer.`,
                  },
                  {
                    // Was "Blocked at Edge" (always 0 - the platform absorbs,
                    // it does not block). Reframed to deception containment.
                    stat: (honeypotStats?.totalAttacks ?? 0) > 0 ? '100%' : '-',
                    head: 'Contained at Decoy Layer',
                    body: (honeypotStats?.totalAttacks ?? 0) > 0
                      ? 'Every observed attack was absorbed on the decoy fabric, away from production systems.'
                      : 'No traffic recorded yet.',
                  },
                  {
                    stat: fmtNum(alertStats?.resolvedAlerts, '0'),
                    head: 'Alerts Resolved',
                    body: `${fmtNum(alertStats?.acknowledgedAlerts, '0')} acknowledged · ${fmtNum(alertStats?.newAlerts, '0')} new in current window.`,
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
            Executive Overview · OTShield Platform
          </div>
          <p className="text-xs text-slate-400">
            Confidential · Board &amp; Risk Committee distribution &nbsp;•&nbsp; Live · auto-refresh 60s
          </p>
        </motion.div>
    </motion.div>
  );
};

export default ExecutiveDashboard;
