import React, { useState, useEffect, useMemo } from 'react';
import api from '../services/api';
// @ts-ignore: file-saver has no type definitions
import { saveAs } from 'file-saver';
import * as XLSX from 'xlsx';
import jsPDF from 'jspdf';
import 'jspdf-autotable';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
  Filler,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import { PageShell, PageHero, Icon } from './theme';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
  Filler
);

interface Alert {
  id: string;
  title: string;
  timestamp: string;
  source: string;
  type: 'ANOMALY' | 'IOA' | 'HONEYPOT' | 'THREAT_INTELLIGENCE' | 'INTRUSION_DETECTION' | 'PORT_SCAN' | 'BRUTE_FORCE' | 'DDoS_ATTACK' | 'MALWARE_DETECTION' | 'PHISHING_ATTACK' | 'SQL_INJECTION' | 'XSS_ATTACK' | 'CSRF_ATTACK' | 'PATH_TRAVERSAL' | 'COMMAND_INJECTION' | 'FAILED_LOGIN' | 'UNAUTHORIZED_ACCESS' | 'PRIVILEGE_ESCALATION' | 'ACCOUNT_LOCKOUT' | 'SUSPICIOUS_LOGIN' | 'FILE_INTEGRITY' | 'PROCESS_MONITORING' | 'REGISTRY_CHANGE' | 'SERVICE_CHANGE' | 'HONEYPOT_TRIGGER' | 'HONEYPOT_INTERACTION' | 'HONEYPOT_EXPLOIT' | 'COMPLIANCE_VIOLATION' | 'DATA_LEAKAGE' | 'ANOMALY_DETECTION' | 'CUSTOM_RULE';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description?: string;
  status: 'NEW' | 'ACKNOWLEDGED' | 'IN_PROGRESS' | 'ESCALATED' | 'RESOLVED' | 'CLOSED' | 'FALSE_POSITIVE';
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  createdAt?: string;
  updatedAt?: string;
  // Fields the Java side already persists on every alert; frontend just
  // wasn't declaring them. Needed for MTTA/MTTR, SLA countdown, and
  // ownership workflow.
  acknowledgedAt?: string | null;
  acknowledgedBy?: string | null;
  resolvedAt?: string | null;
  assignedTo?: string | null;
  assignedBy?: string | null;
  escalated?: boolean | null;
  escalatedAt?: string | null;
  escalatedTo?: string | null;
  mitigationNotes?: string | null;
  rawData?: string | null;
  tags?: string[];
  riskScore?: number | null;
  confidenceScore?: number | null;
  mitreId?: string | null;
  /** Optional linkage to a Case record (populated when analyst opens a case). */
  linkedCaseId?: string | null;
}

// ---------------------------------------------------------------------------
// SLA policy — response targets per severity, in milliseconds.
// CRITICAL 2h / HIGH 8h / MEDIUM 24h / LOW 72h / INFO has no clock.
// Used for the row badge and drawer countdown.
// ---------------------------------------------------------------------------
const SLA_MS: Record<Alert['severity'], number | null> = {
  CRITICAL: 2 * 60 * 60 * 1000,
  HIGH:     8 * 60 * 60 * 1000,
  MEDIUM:   24 * 60 * 60 * 1000,
  LOW:      72 * 60 * 60 * 1000,
  INFO:     null,
};

/**
 * Returns the SLA state for a single alert. `null` kind means the SLA
 * clock doesn't apply (INFO, or terminal states where nothing more can
 * be done). Otherwise `kind` reports how healthy the response window
 * is, `msRemaining` is the raw number, `label` is a human string.
 */
function computeSla(a: Alert): {
  kind: 'none' | 'healthy' | 'warn' | 'breached' | 'met';
  msRemaining: number;
  label: string;
} {
  const budget = SLA_MS[a.severity];
  if (budget == null) return { kind: 'none', msRemaining: 0, label: 'no SLA' };

  // Terminal states: clock is frozen. If we acknowledged inside the
  // budget, the SLA is "met"; otherwise it was breached before action.
  const terminal = a.status === 'ACKNOWLEDGED' || a.status === 'IN_PROGRESS'
                || a.status === 'RESOLVED'     || a.status === 'CLOSED'
                || a.status === 'FALSE_POSITIVE';
  const startedAt = a.createdAt ?? a.timestamp;
  const startedTs = startedAt ? new Date(startedAt).getTime() : NaN;
  if (!startedTs || Number.isNaN(startedTs)) return { kind: 'none', msRemaining: 0, label: 'no start time' };

  if (terminal) {
    const ackTs = a.acknowledgedAt ? new Date(a.acknowledgedAt).getTime() : NaN;
    const stopTs = Number.isNaN(ackTs)
      ? (a.resolvedAt ? new Date(a.resolvedAt).getTime() : Date.now())
      : ackTs;
    const elapsed = stopTs - startedTs;
    return elapsed <= budget
      ? { kind: 'met', msRemaining: 0, label: 'SLA met' }
      : { kind: 'breached', msRemaining: budget - elapsed, label: 'SLA missed' };
  }

  const remaining = (startedTs + budget) - Date.now();
  if (remaining <= 0) {
    return { kind: 'breached', msRemaining: remaining, label: `breached by ${formatShortDuration(-remaining)}` };
  }
  const pctLeft = remaining / budget;
  return {
    kind: pctLeft < 0.25 ? 'warn' : 'healthy',
    msRemaining: remaining,
    label: `${formatShortDuration(remaining)} left`,
  };
}

/** Compact duration like "1h 23m" / "42m" / "3s". Always positive. */
function formatShortDuration(ms: number): string {
  const abs = Math.abs(ms);
  const s = Math.floor(abs / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  if (h < 24) return mm > 0 ? `${h}h ${mm}m` : `${h}h`;
  const d = Math.floor(h / 24);
  const hh = h % 24;
  return hh > 0 ? `${d}d ${hh}h` : `${d}d`;
}

/** Tailwind classes for the SLA badge. */
function slaBadgeClass(kind: ReturnType<typeof computeSla>['kind']): string {
  switch (kind) {
    case 'healthy':  return 'bg-emerald-50 text-emerald-700 ring-emerald-200';
    case 'warn':     return 'bg-amber-50 text-amber-700 ring-amber-200';
    case 'breached': return 'bg-rose-50 text-rose-700 ring-rose-200';
    case 'met':      return 'bg-violet-50 text-violet-700 ring-violet-200';
    case 'none':
    default:         return 'bg-slate-50 text-slate-600 ring-slate-200';
  }
}

/**
 * Reads the currently-logged-in user from localStorage. Falls back to
 * "Analyst" if the value is missing or malformed, so "Assign to me"
 * and "Post note" always have *something* to stamp.
 */
function readCurrentUserName(): string {
  try {
    const raw = localStorage.getItem('user');
    if (!raw) return 'Analyst';
    const u = JSON.parse(raw) as { fullName?: string; email?: string };
    return u.fullName || u.email || 'Analyst';
  } catch {
    return 'Analyst';
  }
}

/**
 * Compute mean time from createdAt to a target timestamp across a set
 * of alerts, ignoring entries that don't have the target timestamp.
 * Returns {ms, count} so the caller can render "—" when nothing has
 * been acknowledged yet.
 */
function meanDurationMs(
  alerts: Alert[],
  getStart: (a: Alert) => string | null | undefined,
  getEnd: (a: Alert) => string | null | undefined,
): { ms: number; count: number } {
  let total = 0;
  let count = 0;
  for (const a of alerts) {
    const s = getStart(a);
    const e = getEnd(a);
    if (!s || !e) continue;
    const sMs = new Date(s).getTime();
    const eMs = new Date(e).getTime();
    if (Number.isNaN(sMs) || Number.isNaN(eMs) || eMs < sMs) continue;
    total += (eMs - sMs);
    count += 1;
  }
  return { ms: count === 0 ? 0 : Math.round(total / count), count };
}

// ---------------------------------------------------------------------------
// Alert comment (audit-trail note) shape mirrored from the Java DTO.
// ---------------------------------------------------------------------------
interface AlertComment {
  id: string;
  alertId: string;
  content: string;
  createdBy?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  commentType?: string | null;
}

interface AuditEntry {
  timestamp: string;
  action: string;
  performedBy: string;
}

const Alerts: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');

  // Add filtering & sorting state
  const [filters, setFilters] = useState<{
    severity: string;
    type: string;
    status: string;
  }>({ severity: '', type: '', status: '' });

  // Search state
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Bulk operations state
  const [selectedAlerts, setSelectedAlerts] = useState<string[]>([]);

  // SOC workflow state -----------------------------------------------------
  /** Opens the alert detail drawer when non-null. */
  const [drawerAlertId, setDrawerAlertId] = useState<string | null>(null);

  /** Re-render tick so SLA countdowns refresh every 30s without fetching. */
  const [, setSlaTick] = useState(0);
  useEffect(() => {
    const h = window.setInterval(() => setSlaTick(t => t + 1), 30_000);
    return () => window.clearInterval(h);
  }, []);

  /** Auto-refresh toggle + last refresh timestamp for the "Live · Xs ago" pill. */
  const [autoRefresh, setAutoRefresh] = useState<boolean>(false);
  const [lastRefreshedAt, setLastRefreshedAt] = useState<Date | null>(null);

  /** Cached current-user name for the row actions. Read once so we don't
   *  hit localStorage on every keystroke / render. */
  const currentUserName = useMemo(() => readCurrentUserName(), []);

  // Correlation state
  const [correlationView, setCorrelationView] = useState<'list' | 'groups'>('list');
  const [correlationGroups, setCorrelationGroups] = useState<Array<{
    id: string;
    name: string;
    alerts: Alert[];
    pattern: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    count: number;
  }>>([]);

  // Enrichment state
  const [enrichmentData, setEnrichmentData] = useState<Map<string, any>>(new Map());
  const [enrichmentLoading, setEnrichmentLoading] = useState(false);
  const [showEnrichmentDetails, setShowEnrichmentDetails] = useState(false);

  // Monitor enrichment data changes for debugging
  useEffect(() => {
    console.log('enrichmentData state changed:', {
      size: enrichmentData.size,
      keys: Array.from(enrichmentData.keys()),
      values: Array.from(enrichmentData.values())
    });
  }, [enrichmentData]);

  // Calculate enrichment summary values
  const enrichmentSummary = useMemo(() => {
    const values = Array.from(enrichmentData.values());
    console.log('Enrichment Summary Debug - Raw Data:', {
      enrichmentDataSize: enrichmentData.size,
      enrichmentDataKeys: Array.from(enrichmentData.keys()),
      enrichmentDataValues: values,
      firstValue: values[0],
      firstValueKeys: values[0] ? Object.keys(values[0]) : 'No values'
    });
    
    const maliciousCount = values.filter(d => d.ipReputation === 'malicious').length;
    const suspiciousCount = values.filter(d => d.ipReputation === 'suspicious').length;
    const cleanCount = values.filter(d => d.ipReputation === 'clean').length;
    const threatTypesCount = values.reduce((sum, d) => sum + (d.threatTypes ? d.threatTypes.length : 0), 0);
    
    console.log('Enrichment Summary Debug - Calculated Values:', {
      totalEnrichmentData: enrichmentData.size,
      enrichmentDataValues: values,
      maliciousCount,
      suspiciousCount,
      cleanCount,
      threatTypesCount,
      reputationBreakdown: values.map(d => d.ipReputation),
      threatTypesBreakdown: values.map(d => d.threatTypes)
    });
    
    return { maliciousCount, suspiciousCount, cleanCount, threatTypesCount };
  }, [enrichmentData]);

  // Shared palette for the Alerts analytics charts. Mirrors the
  // severityBadgeColor map where possible so the bar chart and the
  // row badges tell the same story at a glance.
  const ALERTS_CHART_PALETTE = {
    // Severity (semantic)
    critical: '#E11D48', // rose-600
    high:     '#F97316', // orange-500
    medium:   '#F59E0B', // amber-500
    low:      '#10B981', // emerald-500
    info:     '#8B5CF6', // violet-500
    // Brand ramp (taxonomical)
    violet:   '#8B5CF6',
    fuchsia:  '#D946EF',
    pink:     '#EC4899',
    rose:     '#F43F5E',
    amber:    '#F59E0B',
    emerald:  '#10B981',
    slate:    '#94A3B8', // slate-400, for the "Closed" / neutral lanes
  } as const;

  // Six-colour rotation used for the Type chart. Every type gets a
  // slot via `i % TYPE_RAMP.length` rather than a unique colour, which
  // keeps the surface tidy when 20+ types are present.
  const TYPE_RAMP = [
    ALERTS_CHART_PALETTE.violet,
    ALERTS_CHART_PALETTE.fuchsia,
    ALERTS_CHART_PALETTE.pink,
    ALERTS_CHART_PALETTE.rose,
    ALERTS_CHART_PALETTE.amber,
    ALERTS_CHART_PALETTE.emerald,
  ];

  // Chart data preparation
  const severityChartData = useMemo(() => ({
    labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
    datasets: [{
      label: 'Alert Count',
      data: [
        alerts.filter(a => a.severity === 'CRITICAL').length,
        alerts.filter(a => a.severity === 'HIGH').length,
        alerts.filter(a => a.severity === 'MEDIUM').length,
        alerts.filter(a => a.severity === 'LOW').length,
        alerts.filter(a => a.severity === 'INFO').length,
      ],
      backgroundColor: [
        ALERTS_CHART_PALETTE.critical,
        ALERTS_CHART_PALETTE.high,
        ALERTS_CHART_PALETTE.medium,
        ALERTS_CHART_PALETTE.low,
        ALERTS_CHART_PALETTE.info,
      ],
      borderRadius: 6,
      borderSkipped: false as const,
      maxBarThickness: 28,
    }],
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [alerts]);

  const typeChartData = useMemo(() => ({
    labels: ['ANOMALY', 'IOA', 'HONEYPOT', 'THREAT_INTELLIGENCE', 'INTRUSION_DETECTION', 'PORT_SCAN', 'BRUTE_FORCE', 'DDoS_ATTACK', 'MALWARE_DETECTION', 'PHISHING_ATTACK', 'SQL_INJECTION', 'XSS_ATTACK', 'CSRF_ATTACK', 'PATH_TRAVERSAL', 'COMMAND_INJECTION', 'FAILED_LOGIN', 'UNAUTHORIZED_ACCESS', 'PRIVILEGE_ESCALATION', 'ACCOUNT_LOCKOUT', 'SUSPICIOUS_LOGIN', 'FILE_INTEGRITY', 'PROCESS_MONITORING', 'REGISTRY_CHANGE', 'SERVICE_CHANGE', 'HONEYPOT_TRIGGER', 'HONEYPOT_INTERACTION', 'HONEYPOT_EXPLOIT', 'COMPLIANCE_VIOLATION', 'DATA_LEAKAGE', 'ANOMALY_DETECTION', 'CUSTOM_RULE'],
    datasets: [{
      label: 'Alert Count',
      data: [
        alerts.filter(a => a.type === 'ANOMALY').length,
        alerts.filter(a => a.type === 'IOA').length,
        alerts.filter(a => a.type === 'HONEYPOT').length,
        alerts.filter(a => a.type === 'THREAT_INTELLIGENCE').length,
        alerts.filter(a => a.type === 'INTRUSION_DETECTION').length,
        alerts.filter(a => a.type === 'PORT_SCAN').length,
        alerts.filter(a => a.type === 'BRUTE_FORCE').length,
        alerts.filter(a => a.type === 'DDoS_ATTACK').length,
        alerts.filter(a => a.type === 'MALWARE_DETECTION').length,
        alerts.filter(a => a.type === 'PHISHING_ATTACK').length,
        alerts.filter(a => a.type === 'SQL_INJECTION').length,
        alerts.filter(a => a.type === 'XSS_ATTACK').length,
        alerts.filter(a => a.type === 'CSRF_ATTACK').length,
        alerts.filter(a => a.type === 'PATH_TRAVERSAL').length,
        alerts.filter(a => a.type === 'COMMAND_INJECTION').length,
        alerts.filter(a => a.type === 'FAILED_LOGIN').length,
        alerts.filter(a => a.type === 'UNAUTHORIZED_ACCESS').length,
        alerts.filter(a => a.type === 'PRIVILEGE_ESCALATION').length,
        alerts.filter(a => a.type === 'ACCOUNT_LOCKOUT').length,
        alerts.filter(a => a.type === 'SUSPICIOUS_LOGIN').length,
        alerts.filter(a => a.type === 'FILE_INTEGRITY').length,
        alerts.filter(a => a.type === 'PROCESS_MONITORING').length,
        alerts.filter(a => a.type === 'REGISTRY_CHANGE').length,
        alerts.filter(a => a.type === 'SERVICE_CHANGE').length,
        alerts.filter(a => a.type === 'HONEYPOT_TRIGGER').length,
        alerts.filter(a => a.type === 'HONEYPOT_INTERACTION').length,
        alerts.filter(a => a.type === 'HONEYPOT_EXPLOIT').length,
        alerts.filter(a => a.type === 'COMPLIANCE_VIOLATION').length,
        alerts.filter(a => a.type === 'DATA_LEAKAGE').length,
        alerts.filter(a => a.type === 'ANOMALY_DETECTION').length,
        alerts.filter(a => a.type === 'CUSTOM_RULE').length,
      ],
      // Thirty-one alert types rotated through the six-colour brand
      // ramp. Previously this had a full "indigo → pure black" gradient
      // with pastel greys that made the chart unreadable; a modulo
      // rotation is both tidier and keeps the same colour for the same
      // type across reloads (order is stable).
      backgroundColor: Array.from({ length: 31 }, (_, i) => TYPE_RAMP[i % TYPE_RAMP.length]),
      borderColor: '#FFFFFF',
      borderWidth: 2,
      hoverOffset: 6,
    }],
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [alerts]);

  const statusChartData = useMemo(() => ({
    labels: ['NEW', 'ACKNOWLEDGED', 'IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE'],
    datasets: [{
      label: 'Alert Count',
      data: [
        alerts.filter(a => a.status === 'NEW').length,
        alerts.filter(a => a.status === 'ACKNOWLEDGED').length,
        alerts.filter(a => a.status === 'IN_PROGRESS').length,
        alerts.filter(a => a.status === 'ESCALATED').length,
        alerts.filter(a => a.status === 'RESOLVED').length,
        alerts.filter(a => a.status === 'CLOSED').length,
        alerts.filter(a => a.status === 'FALSE_POSITIVE').length,
      ],
      // Mirrors statusBadgeColor so the same status means the same
      // colour in the table badge and in the chart.
      backgroundColor: [
        ALERTS_CHART_PALETTE.rose,     // NEW (open/unhandled)
        ALERTS_CHART_PALETTE.violet,   // ACKNOWLEDGED
        ALERTS_CHART_PALETTE.fuchsia,  // IN_PROGRESS
        ALERTS_CHART_PALETTE.high,     // ESCALATED (orange)
        ALERTS_CHART_PALETTE.emerald,  // RESOLVED
        ALERTS_CHART_PALETTE.slate,    // CLOSED
        ALERTS_CHART_PALETTE.slate,    // FALSE_POSITIVE
      ],
      borderRadius: 6,
      borderSkipped: false as const,
      maxBarThickness: 28,
    }],
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [alerts]);

  // Alert Trend Chart Data
  const trendChartData = useMemo(() => {
    // Group alerts by hour for the last 24 hours
    const hours = Array.from({ length: 24 }, (_, i) => {
      const date = new Date();
      date.setHours(date.getHours() - (23 - i));
      return date.toLocaleTimeString('en-US', { hour: '2-digit', hour12: false });
    });

    const alertCounts = hours.map(hour => {
      const hourNum = parseInt(hour);
      const count = alerts.filter(alert => {
        const alertHour = new Date(alert.timestamp).getHours();
        return alertHour === hourNum;
      }).length;
      return count;
    });

    return {
      labels: hours,
      datasets: [
        {
          label: 'Alerts per Hour',
          data: alertCounts,
          borderColor: ALERTS_CHART_PALETTE.violet,
          backgroundColor: 'rgba(139, 92, 246, 0.15)',
          borderWidth: 3,
          fill: true,
          tension: 0.4,
          pointBackgroundColor: ALERTS_CHART_PALETTE.fuchsia,
          pointBorderColor: '#fff',
          pointBorderWidth: 2,
          pointRadius: 5,
          pointHoverRadius: 7,
        }
      ]
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alerts]);


  const [sortConfig, setSortConfig] = useState<{
    key: keyof Alert;
    direction: 'asc' | 'desc';
  } | null>(null);

  // Handlers to change sort and derive filtered/sorted list
  const requestSort = (key: keyof Alert) => {
    let direction: 'asc' | 'desc' = 'asc';
    if (sortConfig?.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  const filteredAlerts = useMemo(() => {
    if (!Array.isArray(alerts)) return [];
    
    let filtered = alerts;
    
    // Search filter
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(alert => 
        alert.title?.toLowerCase().includes(query) ||
        alert.source?.toLowerCase().includes(query) ||
        alert.description?.toLowerCase().includes(query) ||
        alert.sourceIp?.toLowerCase().includes(query) ||
        alert.destinationIp?.toLowerCase().includes(query) ||
        alert.type?.toLowerCase().includes(query) ||
        alert.severity?.toLowerCase().includes(query) ||
        alert.status?.toLowerCase().includes(query)
      );
    }
    
    // Existing filters
    filtered = filtered.filter(a =>
      (!filters.severity || a.severity === filters.severity) &&
      (!filters.type     || a.type     === filters.type)     &&
      (!filters.status   || a.status   === filters.status)
    );
    
    console.log('FilteredAlerts: Original alerts count:', alerts.length);
    console.log('FilteredAlerts: Search query:', searchQuery);
    console.log('FilteredAlerts: Filters applied:', filters);
    console.log('FilteredAlerts: Filtered alerts count:', filtered.length);
    return filtered;
  }, [alerts, searchQuery, filters]);

  const sortedAlerts = useMemo(() => {
    if (!Array.isArray(filteredAlerts)) return [];
    if (!sortConfig) {
      console.log('SortedAlerts: No sort config, returning filtered alerts:', filteredAlerts.length);
      return filteredAlerts;
    }
    const sorted = [...filteredAlerts].sort((a, b) => {
      const aRaw = a[sortConfig.key];
      const bRaw = b[sortConfig.key];
      // coerce undefined → empty string, then compare as strings
      const aVal = aRaw != null ? String(aRaw) : '';
      const bVal = bRaw != null ? String(bRaw) : '';
      if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1;
      return 0;
    });
    console.log('SortedAlerts: Sorted alerts count:', sorted.length);
    console.log('SortedAlerts: Sort config:', sortConfig);
    return sorted;
  }, [filteredAlerts, sortConfig]);

  // Pagination state and derived page
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(20);
  const paginatedAlerts = useMemo(() => {
    if (!Array.isArray(filteredAlerts)) return [];
    const start = (currentPage - 1) * pageSize;
    return filteredAlerts.slice(start, start + pageSize);
  }, [filteredAlerts, currentPage, pageSize]);
  const totalPages = Math.max(1, Math.ceil((Array.isArray(filteredAlerts) ? filteredAlerts.length : 0) / pageSize));

  // Fetch alerts (and fire Slack webhook for new Critical alerts on backend)
  const fetchAlerts = async () => {
    setLoading(true);
    try {
      // Try to fetch from backend, but don't fail if endpoint doesn't exist
      let backendAlerts: any[] = [];
      try {
        console.log('FetchAlerts: Attempting to fetch from /api/alerts...');
        const backendResponse = await api.get('/api/alerts');
        console.log('FetchAlerts: Backend response received:', backendResponse);
        console.log('FetchAlerts: Response status:', backendResponse.status);
        console.log('FetchAlerts: Response data:', backendResponse.data);
        console.log('FetchAlerts: Response data type:', typeof backendResponse.data);
        console.log('FetchAlerts: Response data keys:', Object.keys(backendResponse.data || {}));
        
        // Handle both paginated and non-paginated responses
        if (backendResponse.data && backendResponse.data.content) {
          // Paginated response
          console.log('FetchAlerts: Detected paginated response');
          backendAlerts = backendResponse.data.content;
          console.log('FetchAlerts: Extracted content from paginated response:', backendAlerts);
        } else if (Array.isArray(backendResponse.data)) {
          // Direct array response
          console.log('FetchAlerts: Detected direct array response');
          backendAlerts = backendResponse.data;
          console.log('FetchAlerts: Using direct array response:', backendAlerts);
        } else {
          console.log('FetchAlerts: No valid data structure found, setting empty array');
          backendAlerts = [];
        }
        
        console.log('FetchAlerts: Final backendAlerts array:', backendAlerts);
        console.log('FetchAlerts: BackendAlerts length:', backendAlerts.length);
      } catch (backendError) {
        console.error('FetchAlerts: Backend error details:', backendError);
        console.log('FetchAlerts: Backend endpoint not available, using only IOA alerts');
        // Don't set error for backend unavailability
      }

      // Get IOA alerts from localStorage
      const ioaAlertsJson = localStorage.getItem('ioas');
      const ioaAlerts = ioaAlertsJson ? JSON.parse(ioaAlertsJson) : [];
      console.log('FetchAlerts: IOAs from localStorage:', ioaAlerts);

      // Create IOA alerts with proper structure for Alert interface
      const ioaAlertsFormatted = ioaAlerts.map((ioa: any) => ({
        id: `ioa-${ioa.timestamp}-${ioa.sourceIp}-${ioa.type}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        title: ioa.type || 'IOA Alert',
        timestamp: ioa.timestamp || new Date().toISOString(),
        source: `${ioa.sourceIp || 'Unknown'} → ${ioa.destinationIp || 'Unknown'}`,
        type: 'IOA' as const,
        severity: (ioa.severity || 'MEDIUM').toUpperCase() as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
        description: ioa.description || `IOA detected: ${ioa.type}`,
        status: 'NEW' as const,
        sourceIp: ioa.sourceIp,
        destinationIp: ioa.destinationIp,
        protocol: ioa.protocol || 'Unknown',
        createdAt: ioa.timestamp || new Date().toISOString(),
        updatedAt: ioa.timestamp || new Date().toISOString()
      }));
      console.log('FetchAlerts: IOA alerts created:', ioaAlertsFormatted);

      // Combine backend and IOA alerts
      const combinedAlerts = [...backendAlerts, ...ioaAlertsFormatted];
      console.log('FetchAlerts: Final combined alerts:', combinedAlerts);
      console.log('FetchAlerts: Combined alerts length:', combinedAlerts.length);

      setAlerts(combinedAlerts);
      setError('');
    } catch (error) {
      console.error('Error fetching alerts:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      setError(`Failed to fetch alerts: ${errorMessage}`);
    } finally {
      setLoading(false);
      setLastRefreshedAt(new Date());
    }
  };

  // --------------------------------------------------------------------
  // Auto-refresh: re-fetch every 30s while the toggle is on. Kept quiet
  // (no loading spinner) by calling the same fetcher - it does its own
  // state swap. Deliberately only re-runs when autoRefresh toggles so we
  // don't reset the interval on every unrelated render.
  // --------------------------------------------------------------------
  useEffect(() => {
    if (!autoRefresh) return;
    const h = window.setInterval(() => { void fetchAlerts(); }, 30_000);
    return () => window.clearInterval(h);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoRefresh]);

  // --------------------------------------------------------------------
  // Quick per-row action: "Assign to me" — stamps the current user onto
  // assignedTo and tries to persist via the standard assign endpoint.
  // Falls back to optimistic local state if the backend isn't wired.
  // --------------------------------------------------------------------
  const handleAssignToMe = async (alertId: string) => {
    const me = currentUserName;
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, assignedTo: me, assignedBy: me } : a));
    try {
      await api.post(`/api/alerts/${alertId}/assign`, { assignedTo: me });
    } catch {
      // Backend may not implement this yet; optimistic update stays.
    }
  };

  /**
   * Compute MTTA / MTTR over the currently-loaded alerts. Memoised on
   * the alerts list so we're not recomputing on every keystroke in the
   * search bar.
   */
  const { mtta, mttr } = useMemo(() => {
    const a = meanDurationMs(alerts, x => x.createdAt ?? x.timestamp, x => x.acknowledgedAt);
    const r = meanDurationMs(alerts, x => x.createdAt ?? x.timestamp, x => x.resolvedAt);
    return { mtta: a, mttr: r };
  }, [alerts]);

  // Handle alert actions (acknowledge, snooze, resolve)
  const handleAction = async (
    id: string,
    action: 'acknowledge' | 'snooze' | 'resolve'
  ) => {
    try {
      // Update local state immediately for better UX
      setAlerts(prevAlerts => 
        prevAlerts.map(alert => 
          alert.id === id 
            ? { ...alert, status: action === 'acknowledge' ? 'ACKNOWLEDGED' : action === 'snooze' ? 'IN_PROGRESS' : 'RESOLVED' }
            : alert
        )
      );

      // Try to send to backend, but don't fail if endpoint doesn't exist
      try {
        await api.post(`/api/alerts/${id}/${action}`);
      } catch (backendError) {
        console.log(`Backend endpoint not available for ${action}, keeping local state change`);
        // Keep the local state change even if backend fails
      }
    } catch (error) {
      console.error(`Error ${action}ing alert:`, error);
      // Revert local state on error
      fetchAlerts();
    }
  };

  // Bulk action functions
  const handleBulkAction = async (action: 'acknowledge' | 'snooze' | 'resolve') => {
    try {
      // Update local state immediately for better UX
      setAlerts(prevAlerts => 
        prevAlerts.map(alert => 
          selectedAlerts.includes(alert.id)
            ? { ...alert, status: action === 'acknowledge' ? 'ACKNOWLEDGED' : action === 'snooze' ? 'IN_PROGRESS' : 'RESOLVED' }
            : alert
        )
      );

      // Try to send to backend for each selected alert
      for (const alertId of selectedAlerts) {
        try {
          await api.post(`/api/alerts/${alertId}/${action}`);
        } catch (backendError) {
          console.log(`Backend endpoint not available for ${action}, keeping local state change`);
        }
      }

      // Clear selection after bulk action
      setSelectedAlerts([]);
    } catch (error) {
      console.error(`Error performing bulk ${action}:`, error);
      fetchAlerts(); // Revert on error
    }
  };

  const handleSelectAll = () => {
    if (selectedAlerts.length === filteredAlerts.length) {
      setSelectedAlerts([]); // Deselect all
    } else {
      setSelectedAlerts(filteredAlerts.map(alert => alert.id)); // Select all
    }
  };

  const handleSelectAlert = (alertId: string) => {
    setSelectedAlerts(prev => 
      prev.includes(alertId) 
        ? prev.filter(id => id !== alertId)
        : [...prev, alertId]
    );
  };

  // Correlation logic functions
  const generateCorrelationGroups = useMemo(() => {
    if (!Array.isArray(filteredAlerts) || filteredAlerts.length === 0) return [];
    
    const groups: Array<{
      id: string;
      name: string;
      alerts: Alert[];
      pattern: string;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
      count: number;
    }> = [];
    
    // Group by source IP (attack source)
    const sourceIPGroups = new Map<string, Alert[]>();
    filteredAlerts.forEach(alert => {
      if (alert.sourceIp) {
        const key = alert.sourceIp;
        if (!sourceIPGroups.has(key)) {
          sourceIPGroups.set(key, []);
        }
        sourceIPGroups.get(key)!.push(alert);
      }
    });
    
    // Create groups for IPs with multiple alerts
    sourceIPGroups.forEach((alerts, sourceIP) => {
      if (alerts.length > 1) {
        const highestSeverity = alerts.reduce((highest, alert) => {
          const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
          return severityOrder[alert.severity] > severityOrder[highest] ? alert.severity : highest;
        }, alerts[0].severity);
        
        groups.push({
          id: `ip-${sourceIP}`,
          name: `Attack from ${sourceIP}`,
          alerts,
          pattern: 'Multiple alerts from same source IP',
          severity: highestSeverity,
          count: alerts.length
        });
      }
    });
    
    // Group by alert type (attack pattern)
    const typeGroups = new Map<string, Alert[]>();
    filteredAlerts.forEach(alert => {
      const key = alert.type;
      if (!typeGroups.has(key)) {
        typeGroups.set(key, []);
      }
      typeGroups.get(key)!.push(alert);
    });
    
    // Create groups for types with multiple alerts
    typeGroups.forEach((alerts, alertType) => {
      if (alerts.length > 1) {
        const highestSeverity = alerts.reduce((highest, alert) => {
          const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
          return severityOrder[alert.severity] > severityOrder[highest] ? alert.severity : highest;
        }, alerts[0].severity);
        
        groups.push({
          id: `type-${alertType}`,
          name: `${alertType} Attack Pattern`,
          alerts,
          pattern: `Multiple ${alertType} alerts detected`,
          severity: highestSeverity,
          count: alerts.length
        });
      }
    });
    
    // Group by time proximity (within 5 minutes)
    const timeGroups: Alert[][] = [];
    const processedAlerts = new Set<string>();
    
    filteredAlerts.forEach(alert => {
      if (processedAlerts.has(alert.id)) return;
      
      const alertTime = new Date(alert.timestamp).getTime();
      const relatedAlerts = [alert];
      processedAlerts.add(alert.id);
      
      filteredAlerts.forEach(otherAlert => {
        if (processedAlerts.has(otherAlert.id)) return;
        
        const otherTime = new Date(otherAlert.timestamp).getTime();
        const timeDiff = Math.abs(alertTime - otherTime);
        
        if (timeDiff <= 5 * 60 * 1000) { // 5 minutes
          relatedAlerts.push(otherAlert);
          processedAlerts.add(otherAlert.id);
        }
      });
      
      if (relatedAlerts.length > 1) {
        const highestSeverity = relatedAlerts.reduce((highest, alert) => {
          const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
          return severityOrder[alert.severity] > severityOrder[highest] ? alert.severity : highest;
        }, relatedAlerts[0].severity);
        
        timeGroups.push(relatedAlerts);
        groups.push({
          id: `time-${Date.now()}-${Math.random()}`,
          name: `Time-based Correlation`,
          alerts: relatedAlerts,
          pattern: 'Alerts detected within 5 minutes',
          severity: highestSeverity,
          count: relatedAlerts.length
        });
      }
    });
    
    // Sort groups by severity and count
    return groups.sort((a, b) => {
      const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
      if (severityOrder[a.severity] !== severityOrder[b.severity]) {
        return severityOrder[b.severity] - severityOrder[a.severity];
      }
      return b.count - a.count;
    });
  }, [filteredAlerts]);

  const handleCorrelationViewToggle = () => {
    setCorrelationView(prev => prev === 'list' ? 'groups' : 'list');
    if (correlationView === 'list') {
      setCorrelationGroups(generateCorrelationGroups);
    }
  };

  // Enrichment functions
  const enrichIPAddress = async (ip: string): Promise<any> => {
    try {
      console.log(`Starting enrichment for IP: ${ip}`);
      
      // Try to get data from multiple threat intelligence sources
      const enrichmentPromises = [
        // VirusTotal API (if available)
        fetchVirusTotalData(ip),
        // AbuseIPDB API (if available)
        fetchAbuseIPDBData(ip),
        // IP Geolocation API
        fetchIPGeolocationData(ip),
        // Local threat intelligence database
        fetchLocalThreatData(ip)
      ];
      
      const results = await Promise.allSettled(enrichmentPromises);
      console.log(`Enrichment results for ${ip}:`, results);
      
      // Combine results from all sources
      const combinedData = combineEnrichmentResults(results, ip);
      console.log(`Combined enrichment data for ${ip}:`, combinedData);
      
      return combinedData;
    } catch (error) {
      console.error(`Error enriching IP ${ip}:`, error);
      // Return fallback data if enrichment fails
      return getFallbackEnrichmentData(ip);
    }
  };

  // Fetch data from VirusTotal (if API key is available)
  const fetchVirusTotalData = async (ip: string): Promise<any> => {
    try {
      // Use the provided VirusTotal API key
      const vtApiKey = 'e9c2425e877cb358c9dc9af113af07d3bb5f44e17eb662c4675705a529f01f3e';
      console.log('Using VirusTotal API key for enrichment...');
      
      // Try multiple CORS proxy approaches with better error handling
      const proxyServices = [
        { name: 'api.codetabs.com', url: `https://api.codetabs.com/v1/proxy?quest=https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=${vtApiKey}&ip=${ip}` },
        { name: 'cors.bridged.cc', url: `https://cors.bridged.cc/https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=${vtApiKey}&ip=${ip}` },
        { name: 'thingproxy.freeboard.io', url: `https://thingproxy.freeboard.io/fetch/https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=${vtApiKey}&ip=${ip}` }
      ];
      
      for (const service of proxyServices) {
        try {
          console.log(`Trying VirusTotal via proxy: ${service.name}`);
          
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000); // Reduced to 5 second timeout
          
          const response = await fetch(service.url, {
            method: 'GET',
            headers: {
              'Accept': 'application/json',
              'Origin': window.location.origin
            },
            signal: controller.signal
          });
          
          clearTimeout(timeoutId);
          
          if (!response.ok) {
            throw new Error(`VirusTotal API error: ${response.status}`);
          }
          
          const data = await response.json();
          console.log(`VirusTotal data for ${ip}:`, data);
          
          // Validate the response data
          if (data.response_code === -1 || data.verbose_msg?.includes('Invalid IP')) {
            console.log(`⚠️ VirusTotal returned invalid IP response for ${ip}:`, data);
            return null; // Return null for invalid IPs instead of invalid data
          }
          
          // Ensure positives and total are valid numbers
          const positives = typeof data.positives === 'number' && !isNaN(data.positives) ? data.positives : 0;
          const total = typeof data.total === 'number' && !isNaN(data.total) && data.total > 0 ? data.total : 0;
          
          console.log(`✅ VirusTotal validated data for ${ip}: positives=${positives}, total=${total}`);
          
          return {
            source: 'VirusTotal',
            positives: positives,
            total: total,
            categories: data.categories || {},
            country: data.country,
            as_owner: data.as_owner,
            last_analysis_stats: data.last_analysis_stats || {}
          };
          
        } catch (proxyError) {
          console.log(`VirusTotal proxy failed (${service.name}):`, proxyError);
          // Continue to next proxy or fallback
        }
      }
      
      // If all proxies failed, use development fallback immediately
      console.log(`All VirusTotal proxies failed for ${ip}, using development fallback`);
      const devFallback = getDevelopmentThreatData(ip, 'VirusTotal');
      if (devFallback) {
        return devFallback;
      }
      
      return null;
      
    } catch (error) {
      console.log(`VirusTotal enrichment failed for ${ip}:`, error);
      
      // Final fallback to development data
      const devFallback = getDevelopmentThreatData(ip, 'VirusTotal');
      if (devFallback) {
        console.log(`Using VirusTotal development fallback for ${ip} (catch block)`);
        return devFallback;
      }
      
      return null;
    }
  };

  // Fetch data from AbuseIPDB (if API key is available)
  const fetchAbuseIPDBData = async (ip: string): Promise<any> => {
    try {
      // Use the provided AbuseIPDB API key
      const abuseApiKey = '8aa783529bc103a5ba3e395e97bf25c01c952f19f7fce1ce51832cf89333735f39c147f3e1e0abdc';
      console.log('Using AbuseIPDB API key for enrichment...');
      
      // Try multiple CORS proxy approaches with better error handling
      const proxyServices = [
        { name: 'api.codetabs.com', url: `https://api.codetabs.com/v1/proxy?quest=https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}` },
        { name: 'cors.bridged.cc', url: `https://cors.bridged.cc/https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}` },
        { name: 'thingproxy.freeboard.io', url: `https://thingproxy.freeboard.io/fetch/https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}` }
      ];
      
      for (const service of proxyServices) {
        try {
          console.log(`Trying AbuseIPDB via proxy: ${service.name}`);
          
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000); // Reduced to 5 second timeout
          
          const response = await fetch(service.url, {
            method: 'GET',
            headers: {
              'Key': abuseApiKey,
              'Accept': 'application/json',
              'Origin': window.location.origin
            },
            signal: controller.signal
          });
          
          clearTimeout(timeoutId);
          
          if (!response.ok) {
            throw new Error(`AbuseIPDB API error: ${response.status}`);
          }
          
          const data = await response.json();
          console.log(`AbuseIPDB data for ${ip}:`, data);
          console.log(`AbuseIPDB data structure for ${ip}:`, {
            hasData: !!data.data,
            dataKeys: data.data ? Object.keys(data.data) : [],
            countryCode: data.data?.countryCode,
            countryName: data.data?.countryName,
            city: data.data?.city,
            isp: data.data?.isp,
            abuseConfidenceScore: data.data?.abuseConfidenceScore
          });
          
          // Validate the response data
          if (!data.data || typeof data.data.abuseConfidenceScore !== 'number') {
            console.log(`⚠️ AbuseIPDB returned invalid data for ${ip}:`, data);
            return null; // Return null for invalid data
          }
          
          // Ensure abuseConfidenceScore is a valid number
          const abuseConfidenceScore = typeof data.data.abuseConfidenceScore === 'number' && !isNaN(data.data.abuseConfidenceScore) 
            ? data.data.abuseConfidenceScore 
            : 0;
          
          console.log(`✅ AbuseIPDB validated data for ${ip}: abuseConfidenceScore=${abuseConfidenceScore}`);
          
          return {
            source: 'AbuseIPDB',
            abuseConfidenceScore: abuseConfidenceScore,
            countryCode: data.data.countryCode,
            countryName: data.data.countryName,
            isp: data.data.isp,
            domain: data.data.domain,
            totalReports: data.data.totalReports || 0,
            numDistinctUsers: data.data.numDistinctUsers || 0,
            lastReportedAt: data.data.lastReportedAt
          };
          
        } catch (proxyError) {
          console.log(`AbuseIPDB proxy failed (${service.name}):`, proxyError);
          // Continue to next proxy or fallback
        }
      }
      
      // If all proxies failed, use development fallback immediately
      console.log(`All AbuseIPDB proxies failed for ${ip}, using development fallback`);
      const devFallback = getDevelopmentThreatData(ip, 'AbuseIPDB');
      if (devFallback) {
        return devFallback;
      }
      
      return null;
      
    } catch (error) {
      console.log(`AbuseIPDB enrichment failed for ${ip}:`, error);
      
      // Try development fallback as last resort
      const devFallback = getDevelopmentThreatData(ip, 'AbuseIPDB');
      if (devFallback) {
        console.log(`Using AbuseIPDB development fallback for ${ip} (catch block)`);
        return devFallback;
      }
      
      return null;
    }
  };

  // Fetch IP geolocation data
  const fetchIPGeolocationData = async (ip: string): Promise<any> => {
    try {
      // Add delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 100));
      
      console.log(`Fetching geolocation data for IP: ${ip}`);
      
      // Check if this is a private IP that shouldn't be geolocated
      if (ip.startsWith('192.168.') || ip.startsWith('10.') || 
          (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31) ||
          ip === '127.0.0.1' || ip === '::1') {
        console.log(`Skipping geolocation for private/local IP: ${ip}`);
        return {
          source: 'IP Geolocation (Skipped)',
          country: getCountryFromIP(ip),
          countryName: getCountryFromIP(ip),
          region: 'N/A',
          city: 'N/A',
          latitude: null,
          longitude: null,
          timezone: 'N/A',
          org: 'N/A',
          asn: 'N/A',
          note: 'Private IP - geolocation not applicable'
        };
      }

      // Try multiple geolocation services with CORS handling
      const geolocationServices = [
        { name: 'api.codetabs.com + ipapi.co', url: `https://api.codetabs.com/v1/proxy?quest=https://ipapi.co/${ip}/json/` },
        { name: 'cors.bridged.cc + ipapi.co', url: `https://cors.bridged.cc/https://ipapi.co/${ip}/json/` },
        { name: 'thingproxy + ipapi.co', url: `https://thingproxy.freeboard.io/fetch/https://ipapi.co/${ip}/json/` },
        { name: 'api.codetabs.com + ip-api.com', url: `https://api.codetabs.com/v1/proxy?quest=https://ip-api.com/json/${ip}` },
        { name: 'cors.bridged.cc + ip-api.com', url: `https://cors.bridged.cc/https://ip-api.com/json/${ip}` },
        { name: 'thingproxy + ip-api.com', url: `https://thingproxy.freeboard.io/fetch/https://ip-api.com/json/${ip}` }
      ];


      
      for (const service of geolocationServices) {
        try {
          console.log(`Trying geolocation service: ${service.name}`);
          
          // Create an AbortController for timeout handling
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 3000); // Reduced to 3 second timeout
          
          const response = await fetch(service.url, {
            method: 'GET',
            headers: {
              'Accept': 'application/json',
              'Origin': window.location.origin
            },
            signal: controller.signal
          });
          
          clearTimeout(timeoutId);
          
          if (!response.ok) {
            throw new Error(`Geolocation API error: ${response.status} - ${response.statusText}`);
          }
          
          const data = await response.json();
          console.log(`IP Geolocation data for ${ip}:`, data);
          
          // Handle different API response formats
          let processedData: any = {};
          
          if (data.country_code || data.countryCode) {
            // ipapi.co format
            processedData = {
              source: 'IP Geolocation (ipapi.co)',
              country: data.country_code || data.countryCode,
              countryName: data.country_name || data.country,
              region: data.region || data.regionName,
              city: data.city,
              latitude: data.latitude || data.lat,
              longitude: data.longitude || data.lon,
              timezone: data.timezone,
              org: data.org || data.isp,
              asn: data.asn
            };
          } else if (data.country) {
            // ip-api.com format
            processedData = {
              source: 'IP Geolocation (ip-api.com)',
              country: data.countryCode,
              countryName: data.country,
              region: data.regionName,
              city: data.city,
              latitude: data.lat,
              longitude: data.lon,
              timezone: data.timezone,
              org: data.isp,
              asn: data.as
            };
          } else if (data.country_name) {
            // freegeoip.app format
            processedData = {
              source: 'IP Geolocation (freegeoip.app)',
              country: data.country_code,
              countryName: data.country_name,
              region: data.region_name,
              city: data.city,
              latitude: data.latitude,
              longitude: data.longitude,
              timezone: data.timezone,
              org: data.organization,
              asn: null
            };
          } else if (data.origin) {
            // httpbin.org fallback (development workaround)
            console.log(`Using httpbin.org fallback for ${ip}: ${data.origin}`);
            processedData = {
              source: 'IP Geolocation (Development Fallback)',
              country: 'Development',
              countryName: 'Development Environment',
              region: 'Local Development',
              city: 'Local Development',
              latitude: null,
              longitude: null,
              timezone: 'UTC',
              org: 'Development Network',
              asn: null,
              note: 'Using development fallback - real geolocation unavailable'
            };
          }
          
          // Check if we got valid location data
          if (!processedData.country || processedData.country === 'XX') {
            throw new Error('Invalid location data received');
          }
          
          // Validate that we have meaningful location data
          if (!processedData.city || processedData.city === 'Unknown' || processedData.city === '') {
            console.warn(`Missing city data for ${ip}:`, processedData);
          }
          
          if (!processedData.countryName || processedData.countryName === 'Unknown' || processedData.countryName === '') {
            console.warn(`Missing country name for ${ip}:`, processedData);
          }
          
          return processedData;
          
        } catch (serviceError) {
          console.log(`Geolocation service failed: ${service.name}`, serviceError);
          
          // Handle specific error types
          const error = serviceError as Error;
          if (error.name === 'AbortError') {
            console.log(`Service timed out: ${service.name}`);
          } else if (error.message.includes('Failed to fetch')) {
            console.log(`Network error (connection timeout/refused): ${service.name}`);
          } else if (error.message.includes('CORS')) {
            console.log(`CORS error: ${service.name}`);
          }
          
          continue; // Try next service
        }
      }
      
      // If all services failed, try development fallback
      const devFallback = getDevelopmentFallbackData(ip);
      if (devFallback) {
        console.log(`Using development fallback for ${ip}`);
        return devFallback;
      }
      
      // Return basic location data based on IP type for public IPs that failed
      return {
        source: 'IP Geolocation (Fallback)',
        country: getCountryFromIP(ip),
        countryName: getCountryFromIP(ip),
        region: 'Unknown',
        city: 'Unknown',
        latitude: null,
        longitude: null,
        timezone: 'UTC',
        org: 'Unknown',
        asn: 'Unknown',
        note: 'Geolocation failed for public IP - CORS or service unavailable'
      };
      
    } catch (error) {
      console.log(`IP Geolocation enrichment failed for ${ip}:`, error);
      
      // Try to get development fallback data as last resort
      const devFallback = getDevelopmentFallbackData(ip);
      if (devFallback) {
        console.log(`Using development fallback for ${ip} (catch block)`);
        return devFallback;
      }
      
      // Return basic location data based on IP type for public IPs that failed
      return {
        source: 'IP Geolocation (Fallback)',
        country: getCountryFromIP(ip),
        countryName: getCountryFromIP(ip),
        region: 'Unknown',
        city: 'Unknown',
        latitude: null,
        longitude: null,
        timezone: 'UTC',
        org: 'Unknown',
        asn: 'Unknown',
        note: 'Geolocation failed for public IP - CORS or service unavailable'
      };
    }
  };

  // Helper function to determine country from IP address
  const getCountryFromIP = (ip: string): string => {
    // Private IP ranges (RFC 1918)
    if (ip.startsWith('10.') || 
        ip.startsWith('192.168.') || 
        (ip.startsWith('172.') && 
         parseInt(ip.split('.')[1]) >= 16 && 
         parseInt(ip.split('.')[1]) <= 31)) {
      return 'Private Network';
    }
    
    // Localhost
    if (ip === '127.0.0.1' || ip === '::1') {
      return 'Localhost';
    }
    
    // Common public DNS servers and well-known public IPs
    if (ip === '8.8.8.8' || ip === '8.8.4.4') {
      return 'US'; // Google DNS
    }
    if (ip === '1.1.1.1' || ip === '1.0.0.1') {
      return 'US'; // Cloudflare DNS
    }
    if (ip === '208.67.222.222' || ip === '208.67.220.220') {
      return 'US'; // OpenDNS
    }
    
    // If it's not in any of the above categories, it's likely a public IP
    // that just failed geolocation, so we should indicate it needs geolocation
    return 'Public IP (Geolocation Failed)';
  };

  // Fetch data from local threat intelligence database
  const fetchLocalThreatData = async (ip: string): Promise<any> => {
    try {
      // Try to get data from local database or cache
      const response = await api.get(`/threat-intelligence/ip/${ip}`);
      console.log(`Local threat data for ${ip}:`, response.data);
      return {
        source: 'Local Database',
        ...response.data
      };
    } catch (error) {
      console.log(`Local threat data not available for ${ip}:`, error);
      
      // In development mode, provide enhanced fallback data
      if (isDevelopment()) {
        const ipHash = ip.split('.').reduce((acc, octet) => acc + parseInt(octet), 0);
        const isLocal = ip.startsWith('192.168.') || ip.startsWith('10.') || 
                       (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31);
        
        return {
          source: 'Local Database (Development Fallback)',
          isLocal,
          network: getNetworkInfo(ip),
          threatLevel: isLocal ? 'Low' : ['Low', 'Medium', 'High'][ipHash % 3],
          lastSeen: new Date().toISOString(),
          tags: isLocal ? ['internal', 'trusted'] : ['external', 'monitored'],
          confidence: isLocal ? 95 : 70 + (ipHash % 30)
        };
      }
      
      // Return basic local data for production
      return {
        source: 'Local Database (Fallback)',
        isLocal: ip.startsWith('192.168.') || ip.startsWith('10.') || 
                 (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31),
        network: getNetworkInfo(ip)
      };
    }
  };

  // Helper function to get network information
  const getNetworkInfo = (ip: string): string => {
    if (ip.startsWith('192.168.')) {
      return '192.168.x.x (Private)';
    } else if (ip.startsWith('10.')) {
      return '10.x.x.x (Private)';
    } else if (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31) {
      return '172.16-31.x.x (Private)';
    } else if (ip === '127.0.0.1' || ip === '::1') {
      return 'Localhost';
    } else if (ip === '8.8.8.8' || ip === '8.8.4.4' || ip === '1.1.1.1' || ip === '1.0.0.1') {
      return 'Public DNS Server';
    } else {
      return 'Public Network';
    }
  };

  // Combine results from multiple sources
  const combineEnrichmentResults = (results: PromiseSettledResult<any>[], ip: string): any => {
    const vtData = results[0].status === 'fulfilled' ? results[0].value : null;
    const abuseData = results[1].status === 'fulfilled' ? results[1].value : null;
    const geoData = results[2].status === 'fulfilled' ? results[2].value : null;
    const localData = results[3].status === 'fulfilled' ? results[3].value : null;
    
    console.log(`Combining results for ${ip}:`, { vtData, abuseData, geoData, localData });
    
    // Calculate threat score based on available data
    let threatScore = 0;
    let ipReputation: 'malicious' | 'suspicious' | 'clean' | 'unknown' = 'unknown';
    
    console.log(`🔍 Calculating threat score for ${ip}:`, { vtData, abuseData });
    
    if (vtData && vtData.positives !== undefined && vtData.total !== undefined && vtData.total > 0) {
      const vtScore = (vtData.positives / vtData.total) * 100;
      console.log(`📊 VirusTotal score calculation: ${vtData.positives} / ${vtData.total} * 100 = ${vtScore}`);
      if (!isNaN(vtScore)) {
        threatScore = Math.max(threatScore, vtScore);
        console.log(`✅ VirusTotal score added: ${vtScore}, total threat score: ${threatScore}`);
      } else {
        console.log(`⚠️ VirusTotal score is NaN, skipping`);
      }
    } else {
      console.log(`⚠️ VirusTotal data invalid or missing:`, vtData);
    }
    
    if (abuseData && abuseData.abuseConfidenceScore !== undefined) {
      const abuseScore = abuseData.abuseConfidenceScore;
      console.log(`📊 AbuseIPDB score: ${abuseScore}`);
      if (!isNaN(abuseScore)) {
        threatScore = Math.max(threatScore, abuseScore);
        console.log(`✅ AbuseIPDB score added: ${abuseScore}, total threat score: ${threatScore}`);
      } else {
        console.log(`⚠️ AbuseIPDB score is NaN, skipping`);
      }
    } else {
      console.log(`⚠️ AbuseIPDB data invalid or missing:`, abuseData);
    }
    
    console.log(`🎯 Final threat score: ${threatScore}`);
    
    // Determine reputation based on threat score
    if (threatScore >= 80) {
      ipReputation = 'malicious';
    } else if (threatScore >= 30) {
      ipReputation = 'suspicious';
    } else if (threatScore >= 0) {
      ipReputation = 'clean';
    }
    
    // Combine threat types from all sources
    const threatTypes = [];
    if (vtData?.last_analysis_stats) {
      if (vtData.last_analysis_stats.malicious > 0) threatTypes.push('malware');
      if (vtData.last_analysis_stats.suspicious > 0) threatTypes.push('suspicious');
    }
    if (abuseData?.totalReports > 0) {
      threatTypes.push('abuse');
    }
    
    // Get location information with better fallback logic
    let country = 'Unknown';
    let city = 'Unknown';
    let isp = 'Unknown';
    
    // Priority 1: Use geolocation data if available
    if (geoData) {
      country = geoData.country || geoData.countryName || 'Unknown';
      city = geoData.city || 'Unknown';
      isp = geoData.org || 'Unknown';
    }
    
    // Priority 2: Use VirusTotal data if available
    if (country === 'Unknown' && vtData?.country) {
      country = vtData.country;
    }
    if (city === 'Unknown' && vtData?.city) {
      city = vtData.city;
    }
    if (isp === 'Unknown' && vtData?.as_owner) {
      isp = vtData.as_owner;
    }
    
    // Priority 3: Use AbuseIPDB data if available (even if VirusTotal is null)
    console.log(`🔍 Checking AbuseIPDB data for location:`, {
      abuseData,
      hasCountryCode: !!abuseData?.countryCode,
      hasCountryName: !!abuseData?.countryName,
      hasCity: !!abuseData?.city,
      hasISP: !!abuseData?.isp
    });
    
    if (country === 'Unknown' && abuseData?.countryCode) {
      country = abuseData.countryCode;
      console.log(`✅ Using AbuseIPDB countryCode: ${country}`);
    }
    if (city === 'Unknown' && abuseData?.city) {
      city = abuseData.city;
      console.log(`✅ Using AbuseIPDB city: ${city}`);
    }
    if (isp === 'Unknown' && abuseData?.isp) {
      isp = abuseData.isp;
      console.log(`✅ Using AbuseIPDB ISP: ${isp}`);
    }
    
    // Additional AbuseIPDB fallbacks for city
    if (city === 'Unknown' && abuseData?.countryCode) {
      city = `City in ${abuseData.countryCode}`;
      console.log(`✅ Using AbuseIPDB countryCode for city: ${city}`);
    }
    
    // Priority 4: Use local data if available
    if (isp === 'Unknown' && localData?.network) {
      isp = localData.network;
    }
    
    // Priority 5: Use IP-based fallback for private/local IPs
    if (country === 'Unknown') {
      country = getCountryFromIP(ip);
    }
    
    // Priority 6: Provide context for public IPs that failed geolocation
    if (city === 'Unknown') {
      if (ip.startsWith('192.168.') || ip.startsWith('10.') || 
          (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31)) {
        city = 'Private Network';
      } else if (ip === '127.0.0.1' || ip === '::1') {
        city = 'Localhost';
      } else if (ip === '8.8.8.8' || ip === '1.1.1.1' || ip === '8.8.4.4' || ip === '1.0.0.1') {
        city = 'DNS Server';
      } else {
        // For public IPs, try to get country from AbuseIPDB if available
        if (abuseData?.countryCode) {
          city = `City in ${abuseData.countryCode}`;
        } else {
          city = 'Location Unavailable';
        }
      }
    }
    
    // Priority 6a: Ensure private IPs have consistent location values
    if (ip.startsWith('192.168.') || ip.startsWith('10.') || 
        (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31)) {
      city = 'Private Network';
      country = 'Private Network';
      if (isp === 'Unknown') {
        isp = 'Local Network';
      }
    } else if (ip === '127.0.0.1' || ip === '::1') {
      city = 'Localhost';
      country = 'Localhost';
      if (isp === 'Unknown') {
        isp = 'Local System';
      }
    } else if (ip === '8.8.8.8' || ip === '8.8.4.4' || ip === '1.1.1.1' || ip === '1.0.0.1') {
      city = 'DNS Server';
      country = 'US';
      if (isp === 'Unknown') {
        isp = 'Public DNS Service';
      }
    }
    
    // Priority 7: Enhanced country fallback for public IPs
    if (country === 'Unknown' || country === 'Public IP (Geolocation Failed)') {
      if (abuseData?.countryCode) {
        country = abuseData.countryCode;
      } else if (abuseData?.countryName) {
        country = abuseData.countryName;
      } else {
        country = getCountryFromIP(ip);
      }
    }
    
    // Ensure threatScore and confidence are valid numbers
    const finalThreatScore = isNaN(threatScore) ? 0 : Math.round(threatScore);
    const finalConfidence = Math.min(100, Math.round((finalThreatScore || 0) + (threatTypes.length * 10)));
    
    console.log(`🎯 Final calculated values:`, {
      threatScore: finalThreatScore,
      confidence: finalConfidence,
      threatTypes: threatTypes.length
    });
    
    // Final location validation and logging
    console.log(`📍 Final location values for ${ip}:`, {
      country: country,
      city: city,
      isp: isp,
      source: 'AbuseIPDB' in [vtData?.source, abuseData?.source, geoData?.source, localData?.source] ? 'AbuseIPDB' : 'Other'
    });
    
    return {
      ipReputation,
      threatScore: finalThreatScore,
      country: country,
      city: city,
      isp: isp,
      lastSeen: new Date().toISOString(),
      threatTypes: threatTypes.length > 0 ? threatTypes : ['unknown'],
      confidence: finalConfidence,
      sources: [vtData?.source, abuseData?.source, geoData?.source, localData?.source].filter(Boolean),
      rawData: {
        virusTotal: vtData,
        abuseIPDB: abuseData,
        geolocation: geoData,
        local: localData
      }
    };
  };

  // Fallback enrichment data if all APIs fail
  const getFallbackEnrichmentData = (ip: string): any => {
    console.log(`Using fallback enrichment data for ${ip}`);
    
    // Get basic IP information
    const country = getCountryFromIP(ip);
    let city = 'Unknown';
    
    // Determine city based on IP type
    if (country === 'Private Network') {
      city = 'Private Network';
    } else if (country === 'Localhost') {
      city = 'Localhost';
    } else if (country === 'US') {
      city = 'DNS Server';
    } else if (country === 'Public IP (Geolocation Failed)') {
      city = 'Location Unavailable';
    } else {
      city = 'Unknown';
    }
    
    const isp = getNetworkInfo(ip);
    
    return {
      ipReputation: 'unknown' as const,
      threatScore: 0,
      country: country,
      city: city,
      isp: isp,
      lastSeen: new Date().toISOString(),
      threatTypes: ['unknown'],
      confidence: 0,
      sources: ['Fallback'],
      rawData: {},
      note: 'Enrichment failed, using fallback data based on IP address type'
    };
  };

  // Test geolocation for debugging
  const testGeolocation = async (ip: string) => {
    console.log(`🧪 Testing geolocation for IP: ${ip}`);
    console.log(`IP Classification: ${getCountryFromIP(ip)}`);
    console.log(`Network Info: ${getNetworkInfo(ip)}`);
    
    // Check if this is a private IP
    if (ip.startsWith('192.168.') || ip.startsWith('10.') || 
        (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31) ||
        ip === '127.0.0.1' || ip === '::1') {
      console.log(`⚠️ This is a private IP (${ip}) - geolocation is not applicable`);
      console.log(`Expected result: Private Network`);
      return;
    }
    
    try {
      console.log('Testing multiple geolocation services...');
      
      const services = [
        { name: 'cors.bridged.cc + ipapi.co', url: `https://cors.bridged.cc/https://ipapi.co/${ip}/json/` },
        { name: 'api.codetabs.com + ipapi.co', url: `https://api.codetabs.com/v1/proxy?quest=https://ipapi.co/${ip}/json/` },
        { name: 'cors-anywhere + ipapi.co', url: `https://cors-anywhere.herokuapp.com/https://ipapi.co/${ip}/json/` },
        { name: 'cors.bridged.cc + ip-api.com', url: `https://cors.bridged.cc/https://ip-api.com/json/${ip}` },
        { name: 'api.codetabs.com + ip-api.com', url: `https://api.codetabs.com/v1/proxy?quest=https://ip-api.com/json/${ip}` },
        { name: 'Direct ipapi.co', url: `https://ipapi.co/${ip}/json/` },
        { name: 'Development Fallback', url: `https://httpbin.org/ip` }
      ];
      
      for (const service of services) {
        try {
          console.log(`\n🔍 Testing ${service.name}...`);
          const response = await fetch(service.url, {
            method: 'GET',
            headers: {
              'Accept': 'application/json',
              'Origin': window.location.origin
            }
          });
          
          console.log(`Response status: ${response.status}`);
          
          if (response.ok) {
            const data = await response.json();
            console.log(`✅ ${service.name} response:`, data);
          } else {
            console.error(`❌ ${service.name} failed: ${response.status} - ${response.statusText}`);
          }
        } catch (serviceError) {
          console.error(`❌ ${service.name} error:`, serviceError);
        }
      }
      
      // Test our full enrichment logic
      console.log('\n🧪 Testing full enrichment process...');
      const enrichmentResult = await enrichIPAddress(ip);
      console.log(`✅ Full enrichment result:`, enrichmentResult);
      
    } catch (error) {
      console.error(`❌ Geolocation test failed:`, error);
    }
  };

  // Check if we're in development environment
  const isDevelopment = () => {
    return window.location.hostname === 'localhost' || 
           window.location.hostname === '127.0.0.1' || 
           window.location.port === '3000';
  };

  // Get development fallback data for public IPs
  const getDevelopmentFallbackData = (ip: string) => {
    if (isDevelopment()) {
      // Generate deterministic but varied mock data based on IP
      const ipHash = ip.split('.').reduce((acc, octet) => acc + parseInt(octet), 0);
      const mockCountries = ['US', 'DE', 'FR', 'GB', 'JP', 'CA', 'AU', 'BR', 'IN', 'CN'];
      const mockCities = ['New York', 'Berlin', 'Paris', 'London', 'Tokyo', 'Toronto', 'Sydney', 'São Paulo', 'Mumbai', 'Beijing'];
      const mockISPs = ['Comcast', 'Deutsche Telekom', 'Orange', 'BT', 'NTT', 'Rogers', 'Telstra', 'Vivo', 'BSNL', 'China Telecom'];
      
      const countryIndex = ipHash % mockCountries.length;
      const cityIndex = (ipHash + 1) % mockCities.length;
      const ispIndex = (ipHash + 2) % mockISPs.length;
      
      return {
        source: 'IP Geolocation (Development Mode)',
        country: mockCountries[countryIndex],
        countryName: getCountryName(mockCountries[countryIndex]),
        region: `${mockCities[cityIndex]} Region`,
        city: mockCities[cityIndex],
        latitude: 40 + (ipHash % 20) - 10, // Random latitude around 40
        longitude: -74 + (ipHash % 20) - 10, // Random longitude around -74
        timezone: 'UTC-5',
        org: mockISPs[ispIndex],
        asn: `AS${1000 + (ipHash % 9000)}`,
        note: `Development mode: ${ip} - Mock data for testing purposes`
      };
    }
    return null;
  };

  // Helper function to get country names
  const getCountryName = (countryCode: string): string => {
    const countryNames: { [key: string]: string } = {
      'US': 'United States', 'DE': 'Germany', 'FR': 'France', 'GB': 'United Kingdom',
      'JP': 'Japan', 'CA': 'Canada', 'AU': 'Australia', 'BR': 'Brazil', 'IN': 'India', 'CN': 'China'
    };
    return countryNames[countryCode] || countryCode;
  };

  // Get development fallback data for threat intelligence APIs
  const getDevelopmentThreatData = (ip: string, source: 'VirusTotal' | 'AbuseIPDB') => {
    if (!isDevelopment()) return null;
    
    // Generate deterministic mock data based on IP
    const ipHash = ip.split('.').reduce((acc, octet) => acc + parseInt(octet), 0);
    
    if (source === 'VirusTotal') {
      const mockPositives = (ipHash % 10) + 1; // 1-10 positives
      const mockTotal = 50 + (ipHash % 50); // 50-99 total
      
      return {
        source: 'VirusTotal (Development Mode)',
        positives: mockPositives,
        total: mockTotal,
        categories: { 'malware': 'malicious', 'phishing': 'malicious' },
        country: getCountryName('US'),
        as_owner: 'Mock ISP Corporation',
        last_analysis_stats: { malicious: mockPositives, suspicious: 2, harmless: mockTotal - mockPositives - 2 }
      };
    } else if (source === 'AbuseIPDB') {
      const mockScore = (ipHash % 100); // 0-99 abuse score
      
      // Check if this is a private IP
      if (ip.startsWith('192.168.') || ip.startsWith('10.') || 
          (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31) ||
          ip === '127.0.0.1' || ip === '::1') {
        // For private IPs, return consistent local network data
        const mockData = {
          source: 'AbuseIPDB (Development Mode - Private IP)',
          abuseConfidenceScore: mockScore,
          countryCode: 'Private Network',
          countryName: 'Private Network',
          city: 'Private Network',
          isp: 'Local Network',
          domain: 'local-network',
          totalReports: 0,
          numDistinctUsers: 0,
          lastReportedAt: new Date().toISOString()
        };
        
        console.log(`🔄 Development fallback AbuseIPDB data for PRIVATE IP ${ip}:`, mockData);
        return mockData;
      }
      
      // Generate varied mock location data for public IPs
      const mockCountries = ['US', 'DE', 'FR', 'GB', 'CA', 'AU', 'JP', 'BR', 'IN', 'RU'];
      const mockCities = ['New York', 'Berlin', 'Paris', 'London', 'Toronto', 'Sydney', 'Tokyo', 'São Paulo', 'Mumbai', 'Moscow'];
      const mockISPs = ['Comcast', 'Deutsche Telekom', 'Orange', 'BT', 'Rogers', 'Telstra', 'NTT', 'Vivo', 'BSNL', 'Rostelecom'];
      
      const countryIndex = ipHash % mockCountries.length;
      const mockCountryCode = mockCountries[countryIndex];
      const mockCity = mockCities[countryIndex];
      const mockISP = mockISPs[countryIndex];
      
      const mockData = {
        source: 'AbuseIPDB (Development Mode)',
        abuseConfidenceScore: mockScore,
        countryCode: mockCountryCode,
        countryName: getCountryName(mockCountryCode),
        city: mockCity,
        isp: mockISP,
        domain: 'mock-domain.com',
        totalReports: mockScore > 50 ? (ipHash % 20) + 1 : 0,
        numDistinctUsers: mockScore > 50 ? (ipHash % 10) + 1 : 0,
        lastReportedAt: new Date().toISOString()
      };
      
      console.log(`🔄 Development fallback AbuseIPDB data for PUBLIC IP ${ip}:`, mockData);
      return mockData;
    }
    
    return null;
  };

  // Enhanced error handling and user feedback
  const getEnrichmentErrorInfo = (error: any, service: string): string => {
    if (error.name === 'AbortError') {
      return `${service} request timed out. Please try again.`;
    } else if (error.message.includes('Failed to fetch')) {
      return `${service} network error. Check your internet connection.`;
    } else if (error.message.includes('CORS')) {
      return `${service} CORS error. This is a browser security restriction.`;
    } else if (error.message.includes('403')) {
      return `${service} access forbidden. Service may be rate-limited.`;
    } else if (error.message.includes('429')) {
      return `${service} rate limited. Please wait before trying again.`;
    } else if (error.message.includes('500')) {
      return `${service} server error. Please try again later.`;
    } else {
      return `${service} error: ${error.message || 'Unknown error occurred'}`;
    }
  };

  // Helper functions for enrichment display
  const getEnrichmentIcon = (ip: string) => {
    return '🌐';
  };

  const getEnrichmentColor = (reputation: string) => {
    switch (reputation) {
      case 'malicious':
        return 'bg-rose-100 text-rose-700';
      case 'suspicious':
        return 'bg-orange-100 text-orange-700';
      case 'clean':
        return 'bg-emerald-100 text-emerald-700';
      default:
        return 'bg-slate-100 text-slate-700';
    }
  };



  // Export functions
  const exportCSV = () => {
    const csvContent = [
      ['Time', 'Title', 'Source', 'Type', 'Severity', 'Status', 'Description'],
      ...filteredAlerts.map(alert => [
        new Date(alert.timestamp).toLocaleString(),
        alert.title,
        alert.source,
        alert.type,
        alert.severity,
        alert.status,
        alert.description || ''
      ])
    ].map(row => row.map(field => `"${field}"`).join(',')).join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    saveAs(blob, 'alerts.csv');
  };

  const exportXLSX = () => {
    const ws = XLSX.utils.json_to_sheet(filteredAlerts.map(alert => ({
      Time: new Date(alert.timestamp).toLocaleString(),
      Title: alert.title,
      Source: alert.source,
      Type: alert.type,
      Severity: alert.severity,
      Status: alert.status,
      Description: alert.description || ''
    })));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Alerts');
    XLSX.writeFile(wb, 'alerts.xlsx');
  };

  const exportPDF = () => {
    const doc = new jsPDF();
    doc.text('Alert Report', 20, 20);
    
    const tableData = filteredAlerts.map(alert => [
      new Date(alert.timestamp).toLocaleString(),
      alert.title,
      alert.source,
      alert.type,
      alert.severity,
      alert.status
    ]);

    (doc as any).autoTable({
      head: [['Time', 'Title', 'Source', 'Type', 'Severity', 'Status']],
      body: tableData,
      startY: 30
    });

    doc.save('alerts.pdf');
  };

  const downloadJSON = (alert: Alert) => {
    const blob = new Blob([JSON.stringify(alert, null, 2)], { type: 'application/json' });
    saveAs(blob, `alert-${alert.id}.json`);
  };

  const getSortIndicator = (key: keyof Alert): string => {
    if (sortConfig?.key !== key) return '↕';
    return sortConfig.direction === 'asc' ? '↑' : '↓';
  };

  // Type badge: taxonomical (no risk signal) - rotate through the
  // theme ramp so the overall page palette stays coherent.
  const typeBadgeColor = (t: Alert['type']): string => {
    switch (t) {
      case 'ANOMALY':             return 'bg-violet-100 text-violet-700 ring-1 ring-violet-200';
      case 'IOA':                 return 'bg-fuchsia-100 text-fuchsia-700 ring-1 ring-fuchsia-200';
      case 'HONEYPOT':            return 'bg-pink-100 text-pink-700 ring-1 ring-pink-200';
      case 'THREAT_INTELLIGENCE': return 'bg-rose-100 text-rose-700 ring-1 ring-rose-200';
      default:                    return 'bg-slate-100 text-slate-700 ring-1 ring-slate-200';
    }
  };

  // Severity badge: semantic risk - keep the red→green spectrum but
  // swap the specific shades for ring-backed tones that sit next to
  // the rest of the page. CRITICAL→rose, HIGH→orange, MEDIUM→amber,
  // LOW→emerald, INFO→violet (neutral, part of brand).
  const severityBadgeColor = (s: Alert['severity']): string => {
    switch (s) {
      case 'CRITICAL': return 'bg-rose-100 text-rose-700 ring-1 ring-rose-200';
      case 'HIGH':     return 'bg-orange-100 text-orange-700 ring-1 ring-orange-200';
      case 'MEDIUM':   return 'bg-amber-100 text-amber-700 ring-1 ring-amber-200';
      case 'LOW':      return 'bg-emerald-100 text-emerald-700 ring-1 ring-emerald-200';
      case 'INFO':     return 'bg-violet-100 text-violet-700 ring-1 ring-violet-200';
      default:         return 'bg-slate-100 text-slate-700 ring-1 ring-slate-200';
    }
  };

  // Status badge: workflow states. "Open" states stay warm (rose for
  // unhandled, orange for escalated) so they remain visually loud;
  // "in flight" uses violet/fuchsia from the brand; terminal states
  // use emerald (resolved) or slate (closed / false positive).
  const statusBadgeColor = (st: Alert['status']): string => {
    switch (st) {
      case 'NEW':            return 'bg-rose-100 text-rose-700 ring-1 ring-rose-200';
      case 'ACKNOWLEDGED':   return 'bg-violet-100 text-violet-700 ring-1 ring-violet-200';
      case 'IN_PROGRESS':    return 'bg-fuchsia-100 text-fuchsia-700 ring-1 ring-fuchsia-200';
      case 'ESCALATED':      return 'bg-orange-100 text-orange-700 ring-1 ring-orange-200';
      case 'RESOLVED':       return 'bg-emerald-100 text-emerald-700 ring-1 ring-emerald-200';
      case 'CLOSED':         return 'bg-slate-100 text-slate-700 ring-1 ring-slate-200';
      case 'FALSE_POSITIVE': return 'bg-slate-100 text-slate-500 ring-1 ring-slate-200';
      default:               return 'bg-slate-100 text-slate-700 ring-1 ring-slate-200';
    }
  };

  // Mock users for assignment dropdown
  const users = [
    { id: '1', name: 'John Doe' },
    { id: '2', name: 'Jane Smith' },
    { id: '3', name: 'Bob Johnson' }
  ];

  // Audit trail state
  const [auditModalFor, setAuditModalFor] = useState<string | undefined>(undefined);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);

  const viewAudit = async (alertId: string) => {
    // Mock audit data
    const mockAudit = [
      { timestamp: '2024-01-15 10:30:00', action: 'Alert created', performedBy: 'System' },
      { timestamp: '2024-01-15 10:35:00', action: 'Alert acknowledged', performedBy: 'John Doe' }
    ];
    setAuditEntries(mockAudit);
    setAuditModalFor(alertId);
  };



  // Initial fetch of alerts when component mounts
  useEffect(() => {
    fetchAlerts();
  }, []);

  // Listen for localStorage changes to automatically refresh when new IOAs are detected
  useEffect(() => {
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'ioas' && e.newValue) {
        console.log('IOAs updated in localStorage, refreshing alerts...');
        fetchAlerts();
      }
    };

    // Listen for storage events from other tabs/windows
    window.addEventListener('storage', handleStorageChange);

    // Also listen for custom events (for same-tab updates)
    const handleIOAUpdate = () => {
      console.log('IOA update event received, refreshing alerts...');
      fetchAlerts();
    };

    window.addEventListener('ioa-updated', handleIOAUpdate);

    return () => {
      window.removeEventListener('storage', handleStorageChange);
      window.removeEventListener('ioa-updated', handleIOAUpdate);
    };
  }, []);

  const [activeTab, setActiveTab] = useState<'analytics' | 'correlation' | 'enrichment' | 'hunting' | 'incident' | 'responseTime'>('analytics');

  // Threat Hunting state
  const [huntingQueries, setHuntingQueries] = useState<Array<{
    id: string;
    name: string;
    query: string;
    description: string;
    lastRun: string;
    results: number;
    status: 'active' | 'paused' | 'completed';
  }>>([
    {
      id: '1',
      name: 'Suspicious PowerShell Activity',
      query: 'process.name="powershell.exe" AND (command_line CONTAINS "Invoke-Expression" OR command_line CONTAINS "IEX")',
      description: 'Detect potential PowerShell-based attacks using obfuscated commands',
      lastRun: new Date().toISOString(),
      results: 12,
      status: 'active'
    },
    {
      id: '2',
      name: 'Lateral Movement Detection',
      query: 'event_type="authentication" AND source_ip IN (SELECT source_ip FROM events WHERE event_type="failed_login" GROUP BY source_ip HAVING COUNT(*) > 5)',
      description: 'Identify potential lateral movement from previously compromised sources',
      lastRun: new Date(Date.now() - 3600000).toISOString(),
      results: 3,
      status: 'active'
    },
    {
      id: '3',
      name: 'Data Exfiltration Patterns',
      query: 'data_transfer.size > 100MB AND destination_ip NOT IN (SELECT ip FROM whitelist) AND time > now() - 1h',
      description: 'Monitor for large data transfers to suspicious destinations',
      lastRun: new Date(Date.now() - 7200000).toISOString(),
      results: 0,
      status: 'paused'
    }
  ]);



  const [threatIndicators, setThreatIndicators] = useState<Array<{
    id: string;
    type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
    value: string;
    confidence: number;
    threatLevel: 'high' | 'medium' | 'low';
    firstSeen: string;
    lastSeen: string;
    sources: string[];
    tags: string[];
  }>>([
    {
      id: '1',
      type: 'ip',
      value: '192.168.1.100',
      confidence: 85,
      threatLevel: 'high',
      firstSeen: new Date(Date.now() - 86400000).toISOString(),
      lastSeen: new Date().toISOString(),
      sources: ['Firewall', 'IDS', 'Threat Intel'],
      tags: ['malware', 'command-control', 'suspicious']
    },
    {
      id: '2',
      type: 'domain',
      value: 'malicious-domain.com',
      confidence: 95,
      threatLevel: 'high',
      firstSeen: new Date(Date.now() - 172800000).toISOString(),
      lastSeen: new Date().toISOString(),
      sources: ['DNS', 'Proxy', 'Threat Intel'],
      tags: ['phishing', 'malware-distribution']
    },
    {
      id: '3',
      type: 'hash',
      value: 'a1b2c3d4e5f6...',
      confidence: 78,
      threatLevel: 'medium',
      firstSeen: new Date(Date.now() - 259200000).toISOString(),
      lastSeen: new Date(Date.now() - 86400000).toISOString(),
      sources: ['Antivirus', 'Sandbox'],
      tags: ['trojan', 'keylogger']
    }
  ]);

  const [investigationSessions, setInvestigationSessions] = useState<Array<{
    id: string;
    title: string;
    description: string;
    status: 'open' | 'in_progress' | 'closed';
    assignedTo: string;
    createdAt: string;
    updatedAt: string;
    evidence: Array<{
      id: string;
      type: 'log' | 'alert' | 'network' | 'file' | 'process';
      content: string;
      timestamp: string;
      source: string;
    }>;
  }>>([
    {
      id: '1',
      title: 'Suspicious Network Activity Investigation',
      description: 'Investigating unusual network traffic patterns from internal hosts',
      status: 'in_progress',
      assignedTo: 'Security Analyst',
      createdAt: new Date(Date.now() - 86400000).toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: [
        {
          id: '1',
          type: 'network',
          content: 'Multiple connection attempts to external IPs on port 443',
          timestamp: new Date().toISOString(),
          source: 'Network Monitor'
        },
        {
          id: '2',
          type: 'alert',
          content: 'High volume of encrypted traffic detected',
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          source: 'IDS'
        }
      ]
    }
  ]);

  // Threat Hunting functions
  const createHuntingQuery = () => {
    const newQuery = {
      id: Date.now().toString(),
      name: 'New Hunting Query',
      query: '',
      description: 'Enter query description',
      lastRun: new Date().toISOString(),
      results: 0,
      status: 'active' as const
    };
    setHuntingQueries([...huntingQueries, newQuery]);
  };

  const runHuntingQuery = (queryId: string) => {
    setHuntingQueries(prev => prev.map(q => 
      q.id === queryId 
        ? { ...q, lastRun: new Date().toISOString(), results: Math.floor(Math.random() * 50) }
        : q
    ));
  };

  const addThreatIndicator = () => {
    const newIndicator = {
      id: Date.now().toString(),
      type: 'ip' as const,
      value: '0.0.0.0',
      confidence: 50,
      threatLevel: 'medium' as const,
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      sources: ['Manual Entry'],
      tags: ['suspicious']
    };
    setThreatIndicators([...threatIndicators, newIndicator]);
  };

  const createInvestigationSession = () => {
    const newSession = {
      id: Date.now().toString(),
      title: 'New Investigation',
      description: 'Enter investigation description',
      status: 'open' as const,
      assignedTo: 'Current User',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: []
    };
    setInvestigationSessions([...investigationSessions, newSession]);
  };

  // Incident Response state
  const [incidents, setIncidents] = useState<Array<{
    id: string;
    title: string;
    description: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    status: 'OPEN' | 'IN_PROGRESS' | 'ESCALATED' | 'RESOLVED' | 'CLOSED';
    priority: 'P1' | 'P2' | 'P3' | 'P4';
    assignedTo: string;
    createdAt: string;
    updatedAt: string;
    affectedAssets: string[];
    affectedUsers: number;
    estimatedImpact: string;
    responseTime: number; // in minutes
    mttr: number; // Mean Time to Resolution in minutes
    tags: string[];
    notes: Array<{
      id: string;
      content: string;
      author: string;
      timestamp: string;
      type: 'note' | 'action' | 'decision';
    }>;
  }>>([
    {
      id: '1',
      title: 'Suspicious Network Activity Detected',
      description: 'Multiple failed login attempts and unusual network traffic patterns detected from internal hosts',
      severity: 'HIGH',
      status: 'IN_PROGRESS',
      priority: 'P2',
      assignedTo: 'Security Team Lead',
      createdAt: new Date(Date.now() - 7200000).toISOString(),
      updatedAt: new Date().toISOString(),
      affectedAssets: ['Web Server 01', 'Database Server', 'Load Balancer'],
      affectedUsers: 150,
      estimatedImpact: 'Medium - Potential data exposure risk',
      responseTime: 15,
      mttr: 240,
      tags: ['network', 'authentication', 'internal-threat'],
      notes: [
        {
          id: '1',
          content: 'Initial assessment completed. Suspicious activity confirmed.',
          author: 'Security Analyst',
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          type: 'note'
        },
        {
          id: '2',
          content: 'Isolated affected systems. Monitoring for further activity.',
          author: 'Security Team Lead',
          timestamp: new Date(Date.now() - 1800000).toISOString(),
          type: 'action'
        }
      ]
    },
    {
      id: '2',
      title: 'Malware Detection on Endpoint',
      description: 'Antivirus software detected suspicious file behavior on multiple endpoints',
      severity: 'CRITICAL',
      status: 'ESCALATED',
      priority: 'P1',
      assignedTo: 'Incident Response Team',
      createdAt: new Date(Date.now() - 14400000).toISOString(),
      updatedAt: new Date().toISOString(),
      affectedAssets: ['Workstation-001', 'Workstation-002', 'Workstation-003'],
      affectedUsers: 3,
      estimatedImpact: 'High - Potential data breach and system compromise',
      responseTime: 5,
      mttr: 180,
      tags: ['malware', 'endpoint', 'data-breach'],
      notes: [
        {
          id: '1',
          content: 'Malware samples collected for analysis.',
          author: 'Forensics Team',
          timestamp: new Date(Date.now() - 7200000).toISOString(),
          type: 'note'
        },
        {
          id: '2',
          content: 'Escalated to senior management due to critical severity.',
          author: 'Incident Manager',
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          type: 'decision'
        }
      ]
    }
  ]);

  const [responseProcedures, setResponseProcedures] = useState<Array<{
    id: string;
    name: string;
    description: string;
    category: 'INCIDENT_RESPONSE' | 'FORENSICS' | 'COMMUNICATION' | 'RECOVERY' | 'LESSONS_LEARNED';
    steps: Array<{
      id: string;
      order: number;
      action: string;
      description: string;
      estimatedTime: number;
      responsible: string;
      completed: boolean;
    }>;
    lastUpdated: string;
    version: string;
  }>>([
    {
      id: '1',
      name: 'Data Breach Response Procedure',
      description: 'Standard operating procedure for responding to data breach incidents',
      category: 'INCIDENT_RESPONSE',
      steps: [
        {
          id: '1',
          order: 1,
          action: 'Immediate Containment',
          description: 'Isolate affected systems and networks to prevent further data loss',
          estimatedTime: 30,
          responsible: 'Security Team',
          completed: false
        },
        {
          id: '2',
          order: 2,
          action: 'Evidence Preservation',
          description: 'Document and preserve all evidence for forensic analysis',
          estimatedTime: 60,
          responsible: 'Forensics Team',
          completed: false
        },
        {
          id: '3',
          order: 3,
          action: 'Stakeholder Notification',
          description: 'Notify relevant stakeholders and legal team',
          estimatedTime: 45,
          responsible: 'Incident Manager',
          completed: false
        }
      ],
      lastUpdated: new Date(Date.now() - 86400000).toISOString(),
      version: '2.1'
    },
    {
      id: '2',
      name: 'Malware Incident Response',
      description: 'Procedure for handling malware detection and removal',
      category: 'INCIDENT_RESPONSE',
      steps: [
        {
          id: '1',
          order: 1,
          action: 'Threat Assessment',
          description: 'Assess the type and scope of malware infection',
          estimatedTime: 30,
          responsible: 'Security Analyst',
          completed: false
        },
        {
          id: '2',
          order: 2,
          action: 'System Isolation',
          description: 'Isolate infected systems from network',
          estimatedTime: 15,
          responsible: 'Network Team',
          completed: false
        },
        {
          id: '3',
          order: 3,
          action: 'Malware Removal',
          description: 'Remove malware and restore system integrity',
          estimatedTime: 120,
          responsible: 'IT Support',
          completed: false
        }
      ],
      lastUpdated: new Date(Date.now() - 172800000).toISOString(),
      version: '1.8'
    }
  ]);

  // Incident Response functions
  const createIncident = () => {
    const newIncident = {
      id: Date.now().toString(),
      title: 'New Incident',
      description: 'Enter incident description',
      severity: 'MEDIUM' as const,
      status: 'OPEN' as const,
      priority: 'P3' as const,
      assignedTo: 'Unassigned',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      affectedAssets: [],
      affectedUsers: 0,
      estimatedImpact: 'Low',
      responseTime: 0,
      mttr: 0,
      tags: [],
      notes: []
    };
    setIncidents([...incidents, newIncident]);
  };

  const updateIncidentStatus = (incidentId: string, newStatus: 'OPEN' | 'IN_PROGRESS' | 'ESCALATED' | 'RESOLVED' | 'CLOSED') => {
    setIncidents(prev => prev.map(incident => 
      incident.id === incidentId 
        ? { ...incident, status: newStatus, updatedAt: new Date().toISOString() }
        : incident
    ));
  };

  const addIncidentNote = (incidentId: string, content: string, type: 'note' | 'action' | 'decision') => {
    const newNote = {
      id: Date.now().toString(),
      content,
      author: 'Current User',
      timestamp: new Date().toISOString(),
      type
    };
    
    setIncidents(prev => prev.map(incident => 
      incident.id === incidentId 
        ? { 
            ...incident, 
            notes: [...incident.notes, newNote],
            updatedAt: new Date().toISOString()
          }
        : incident
    ));
  };

  const createResponseProcedure = () => {
    const newProcedure = {
      id: Date.now().toString(),
      name: 'New Response Procedure',
      description: 'Enter procedure description',
      category: 'INCIDENT_RESPONSE' as const,
      steps: [],
      lastUpdated: new Date().toISOString(),
      version: '1.0'
    };
    setResponseProcedures([...responseProcedures, newProcedure]);
  };

  if (loading) return <div className="p-4 text-slate-500">Loading alerts...</div>;
  if (error) return <div className="p-4 text-rose-600">{error}</div>;

  return (
    <PageShell>
      <PageHero
        eyebrow="ALERT MANAGEMENT"
        icon={<Icon.Alert className="w-3.5 h-3.5" />}
        title={
          <span>
            Alerts &amp; incident triage
            <span className="block text-violet-100/90 font-medium text-lg md:text-xl mt-2">
              High-confidence signals from the deception layer, ranked by severity.
            </span>
          </span>
        }
      />

      <div className="bg-white shadow-sm ring-1 ring-slate-200/70 rounded-2xl p-6">
        {/* Alert Statistics Dashboard.
            Seven buckets: four severity tiers, an "Unassigned" ops KPI
            (ported from the deleted AlertManagement page), plus MTTA
            and MTTR — SOC-standard response metrics derived from each
            alert's createdAt → acknowledgedAt/resolvedAt deltas. */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-6">
          {[
            { sev: 'CRITICAL', label: 'Critical', gradient: 'from-rose-500 to-orange-500',    textColor: 'text-rose-700' },
            { sev: 'HIGH',     label: 'High',     gradient: 'from-orange-500 to-amber-500',   textColor: 'text-orange-700' },
            { sev: 'MEDIUM',   label: 'Medium',   gradient: 'from-amber-500 to-yellow-400',   textColor: 'text-amber-700' },
            { sev: 'LOW',      label: 'Low',      gradient: 'from-violet-500 to-fuchsia-500', textColor: 'text-violet-700' },
          ].map((row) => (
            <div key={row.sev} className="relative overflow-hidden bg-white rounded-2xl p-4 ring-1 ring-slate-200/70 shadow-sm">
              <div className={`absolute inset-x-0 top-0 h-1 bg-gradient-to-r ${row.gradient}`} />
              <div className={`text-3xl font-bold ${row.textColor}`}>
                {alerts.filter(a => a.severity === row.sev).length}
              </div>
              <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mt-1">{row.label}</div>
            </div>
          ))}
          {/* Unassigned = alerts without an owner, regardless of severity.
              We match both the literal "Unassigned" sentinel used by the
              local IOA ingest path and a genuinely missing assignedTo
              so the count stays honest no matter which producer wrote
              the row. */}
          <div className="relative overflow-hidden bg-white rounded-2xl p-4 ring-1 ring-slate-200/70 shadow-sm">
            <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-fuchsia-500 to-pink-500" />
            <div className="text-3xl font-bold text-fuchsia-700">
              {alerts.filter(a => {
                const owner = (a as unknown as { assignedTo?: string | null }).assignedTo;
                return !owner || owner === 'Unassigned';
              }).length}
            </div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mt-1">Unassigned</div>
          </div>

          {/* MTTA = Mean Time To Acknowledge. Computed on the client over
              whichever page the table currently shows, so the number is
              "how fast are we triaging *these* alerts" rather than a
              server-side time series. Falls back to an em-dash when
              nothing has been acknowledged yet. */}
          <div className="relative overflow-hidden bg-white rounded-2xl p-4 ring-1 ring-slate-200/70 shadow-sm">
            <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-violet-500 to-pink-500" />
            <div className="text-3xl font-bold text-violet-700 leading-none">
              {mtta.count === 0 ? '—' : formatShortDuration(mtta.ms)}
            </div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mt-1">MTTA</div>
            <div className="text-[10px] text-slate-400 mt-0.5">{mtta.count} ack{mtta.count === 1 ? '' : 's'}</div>
          </div>

          {/* MTTR = Mean Time To Resolve. Same trick, different ramp. */}
          <div className="relative overflow-hidden bg-white rounded-2xl p-4 ring-1 ring-slate-200/70 shadow-sm">
            <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-pink-500 to-rose-500" />
            <div className="text-3xl font-bold text-pink-700 leading-none">
              {mttr.count === 0 ? '—' : formatShortDuration(mttr.ms)}
            </div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mt-1">MTTR</div>
            <div className="text-[10px] text-slate-400 mt-0.5">{mttr.count} resolved</div>
          </div>
        </div>

        {/* All Alerts Table */}
        <div className="bg-white shadow-lg rounded-lg p-6 mb-6 ring-1 ring-slate-200">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold text-slate-800">All Alerts</h2>
            <div className="flex items-center space-x-4">
              {/* Auto-refresh toggle. When on the alerts list silently
                  re-fetches every 30s so an analyst parked on the page
                  doesn't miss incoming signals. Off by default so the
                  page doesn't poll a backend nobody is watching. */}
              <button
                type="button"
                onClick={() => setAutoRefresh(v => !v)}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold ring-1 transition ${
                  autoRefresh
                    ? 'bg-emerald-50 text-emerald-700 ring-emerald-200 hover:bg-emerald-100'
                    : 'bg-slate-50 text-slate-600 ring-slate-200 hover:bg-slate-100'
                }`}
                title={autoRefresh ? 'Auto-refreshing every 30 seconds' : 'Auto-refresh is off'}
              >
                <span className={`h-1.5 w-1.5 rounded-full ${autoRefresh ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`} />
                {autoRefresh ? 'Live · 30s' : 'Auto-refresh off'}
                {lastRefreshedAt && (
                  <span className="text-slate-400 font-normal">
                    · {Math.max(0, Math.round((Date.now() - lastRefreshedAt.getTime()) / 1000))}s ago
                  </span>
                )}
              </button>
              <div className="flex items-center space-x-2">
                <span className="text-sm text-slate-600">Show:</span>
                <select
                  value={filters.severity}
                  onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
                  className="border border-slate-300 rounded px-2 py-1 text-sm"
                >
                  <option value="">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                  <option value="INFO">Info</option>
                </select>
                <select
                  value={filters.type}
                  onChange={(e) => setFilters({ ...filters, type: e.target.value })}
                  className="border border-slate-300 rounded px-2 py-1 text-sm"
                >
                  <option value="">All Types</option>
                  <option value="ANOMALY">Anomaly</option>
                  <option value="IOA">IOA</option>
                  <option value="HONEYPOT">Honeypot</option>
                  <option value="THREAT_INTELLIGENCE">Threat Intelligence</option>
                  <option value="INTRUSION_DETECTION">Intrusion Detection</option>
                  <option value="PORT_SCAN">Port Scan</option>
                  <option value="BRUTE_FORCE">Brute Force</option>
                  <option value="DDoS_ATTACK">DDoS Attack</option>
                  <option value="MALWARE_DETECTION">Malware Detection</option>
                  <option value="PHISHING_ATTACK">Phishing Attack</option>
                  <option value="SQL_INJECTION">SQL Injection</option>
                  <option value="XSS_ATTACK">XSS Attack</option>
                  <option value="CSRF_ATTACK">CSRF Attack</option>
                  <option value="PATH_TRAVERSAL">Path Traversal</option>
                  <option value="COMMAND_INJECTION">Command Injection</option>
                  <option value="FAILED_LOGIN">Failed Login</option>
                  <option value="UNAUTHORIZED_ACCESS">Unauthorized Access</option>
                  <option value="PRIVILEGE_ESCALATION">Privilege Escalation</option>
                  <option value="ACCOUNT_LOCKOUT">Account Lockout</option>
                  <option value="SUSPICIOUS_LOGIN">Suspicious Login</option>
                  <option value="FILE_INTEGRITY">File Integrity</option>
                  <option value="PROCESS_MONITORING">Process Monitoring</option>
                  <option value="REGISTRY_CHANGE">Registry Change</option>
                  <option value="SERVICE_CHANGE">Service Change</option>
                  <option value="HONEYPOT_TRIGGER">Honeypot Trigger</option>
                  <option value="HONEYPOT_INTERACTION">Honeypot Interaction</option>
                  <option value="HONEYPOT_EXPLOIT">Honeypot Exploit</option>
                  <option value="COMPLIANCE_VIOLATION">Compliance Violation</option>
                  <option value="DATA_LEAKAGE">Data Leakage</option>
                  <option value="ANOMALY_DETECTION">Anomaly Detection</option>
                  <option value="CUSTOM_RULE">Custom Rule</option>
                </select>
                <select
                  value={filters.status}
                  onChange={(e) => setFilters({ ...filters, status: e.target.value })}
                  className="border border-slate-300 rounded px-2 py-1 text-sm"
                >
                  <option value="">All Statuses</option>
                  <option value="NEW">New</option>
                  <option value="ACKNOWLEDGED">Acknowledged</option>
                  <option value="IN_PROGRESS">In Progress</option>
                  <option value="ESCALATED">Escalated</option>
                  <option value="RESOLVED">Resolved</option>
                  <option value="CLOSED">Closed</option>
                  <option value="FALSE_POSITIVE">False Positive</option>
                </select>
              </div>
              <div className="flex items-center space-x-2">
          <button
            onClick={exportCSV}
                  className="px-3 py-1 bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200 text-sm rounded hover:bg-emerald-100 transition"
          >
            Export CSV
          </button>
          <button
            onClick={exportXLSX}
                  className="px-3 py-1 bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white text-sm rounded hover:shadow-md transition"
          >
            Export XLSX
          </button>
          <button
            onClick={exportPDF}
                  className="px-3 py-1 bg-rose-50 text-rose-700 ring-1 ring-rose-200 text-sm rounded hover:bg-rose-100 transition"
          >
            Export PDF
          </button>
              </div>
            </div>
          </div>

          {/* Search Bar */}
          <div className="mb-4">
            <div className="relative">
              <input
                type="text"
                placeholder="Search alerts by title, source, IP, or description..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-violet-400 focus:border-transparent"
              />
              <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                <svg className="h-5 w-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
            </div>
        </div>

          {/* Bulk Operations Bar */}
          {selectedAlerts.length > 0 && (
            <div className="bg-violet-50 ring-1 ring-violet-200 rounded-lg p-3 mb-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-violet-700">
                  {selectedAlerts.length} alert(s) selected
                </span>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleBulkAction('acknowledge')}
                    className="px-3 py-1 bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white text-sm rounded hover:shadow-md transition"
                  >
                    Acknowledge Selected
                  </button>
                  <button
                    onClick={() => handleBulkAction('snooze')}
                    className="px-3 py-1 bg-amber-50 text-amber-700 ring-1 ring-amber-200 text-sm rounded hover:bg-amber-100 transition"
                  >
                    Snooze Selected
                  </button>
                  <button
                    onClick={() => handleBulkAction('resolve')}
                    className="px-3 py-1 bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200 text-sm rounded hover:bg-emerald-100 transition"
                  >
                    Resolve Selected
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Clear All Button */}
          <div className="mb-4">
          <button
              onClick={() => {
                setFilters({ severity: '', type: '', status: '' });
                setSearchQuery('');
                setSelectedAlerts([]);
              }}
              className="px-4 py-2 bg-slate-100 text-slate-700 ring-1 ring-slate-200 rounded-lg hover:bg-slate-200 transition"
            >
              Clear All
          </button>
        </div>

          {/* Alerts Table */}
          <div className="overflow-x-auto max-h-96 overflow-y-auto custom-scrollbar">
              <table className="min-w-full divide-y divide-slate-200">
              <thead className="bg-slate-50">
                <tr>
                  <th className="px-3 py-3 text-left">
                    <input
                      type="checkbox"
                      checked={selectedAlerts.length === filteredAlerts.length && filteredAlerts.length > 0}
                      onChange={handleSelectAll}
                      className="rounded border-slate-300 text-violet-600 focus:ring-violet-500"
                    />
                  </th>
                  <th className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider cursor-pointer" onClick={() => requestSort('timestamp')}>
                    Time {getSortIndicator('timestamp')}
                  </th>
                  <th className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider cursor-pointer" onClick={() => requestSort('title')}>
                    Title {getSortIndicator('title')}
                  </th>
                  <th className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider cursor-pointer" onClick={() => requestSort('source')}>
                    Source {getSortIndicator('source')}
                  </th>
                  <th className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider cursor-pointer" onClick={() => requestSort('type')}>
                    Type {getSortIndicator('type')}
                  </th>
                  <th className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider cursor-pointer" onClick={() => requestSort('severity')}>
                    Severity {getSortIndicator('severity')}
                  </th>
                  <th className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider cursor-pointer" onClick={() => requestSort('status')}>
                    Status {getSortIndicator('status')}
                  </th>
                  <th className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                    IP Addresses
                  </th>
                  <th className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                    Assignment
                  </th>
                  <th className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                    Actions
                  </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-slate-200">
                {filteredAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => setDrawerAlertId(alert.id)}
                    className="hover:bg-violet-50/40 cursor-pointer transition"
                  >
                    <td
                      className="px-3 py-4 whitespace-nowrap"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <input
                        type="checkbox"
                        checked={selectedAlerts.includes(alert.id)}
                        onChange={() => handleSelectAlert(alert.id)}
                        className="rounded border-slate-300 text-violet-600 focus:ring-violet-500"
                      />
                    </td>
                    <td className="px-3 py-4 whitespace-nowrap text-sm text-slate-900">
                        {new Date(alert.timestamp).toLocaleString()}
                      </td>
                    <td className="px-3 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-slate-900">{alert.title}</div>
                      {alert.description && (
                        <div className="text-sm text-slate-500 truncate max-w-xs">{alert.description}</div>
                      )}
                    </td>
                    <td className="px-3 py-4 whitespace-nowrap text-sm text-slate-900">
                        {alert.source}
                      </td>
                    <td className="px-3 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${typeBadgeColor(alert.type)}`}>
                          {alert.type}
                        </span>
                      </td>
                    <td className="px-3 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityBadgeColor(alert.severity)}`}>
                          {alert.severity}
                        </span>
                      </td>
                    <td className="px-3 py-4 whitespace-nowrap">
                      <div className="flex flex-col gap-1 items-start">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusBadgeColor(alert.status)}`}>
                          {alert.status}
                        </span>
                        {(() => {
                          const sla = computeSla(alert);
                          if (sla.kind === 'none') return null;
                          return (
                            <span
                              className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold ring-1 ${slaBadgeClass(sla.kind)}`}
                              title={`SLA: ${SLA_MS[alert.severity]! / 3600000}h window`}
                            >
                              {sla.kind === 'breached' && <span>!</span>}
                              {sla.label}
                            </span>
                          );
                        })()}
                      </div>
                    </td>
                    <td className="px-3 py-4 whitespace-nowrap text-sm text-slate-900">
                      <div className="text-xs">
                        {alert.sourceIp && <div>From: {alert.sourceIp}</div>}
                        {alert.destinationIp && <div>To: {alert.destinationIp}</div>}
                        {!alert.sourceIp && !alert.destinationIp && <div className="text-slate-400">N/A</div>}
                      </div>
                    </td>
                    <td
                      className="px-3 py-4 whitespace-nowrap"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {/* Current assignment + "me" shortcut. Showing who
                          it's assigned to next to the dropdown saves the
                          analyst a click when the owner is already them. */}
                      <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[11px] text-slate-600 truncate max-w-[9rem]" title={alert.assignedTo ?? 'Unassigned'}>
                            {alert.assignedTo && alert.assignedTo !== 'Unassigned' ? alert.assignedTo : <span className="text-slate-400">Unassigned</span>}
                          </span>
                          {alert.assignedTo !== currentUserName && (
                            <button
                              type="button"
                              onClick={(e) => { e.stopPropagation(); void handleAssignToMe(alert.id); }}
                              className="px-1.5 py-0.5 rounded text-[10px] font-semibold text-violet-700 bg-violet-50 ring-1 ring-violet-200 hover:bg-violet-100 transition"
                              title="Assign to me"
                            >
                              me
                            </button>
                          )}
                        </div>
                        <select
                          className="border border-slate-300 rounded px-2 py-1 text-xs"
                          defaultValue=""
                          onChange={(e) => {
                            // Handle assignment logic here
                            console.log(`Assigning alert ${alert.id} to ${e.target.value}`);
                          }}
                        >
                          <option value="">Assign team…</option>
                          <option value="security-team-a">Security Team A</option>
                          <option value="security-team-b">Security Team B</option>
                          <option value="network-team">Network Team</option>
                          <option value="it-support">IT Support</option>
                          <option value="compliance-team">Compliance Team</option>
                        </select>
                      </div>
                    </td>
                    <td
                      className="px-3 py-4 whitespace-nowrap text-sm font-medium"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => setDrawerAlertId(alert.id)}
                          className="text-violet-700 hover:text-violet-900 text-xs font-semibold"
                          title="Open details"
                        >
                          Details
                        </button>
                        {alert.status === 'NEW' && (
                            <button
                              onClick={() => handleAction(alert.id, 'acknowledge')}
                            className="text-violet-700 hover:text-violet-900 text-xs"
                            >
                              Acknowledge
                            </button>
                        )}
                        {alert.status === 'ACKNOWLEDGED' && (
                            <button
                              onClick={() => handleAction(alert.id, 'snooze')}
                            className="text-amber-600 hover:text-amber-900 text-xs"
                            >
                              Snooze
                            </button>
                        )}
                        {alert.status === 'IN_PROGRESS' && (
                            <button
                              onClick={() => handleAction(alert.id, 'resolve')}
                            className="text-emerald-600 hover:text-emerald-900 text-xs"
                            >
                              Resolve
                            </button>
                        )}
                            <button
                          onClick={() => downloadJSON(alert)}
                          className="text-slate-600 hover:text-slate-900 text-xs"
                            >
                          Download
                            </button>
                            <button
                          onClick={() => viewAudit(alert.id)}
                          className="text-violet-700 hover:text-violet-900 text-xs"
                            >
                          Audit
                            </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {filteredAlerts.length > 0 && (
            <div className="mt-4 flex items-center justify-between">
              <div className="text-sm text-slate-700">
                Showing {Math.min((currentPage - 1) * pageSize + 1, filteredAlerts.length)} to {Math.min(currentPage * pageSize, filteredAlerts.length)} of {filteredAlerts.length} results
              </div>
              <div className="flex items-center space-x-2">
                          <button
                  onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-1 border border-slate-300 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50"
                          >
                  Previous
                          </button>
                <span className="text-sm text-slate-700">
                  Page {currentPage} of {Math.ceil(filteredAlerts.length / pageSize)}
                </span>
                <button
                  onClick={() => setCurrentPage(Math.min(Math.ceil(filteredAlerts.length / pageSize), currentPage + 1))}
                  disabled={currentPage >= Math.ceil(filteredAlerts.length / pageSize)}
                  className="px-3 py-1 border border-slate-300 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Combined Alert Correlation and Threat Intelligence Enrichment */}
        <div className="bg-white shadow-lg rounded-lg p-6 mb-6 ring-1 ring-slate-200">
          {/* Tab Navigation */}
          <div className="flex space-x-1 mb-6 border-b border-slate-200">
                        <button
              onClick={() => setActiveTab('analytics')}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                activeTab === 'analytics'
                  ? 'bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white border-b-2 border-violet-500'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              Alert Analytics & Reporting
                        </button>
            <button
              onClick={() => setActiveTab('correlation')}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                activeTab === 'correlation'
                  ? 'bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white border-b-2 border-violet-500'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              Alert Correlation
            </button>
            <button
              onClick={() => setActiveTab('enrichment')}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                activeTab === 'enrichment'
                  ? 'bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white border-b-2 border-violet-500'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              Threat Intelligence Enrichment
            </button>
            <button
              onClick={() => setActiveTab('hunting')}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                activeTab === 'hunting'
                  ? 'bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white border-b-2 border-violet-500'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              Threat Hunting
            </button>
            <button
              onClick={() => setActiveTab('incident')}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                activeTab === 'incident'
                  ? 'bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white border-b-2 border-violet-500'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              Incident Response
            </button>
            <button
              onClick={() => setActiveTab('responseTime')}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                activeTab === 'responseTime'
                  ? 'bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white border-b-2 border-violet-500'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              Alert Response Time Metrics
            </button>

          </div>

          {/* Tab Content */}
          {activeTab === 'correlation' && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold text-slate-800">Alert Correlation</h2>
                <div className="flex items-center space-x-4">
                  <span className="text-sm text-slate-600">
                    {correlationView === 'groups' ? `${correlationGroups.length} correlation groups found` : 'Individual alerts view'}
                  </span>
                  <button
                    onClick={handleCorrelationViewToggle}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                      correlationView === 'groups'
                        ? 'bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white hover:shadow-md'
                        : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                    }`}
                  >
                    {correlationView === 'list' ? 'Show Correlations' : 'Show Individual'}
                  </button>
                </div>
              </div>

              {correlationView === 'groups' && correlationGroups.length > 0 ? (
                <div className="max-h-96 overflow-y-auto custom-scrollbar space-y-4 pr-2">
                  {correlationGroups.map((group) => (
                    <div
                      key={group.id}
                      className={`p-4 rounded-lg border-2 transition-all hover:shadow-lg ${
                        group.severity === 'CRITICAL' ? 'border-rose-300 bg-rose-50' :
                        group.severity === 'HIGH' ? 'border-orange-300 bg-orange-50' :
                        group.severity === 'MEDIUM' ? 'border-amber-300 bg-amber-50' :
                        group.severity === 'LOW' ? 'border-emerald-300 bg-emerald-50' :
                        'border-slate-200 bg-slate-50'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <h3 className="text-lg font-semibold text-slate-800">{group.name}</h3>
                          <p className="text-sm text-slate-600">{group.pattern}</p>
                        </div>
                        <div className="text-right">
                          <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${
                            group.severity === 'CRITICAL' ? 'bg-rose-100 text-rose-700' :
                            group.severity === 'HIGH' ? 'bg-orange-100 text-orange-700' :
                            group.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-700' :
                            group.severity === 'LOW' ? 'bg-emerald-100 text-emerald-700' :
                            'bg-slate-100 text-slate-700'
                          }`}>
                            {group.severity}
                          </div>
                          <div className="text-2xl font-bold text-slate-700 mt-1">{group.count}</div>
                          <div className="text-xs text-slate-500">alerts</div>
                        </div>
                      </div>

                      <div className="space-y-2">
                        {group.alerts.slice(0, 3).map((alert) => (
                          <div key={alert.id} className="flex items-center justify-between p-2 bg-white rounded border">
                            <div className="flex-1">
                              <div className="font-medium text-sm text-slate-800">{alert.title}</div>
                              <div className="text-xs text-slate-500">{alert.source} • {new Date(alert.timestamp).toLocaleString()}</div>
                            </div>
                            <div className="flex items-center space-x-2">
                              <span className={`px-2 py-1 rounded-full text-xs font-medium ${severityBadgeColor(alert.severity)}`}>
                                {alert.severity}
                              </span>
                              <span className={`px-2 py-1 rounded-full text-xs font-medium ${typeBadgeColor(alert.type)}`}>
                                {alert.type}
                              </span>
                            </div>
                          </div>
                        ))}
                        {group.alerts.length > 3 && (
                          <div className="text-center text-sm text-slate-500 py-2">
                            +{group.alerts.length - 3} more alerts
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : correlationView === 'groups' ? (
                <div className="text-center py-8 text-slate-500">
                  <div className="text-4xl mb-2">🔍</div>
                  <p>No correlation patterns found</p>
                  <p className="text-sm">Try switching to individual view or check if you have multiple related alerts</p>
                </div>
              ) : null}
            </div>
          )}

          {activeTab === 'enrichment' && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-slate-800">Threat Intelligence Enrichment</h3>
                <div className="flex items-center space-x-4">
                  {/* Debug display - temporary */}
                  <div className="text-xs text-slate-500 bg-slate-100 px-2 py-1 rounded">
                    Debug: enrichmentData.size = {enrichmentData.size}
                  </div>
                  <span className="text-sm text-slate-600">
                    {Array.from(enrichmentData.keys()).length} IP addresses enriched
                  </span>
                  <div className="text-xs text-slate-500 bg-amber-100 px-2 py-1 rounded">
                    {enrichmentData.size > 0 ? 
                      `${enrichmentSummary.maliciousCount} malicious, ${enrichmentSummary.suspiciousCount} suspicious` : 
                      'No data yet'
                    }
                  </div>
                        <button
                    onClick={async () => {
                      // If details are showing, just hide them
                      if (showEnrichmentDetails) {
                        setShowEnrichmentDetails(false);
                        return;
                      }
                      
                      // If details are hidden, show them and enrich IPs
                      setShowEnrichmentDetails(true);
                      setEnrichmentLoading(true);
                      console.log('Starting enrichment process...');
                      
                      // Get unique IP addresses from alerts
                      const uniqueIPs = new Set([
                        ...alerts.map(alert => alert.sourceIp).filter((ip): ip is string => Boolean(ip)),
                        ...alerts.map(alert => alert.destinationIp).filter((ip): ip is string => Boolean(ip))
                      ]);
                      
                      console.log('Unique IPs found:', Array.from(uniqueIPs));
                      
                      // Check if there are any IPs to enrich
                      if (uniqueIPs.size === 0) {
                        console.log('No IPs found to enrich');
                        setEnrichmentLoading(false);
                        // Show a message that there are no IPs to enrich
                        alert('No IP addresses found in alerts to enrich. Please ensure your alerts contain source or destination IP addresses.');
                        return;
                      }
                      
                      const newEnrichmentData = new Map();
                      
                      // Enrich each IP address
                      for (const ip of Array.from(uniqueIPs)) {
                        try {
                          console.log(`Enriching IP: ${ip}`);
                          const data = await enrichIPAddress(ip);
                          console.log(`Enrichment result for ${ip}:`, data);
                          newEnrichmentData.set(ip, data);
                        } catch (error) {
                          console.error(`Error enriching IP ${ip}:`, error);
                          // Add fallback data for failed enrichments
                          const fallbackData = getFallbackEnrichmentData(ip);
                          fallbackData.error = error instanceof Error ? error.message : 'Unknown error';
                          newEnrichmentData.set(ip, fallbackData);
                        }
                      }
                      
                      console.log('Final enrichment data map:', newEnrichmentData);
                      console.log('Enrichment data size:', newEnrichmentData.size);
                      console.log('Enrichment data entries:', Array.from(newEnrichmentData.entries()));
                      
                      // Ensure the state is updated correctly
                      setEnrichmentData(new Map(newEnrichmentData));
                      setEnrichmentLoading(false);
                      
                      // Force a re-render to ensure UI updates
                      setTimeout(() => {
                        console.log('State update verification - enrichmentData size:', newEnrichmentData.size);
                        console.log('State update verification - showEnrichmentDetails:', showEnrichmentDetails);
                      }, 100);
                      
                      console.log('=== ENRICHMENT PROCESS COMPLETE ===');
                    }}
                    className={`px-4 py-2 rounded-lg transition duration-200 flex items-center space-x-2 text-white ${
                      enrichmentLoading
                        ? 'bg-slate-400 cursor-not-allowed'
                        : 'bg-gradient-to-r from-violet-500 to-fuchsia-500 hover:shadow-md'
                    }`}
                    disabled={enrichmentLoading}
                  >
                    {enrichmentLoading ? 'Enriching...' : (showEnrichmentDetails ? 'Hide Details' : 'Enrich All IPs')}
                        </button>
                </div>
              </div>

              {/* Enrichment Summary Cards */}
              {enrichmentData.size > 0 && (
                <div className="grid grid-cols-4 gap-4 mb-6">
                  <div className="bg-rose-50 border-l-4 border-rose-400 p-4 rounded shadow-sm">
                    <div className="text-2xl font-bold text-rose-600">
                      {enrichmentSummary.maliciousCount}
                    </div>
                    <div className="text-sm text-rose-500 font-medium">Malicious IPs</div>
                  </div>
                  <div className="bg-orange-50 border-l-4 border-orange-400 p-4 rounded shadow-sm">
                    <div className="text-2xl font-bold text-orange-600">
                      {enrichmentSummary.suspiciousCount}
                    </div>
                    <div className="text-sm text-orange-500 font-medium">Suspicious IPs</div>
                  </div>
                  <div className="bg-emerald-50 border-l-4 border-emerald-400 p-4 rounded shadow-sm">
                    <div className="text-2xl font-bold text-emerald-600">
                      {enrichmentSummary.cleanCount}
                    </div>
                    <div className="text-sm text-emerald-500 font-medium">Clean IPs</div>
                  </div>
                  <div className="bg-violet-50 border-l-4 border-violet-400 p-4 rounded shadow-sm">
                    <div className="text-2xl font-bold text-violet-600">
                      {enrichmentSummary.threatTypesCount}
                    </div>
                    <div className="text-sm text-violet-500 font-medium">Threat Types</div>
                  </div>
                </div>
              )}

              {/* Show placeholder when no enrichment data */}
              {enrichmentData.size === 0 && showEnrichmentDetails && !enrichmentLoading && (
                <div className="text-center py-8 text-slate-500 mb-6">
                  <div className="text-4xl mb-2">🔍</div>
                  <p>No IP addresses have been enriched yet.</p>
                  <p className="text-sm">Click "Enrich All IPs" to start the enrichment process.</p>
                </div>
              )}

              {/* Show loading state when enrichment is in progress */}
              {enrichmentLoading && showEnrichmentDetails && (
                <div className="text-center py-8 text-slate-500 mb-6">
                  <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-violet-600 mb-4"></div>
                  <p className="text-lg text-slate-600">Enriching IP addresses...</p>
                  <p className="text-sm text-slate-500 mt-2">Please wait while we gather threat intelligence data from multiple sources</p>
                  <div className="mt-4 text-xs text-slate-400">
                    <p>Fetching from: VirusTotal, AbuseIPDB, IP Geolocation, Local Database</p>
                  </div>
                </div>
              )}

              {/* Enriched IP Details */}
              {showEnrichmentDetails && (
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-slate-800 mb-3">Enriched IP Addresses</h3>
                  {Array.from(enrichmentData.entries()).length > 0 ? (
                    <div className="max-h-96 overflow-y-auto pr-2 space-y-4 custom-scrollbar">
                      {Array.from(enrichmentData.entries()).map(([ip, data]) => {
                        // Debug logging to help identify data structure issues
                        console.log(`Enrichment data for IP ${ip}:`, data);
                        console.log(`threatTypes type:`, typeof data.threatTypes, 'value:', data.threatTypes);
                        
                        return (
                          <div key={ip} className="bg-slate-50 rounded-lg p-4 ring-1 ring-slate-200">
                            <div className="flex items-center justify-between mb-3">
                              <h4 className="text-lg font-medium text-slate-800">{ip}</h4>
                              <div className="flex items-center space-x-2">
                                <span className={`px-2 py-1 rounded-full text-xs font-medium ${getEnrichmentColor(data.ipReputation)}`}>
                                  {data.ipReputation.toUpperCase()}
                                </span>
                                <span className="text-sm text-slate-600">Score: {data.threatScore}</span>
                                {data.source && data.source.includes('Development Mode') && (
                                  <span className="px-2 py-1 bg-amber-100 text-amber-700 text-xs rounded-full font-medium">
                                    🔄 Dev Fallback
                                  </span>
                                )}
                              </div>
                            </div>
                            
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                              <div>
                                <span className="text-slate-500">Location:</span>
                                <p className="font-medium">{data.city}, {data.country}</p>
                                <p className="text-xs text-slate-400">Debug: city="{data.city}", country="{data.country}"</p>
                                {data.source && data.source.includes('Development Mode') && (
                                  <p className="text-xs text-amber-600">🔄 Dev fallback data</p>
                                )}
                              </div>
                              <div>
                                <span className="text-slate-500">ISP:</span>
                                <p className="font-medium">{data.isp}</p>
                                {data.source && data.source.includes('Development Mode') && (
                                  <p className="text-xs text-amber-600">🔄 Dev fallback data</p>
                                )}
                              </div>
                              <div>
                                <span className="text-slate-500">Last Seen:</span>
                                <p className="font-medium">{new Date(data.lastSeen).toLocaleDateString()}</p>
                              </div>
                              <div>
                                <span className="text-slate-500">Confidence:</span>
                                <p className="font-medium">{data.confidence}%</p>
                              </div>
                            </div>
                            
                            {Array.isArray(data.threatTypes) && data.threatTypes.length > 0 && (
                              <div className="mt-3">
                                <span className="text-slate-500 text-sm">Threat Types:</span>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {data.threatTypes.map((type: string, index: number) => (
                                    <span key={index} className="px-2 py-1 bg-rose-100 text-rose-700 text-xs rounded-full">
                                      {type}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                            
                            {/* Data Sources */}
                            {data.sources && data.sources.length > 0 && (
                              <div className="mt-3">
                                <span className="text-slate-500 text-sm">Data Sources:</span>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {data.sources.map((source: string, index: number) => (
                                    <span key={index} className="px-2 py-1 bg-emerald-100 text-emerald-700 text-xs rounded-full">
                                      {source}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                            
                            {/* Raw Data Toggle */}
                            <div className="mt-3">
                              <details className="text-sm">
                                <summary className="cursor-pointer text-slate-600 hover:text-slate-800 font-medium">
                                  📊 Raw Data
                                </summary>
                                <div className="mt-2 p-3 bg-slate-100 rounded text-xs font-mono overflow-x-auto">
                                  <pre>{JSON.stringify(data.rawData, null, 2)}</pre>
                                </div>
                              </details>
                            </div>
                            
                            {/* Error Display */}
                            {data.error && (
                              <div className="mt-3 p-2 bg-rose-50 ring-1 ring-rose-200 rounded">
                                <span className="text-xs text-rose-600 font-medium">⚠️ Enrichment Error:</span>
                                <p className="text-xs text-rose-500 mt-1">{data.error}</p>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ) : !enrichmentLoading && (
                    <div className="text-center py-8 text-slate-500">
                      <div className="text-4xl mb-2">📊</div>
                      <p>No enrichment data available.</p>
                      <p className="text-sm">Click "Enrich All IPs" to gather threat intelligence data.</p>
                    </div>
                  )}
                </div>
              )}

              {/* API Configuration Info */}
              <div className="bg-violet-50 ring-1 ring-violet-200 rounded-lg p-4 mb-6">
                <h4 className="text-sm font-medium text-violet-700 mb-2">🔑 API Configuration</h4>
                <div className="text-xs text-violet-700 space-y-1">
                  <p><strong>VirusTotal:</strong> ✅ Configured (API Key Active)</p>
                  <p><strong>AbuseIPDB:</strong> ✅ Configured (API Key Active)</p>
                  <p><strong>IP Geolocation:</strong> ✅ Multiple Services + CORS Proxy</p>
                  <p><strong>Local Database:</strong> ✅ Available</p>
                </div>
                <div className="mt-2 text-xs text-violet-600">
                  <p><strong>VirusTotal Status:</strong> ✅ Active - Threat intelligence data will be fetched</p>
                  <p><strong>AbuseIPDB Status:</strong> ✅ Active - IP reputation data will be fetched</p>
                  <p><strong>Geolocation Status:</strong> ✅ Active - Multiple reliable proxies + 5s timeout</p>
                </div>
                <div className="mt-2 text-xs text-violet-600">
                  <p><strong>Note:</strong> Both VirusTotal and AbuseIPDB APIs are now active! Full threat intelligence and reputation data will be provided.</p>
                  <p><strong>CORS Note:</strong> Geolocation uses multiple reliable proxy services with timeout handling.</p>
                  <p><strong>Fallback:</strong> If all proxies fail, development fallback data will be provided.</p>
                  <p><strong>Timeout:</strong> Each service has a 5-second timeout to prevent long waits.</p>
                  {isDevelopment() && (
                    <div className="mt-2 p-2 bg-amber-50 ring-1 ring-amber-200 rounded">
                      <p className="text-amber-700"><strong>🔄 Development Mode Active:</strong></p>
                      <p className="text-amber-700">• Enhanced fallback data will be provided when APIs fail</p>
                      <p className="text-amber-700">• Mock threat intelligence data for testing</p>
                      <p className="text-amber-700">• Realistic geolocation fallbacks</p>
                    </div>
                  )}
                </div>
              </div>



              {/* Enrichment Instructions */}
              {!showEnrichmentDetails && (
                <div className="text-center py-8 text-slate-500">
                  <div className="text-4xl mb-2">🔍</div>
                  <p>Click "Enrich All IPs" to get threat intelligence data</p>
                  <p className="text-sm">
                    This will analyze all IP addresses in your alerts and provide detailed threat intelligence information
                  </p>
                </div>
              )}

              {/* Debug Information */}
              {showEnrichmentDetails && (
                <div className="bg-slate-100 border border-slate-300 rounded-lg p-3 mb-4 text-xs text-slate-600">
                  <p><strong>Debug Info:</strong></p>
                  <p>enrichmentData.size: {enrichmentData.size}</p>
                  <p>enrichmentLoading: {enrichmentLoading ? 'true' : 'false'}</p>
                  <p>showEnrichmentDetails: {showEnrichmentDetails ? 'true' : 'false'}</p>
                  <p>Unique IPs found: {Array.from(new Set([
                    ...alerts.map(alert => alert.sourceIp).filter(Boolean),
                    ...alerts.map(alert => alert.destinationIp).filter(Boolean)
                  ])).length}</p>
                </div>
              )}

              {/* Show placeholder when no enrichment data */}
              {enrichmentData.size === 0 && showEnrichmentDetails && !enrichmentLoading && (
                <div className="text-center py-8 text-slate-500 mb-6">
                  <div className="text-4xl mb-2">🔍</div>
                  <p>No IP addresses have been enriched yet.</p>
                  <p className="text-sm">Click "Enrich All IPs" to start the enrichment process.</p>
                </div>
              )}

              {/* Enrichment Summary and Status */}
              {showEnrichmentDetails && enrichmentData.size > 0 && (
                <div className="bg-violet-50 ring-1 ring-violet-200 rounded-lg p-4 mb-6">
                  <h4 className="text-sm font-medium text-violet-700 mb-2">📊 Enrichment Summary</h4>
                  <div className="text-xs text-violet-700 space-y-1">
                    <p><strong>Total IPs Enriched:</strong> {enrichmentData.size}</p>
                    <p><strong>Development Mode:</strong> {isDevelopment() ? '✅ Active' : '❌ Inactive'}</p>
                    {isDevelopment() && (
                      <p><strong>Fallback Data:</strong> Available for testing when APIs fail</p>
                    )}
                    <p><strong>Data Sources:</strong> VirusTotal, AbuseIPDB, IP Geolocation, Local Database</p>
                  </div>
                  {isDevelopment() && (
                    <div className="mt-2 p-2 bg-amber-50 ring-1 ring-amber-200 rounded">
                      <p className="text-amber-700 text-xs"><strong>💡 Development Note:</strong></p>
                      <p className="text-amber-700 text-xs">• Yellow "🔄 Dev Fallback" badges indicate mock data for testing</p>
                      <p className="text-amber-700 text-xs">• This allows you to test the UI without external API dependencies</p>
                      <p className="text-amber-700 text-xs">• In production, real threat intelligence data will be used</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'analytics' && (
            <div>
              <h2 className="text-xl font-semibold text-slate-800 mb-4">Alert Analytics & Reporting</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                 {/* Severity Distribution Chart */}
                 <div className="bg-white p-6 rounded-lg shadow-md">
                   <h3 className="text-lg font-semibold text-slate-800 mb-4">Alert Severity Distribution</h3>
                   <div className="flex items-center justify-between mb-4">
                     <span className="text-sm text-slate-600">Total Alerts: {alerts.length}</span>
                     <span className="text-sm text-slate-600">Critical: {alerts.filter(a => a.severity === 'CRITICAL').length}</span>
                     <span className="text-sm text-slate-600">High: {alerts.filter(a => a.severity === 'HIGH').length}</span>
                     <span className="text-sm text-slate-600">Medium: {alerts.filter(a => a.severity === 'MEDIUM').length}</span>
                     <span className="text-sm text-slate-600">Low: {alerts.filter(a => a.severity === 'LOW').length}</span>
                   </div>
                   <div className="h-64 w-full">
                     <Bar 
                       data={severityChartData}
                       options={{
                         responsive: true,
                         maintainAspectRatio: false,
                         animation: {
                           duration: 2000,
                           easing: 'easeInOutQuart',
                           onProgress: function(animation) {
                             const chart = animation.chart;
                             const ctx = chart.ctx;
                             const dataset = chart.data.datasets[0];
                             const meta = chart.getDatasetMeta(0);
                             
                             if (meta.data) {
                               meta.data.forEach((bar, index) => {
                                 const value = dataset.data[index];
                                 if (typeof value === 'number' && value > 0) {
                                   ctx.save();
                                   ctx.textAlign = 'center';
                                   ctx.textBaseline = 'bottom';
                                   ctx.font = '12px Arial';
                                   ctx.fillStyle = '#374151';
                                   ctx.fillText(value.toString(), bar.x, bar.y - 5);
                                   ctx.restore();
                                 }
                               });
                             }
                           }
                         },
                         plugins: {
                           legend: {
                             display: false,
                           },
                           title: {
                             display: false,
                           },
                           tooltip: {
                             backgroundColor: 'rgba(0, 0, 0, 0.8)',
                             titleColor: '#fff',
                             bodyColor: '#fff',
                             borderColor: '#374151',
                             borderWidth: 1,
                             cornerRadius: 8,
                             displayColors: true,
                             callbacks: {
                               label: function(context) {
                                 return `Alerts: ${context.parsed.y}`;
                               }
                             }
                           }
                         },
                         scales: {
                           y: {
                             beginAtZero: true,
                             ticks: {
                               stepSize: 1,
                               font: {
                                 size: 12
                               },
                               color: '#6B7280'
                             },
                             grid: {
                               color: 'rgba(107, 114, 128, 0.1)'
                             }
                           },
                           x: {
                             ticks: {
                               font: {
                                 size: 11
                               },
                               color: '#374151'
                             },
                             grid: {
                               display: false
                             }
                           }
                         },
                         interaction: {
                           intersect: false,
                           mode: 'index'
                         },
                         elements: {
                           bar: {
                             borderRadius: 6,
                             borderSkipped: false
                           }
                         }
                       }}
                     />
                   </div>
                 </div>

                                 {/* Type Distribution Chart */}
                 <div className="bg-white p-6 rounded-lg shadow-md">
                   <h3 className="text-lg font-semibold text-slate-800 mb-4">Alert Type Distribution</h3>
                   <div className="flex items-center justify-between mb-4">
                     <span className="text-sm text-slate-600">Total Alerts: {alerts.length}</span>
                     <span className="text-sm text-slate-600">Anomaly: {alerts.filter(a => a.type === 'ANOMALY').length}</span>
                     <span className="text-sm text-slate-600">IOA: {alerts.filter(a => a.type === 'IOA').length}</span>
                     <span className="text-sm text-slate-600">Honeypot: {alerts.filter(a => a.type === 'HONEYPOT').length}</span>
                     <span className="text-sm text-slate-600">Threat Intelligence: {alerts.filter(a => a.type === 'THREAT_INTELLIGENCE').length}</span>
                   </div>
                   <div className="h-64 w-full">
                     <Doughnut 
                       data={typeChartData}
                       options={{
                         responsive: true,
                         maintainAspectRatio: false,
                         animation: {
                           duration: 2500,
                           easing: 'easeInOutBack',
                           animateRotate: true,
                           animateScale: true
                         },
                         plugins: {
                           legend: {
                             position: 'bottom',
                             labels: {
                               boxWidth: 12,
                               padding: 15,
                               font: {
                                 size: 10,
                               },
                               usePointStyle: true,
                               pointStyle: 'circle'
                             },
                           },
                           title: {
                             display: false,
                           },
                           tooltip: {
                             backgroundColor: 'rgba(0, 0, 0, 0.9)',
                             titleColor: '#fff',
                             bodyColor: '#fff',
                             borderColor: '#374151',
                             borderWidth: 1,
                             cornerRadius: 8,
                             displayColors: true,
                             callbacks: {
                               label: function(context) {
                                 const total = context.dataset.data.reduce((a: number, b: number) => a + b, 0);
                                 const percentage = ((context.parsed / total) * 100).toFixed(1);
                                 return `${context.label}: ${context.parsed} (${percentage}%)`;
                               }
                             }
                           }
                         },
                         elements: {
                           arc: {
                             borderWidth: 2,
                             borderColor: '#fff',
                             borderRadius: 4
                           }
                         },
                         cutout: '60%'
                       }}
                     />
                   </div>
                 </div>

                                 {/* Status Distribution Chart */}
                 <div className="bg-white p-6 rounded-lg shadow-md">
                   <h3 className="text-lg font-semibold text-slate-800 mb-4">Alert Status Distribution</h3>
                   <div className="flex items-center justify-between mb-4">
                     <span className="text-sm text-slate-600">Total Alerts: {alerts.length}</span>
                     <span className="text-sm text-slate-600">New: {alerts.filter(a => a.status === 'NEW').length}</span>
                     <span className="text-sm text-slate-600">Acknowledged: {alerts.filter(a => a.status === 'ACKNOWLEDGED').length}</span>
                     <span className="text-sm text-slate-600">In Progress: {alerts.filter(a => a.status === 'IN_PROGRESS').length}</span>
                     <span className="text-sm text-slate-600">Escalated: {alerts.filter(a => a.status === 'ESCALATED').length}</span>
                     <span className="text-sm text-slate-600">Resolved: {alerts.filter(a => a.status === 'RESOLVED').length}</span>
                     <span className="text-sm text-slate-600">Closed: {alerts.filter(a => a.status === 'CLOSED').length}</span>
                     <span className="text-sm text-slate-600">False Positive: {alerts.filter(a => a.status === 'FALSE_POSITIVE').length}</span>
                   </div>
                   <div className="h-64 w-full">
                     <Bar 
                       data={statusChartData}
                       options={{
                         responsive: true,
                         maintainAspectRatio: false,
                         animation: {
                           duration: 1800,
                           easing: 'easeOutBounce',
                           onProgress: function(animation) {
                             const chart = animation.chart;
                             const ctx = chart.ctx;
                             const dataset = chart.data.datasets[0];
                             const meta = chart.getDatasetMeta(0);
                             
                             if (meta.data) {
                               meta.data.forEach((bar, index) => {
                                 const value = dataset.data[index];
                                 if (typeof value === 'number' && value > 0) {
                                   ctx.save();
                                   ctx.textAlign = 'center';
                                   ctx.textBaseline = 'bottom';
                                   ctx.font = '12px Arial';
                                   ctx.fillStyle = '#374151';
                                   ctx.fillText(value.toString(), bar.x, bar.y - 5);
                                   ctx.restore();
                                 }
                               });
                             }
                           }
                         },
                         plugins: {
                           legend: {
                             display: false,
                           },
                           title: {
                             display: false,
                           },
                           tooltip: {
                             backgroundColor: 'rgba(0, 0, 0, 0.8)',
                             titleColor: '#fff',
                             bodyColor: '#fff',
                             borderColor: '#374151',
                             borderWidth: 1,
                             cornerRadius: 8,
                             displayColors: true,
                             callbacks: {
                               label: function(context) {
                                 return `Alerts: ${context.parsed.y}`;
                               }
                             }
                           }
                         },
                         scales: {
                           y: {
                             beginAtZero: true,
                             ticks: {
                               stepSize: 1,
                               font: {
                                 size: 12
                               },
                               color: '#6B7280'
                             },
                             grid: {
                               color: 'rgba(107, 114, 128, 0.1)'
                             }
                           },
                           x: {
                             ticks: {
                               font: {
                                 size: 11
                               },
                               color: '#374151'
                             },
                             grid: {
                               display: false
                             }
                           }
                         },
                         interaction: {
                           intersect: false,
                           mode: 'index'
                         },
                         elements: {
                           bar: {
                             borderRadius: 6,
                             borderSkipped: false
                           }
                         }
                       }}
                     />
                   </div>
                 </div>

                {/* Recent Activity Table */}
                <div className="bg-white p-6 rounded-lg shadow-md">
                  <h3 className="text-lg font-semibold text-slate-800 mb-4">Recent Activity</h3>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-slate-200">
                      <thead className="bg-slate-50 sticky top-0 z-10">
                        <tr>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Time</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Alert ID</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Action</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Performed By</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-slate-200">
                        {alerts.slice(-10).map(alert => (
                          <tr key={alert.id}>
                            <td className="px-4 py-2 text-sm text-slate-700 whitespace-nowrap">
                              {new Date(alert.timestamp).toLocaleString()}
                            </td>
                            <td className="px-4 py-2 text-sm text-slate-700 whitespace-nowrap font-medium">
                              {alert.id}
                            </td>
                            <td className="px-4 py-2 text-sm text-slate-700 whitespace-nowrap">
                              {alert.status === 'NEW' && 'Acknowledged'}
                              {alert.status === 'ACKNOWLEDGED' && 'Snoozed'}
                              {alert.status === 'IN_PROGRESS' && 'Resolved'}
                              {alert.status === 'ESCALATED' && 'Escalated'}
                              {alert.status === 'RESOLVED' && 'Resolved'}
                              {alert.status === 'CLOSED' && 'Closed'}
                              {alert.status === 'FALSE_POSITIVE' && 'Marked False Positive'}
                            </td>
                            <td className="px-4 py-2 text-sm text-slate-700 whitespace-nowrap">
                              {/* This would ideally be fetched from a backend or a more robust source */}
                              {alert.id.substring(0, 5)}...
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

                {/* Alert Trend Chart */}
                <div className="bg-white p-6 rounded-lg shadow-md col-span-2">
                  <h3 className="text-lg font-semibold text-slate-800 mb-4">Alert Trend (Last 24 Hours)</h3>
                  <div className="h-64 w-full">
                    <Line 
                      data={trendChartData}
                      options={{
                        responsive: true,
                        maintainAspectRatio: false,
                         animation: {
                           duration: 3000,
                           easing: 'easeInOutElastic',
                           onProgress: function(animation) {
                            const chart = animation.chart;
                            const ctx = chart.ctx;
                            const dataset = chart.data.datasets[0];
                            const meta = chart.getDatasetMeta(0);
                            
                            if (meta.data) {
                              meta.data.forEach((point, index) => {
                                const value = dataset.data[index];
                                if (typeof value === 'number' && value > 0) {
                                  ctx.save();
                                  ctx.textAlign = 'center';
                                  ctx.textBaseline = 'bottom';
                                  ctx.font = 'bold 12px Arial';
                                  ctx.fillStyle = '#374151';
                                  ctx.fillText(value.toString(), point.x, point.y - 10);
                                  ctx.restore();
                                }
                              });
                            }
                          }
                        },
                        plugins: {
                          legend: {
                            display: false,
                          },
                          title: {
                            display: false,
                          },
                          tooltip: {
                            backgroundColor: 'rgba(0, 0, 0, 0.9)',
                            titleColor: '#fff',
                            bodyColor: '#fff',
                            borderColor: '#374151',
                            borderWidth: 1,
                            cornerRadius: 8,
                            displayColors: true,
                            callbacks: {
                              label: function(context) {
                                return `Alerts: ${context.parsed.y}`;
                              }
                            }
                          }
                        },
                        scales: {
                          y: {
                            beginAtZero: true,
                            ticks: {
                              stepSize: 1,
                              font: {
                                size: 12
                              },
                              color: '#6B7280'
                            },
                            grid: {
                              color: 'rgba(107, 114, 128, 0.1)'
                            }
                          },
                          x: {
                            ticks: {
                              font: {
                                size: 11
                              },
                              color: '#374151'
                            },
                            grid: {
                              color: 'rgba(107, 114, 128, 0.05)'
                            }
                          }
                        },
                        interaction: {
                          intersect: false,
                          mode: 'index'
                        },
                        elements: {
                          line: {
                            borderJoinStyle: 'round'
                          },
                          point: {
                            hoverRadius: 10,
                            hitRadius: 10
                          }
                        }
                      }}
                    />
        </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'hunting' && (
            <div>
              <h2 className="text-xl font-semibold text-slate-800 mb-4">Threat Hunting</h2>
              
              {/* Hunting Queries Section */}
              <div className="mb-8">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-slate-700">Hunting Queries</h3>
          <button
                    onClick={createHuntingQuery}
                    className="px-4 py-2 bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white rounded-lg hover:shadow-md transition"
          >
                    + New Query
          </button>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {huntingQueries.map((query) => (
                    <div key={query.id} className="bg-white p-4 rounded-lg ring-1 ring-slate-200 shadow-sm">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-medium text-slate-800">{query.name}</h4>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                          query.status === 'active' ? 'bg-emerald-100 text-emerald-700' :
                          query.status === 'paused' ? 'bg-amber-100 text-amber-700' :
                          'bg-slate-100 text-slate-700'
                        }`}>
                          {query.status}
          </span>
                      </div>
                      <p className="text-sm text-slate-600 mb-3">{query.description}</p>
                      <div className="text-xs text-slate-500 mb-3">
                        <div>Last Run: {new Date(query.lastRun).toLocaleString()}</div>
                        <div>Results: {query.results}</div>
                      </div>
                      <div className="flex space-x-2">
          <button
                          onClick={() => runHuntingQuery(query.id)}
                          className="px-3 py-1 bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white text-xs rounded hover:shadow-md transition"
          >
                          Run Query
                        </button>
                        <button className="px-3 py-1 bg-slate-100 text-slate-700 ring-1 ring-slate-200 text-xs rounded hover:bg-slate-200 transition">
                          Edit
          </button>
                      </div>
                    </div>
                  ))}
                </div>
        </div>

              {/* Threat Indicators Section */}
              <div className="mb-8">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-slate-700">Threat Indicators</h3>
                  <button
                    onClick={addThreatIndicator}
                    className="px-4 py-2 bg-rose-50 text-rose-700 ring-1 ring-rose-200 rounded-lg hover:bg-rose-100 transition"
                  >
                    + Add Indicator
                  </button>
                </div>
                
                <div className="bg-white rounded-lg ring-1 ring-slate-200 overflow-hidden">
                  <table className="min-w-full divide-y divide-slate-200">
                    <thead className="bg-slate-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Type</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Value</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Confidence</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Threat Level</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Last Seen</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-slate-200">
                      {threatIndicators.map((indicator) => (
                        <tr key={indicator.id}>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-100 text-emerald-700">
                              {indicator.type.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-slate-900">
                            {indicator.value}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500">
                            {indicator.confidence}%
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              indicator.threatLevel === 'high' ? 'bg-rose-100 text-rose-700' :
                              indicator.threatLevel === 'medium' ? 'bg-amber-100 text-amber-700' :
                              'bg-emerald-100 text-emerald-700'
                            }`}>
                              {indicator.threatLevel.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500">
                            {new Date(indicator.lastSeen).toLocaleDateString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                            <button className="text-violet-700 hover:text-violet-900 mr-3">View</button>
                            <button className="text-rose-600 hover:text-rose-900">Remove</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Investigation Sessions Section */}
              <div className="mb-8">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-slate-700">Investigation Sessions</h3>
              <button
                    onClick={createInvestigationSession}
                    className="px-4 py-2 bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200 rounded-lg hover:bg-emerald-100 transition"
              >
                    + New Investigation
              </button>
                </div>
                
                <div className="space-y-4">
                  {investigationSessions.map((session) => (
                    <div key={session.id} className="bg-white p-4 rounded-lg ring-1 ring-slate-200 shadow-sm">
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <h4 className="font-medium text-slate-800">{session.title}</h4>
                          <p className="text-sm text-slate-600">{session.description}</p>
                        </div>
                        <div className="text-right">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            session.status === 'open' ? 'bg-emerald-100 text-emerald-700' :
                            session.status === 'in_progress' ? 'bg-amber-100 text-amber-700' :
                            'bg-emerald-100 text-emerald-700'
                          }`}>
                            {session.status.replace('_', ' ').toUpperCase()}
                          </span>
                          <div className="text-xs text-slate-500 mt-1">Assigned to: {session.assignedTo}</div>
                        </div>
                      </div>
                      
                      <div className="text-xs text-slate-500 mb-3">
                        Created: {new Date(session.createdAt).toLocaleString()} | 
                        Updated: {new Date(session.updatedAt).toLocaleString()}
                      </div>
                      
                      {session.evidence.length > 0 && (
                        <div className="border-t border-slate-200 pt-3">
                          <h5 className="text-sm font-medium text-slate-700 mb-2">Evidence ({session.evidence.length})</h5>
                          <div className="space-y-2">
                            {session.evidence.map((evidence) => (
                              <div key={evidence.id} className="flex items-center space-x-3 p-2 bg-slate-50 rounded">
                                <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                                  evidence.type === 'log' ? 'bg-emerald-100 text-emerald-700' :
                                  evidence.type === 'alert' ? 'bg-rose-100 text-rose-700' :
                                  evidence.type === 'network' ? 'bg-emerald-100 text-emerald-700' :
                                  evidence.type === 'file' ? 'bg-violet-100 text-violet-700' :
                                  'bg-slate-100 text-slate-700'
                                }`}>
                                  {evidence.type.toUpperCase()}
                                </span>
                                <span className="text-sm text-slate-700 flex-1">{evidence.content}</span>
                                <span className="text-xs text-slate-500">{evidence.source}</span>
                              </div>
                            ))}
            </div>
          </div>
        )}

                      <div className="flex justify-end space-x-2 mt-3 pt-3 border-t border-slate-200">
                        <button className="px-3 py-1 bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white text-sm rounded hover:shadow-md transition">
                          Add Evidence
                        </button>
                        <button className="px-3 py-1 bg-slate-100 text-slate-700 ring-1 ring-slate-200 text-sm rounded hover:bg-slate-200 transition">
                          Update Status
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'incident' && (
            <div className="max-h-96 overflow-y-auto custom-scrollbar pr-2">
              <h2 className="text-xl font-semibold text-slate-800 mb-4">Incident Response</h2>
              
              {/* Incidents Section */}
              <div className="mb-8">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-slate-700">Incidents</h3>
          <button
                    onClick={createIncident}
                    className="px-4 py-2 bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white rounded-lg hover:shadow-md transition"
          >
                    + New Incident
          </button>
        </div>
                
                <div className="space-y-4">
                  {incidents.map((incident) => (
                    <div key={incident.id} className="bg-white p-4 rounded-lg ring-1 ring-slate-200 shadow-sm">
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <h4 className="font-medium text-slate-800">{incident.title}</h4>
                          <p className="text-sm text-slate-600">{incident.description}</p>
                        </div>
                        <div className="text-right">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            incident.status === 'OPEN' ? 'bg-emerald-100 text-emerald-700' :
                            incident.status === 'IN_PROGRESS' ? 'bg-amber-100 text-amber-700' :
                            incident.status === 'ESCALATED' ? 'bg-rose-100 text-rose-700' :
                            'bg-emerald-100 text-emerald-700'
                          }`}>
                            {incident.status.toUpperCase()}
                          </span>
                          <div className="text-xs text-slate-500 mt-1">Assigned to: {incident.assignedTo}</div>
                        </div>
                      </div>
                      
                      <div className="text-xs text-slate-500 mb-3">
                        Created: {new Date(incident.createdAt).toLocaleString()} | 
                        Updated: {new Date(incident.updatedAt).toLocaleString()}
                      </div>
                      
                      <div className="text-sm text-slate-600 mb-3">
                        <strong>Severity:</strong> {incident.severity}
                      </div>
                      
                      <div className="text-sm text-slate-600 mb-3">
                        <strong>Priority:</strong> {incident.priority}
                      </div>
                      
                      <div className="text-sm text-slate-600 mb-3">
                        <strong>Estimated Impact:</strong> {incident.estimatedImpact}
                      </div>
                      
                      <div className="text-sm text-slate-600 mb-3">
                        <strong>Response Time:</strong> {incident.responseTime} minutes
                      </div>
                      
                      <div className="text-sm text-slate-600 mb-3">
                        <strong>MTTR:</strong> {incident.mttr} minutes
                      </div>
                      
                      <div className="text-sm text-slate-600 mb-3">
                        <strong>Tags:</strong> {incident.tags.join(', ')}
                      </div>
                      
                      <div className="text-sm text-slate-600 mb-3">
                        <strong>Notes:</strong>
                        <ul className="list-disc pl-6">
                          {incident.notes.map((note) => (
                            <li key={note.id}>{note.content}</li>
                          ))}
                        </ul>
                      </div>
                      
                      <div className="flex justify-end space-x-2 mt-3 pt-3 border-t border-slate-200">
                        <button className="px-3 py-1 bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white text-sm rounded hover:shadow-md transition">
                          Add Note
                        </button>
                        <button className="px-3 py-1 bg-slate-100 text-slate-700 ring-1 ring-slate-200 text-sm rounded hover:bg-slate-200 transition">
                          Update Status
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Response Procedures Section */}
              <div className="mb-8">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-slate-700">Response Procedures</h3>
                  <button
                    onClick={createResponseProcedure}
                    className="px-4 py-2 bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200 rounded-lg hover:bg-emerald-100 transition"
                  >
                    + New Procedure
                  </button>
                </div>
                
                <div className="space-y-4">
                  {responseProcedures.map((procedure) => (
                    <div key={procedure.id} className="bg-white p-4 rounded-lg ring-1 ring-slate-200 shadow-sm">
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <h4 className="font-medium text-slate-800">{procedure.name}</h4>
                          <p className="text-sm text-slate-600">{procedure.description}</p>
                        </div>
                        <div className="text-right">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            procedure.category === 'INCIDENT_RESPONSE' ? 'bg-emerald-100 text-emerald-700' :
                            procedure.category === 'FORENSICS' ? 'bg-emerald-100 text-emerald-700' :
                            procedure.category === 'COMMUNICATION' ? 'bg-amber-100 text-amber-700' :
                            procedure.category === 'RECOVERY' ? 'bg-orange-100 text-orange-700' :
                            'bg-violet-100 text-violet-700'
                          }`}>
                            {procedure.category.toUpperCase()}
                          </span>
                          <div className="text-xs text-slate-500 mt-1">Last Updated: {new Date(procedure.lastUpdated).toLocaleString()}</div>
                        </div>
                      </div>
                      
                      <div className="text-sm text-slate-600 mb-3">
                        <strong>Steps:</strong>
                        <ul className="list-disc pl-6">
                          {procedure.steps.map((step) => (
                            <li key={step.id}>{step.action}</li>
                          ))}
                        </ul>
                      </div>
                      
                      <div className="text-sm text-slate-600 mb-3">
                        <strong>Estimated Time:</strong> {procedure.steps.reduce((total, step) => total + step.estimatedTime, 0)} minutes
                      </div>
                      
                      <div className="text-sm text-slate-600 mb-3">
                        <strong>Responsible:</strong> {procedure.steps.filter(step => step.completed).length} of {procedure.steps.length} steps completed
                      </div>
                      
                      <div className="flex justify-end space-x-2 mt-3 pt-3 border-t border-slate-200">
                        <button className="px-3 py-1 bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white text-sm rounded hover:shadow-md transition">
                          Add Step
                        </button>
                        <button className="px-3 py-1 bg-slate-100 text-slate-700 ring-1 ring-slate-200 text-sm rounded hover:bg-slate-200 transition">
                          Update Status
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'responseTime' && (
            <div className="max-h-96 overflow-y-auto custom-scrollbar pr-2">
              <h2 className="text-xl font-semibold text-slate-800 mb-4">Alert Response Time Metrics</h2>
              
              {/* Response Time Overview Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-gradient-to-r from-green-500 to-green-600 p-4 rounded-lg text-white">
                  <div className="text-2xl font-bold">2.3 min</div>
                  <div className="text-sm opacity-90">Average Response Time</div>
                </div>
                <div className="bg-gradient-to-r from-blue-500 to-blue-600 p-4 rounded-lg text-white">
                  <div className="text-2xl font-bold">15 min</div>
                  <div className="text-sm opacity-90">Target Response Time</div>
                </div>
                <div className="bg-gradient-to-r from-yellow-500 to-yellow-600 p-4 rounded-lg text-white">
                  <div className="text-2xl font-bold">87%</div>
                  <div className="text-sm opacity-90">SLA Compliance</div>
                </div>
                <div className="bg-gradient-to-r from-purple-500 to-purple-600 p-4 rounded-lg text-white">
                  <div className="text-2xl font-bold">45 min</div>
                  <div className="text-sm opacity-90">Mean Time to Resolution</div>
                </div>
              </div>

              {/* Response Time by Severity */}
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-slate-700 mb-4">Response Time by Severity</h3>
                <div className="bg-white p-4 rounded-lg ring-1 ring-slate-200">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-slate-700">Critical</span>
                      <div className="flex items-center space-x-2">
                        <div className="w-32 bg-slate-200 rounded-full h-2">
                          <div className="bg-rose-500 h-2 rounded-full" style={{ width: '85%' }}></div>
                        </div>
                        <span className="text-sm text-slate-600">1.2 min</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-slate-700">High</span>
                      <div className="flex items-center space-x-2">
                        <div className="w-32 bg-slate-200 rounded-full h-2">
                          <div className="bg-orange-500 h-2 rounded-full" style={{ width: '70%' }}></div>
                        </div>
                        <span className="text-sm text-slate-600">2.8 min</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-slate-700">Medium</span>
                      <div className="flex items-center space-x-2">
                        <div className="w-32 bg-slate-200 rounded-full h-2">
                          <div className="bg-amber-500 h-2 rounded-full" style={{ width: '55%' }}></div>
                        </div>
                        <span className="text-sm text-slate-600">4.1 min</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-slate-700">Low</span>
                      <div className="flex items-center space-x-2">
                        <div className="w-32 bg-slate-200 rounded-full h-2">
                          <div className="bg-violet-500 h-2 rounded-full" style={{ width: '40%' }}></div>
                        </div>
                        <span className="text-sm text-slate-600">6.5 min</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Response Time Trends */}
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-slate-700 mb-4">Response Time Trends (Last 30 Days)</h3>
                <div className="bg-white p-4 rounded-lg ring-1 ring-slate-200">
                  <div className="grid grid-cols-7 gap-2 text-center">
                    {Array.from({ length: 7 }, (_, i) => {
                      const daysAgo = 6 - i;
                      const responseTime = Math.random() * 5 + 1; // Random time between 1-6 minutes
                      return (
                        <div key={i} className="space-y-2">
                          <div className="text-xs text-slate-500">
                            {daysAgo === 0 ? 'Today' : daysAgo === 1 ? '1d ago' : `${daysAgo}d ago`}
                          </div>
                          <div className="text-sm font-medium text-slate-700">{responseTime.toFixed(1)}m</div>
                          <div 
                            className="mx-auto bg-gradient-to-t from-violet-500 to-fuchsia-500 rounded-t"
                            style={{ 
                              height: `${(responseTime / 6) * 40}px`,
                              width: '20px'
                            }}
                          ></div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Performance Metrics */}
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-slate-700 mb-4">Performance Metrics</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-white p-4 rounded-lg ring-1 ring-slate-200">
                    <h4 className="font-medium text-slate-800 mb-3">Response Time Distribution</h4>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-600">0-1 min:</span>
                        <span className="font-medium">35%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-600">1-2 min:</span>
                        <span className="font-medium">28%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-600">2-3 min:</span>
                        <span className="font-medium">22%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-600">3+ min:</span>
                        <span className="font-medium">15%</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="bg-white p-4 rounded-lg ring-1 ring-slate-200">
                    <h4 className="font-medium text-slate-800 mb-3">SLA Performance</h4>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-600">Critical (≤2 min):</span>
                        <span className="font-medium text-emerald-600">95%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-600">High (≤5 min):</span>
                        <span className="font-medium text-emerald-600">88%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-600">Medium (≤15 min):</span>
                        <span className="font-medium text-amber-600">75%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-600">Low (≤30 min):</span>
                        <span className="font-medium text-rose-600">62%</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Team Performance */}
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-slate-700 mb-4">Team Performance</h3>
                <div className="bg-white p-4 rounded-lg ring-1 ring-slate-200">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-slate-700">Security Team A</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm text-slate-600">1.8 min avg</span>
                        <span className="text-xs bg-emerald-100 text-emerald-700 px-2 py-1 rounded">Excellent</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-slate-700">Security Team B</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm text-slate-600">2.4 min avg</span>
                        <span className="text-xs bg-emerald-100 text-emerald-700 px-2 py-1 rounded">Good</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-slate-700">Network Team</span>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-slate-600">3.1 min avg</span>
                        <span className="text-xs bg-amber-100 text-amber-700 px-2 py-1 rounded">Average</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-slate-700">IT Support</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm text-slate-600">4.2 min avg</span>
                        <span className="text-xs bg-rose-100 text-rose-700 px-2 py-1 rounded">Needs Improvement</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}



        </div>
      </div>

      {/* Alert detail drawer — mounted at root so it floats over the
          whole page and doesn't participate in the main grid layout.
          The drawer handles its own Esc / backdrop dismissal. */}
      {drawerAlertId && (() => {
        const a = alerts.find(x => x.id === drawerAlertId);
        if (!a) return null;
        return (
          <AlertDetailDrawer
            alert={a}
            currentUserName={currentUserName}
            onClose={() => setDrawerAlertId(null)}
            onPatch={(patch) => {
              setAlerts(prev => prev.map(x => x.id === drawerAlertId ? { ...x, ...patch } : x));
            }}
          />
        );
      })()}
    </PageShell>
  );
};

// ===========================================================================
// AlertDetailDrawer
//
// Right-side slide-over for a single alert. Shows severity + status +
// SLA in the header, a meta grid with all the backend fields, the full
// description, an audit-trail of analyst notes (add / list), and an
// action bar (acknowledge / resolve / assign to me / escalate / open
// case).
//
// Lives inside Alerts.tsx because it's exclusively used from this
// screen; lifting it into its own file would mean re-exporting a
// handful of Alerts-internal helpers, which isn't worth the churn.
// ===========================================================================

interface AlertDetailDrawerProps {
  alert: Alert;
  currentUserName: string;
  onClose: () => void;
  onPatch: (patch: Partial<Alert>) => void;
}

const AlertDetailDrawer: React.FC<AlertDetailDrawerProps> = ({
  alert, currentUserName, onClose, onPatch,
}) => {
  const [comments, setComments] = useState<AlertComment[]>([]);
  const [commentsLoading, setCommentsLoading] = useState(true);
  const [newNote, setNewNote] = useState('');
  const [postingNote, setPostingNote] = useState(false);
  const [caseLinkBusy, setCaseLinkBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Close on Esc. The drawer is the only modal-ish thing on screen so
  // a global listener is fine.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  // Load comments every time the drawer opens on a different alert.
  useEffect(() => {
    let cancelled = false;
    setCommentsLoading(true);
    (async () => {
      try {
        const res = await api.get(`/api/alert-comments/alert/${alert.id}`);
        // Backend paginates - content array is what we need.
        const data = (res.data?.content ?? res.data ?? []) as AlertComment[];
        if (!cancelled) setComments(Array.isArray(data) ? data : []);
      } catch {
        if (!cancelled) setComments([]);
      } finally {
        if (!cancelled) setCommentsLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [alert.id]);

  const sla = computeSla(alert);

  const postNote = async () => {
    const text = newNote.trim();
    if (!text) return;
    setPostingNote(true);
    setError(null);
    try {
      const body = { content: text, createdBy: currentUserName, commentType: 'INTERNAL' };
      const res = await api.post(`/api/alert-comments/alert/${alert.id}/quick`, body);
      const created = (res.data ?? {
        id: String(Date.now()),
        alertId: alert.id,
        content: text,
        createdBy: currentUserName,
        createdAt: new Date().toISOString(),
      }) as AlertComment;
      setComments(prev => [created, ...prev]);
      setNewNote('');
    } catch (e: unknown) {
      // Optimistically append a client-side note so the analyst doesn't
      // lose their text if the backend endpoint isn't wired yet.
      const offline: AlertComment = {
        id: `local-${Date.now()}`,
        alertId: alert.id,
        content: text,
        createdBy: currentUserName,
        createdAt: new Date().toISOString(),
        commentType: 'INTERNAL',
      };
      setComments(prev => [offline, ...prev]);
      setNewNote('');
      setError(e instanceof Error ? `${e.message} - note saved locally.` : 'Note saved locally.');
    } finally {
      setPostingNote(false);
    }
  };

  const postStatusAction = async (action: 'acknowledge' | 'resolve' | 'escalate') => {
    try {
      await api.post(`/api/alerts/${alert.id}/${action}`);
    } catch {
      // Best effort - optimistic patch still applies.
    }
    const nowIso = new Date().toISOString();
    if (action === 'acknowledge') {
      onPatch({ status: 'ACKNOWLEDGED', acknowledgedAt: nowIso, acknowledgedBy: currentUserName });
    } else if (action === 'resolve') {
      onPatch({ status: 'RESOLVED', resolvedAt: nowIso });
    } else {
      onPatch({ status: 'ESCALATED', escalated: true, escalatedAt: nowIso, escalatedTo: currentUserName });
    }
  };

  const assignToMe = async () => {
    try { await api.post(`/api/alerts/${alert.id}/assign`, { assignedTo: currentUserName }); }
    catch { /* optimistic */ }
    onPatch({ assignedTo: currentUserName, assignedBy: currentUserName });
  };

  /**
   * Open a Case from this alert. The backend Case endpoint accepts a
   * freeform payload; we seed it with the alert's headline fields and,
   * on success, patch the alert locally with the returned case id so
   * subsequent opens show "Linked to case #X" directly.
   */
  const openCase = async () => {
    setCaseLinkBusy(true);
    setError(null);
    try {
      const body = {
        title: `[${alert.severity}] ${alert.title}`,
        summary: alert.description ?? '',
        severity: alert.severity,
        status: 'OPEN',
        sourceAlertId: alert.id,
        sourceIp: alert.sourceIp,
        destinationIp: alert.destinationIp,
      };
      const res = await api.post('/api/cases', body);
      const created = res.data as { id?: string };
      if (created?.id) {
        onPatch({ linkedCaseId: created.id });
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to open case');
    } finally {
      setCaseLinkBusy(false);
    }
  };

  const sevClass =
    alert.severity === 'CRITICAL' ? 'bg-rose-50 text-rose-700 ring-rose-200' :
    alert.severity === 'HIGH'     ? 'bg-orange-50 text-orange-700 ring-orange-200' :
    alert.severity === 'MEDIUM'   ? 'bg-amber-50 text-amber-700 ring-amber-200' :
    alert.severity === 'LOW'      ? 'bg-emerald-50 text-emerald-700 ring-emerald-200' :
                                    'bg-slate-50 text-slate-700 ring-slate-200';
  const statusClass =
    alert.status === 'NEW' || alert.status === 'ESCALATED' ? 'bg-rose-50 text-rose-700 ring-rose-200' :
    alert.status === 'RESOLVED' || alert.status === 'CLOSED' ? 'bg-emerald-50 text-emerald-700 ring-emerald-200' :
                                    'bg-violet-50 text-violet-700 ring-violet-200';

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-900/20 backdrop-blur-sm z-40"
        onClick={onClose}
      />
      {/* Panel */}
      <aside className="fixed inset-y-0 right-0 w-full max-w-2xl bg-white shadow-2xl z-50 overflow-y-auto">
        <div className="p-6">
          {/* Header */}
          <div className="flex items-start justify-between gap-4 mb-4">
            <div className="min-w-0">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-1">
                Alert detail
              </div>
              <h2 className="text-lg font-bold text-slate-900 break-words">{alert.title}</h2>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-lg text-slate-500 hover:bg-slate-100 transition flex-shrink-0"
              aria-label="Close"
            >
              ✕
            </button>
          </div>

          {/* Badge strip */}
          <div className="flex flex-wrap items-center gap-2 mb-5">
            <span className={`inline-flex px-2.5 py-0.5 text-[11px] font-semibold rounded-full ring-1 ${sevClass}`}>
              {alert.severity}
            </span>
            <span className={`inline-flex px-2.5 py-0.5 text-[11px] font-semibold rounded-full ring-1 ${statusClass}`}>
              {alert.status}
            </span>
            {sla.kind !== 'none' && (
              <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold ring-1 ${slaBadgeClass(sla.kind)}`}>
                {sla.kind === 'breached' && <span>!</span>}
                SLA · {sla.label}
              </span>
            )}
            {alert.linkedCaseId && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-fuchsia-50 text-fuchsia-700 ring-1 ring-fuchsia-200">
                Linked to case {alert.linkedCaseId.slice(0, 8)}
              </span>
            )}
          </div>

          {error && (
            <div className="mb-4 px-3 py-2 rounded-lg bg-rose-50 ring-1 ring-rose-200 text-xs text-rose-700">
              {error}
            </div>
          )}

          {/* Action bar */}
          <div className="flex flex-wrap gap-2 mb-6">
            {alert.status === 'NEW' && (
              <button
                onClick={() => void postStatusAction('acknowledge')}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-violet-500 to-fuchsia-500 hover:shadow-md transition"
              >
                Acknowledge
              </button>
            )}
            {(alert.status === 'ACKNOWLEDGED' || alert.status === 'IN_PROGRESS' || alert.status === 'ESCALATED') && (
              <button
                onClick={() => void postStatusAction('resolve')}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-emerald-700 bg-emerald-50 ring-1 ring-emerald-200 hover:bg-emerald-100 transition"
              >
                Resolve
              </button>
            )}
            {alert.status !== 'ESCALATED' && alert.status !== 'RESOLVED' && alert.status !== 'CLOSED' && (
              <button
                onClick={() => void postStatusAction('escalate')}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-orange-700 bg-orange-50 ring-1 ring-orange-200 hover:bg-orange-100 transition"
              >
                Escalate
              </button>
            )}
            {alert.assignedTo !== currentUserName && (
              <button
                onClick={() => void assignToMe()}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-violet-700 bg-violet-50 ring-1 ring-violet-200 hover:bg-violet-100 transition"
              >
                Assign to me
              </button>
            )}
            {!alert.linkedCaseId && (
              <button
                onClick={() => void openCase()}
                disabled={caseLinkBusy}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-fuchsia-700 bg-fuchsia-50 ring-1 ring-fuchsia-200 hover:bg-fuchsia-100 transition disabled:opacity-50"
              >
                {caseLinkBusy ? 'Opening…' : 'Open case'}
              </button>
            )}
          </div>

          {/* Meta grid */}
          <div className="grid grid-cols-2 gap-3 text-sm mb-6">
            <MetaField label="Type">{alert.type}</MetaField>
            <MetaField label="Source">{alert.source}</MetaField>
            <MetaField label="Source IP">{alert.sourceIp ?? <span className="text-slate-400">—</span>}</MetaField>
            <MetaField label="Destination IP">{alert.destinationIp ?? <span className="text-slate-400">—</span>}</MetaField>
            <MetaField label="Source port">{alert.sourcePort ?? <span className="text-slate-400">—</span>}</MetaField>
            <MetaField label="Destination port">{alert.destinationPort ?? <span className="text-slate-400">—</span>}</MetaField>
            <MetaField label="Protocol">{alert.protocol ?? <span className="text-slate-400">—</span>}</MetaField>
            <MetaField label="Assigned to">{alert.assignedTo ?? <span className="text-slate-400">—</span>}</MetaField>
            <MetaField label="Detected at">{alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '—'}</MetaField>
            <MetaField label="Acknowledged at">{alert.acknowledgedAt ? new Date(alert.acknowledgedAt).toLocaleString() : <span className="text-slate-400">—</span>}</MetaField>
            <MetaField label="Resolved at">{alert.resolvedAt ? new Date(alert.resolvedAt).toLocaleString() : <span className="text-slate-400">—</span>}</MetaField>
            <MetaField label="MITRE">{alert.mitreId ?? <span className="text-slate-400">—</span>}</MetaField>
          </div>

          {/* Description */}
          {alert.description && (
            <div className="mb-5">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Description</div>
              <div className="whitespace-pre-wrap text-sm text-slate-800 bg-slate-50 rounded-lg p-3 ring-1 ring-slate-100">
                {alert.description}
              </div>
            </div>
          )}

          {/* Raw payload (collapsed unless present) */}
          {alert.rawData && (
            <details className="mb-5">
              <summary className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 cursor-pointer">
                Raw payload
              </summary>
              <pre className="mt-2 p-3 rounded-lg bg-slate-900 text-slate-100 text-[11px] overflow-x-auto">
                {alert.rawData}
              </pre>
            </details>
          )}

          {/* Notes / audit trail */}
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
              Notes ({comments.length})
            </div>
            <div className="flex gap-2 mb-3">
              <input
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void postNote(); } }}
                placeholder="Add a note for the audit trail…"
                className="flex-1 px-3 py-2 rounded-lg ring-1 ring-slate-200 text-sm focus:ring-2 focus:ring-violet-400 focus:outline-none"
              />
              <button
                onClick={() => void postNote()}
                disabled={postingNote || !newNote.trim()}
                className="px-3 py-2 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-violet-500 to-fuchsia-500 disabled:opacity-50"
              >
                {postingNote ? 'Posting…' : 'Post'}
              </button>
            </div>
            {commentsLoading ? (
              <div className="text-xs text-slate-500">Loading notes…</div>
            ) : comments.length === 0 ? (
              <div className="text-xs text-slate-500 italic">No notes yet.</div>
            ) : (
              <ol className="space-y-2">
                {comments.map(c => (
                  <li key={c.id} className="rounded-lg ring-1 ring-slate-200 bg-white p-2.5">
                    <div className="text-[10px] font-semibold text-slate-500 mb-1">
                      {c.createdBy ?? 'unknown'} · {c.createdAt ? new Date(c.createdAt).toLocaleString() : ''}
                    </div>
                    <div className="text-sm text-slate-800 whitespace-pre-wrap">{c.content}</div>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
      </aside>
    </>
  );
};

/** Two-cell row in the drawer meta grid. */
const MetaField: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div>
    <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-0.5">{label}</div>
    <div className="text-sm text-slate-800 break-words">{children}</div>
  </div>
);

export default Alerts; 