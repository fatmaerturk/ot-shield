import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import assetService, {
  ASSET_TYPE_OPTIONS,
  AssetDTO,
  CRITICALITY_OPTIONS,
  CriticalityLevel,
  criticalityLabel,
  PURDUE_LEVEL_OPTIONS,
  PurdueLevel,
  purdueLevelLabel,
  purdueLevelShort,
  AssetType,
} from '../services/assetService';
import { alertService } from '../services/alertService';
import anomalyService, { Anomaly } from '../services/anomalyService';
import dpiService, {
  DpiEvent,
  FunctionCodeStat,
  ObservedConnection,
} from '../services/dpiService';
import type { Alert } from '../types/alert';

interface Vulnerability {
  /** CVE id, e.g. CVE-2024-12345 */
  id: string;
  /** Backend's Vulnerability model calls this field `title`, but CIRCL returns the CVE summary. */
  title: string;
  /** CIRCL returns CVSS base score as string (e.g. "9.8") or "N/A". */
  severity: string;
  publishedDate: string;
  url: string;
}

type VulnSeverityTier = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

/** Convert CVSS base score → severity tier (CVSS v3 thresholds). */
const cvssToTier = (raw: string | undefined | null): VulnSeverityTier => {
  if (raw === undefined || raw === null) return 'UNKNOWN';
  const s = String(raw).trim();
  if (!s || s.toUpperCase() === 'N/A') return 'UNKNOWN';
  const n = Number(s);
  if (Number.isNaN(n)) {
    const u = s.toUpperCase();
    if (u === 'CRITICAL' || u === 'HIGH' || u === 'MEDIUM' || u === 'LOW') {
      return u;
    }
    return 'UNKNOWN';
  }
  if (n >= 9.0) return 'CRITICAL';
  if (n >= 7.0) return 'HIGH';
  if (n >= 4.0) return 'MEDIUM';
  if (n > 0.0) return 'LOW';
  return 'UNKNOWN';
};

const VULN_TIER_RANK: Record<VulnSeverityTier, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

const TABS = [
  'Device Information',
  'Risk',
  'Vulnerabilities',
  'Alerts & Insights',
  'OT Activity',
  'Data Sources',
  'Location',
  'Network Security',
  'Utilization',
  'History',
] as const;

type TabName = (typeof TABS)[number];

// ---------------------------------------------------------------------------
// Small presentation helpers
// ---------------------------------------------------------------------------

const Field: React.FC<{ label: string; children?: React.ReactNode }> = ({ label, children }) => (
  <div>
    <h4 className="text-xs uppercase text-gray-500">{label}</h4>
    <p className="font-medium break-all">
      {children === undefined || children === null || children === '' ? (
        <span className="text-gray-400">-</span>
      ) : (
        children
      )}
    </p>
  </div>
);

type EditableFieldProps =
  | {
      label: string;
      isEditing: boolean;
      kind?: 'text' | 'number';
      value: string | number | undefined | null;
      display?: React.ReactNode;
      onChange: (v: string) => void;
      placeholder?: string;
    }
  | {
      label: string;
      isEditing: boolean;
      kind: 'select';
      value: string | undefined | null;
      display?: React.ReactNode;
      options: Array<{ value: string; label: string }>;
      onChange: (v: string) => void;
      placeholder?: string;
    };

const EditableField: React.FC<EditableFieldProps> = (props) => {
  const { label, isEditing, display } = props;
  if (!isEditing) {
    return <Field label={label}>{display !== undefined ? display : props.value ?? undefined}</Field>;
  }
  return (
    <div>
      <h4 className="text-xs uppercase text-gray-500">{label}</h4>
      {props.kind === 'select' ? (
        <select
          value={(props.value as string) ?? ''}
          onChange={e => props.onChange(e.target.value)}
          className="mt-1 w-full border border-gray-300 rounded px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
        >
          <option value="">{props.placeholder || 'Select'}</option>
          {props.options.map(o => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      ) : (
        <input
          type={props.kind === 'number' ? 'number' : 'text'}
          value={props.value === undefined || props.value === null ? '' : String(props.value)}
          onChange={e => props.onChange(e.target.value)}
          placeholder={props.placeholder}
          className="mt-1 w-full border border-gray-300 rounded px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
      )}
    </div>
  );
};

const TagEditor: React.FC<{
  tags: string[];
  onChange: (next: string[]) => void;
}> = ({ tags, onChange }) => {
  const [draft, setDraft] = useState('');
  const add = () => {
    const v = draft.trim();
    if (!v) return;
    if (tags.some(t => t.toLowerCase() === v.toLowerCase())) {
      setDraft('');
      return;
    }
    onChange([...tags, v]);
    setDraft('');
  };
  return (
    <div>
      <div className="flex flex-wrap gap-2 mb-2">
        {tags.length === 0 && <span className="text-xs text-gray-400">No tags</span>}
        {tags.map(t => (
          <span
            key={t}
            className="px-2 py-1 text-xs rounded bg-blue-100 text-blue-700 flex items-center gap-1"
          >
            {t}
            <button
              type="button"
              onClick={() => onChange(tags.filter(x => x !== t))}
              className="text-blue-500 hover:text-red-500"
              title="Remove tag"
            >
              ✕
            </button>
          </span>
        ))}
      </div>
      <div className="flex gap-2">
        <input
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter') {
              e.preventDefault();
              add();
            }
          }}
          placeholder="Add tag and press Enter"
          className="flex-1 border border-gray-300 rounded px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
        <button
          type="button"
          onClick={add}
          className="px-3 py-1 bg-blue-600 text-white text-sm rounded hover:bg-blue-700"
        >
          Add
        </button>
      </div>
    </div>
  );
};

const formatDate = (iso?: string): string => {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
};

const riskTier = (score?: number): { label: string; color: string } => {
  if (score === undefined || score === null) return { label: 'N/A', color: 'text-gray-400' };
  if (score >= 75) return { label: 'HIGH', color: 'text-red-600' };
  if (score >= 50) return { label: 'MEDIUM', color: 'text-orange-500' };
  if (score >= 25) return { label: 'LOW', color: 'text-yellow-500' };
  return { label: 'MINIMAL', color: 'text-green-600' };
};

const severityBadge = (sev?: string): string => {
  const s = (sev || '').toUpperCase();
  switch (s) {
    case 'CRITICAL':
      return 'bg-red-100 text-red-800 border border-red-200';
    case 'HIGH':
      return 'bg-orange-100 text-orange-800 border border-orange-200';
    case 'MEDIUM':
      return 'bg-yellow-100 text-yellow-800 border border-yellow-200';
    case 'LOW':
      return 'bg-blue-100 text-blue-800 border border-blue-200';
    case 'INFO':
      return 'bg-gray-100 text-gray-700 border border-gray-200';
    default:
      return 'bg-gray-100 text-gray-600 border border-gray-200';
  }
};

const criticalityBadge = (c?: string): string => {
  const s = (c || '').toUpperCase();
  switch (s) {
    case 'CRITICAL':
      return 'bg-red-100 text-red-800';
    case 'HIGH':
      return 'bg-orange-100 text-orange-800';
    case 'MEDIUM':
      return 'bg-yellow-100 text-yellow-800';
    case 'LOW':
      return 'bg-green-100 text-green-800';
    case 'INFO':
      return 'bg-gray-100 text-gray-700';
    default:
      return 'bg-gray-100 text-gray-500';
  }
};

const compareAny = (a: unknown, b: unknown, dir: 'asc' | 'desc'): number => {
  const nullish = (x: unknown) => x === undefined || x === null || x === '';
  if (nullish(a) && nullish(b)) return 0;
  if (nullish(a)) return 1; // push nulls to end regardless of dir
  if (nullish(b)) return -1;
  const an = typeof a === 'number' ? a : Number(a);
  const bn = typeof b === 'number' ? b : Number(b);
  const numeric =
    !Number.isNaN(an) && !Number.isNaN(bn) &&
    (typeof a === 'number' || /^-?\d/.test(String(a))) &&
    (typeof b === 'number' || /^-?\d/.test(String(b)));
  const cmp = numeric
    ? an - bn
    : String(a).localeCompare(String(b), undefined, { numeric: true });
  return dir === 'asc' ? cmp : -cmp;
};

const deviceIconFor = (asset?: AssetDTO): string => {
  if (!asset) return '/assets/devices/workstation.svg';
  const t = (asset.assetType || '').toLowerCase();
  const name = (asset.name || '').toLowerCase();
  if (t.includes('plc')) return '/assets/devices/plc.svg';
  if (t.includes('hmi')) return '/assets/devices/hmi.svg';
  if (t.includes('router') || name.includes('router')) return '/assets/devices/router.svg';
  if (t.includes('switch') || name.includes('switch')) return '/assets/devices/switch.svg';
  if (t.includes('server') || t.includes('historian') || t.includes('scada')) {
    return '/assets/devices/server.svg';
  }
  if (t.includes('sensor') || t.includes('actuator') || asset.purdueLevel === 'LEVEL_0') {
    return '/assets/devices/iot.svg';
  }
  return '/assets/devices/workstation.svg';
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const Assets: React.FC = () => {
  const navigate = useNavigate();

  const [assets, setAssets] = useState<AssetDTO[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabName>('Device Information');

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string>('');
  const [isDeleting, setIsDeleting] = useState<string | null>(null);

  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [isLoadingVulnerabilities, setIsLoadingVulnerabilities] = useState<boolean>(false);
  const [vulnerabilitiesError, setVulnerabilitiesError] = useState<string>('');

  // Edit mode state (Faz 2)
  const [isEditing, setIsEditing] = useState<boolean>(false);
  const [draft, setDraft] = useState<AssetDTO | null>(null);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [saveError, setSaveError] = useState<string>('');

  // Risk tab sorting (Faz 3)
  type RiskSortKey = 'name' | 'ipAddress' | 'purdueLevel' | 'criticalityLevel' | 'vulnerabilityCount' | 'riskScore';
  const [riskSortKey, setRiskSortKey] = useState<RiskSortKey>('riskScore');
  const [riskSortDir, setRiskSortDir] = useState<'asc' | 'desc'>('desc');

  // Alerts & Insights tab (Faz 3)
  const [insights, setInsights] = useState<{
    anomalies: Anomaly[];
    alerts: Alert[];
  }>({ anomalies: [], alerts: [] });
  const [isLoadingInsights, setIsLoadingInsights] = useState<boolean>(false);
  const [insightsError, setInsightsError] = useState<string>('');

  // Vulnerabilities tab (Faz 4)
  const [vulnFilter, setVulnFilter] = useState<VulnSeverityTier | 'ALL'>('ALL');
  const [vulnSearch, setVulnSearch] = useState<string>('');
  const [vulnSortKey, setVulnSortKey] = useState<'severity' | 'publishedDate' | 'id'>('severity');
  const [vulnSortDir, setVulnSortDir] = useState<'asc' | 'desc'>('desc');

  // OT Activity tab (Faz 5a)
  type OtWindow = '24h' | '7d' | '30d';
  const [otWindow, setOtWindow] = useState<OtWindow>('7d');
  const [otEvents, setOtEvents] = useState<DpiEvent[]>([]);
  const [otStats, setOtStats] = useState<FunctionCodeStat[]>([]);
  const [otPeers, setOtPeers] = useState<ObservedConnection[]>([]);
  const [isLoadingOtActivity, setIsLoadingOtActivity] = useState<boolean>(false);
  const [otActivityError, setOtActivityError] = useState<string>('');

  // Data Sources tab (Faz 5b)
  interface HoneypotLogLite {
    id: string | number;
    timestamp: string;
    sourceIp: string;
    protocol: string;
    attackType?: string;
    severity?: string;
  }
  interface DataSourcesState {
    // system-level
    honeypotStats: Record<string, unknown> | null;
    conpotStatus: { isRunning?: boolean; simulationMode?: boolean } | null;
    conpotLogCount: number;
    dpiSessions: Array<{ id: string; eventCount: number; firstSeen?: string; lastSeen?: string }>;
    totalDpiEvents: number;
    // asset-scoped provenance
    assetHoneypotLogs: HoneypotLogLite[];
    assetDpiSessions: Array<{ id: string; eventCount: number; firstSeen?: string; lastSeen?: string }>;
    assetFirstDpiEvent: DpiEvent | null;
    assetLastDpiEvent: DpiEvent | null;
  }
  const [dataSources, setDataSources] = useState<DataSourcesState>({
    honeypotStats: null,
    conpotStatus: null,
    conpotLogCount: 0,
    dpiSessions: [],
    totalDpiEvents: 0,
    assetHoneypotLogs: [],
    assetDpiSessions: [],
    assetFirstDpiEvent: null,
    assetLastDpiEvent: null,
  });
  const [isLoadingDataSources, setIsLoadingDataSources] = useState<boolean>(false);
  const [dataSourcesError, setDataSourcesError] = useState<string>('');

  // ---------- Location tab state ----------
  interface LocationPeer {
    ip: string;
    protocol: string;
    count: number;
    /** true iff this IP belongs to another known asset */
    isKnownAsset: boolean;
    /** name of the matched asset (if any) */
    peerName?: string;
    /** derived zone of the peer */
    peerZone?: string;
    /** inbound / outbound direction relative to the selected asset */
    direction: 'in' | 'out';
  }
  const [locationPeers, setLocationPeers] = useState<LocationPeer[]>([]);
  const [isLoadingLocation, setIsLoadingLocation] = useState<boolean>(false);
  const [locationError, setLocationError] = useState<string>('');

  // ---------- Utilization tab state ----------
  // Window selector + an events sample for this asset, big enough to build a
  // protocol mix and an hour-by-hour histogram.
  type UtilWindow = '24h' | '7d' | '30d';
  const [utilWindow, setUtilWindow] = useState<UtilWindow>('7d');
  const [utilEvents, setUtilEvents] = useState<DpiEvent[]>([]);
  const [isLoadingUtil, setIsLoadingUtil] = useState<boolean>(false);
  const [utilError, setUtilError] = useState<string>('');

  // ---------- History tab state ----------
  // We pull the most-recent DPI events for the asset, then merge with the
  // asset's lifecycle events + anomalies + alerts into a single timeline.
  const [historyDpi, setHistoryDpi] = useState<DpiEvent[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState<boolean>(false);
  const [historyError, setHistoryError] = useState<string>('');

  const loadAssets = useCallback(async () => {
    setIsLoading(true);
    setLoadError('');
    try {
      const rows = await assetService.listAll();
      setAssets(rows);
      setSelectedId(prev => {
        if (prev && rows.some(r => r.id === prev)) return prev;
        return rows.length > 0 ? rows[0].id : null;
      });
    } catch (err: any) {
      console.error('Failed to load assets', err);
      const msg =
        err?.response?.status === 401 || err?.response?.status === 403
          ? 'You are not authorized to view assets. Please log in again.'
          : 'Failed to load assets from backend.';
      setLoadError(msg);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  // Vulnerabilities tab - only tab that already had a real endpoint
  useEffect(() => {
    const selected = assets.find(a => a.id === selectedId);
    if (activeTab !== 'Vulnerabilities' || !selected) return;

    const fetchVulns = async () => {
      setIsLoadingVulnerabilities(true);
      setVulnerabilitiesError('');
      try {
        const manufacturer = selected.manufacturer?.trim() || '';
        if (!manufacturer) {
          setVulnerabilities([]);
          return;
        }
        const res = await api.get<Vulnerability[]>(
          `/api/vulnerabilities?manufacturer=${encodeURIComponent(manufacturer)}`
        );
        setVulnerabilities(Array.isArray(res.data) ? res.data : []);
      } catch (err) {
        console.error('Error fetching vulnerabilities:', err);
        // Surface the real cause so the user can distinguish network/outbound
        // failures from "vendor has no CVEs".
        const anyErr = err as { response?: { status?: number; data?: unknown }; message?: string };
        const status = anyErr?.response?.status;
        const dataMsg =
          typeof anyErr?.response?.data === 'string'
            ? (anyErr.response.data as string)
            : (anyErr?.response?.data as { message?: string } | undefined)?.message;
        const detail = dataMsg || anyErr?.message || 'Unknown error';
        setVulnerabilitiesError(
          status
            ? `Failed to load vulnerabilities (HTTP ${status}): ${detail}`
            : `Failed to load vulnerabilities: ${detail}`
        );
      } finally {
        setIsLoadingVulnerabilities(false);
      }
    };
    fetchVulns();
  }, [activeTab, selectedId, assets]);

  // Alerts & Insights - fetch anomalies + alerts for the selected asset
  // Also triggered by Network Security tab, which reuses the same feed.
  useEffect(() => {
    const selected = assets.find(a => a.id === selectedId);
    if (
      !selected ||
      (activeTab !== 'Alerts & Insights' &&
        activeTab !== 'Network Security' &&
        activeTab !== 'History')
    ) {
      return;
    }

    const ip = selected.ipAddress?.trim();
    const hostname = selected.hostname?.trim() || selected.name?.trim();

    if (!ip && !hostname) {
      setInsights({ anomalies: [], alerts: [] });
      return;
    }

    let cancelled = false;
    const fetchInsights = async () => {
      setIsLoadingInsights(true);
      setInsightsError('');
      try {
        const [anomRaw, alertRaw] = await Promise.all([
          anomalyService
            .getAnomaliesByAsset(hostname, ip)
            .catch(err => {
              console.warn('anomalies lookup failed', err);
              return [] as Anomaly[];
            }),
          ip
            ? alertService.getAlertsByIpAddress(ip).catch(err => {
                console.warn('alerts lookup failed', err);
                return [] as Alert[];
              })
            : Promise.resolve([] as Alert[]),
        ]);
        if (cancelled) return;
        const anomalies = Array.isArray(anomRaw) ? (anomRaw as Anomaly[]) : [];
        const alerts = Array.isArray(alertRaw) ? (alertRaw as Alert[]) : [];
        setInsights({ anomalies, alerts });
      } catch (err: any) {
        if (cancelled) return;
        console.error('Failed to load insights', err);
        setInsightsError('Failed to load alerts and anomalies for this asset.');
      } finally {
        if (!cancelled) setIsLoadingInsights(false);
      }
    };
    fetchInsights();
    return () => {
      cancelled = true;
    };
  }, [activeTab, selectedId, assets]);

  // OT Activity - fetch DPI events, function stats, and peer list (Faz 5a)
  useEffect(() => {
    const selected = assets.find(a => a.id === selectedId);
    if (activeTab !== 'OT Activity' || !selected) return;

    const ip = selected.ipAddress?.trim();
    if (!ip) {
      setOtEvents([]);
      setOtStats([]);
      setOtPeers([]);
      return;
    }

    // Compute window boundaries as ISO local-date-time (backend expects no timezone).
    const now = new Date();
    const hours = otWindow === '24h' ? 24 : otWindow === '7d' ? 24 * 7 : 24 * 30;
    const from = new Date(now.getTime() - hours * 60 * 60 * 1000);
    const fmt = (d: Date): string => {
      const pad = (n: number) => n.toString().padStart(2, '0');
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(
        d.getHours()
      )}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    };
    const fromIso = fmt(from);
    const toIso = fmt(now);

    let cancelled = false;
    const fetchActivity = async () => {
      setIsLoadingOtActivity(true);
      setOtActivityError('');
      try {
        const [eventsPage, stats, peers] = await Promise.all([
          dpiService.search({ ip, from: fromIso, to: toIso, size: 100 }).catch(err => {
            console.warn('DPI events lookup failed', err);
            return { content: [] as DpiEvent[] } as { content: DpiEvent[] };
          }),
          dpiService.nodeStats(ip, fromIso, toIso).catch(err => {
            console.warn('DPI node stats lookup failed', err);
            return [] as FunctionCodeStat[];
          }),
          dpiService.observedConnections(fromIso, toIso).catch(err => {
            console.warn('observed connections lookup failed', err);
            return [] as ObservedConnection[];
          }),
        ]);
        if (cancelled) return;
        setOtEvents(Array.isArray(eventsPage.content) ? eventsPage.content : []);
        setOtStats(Array.isArray(stats) ? stats : []);
        // Filter to only peers where this asset participates
        const filtered = (Array.isArray(peers) ? peers : []).filter(
          p => p.sourceIp === ip || p.destinationIp === ip
        );
        setOtPeers(filtered);
      } catch (err) {
        if (cancelled) return;
        console.error('Failed to load OT activity', err);
        setOtActivityError('Failed to load OT activity data.');
      } finally {
        if (!cancelled) setIsLoadingOtActivity(false);
      }
    };
    fetchActivity();
    return () => {
      cancelled = true;
    };
  }, [activeTab, selectedId, assets, otWindow]);

  // Data Sources - compose from honeypot + conpot + dpi + asset metadata (Faz 5b)
  useEffect(() => {
    const selected = assets.find(a => a.id === selectedId);
    if (activeTab !== 'Data Sources' || !selected) return;

    const ip = selected.ipAddress?.trim() || '';

    let cancelled = false;
    const fetchAll = async () => {
      setIsLoadingDataSources(true);
      setDataSourcesError('');

      // System-level queries - never fail the whole panel if one errors
      const honeypotStatsP = api
        .get<Record<string, unknown>>('/api/honeypot/stats')
        .then(r => r.data)
        .catch(err => {
          console.warn('honeypot stats failed', err);
          return null;
        });
      const conpotStatusP = api
        .get<{ isRunning?: boolean; simulationMode?: boolean }>('/api/conpot/status')
        .then(r => r.data)
        .catch(err => {
          console.warn('conpot status failed', err);
          return null;
        });
      const conpotLogsP = api
        .get<{ logs?: unknown[]; count?: number }>('/api/conpot/logs')
        .then(r => (typeof r.data?.count === 'number' ? r.data.count : 0))
        .catch(err => {
          console.warn('conpot logs failed', err);
          return 0;
        });

      // Pcap/DPI sessions - derive from DpiEvent.pcapSessionId
      // Fetch a decent slice of recent global events, group by sessionId.
      const globalEventsP = dpiService
        .search({ size: 500, page: 0 })
        .then(page => page.content)
        .catch(err => {
          console.warn('global DPI events failed', err);
          return [] as DpiEvent[];
        });

      // Asset-scoped queries
      const assetHoneypotP: Promise<HoneypotLogLite[]> = ip
        ? api
            .get<HoneypotLogLite[]>('/api/honeypot/logs', {
              params: { sourceIp: ip, size: 100 },
            })
            .then(r => (Array.isArray(r.data) ? r.data : []))
            .catch(err => {
              console.warn('honeypot logs by IP failed', err);
              return [];
            })
        : Promise.resolve([]);

      const assetEventsP: Promise<DpiEvent[]> = ip
        ? dpiService
            .search({ ip, size: 500, page: 0 })
            .then(page => page.content)
            .catch(err => {
              console.warn('asset DPI events failed', err);
              return [] as DpiEvent[];
            })
        : Promise.resolve([]);

      try {
        const [honeypotStats, conpotStatus, conpotLogCount, globalEvents, assetHoneypotLogs, assetEvents] =
          await Promise.all([honeypotStatsP, conpotStatusP, conpotLogsP, globalEventsP, assetHoneypotP, assetEventsP]);

        if (cancelled) return;

        // Group global events by session ID
        const sessionAgg = new Map<string, { eventCount: number; firstSeen?: string; lastSeen?: string }>();
        for (const e of globalEvents) {
          const sid = e.pcapSessionId || '(unknown)';
          const existing = sessionAgg.get(sid) ?? { eventCount: 0 };
          existing.eventCount += 1;
          if (e.eventTime) {
            if (!existing.firstSeen || e.eventTime < existing.firstSeen) existing.firstSeen = e.eventTime;
            if (!existing.lastSeen || e.eventTime > existing.lastSeen) existing.lastSeen = e.eventTime;
          }
          sessionAgg.set(sid, existing);
        }
        const dpiSessions = Array.from(sessionAgg.entries())
          .map(([id, v]) => ({ id, ...v }))
          .sort((a, b) => (b.lastSeen || '').localeCompare(a.lastSeen || ''));

        // Asset-scoped session breakdown
        const assetSessionAgg = new Map<string, { eventCount: number; firstSeen?: string; lastSeen?: string }>();
        for (const e of assetEvents) {
          const sid = e.pcapSessionId || '(unknown)';
          const existing = assetSessionAgg.get(sid) ?? { eventCount: 0 };
          existing.eventCount += 1;
          if (e.eventTime) {
            if (!existing.firstSeen || e.eventTime < existing.firstSeen) existing.firstSeen = e.eventTime;
            if (!existing.lastSeen || e.eventTime > existing.lastSeen) existing.lastSeen = e.eventTime;
          }
          assetSessionAgg.set(sid, existing);
        }
        const assetDpiSessions = Array.from(assetSessionAgg.entries())
          .map(([id, v]) => ({ id, ...v }))
          .sort((a, b) => (b.lastSeen || '').localeCompare(a.lastSeen || ''));

        // First / last DPI event for this asset (by eventTime)
        let assetFirstDpiEvent: DpiEvent | null = null;
        let assetLastDpiEvent: DpiEvent | null = null;
        for (const e of assetEvents) {
          if (!e.eventTime) continue;
          if (!assetFirstDpiEvent || e.eventTime < (assetFirstDpiEvent.eventTime || '')) {
            assetFirstDpiEvent = e;
          }
          if (!assetLastDpiEvent || e.eventTime > (assetLastDpiEvent.eventTime || '')) {
            assetLastDpiEvent = e;
          }
        }

        setDataSources({
          honeypotStats,
          conpotStatus,
          conpotLogCount,
          dpiSessions,
          totalDpiEvents: globalEvents.length,
          assetHoneypotLogs,
          assetDpiSessions,
          assetFirstDpiEvent,
          assetLastDpiEvent,
        });
      } catch (err) {
        if (cancelled) return;
        console.error('Failed to load data sources', err);
        setDataSourcesError('Failed to load data source information.');
      } finally {
        if (!cancelled) setIsLoadingDataSources(false);
      }
    };
    fetchAll();
    return () => {
      cancelled = true;
    };
  }, [activeTab, selectedId, assets]);

  // ========== Location tab data loader ==========
  // Pulls the full observedConnections set so we can render "who does this
  // asset talk to" and "is that a known asset or an outsider". The Network
  // Security tab reuses this same feed for its exposure/segmentation panels.
  useEffect(() => {
    const selected = assets.find(a => a.id === selectedId);
    if (
      !selected ||
      (activeTab !== 'Location' && activeTab !== 'Network Security')
    ) {
      return;
    }
    const ip = selected.ipAddress?.trim() || '';
    if (!ip) {
      setLocationPeers([]);
      setLocationError('');
      return;
    }

    let cancelled = false;
    const fetchAll = async () => {
      setIsLoadingLocation(true);
      setLocationError('');
      try {
        const conns = await dpiService.observedConnections();
        if (cancelled) return;

        // Build a quick IP → asset lookup so we can tell friend from stranger.
        const assetByIp = new Map<string, AssetDTO>();
        for (const a of assets) {
          const aip = a.ipAddress?.trim();
          if (aip) assetByIp.set(aip, a);
        }

        // Aggregate by (peerIp, protocol, direction); an unordered pair may
        // contribute to both "in" and "out" if the traffic is bidirectional.
        const peerAgg = new Map<string, LocationPeer>();
        for (const c of conns) {
          let peerIp: string | null = null;
          let direction: 'in' | 'out' | null = null;
          if (c.sourceIp === ip) {
            peerIp = c.destinationIp;
            direction = 'out';
          } else if (c.destinationIp === ip) {
            peerIp = c.sourceIp;
            direction = 'in';
          }
          if (!peerIp || !direction) continue;

          const key = `${peerIp}__${c.protocol}__${direction}`;
          const existing = peerAgg.get(key);
          const peerAsset = assetByIp.get(peerIp);
          const next: LocationPeer = existing ?? {
            ip: peerIp,
            protocol: c.protocol,
            count: 0,
            isKnownAsset: !!peerAsset,
            peerName: peerAsset?.name,
            peerZone: peerAsset?.purdueLevel
              ? purdueLevelShort(peerAsset.purdueLevel)
              : undefined,
            direction,
          };
          next.count += c.count;
          peerAgg.set(key, next);
        }

        const peers = Array.from(peerAgg.values()).sort((a, b) => b.count - a.count);
        setLocationPeers(peers);
      } catch (err) {
        if (cancelled) return;
        console.error('Failed to load location peers', err);
        setLocationError('Failed to load network neighbors.');
      } finally {
        if (!cancelled) setIsLoadingLocation(false);
      }
    };
    fetchAll();
    return () => {
      cancelled = true;
    };
  }, [activeTab, selectedId, assets]);

  // ========== Utilization tab data loader ==========
  // Pulls a generous slice of asset-scoped DPI events within the selected
  // window; downstream renderers bucket them into hours / protocols / peers.
  useEffect(() => {
    const selected = assets.find(a => a.id === selectedId);
    if (activeTab !== 'Utilization' || !selected) return;
    const ip = selected.ipAddress?.trim() || '';
    if (!ip) {
      setUtilEvents([]);
      setUtilError('');
      return;
    }

    // Build ISO local date-time window (backend expects server-local, no TZ)
    const now = new Date();
    const from = new Date(now);
    if (utilWindow === '24h') from.setHours(from.getHours() - 24);
    else if (utilWindow === '7d') from.setDate(from.getDate() - 7);
    else from.setDate(from.getDate() - 30);
    const isoLocal = (d: Date) => {
      const pad = (n: number) => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(
        d.getHours()
      )}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    };

    let cancelled = false;
    const fetchAll = async () => {
      setIsLoadingUtil(true);
      setUtilError('');
      try {
        const page = await dpiService.search({
          ip,
          from: isoLocal(from),
          to: isoLocal(now),
          size: 1000,
          page: 0,
        });
        if (cancelled) return;
        setUtilEvents(page.content);
      } catch (err) {
        if (cancelled) return;
        console.error('Failed to load utilization events', err);
        setUtilError('Failed to load utilization data.');
      } finally {
        if (!cancelled) setIsLoadingUtil(false);
      }
    };
    fetchAll();
    return () => {
      cancelled = true;
    };
  }, [activeTab, selectedId, assets, utilWindow]);

  // ========== History tab data loader ==========
  // Pulls the most recent 50 DPI events for the asset so they can be merged
  // with lifecycle events + anomalies + alerts into a chronological timeline.
  useEffect(() => {
    const selected = assets.find(a => a.id === selectedId);
    if (activeTab !== 'History' || !selected) return;
    const ip = selected.ipAddress?.trim() || '';
    if (!ip) {
      setHistoryDpi([]);
      setHistoryError('');
      return;
    }

    let cancelled = false;
    const fetchAll = async () => {
      setIsLoadingHistory(true);
      setHistoryError('');
      try {
        const events = await dpiService.recentForNode(ip, 50);
        if (cancelled) return;
        setHistoryDpi(events);
      } catch (err) {
        if (cancelled) return;
        console.error('Failed to load history DPI', err);
        setHistoryError('Failed to load DPI history.');
      } finally {
        if (!cancelled) setIsLoadingHistory(false);
      }
    };
    fetchAll();
    return () => {
      cancelled = true;
    };
  }, [activeTab, selectedId, assets]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/login');
  };

  const handleDelete = async (asset: AssetDTO) => {
    const ok = window.confirm(
      `Delete asset "${asset.name}" (${asset.ipAddress || '-'})?\n\nThis cannot be undone.`
    );
    if (!ok) return;
    setIsDeleting(asset.id);
    try {
      await assetService.remove(asset.id);
      setAssets(prev => prev.filter(a => a.id !== asset.id));
      setSelectedId(prev => {
        if (prev !== asset.id) return prev;
        const remaining = assets.filter(a => a.id !== asset.id);
        return remaining.length > 0 ? remaining[0].id : null;
      });
    } catch (err: any) {
      console.error('Failed to delete asset', err);
      const msg =
        err?.response?.status === 403
          ? 'You do not have permission to delete assets (admin only).'
          : 'Failed to delete asset. See console for details.';
      window.alert(msg);
    } finally {
      setIsDeleting(null);
    }
  };

  const selected = useMemo(
    () => assets.find(a => a.id === selectedId) || null,
    [assets, selectedId]
  );

  // Switching asset or tab while editing -> discard draft
  useEffect(() => {
    if (isEditing) {
      setIsEditing(false);
      setDraft(null);
      setSaveError('');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, activeTab]);

  const beginEdit = () => {
    if (!selected) return;
    setDraft({ ...selected, tags: selected.tags ? [...selected.tags] : [] });
    setSaveError('');
    setIsEditing(true);
  };

  const cancelEdit = () => {
    setIsEditing(false);
    setDraft(null);
    setSaveError('');
  };

  const updateDraft = <K extends keyof AssetDTO>(key: K, value: AssetDTO[K]) => {
    setDraft(prev => (prev ? { ...prev, [key]: value } : prev));
  };

  const saveEdit = async () => {
    if (!draft) return;
    setIsSaving(true);
    setSaveError('');
    try {
      // Coerce empty strings to undefined so backend doesn't store ""
      const payload: Partial<AssetDTO> = { ...draft };
      (Object.keys(payload) as Array<keyof AssetDTO>).forEach(k => {
        const v = payload[k];
        if (typeof v === 'string' && v.trim() === '') {
          (payload as Record<keyof AssetDTO, unknown>)[k] = undefined;
        }
      });
      const updated = await assetService.update(draft.id, payload);
      setAssets(prev => prev.map(a => (a.id === updated.id ? updated : a)));
      setIsEditing(false);
      setDraft(null);
    } catch (err: any) {
      console.error('Failed to save asset', err);
      const status = err?.response?.status;
      setSaveError(
        status === 403
          ? 'You do not have permission to edit assets (admin/analyst only).'
          : status === 404
          ? 'Asset no longer exists. Refresh the list.'
          : 'Failed to save changes. See console for details.'
      );
    } finally {
      setIsSaving(false);
    }
  };

  const view: AssetDTO | null = isEditing && draft ? draft : selected;

  // -------------------------------------------------------------------------
  // Renderers
  // -------------------------------------------------------------------------

  const renderDeviceList = () => (
    <div className="pcap-devices mb-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold">Assets</h2>
        <div className="flex items-center gap-3 text-sm text-gray-500">
          <span>{assets.length} total</span>
          <button
            onClick={loadAssets}
            className="px-3 py-1 border border-gray-300 rounded hover:bg-gray-50"
          >
            Refresh
          </button>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 max-h-[400px] overflow-y-auto pr-2">
        {assets.map(a => {
          const r = riskTier(a.riskScore);
          const isSelected = selectedId === a.id;
          return (
            <div
              key={a.id}
              onClick={() => setSelectedId(a.id)}
              className={`relative border rounded-lg p-4 cursor-pointer transition-all hover:bg-gray-50 ${
                isSelected ? 'border-blue-500 bg-blue-50' : 'border-gray-200'
              }`}
            >
              <button
                onClick={e => {
                  e.stopPropagation();
                  handleDelete(a);
                }}
                disabled={isDeleting === a.id}
                title="Delete asset"
                className="absolute top-2 right-2 text-gray-300 hover:text-red-500 text-xs px-1"
              >
                {isDeleting === a.id ? '…' : '✕'}
              </button>
              <div className="flex items-start">
                <img src={deviceIconFor(a)} alt="Device" className="w-12 h-12 mr-3" />
                <div className="flex-1 min-w-0">
                  <h3 className="font-medium truncate">{a.name}</h3>
                  <div className="flex items-center text-sm text-gray-600">
                    <span
                      className={`h-2 w-2 rounded-full mr-2 ${
                        a.isOnline ? 'bg-green-500' : 'bg-gray-400'
                      }`}
                    />
                    {a.isOnline ? 'Online' : 'Offline'}
                  </div>
                  <div className="mt-1 text-xs text-gray-500 truncate">
                    {[a.manufacturer, a.assetType, purdueLevelShort(a.purdueLevel)]
                      .filter(Boolean)
                      .join(' • ')}
                  </div>
                </div>
              </div>
              <div className="mt-2 text-xs flex justify-between">
                <span>
                  Risk:{' '}
                  <span className={`${r.color} font-bold`}>
                    {a.riskScore ?? '-'}{' '}
                    <span className="uppercase">({r.label})</span>
                  </span>
                </span>
                <span className="text-gray-500">
                  {a.assetCategory ? a.assetCategory.replace(/_/g, ' ') : ''}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );

  const renderDeviceInformation = () => {
    if (!view || !selected) return null;
    const r = riskTier(view.riskScore);
    const purdueOptions = PURDUE_LEVEL_OPTIONS.map(p => ({
      value: p,
      label: purdueLevelLabel(p),
    }));
    const criticalityOptions = CRITICALITY_OPTIONS.map(c => ({
      value: c,
      label: criticalityLabel(c),
    }));
    const assetTypeOptions = ASSET_TYPE_OPTIONS.map(t => ({
      value: t,
      label: t.replace(/_/g, ' '),
    }));

    return (
      <div>
        <div className="device-info-header mt-4 flex border-b pb-6">
          <div className="device-image w-48 p-4">
            <img src={deviceIconFor(view)} alt="Device" className="w-full" />
          </div>
          <div className="device-details flex-1 grid grid-cols-2 gap-4 p-4">
            <EditableField
              label="Device Name"
              isEditing={isEditing}
              value={view.name}
              onChange={v => updateDraft('name', v)}
              placeholder="e.g. PLC-Pump-01"
            />
            <Field label="Status">
              <span
                className={`h-2 w-2 rounded-full mr-2 inline-block ${
                  view.isOnline ? 'bg-green-500' : 'bg-gray-400'
                }`}
              />
              {view.isOnline ? 'Online' : 'Offline'}
            </Field>
            <EditableField
              label="Manufacturer"
              isEditing={isEditing}
              value={view.manufacturer}
              onChange={v => updateDraft('manufacturer', v)}
              placeholder="e.g. Siemens"
            />
            <EditableField
              label="Type"
              isEditing={isEditing}
              kind="select"
              value={view.assetType}
              options={assetTypeOptions}
              onChange={v => updateDraft('assetType', (v || undefined) as AssetType | undefined)}
              placeholder="Select type"
            />
            <EditableField
              label="Model"
              isEditing={isEditing}
              value={view.model}
              onChange={v => updateDraft('model', v)}
              placeholder="e.g. S7-1500"
            />
            <EditableField
              label="Hostname"
              isEditing={isEditing}
              value={view.hostname}
              onChange={v => updateDraft('hostname', v)}
            />
          </div>
          <div className="device-actions flex flex-col items-end justify-between p-4">
            <div className="risk-score text-right">
              <span className="text-sm text-gray-500">RISK SCORE:</span>
              <span className={`ml-2 font-bold ${r.color}`}>
                {r.label} ({view.riskScore ?? '-'})
              </span>
            </div>
            <div className="flex space-x-2 mt-4">
              {!isEditing ? (
                <>
                  <button
                    onClick={beginEdit}
                    className="flex items-center px-3 py-1.5 bg-purple-600 text-white text-sm rounded hover:bg-purple-700"
                  >
                    ✎ Edit
                  </button>
                  <button
                    onClick={() => handleDelete(selected)}
                    className="flex items-center px-3 py-1.5 text-red-500 hover:text-red-700 text-sm"
                  >
                    🗑 Delete
                  </button>
                </>
              ) : (
                <>
                  <button
                    onClick={saveEdit}
                    disabled={isSaving}
                    className="flex items-center px-3 py-1.5 bg-green-600 text-white text-sm rounded hover:bg-green-700 disabled:opacity-50"
                  >
                    {isSaving ? 'Saving…' : '✓ Save'}
                  </button>
                  <button
                    onClick={cancelEdit}
                    disabled={isSaving}
                    className="flex items-center px-3 py-1.5 border border-gray-300 text-gray-700 text-sm rounded hover:bg-gray-50 disabled:opacity-50"
                  >
                    Cancel
                  </button>
                </>
              )}
            </div>
            {saveError && (
              <p className="text-xs text-red-500 mt-2 text-right max-w-xs">{saveError}</p>
            )}
          </div>
        </div>

        <div className="labels-assignees flex border-b py-4">
          <div className="w-3/4 px-4">
            <h3 className="text-xs uppercase text-gray-500 mb-2">Tags</h3>
            {isEditing ? (
              <TagEditor
                tags={view.tags || []}
                onChange={next => updateDraft('tags', next)}
              />
            ) : (
              <div className="flex flex-wrap gap-2">
                {(view.tags && view.tags.length > 0) ? (
                  view.tags.map(t => (
                    <span
                      key={t}
                      className="px-2 py-1 text-xs rounded bg-blue-100 text-blue-700"
                    >
                      {t}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-gray-400">No tags</span>
                )}
              </div>
            )}
          </div>
          <div className="w-1/4 px-4">
            <h3 className="text-xs uppercase text-gray-500 mb-2">Owner</h3>
            {isEditing ? (
              <input
                value={view.owner ?? ''}
                onChange={e => updateDraft('owner', e.target.value)}
                placeholder="Owner name"
                className="w-full border border-gray-300 rounded px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
              />
            ) : (
              <div className="text-sm">
                {view.owner || view.responsiblePerson ? (
                  <>
                    <div>{view.owner || view.responsiblePerson}</div>
                    {view.contactEmail && (
                      <div className="text-gray-500">{view.contactEmail}</div>
                    )}
                  </>
                ) : (
                  <span className="text-xs text-gray-400">Unassigned</span>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="detailed-info mt-6">
          <div className="flex items-center">
            <div className="w-8 h-8 mr-2 flex items-center justify-center rounded-lg bg-purple-100 text-purple-700">
              <span>📱</span>
            </div>
            <h2 className="text-xl font-semibold text-purple-800">DEVICE INFORMATION</h2>
            {isEditing && (
              <span className="ml-3 px-2 py-0.5 text-xs rounded bg-yellow-100 text-yellow-800">
                Editing
              </span>
            )}
          </div>

          <div className="mt-4">
            <h3 className="font-medium text-lg border-b pb-2">Identifiers</h3>
            <div className="grid grid-cols-6 gap-4 mt-2">
              <EditableField
                label="IP Address"
                isEditing={isEditing}
                value={view.ipAddress}
                onChange={v => updateDraft('ipAddress', v)}
                placeholder="10.10.2.20"
              />
              <EditableField
                label="MAC"
                isEditing={isEditing}
                value={view.macAddress}
                onChange={v => updateDraft('macAddress', v)}
                placeholder="AA:BB:CC:DD:EE:FF"
              />
              <Field label="Asset ID">{view.id}</Field>
              <EditableField
                label="Serial Number"
                isEditing={isEditing}
                value={view.serialNumber}
                onChange={v => updateDraft('serialNumber', v)}
              />
              <Field label="Category">
                {view.assetCategory ? view.assetCategory.replace(/_/g, ' ') : undefined}
              </Field>
              <EditableField
                label="Type"
                isEditing={isEditing}
                kind="select"
                value={view.assetType}
                options={assetTypeOptions}
                onChange={v => updateDraft('assetType', (v || undefined) as AssetType | undefined)}
              />
            </div>
            <div className="grid grid-cols-6 gap-4 mt-4">
              <EditableField
                label="Manufacturer"
                isEditing={isEditing}
                value={view.manufacturer}
                onChange={v => updateDraft('manufacturer', v)}
              />
              <EditableField
                label="Model"
                isEditing={isEditing}
                value={view.model}
                onChange={v => updateDraft('model', v)}
              />
              <EditableField
                label="Firmware"
                isEditing={isEditing}
                value={view.firmwareVersion}
                onChange={v => updateDraft('firmwareVersion', v)}
              />
              <EditableField
                label="Patch Level"
                isEditing={isEditing}
                value={view.patchLevel}
                onChange={v => updateDraft('patchLevel', v)}
              />
              <EditableField
                label="OS"
                isEditing={isEditing}
                value={view.operatingSystem}
                onChange={v => updateDraft('operatingSystem', v)}
              />
              <EditableField
                label="OS Version"
                isEditing={isEditing}
                value={view.osVersion}
                onChange={v => updateDraft('osVersion', v)}
              />
            </div>
            <div className="grid grid-cols-6 gap-4 mt-4">
              <EditableField
                label="Purdue Level"
                isEditing={isEditing}
                kind="select"
                value={view.purdueLevel}
                display={purdueLevelLabel(view.purdueLevel)}
                options={purdueOptions}
                onChange={v => updateDraft('purdueLevel', (v || undefined) as PurdueLevel | undefined)}
              />
              <EditableField
                label="OT Criticality"
                isEditing={isEditing}
                kind="select"
                value={view.criticalityLevel}
                display={criticalityLabel(view.criticalityLevel)}
                options={criticalityOptions}
                onChange={v =>
                  updateDraft('criticalityLevel', (v || undefined) as CriticalityLevel | undefined)
                }
              />
              <EditableField
                label="Risk Score"
                isEditing={isEditing}
                kind="number"
                value={view.riskScore}
                display={
                  <span className={r.color}>
                    {view.riskScore ?? '-'} ({r.label})
                  </span>
                }
                onChange={v => {
                  const n = v === '' ? undefined : Number(v);
                  updateDraft('riskScore', Number.isFinite(n as number) ? (n as number) : undefined);
                }}
              />
              <Field label="Vulnerabilities">{view.vulnerabilityCount ?? 0}</Field>
              <Field label="Backup">
                {view.backupStatus ? view.backupStatus.replace(/_/g, ' ') : undefined}
              </Field>
              <Field label="Monitoring">
                {view.monitoringStatus ? view.monitoringStatus.replace(/_/g, ' ') : undefined}
              </Field>
            </div>
          </div>

          <div className="mt-8">
            <h3 className="font-medium text-lg border-b pb-2">Ownership & Contact</h3>
            <div className="grid grid-cols-6 gap-4 mt-2">
              <EditableField
                label="Owner"
                isEditing={isEditing}
                value={view.owner}
                onChange={v => updateDraft('owner', v)}
              />
              <EditableField
                label="Responsible Person"
                isEditing={isEditing}
                value={view.responsiblePerson}
                onChange={v => updateDraft('responsiblePerson', v)}
              />
              <EditableField
                label="Contact Email"
                isEditing={isEditing}
                value={view.contactEmail}
                onChange={v => updateDraft('contactEmail', v)}
                placeholder="name@example.com"
              />
              <EditableField
                label="Contact Phone"
                isEditing={isEditing}
                value={view.contactPhone}
                onChange={v => updateDraft('contactPhone', v)}
              />
              <EditableField
                label="Location"
                isEditing={isEditing}
                value={view.location}
                onChange={v => updateDraft('location', v)}
                placeholder="e.g. Plant 2, Rack A4"
              />
              <EditableField
                label="Department"
                isEditing={isEditing}
                value={view.department}
                onChange={v => updateDraft('department', v)}
              />
            </div>
          </div>

          <div className="mt-8">
            <h3 className="font-medium text-lg border-b pb-2">Lifecycle</h3>
            <div className="grid grid-cols-6 gap-4 mt-2">
              <Field label="First Seen">{formatDate(view.firstSeen)}</Field>
              <Field label="Last Seen">{formatDate(view.lastSeen)}</Field>
              <Field label="Purchase Date">{formatDate(view.purchaseDate)}</Field>
              <Field label="Warranty Expiry">{formatDate(view.warrantyExpiry)}</Field>
              <Field label="Last Maintenance">{formatDate(view.lastMaintenance)}</Field>
              <Field label="Next Maintenance">{formatDate(view.nextMaintenance)}</Field>
            </div>
          </div>

          <div className="mt-8">
            <h3 className="font-medium text-lg border-b pb-2">Description & Notes</h3>
            <div className="grid grid-cols-2 gap-4 mt-2">
              <div>
                <h4 className="text-xs uppercase text-gray-500">Description</h4>
                {isEditing ? (
                  <textarea
                    value={view.description ?? ''}
                    onChange={e => updateDraft('description', e.target.value)}
                    rows={3}
                    className="mt-1 w-full border border-gray-300 rounded px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
                  />
                ) : (
                  <p className="mt-1 text-sm text-gray-700 whitespace-pre-wrap">
                    {view.description || <span className="text-gray-400">-</span>}
                  </p>
                )}
              </div>
              <div>
                <h4 className="text-xs uppercase text-gray-500">Notes</h4>
                {isEditing ? (
                  <textarea
                    value={view.notes ?? ''}
                    onChange={e => updateDraft('notes', e.target.value)}
                    rows={3}
                    className="mt-1 w-full border border-gray-300 rounded px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
                  />
                ) : (
                  <p className="mt-1 text-sm text-gray-700 whitespace-pre-wrap">
                    {view.notes || <span className="text-gray-400">-</span>}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderRisk = () => {
    const high = assets.filter(a => (a.riskScore ?? 0) >= 75).length;
    const medium = assets.filter(a => (a.riskScore ?? 0) >= 50 && (a.riskScore ?? 0) < 75).length;
    const critical = assets.filter(a => a.criticalityLevel === 'CRITICAL').length;
    const totalVulns = assets.reduce((sum, a) => sum + (a.vulnerabilityCount ?? 0), 0);

    const sorted = [...assets].sort((a, b) => {
      const av = (a as any)[riskSortKey];
      const bv = (b as any)[riskSortKey];
      return compareAny(av, bv, riskSortDir);
    });

    const toggleSort = (key: RiskSortKey) => {
      if (riskSortKey === key) {
        setRiskSortDir(prev => (prev === 'asc' ? 'desc' : 'asc'));
      } else {
        setRiskSortKey(key);
        setRiskSortDir(key === 'name' || key === 'ipAddress' || key === 'purdueLevel' ? 'asc' : 'desc');
      }
    };

    const SortHeader: React.FC<{ k: RiskSortKey; label: string; align?: 'left' | 'right' }> = ({
      k, label, align,
    }) => (
      <th
        onClick={() => toggleSort(k)}
        className={`px-4 py-2 cursor-pointer select-none ${align === 'right' ? 'text-right' : 'text-left'}`}
      >
        <span className="inline-flex items-center gap-1">
          {label}
          {riskSortKey === k && (
            <span className="text-xs">{riskSortDir === 'asc' ? '▲' : '▼'}</span>
          )}
        </span>
      </th>
    );

    return (
      <div className="p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-bold">Risk Analysis</h3>
          <div className="flex items-center gap-2 text-sm">
            <span className="px-3 py-1 rounded bg-red-100 text-red-700 font-medium">
              {high} high-risk
            </span>
            <span className="px-3 py-1 rounded bg-orange-100 text-orange-700 font-medium">
              {medium} medium-risk
            </span>
            <span className="px-3 py-1 rounded bg-purple-100 text-purple-700 font-medium">
              {critical} critical assets
            </span>
            <span className="px-3 py-1 rounded bg-gray-100 text-gray-700 font-medium">
              {totalVulns} total vulns
            </span>
          </div>
        </div>

        <div className="overflow-x-auto border rounded-lg">
          <table className="min-w-full bg-white">
            <thead className="bg-gray-50 text-xs uppercase text-gray-500">
              <tr>
                <SortHeader k="name" label="Asset" />
                <SortHeader k="ipAddress" label="IP" />
                <SortHeader k="purdueLevel" label="Purdue" />
                <SortHeader k="criticalityLevel" label="Criticality" />
                <SortHeader k="vulnerabilityCount" label="Vulns" align="right" />
                <SortHeader k="riskScore" label="Risk Score" align="right" />
              </tr>
            </thead>
            <tbody>
              {sorted.map(a => {
                const r = riskTier(a.riskScore);
                return (
                  <tr
                    key={a.id}
                    onClick={() => setSelectedId(a.id)}
                    className={`border-t cursor-pointer hover:bg-blue-50 ${
                      selectedId === a.id ? 'bg-blue-50' : ''
                    }`}
                  >
                    <td className="px-4 py-2 font-medium">{a.name}</td>
                    <td className="px-4 py-2 text-sm text-gray-600">{a.ipAddress || '-'}</td>
                    <td className="px-4 py-2 text-sm">{purdueLevelShort(a.purdueLevel)}</td>
                    <td className="px-4 py-2">
                      {a.criticalityLevel ? (
                        <span
                          className={`px-2 py-0.5 text-xs rounded ${criticalityBadge(
                            a.criticalityLevel
                          )}`}
                        >
                          {criticalityLabel(a.criticalityLevel)}
                        </span>
                      ) : (
                        <span className="text-xs text-gray-400">-</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-right">{a.vulnerabilityCount ?? 0}</td>
                    <td className="px-4 py-2 text-right">
                      <span className={`${r.color} font-bold`}>
                        {a.riskScore ?? '-'}{' '}
                        <span className="text-xs uppercase">({r.label})</span>
                      </span>
                    </td>
                  </tr>
                );
              })}
              {assets.length === 0 && (
                <tr>
                  <td className="px-4 py-2 text-gray-400" colSpan={6}>
                    No assets yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const renderAlertsInsights = () => {
    if (!selected) return null;
    if (isLoadingInsights) {
      return <div className="p-4 text-gray-500">Loading alerts and anomalies…</div>;
    }
    if (insightsError) {
      return <div className="p-4 text-red-500">{insightsError}</div>;
    }

    type FeedItem = {
      kind: 'anomaly' | 'alert';
      id: string;
      title: string;
      description?: string;
      severity?: string;
      status?: string;
      timestamp?: string;
      sourceIp?: string;
      destinationIp?: string;
      mitreId?: string;
    };

    const items: FeedItem[] = [
      ...insights.anomalies.map<FeedItem>(a => ({
        kind: 'anomaly',
        id: a.id,
        title: a.title,
        description: a.description,
        severity: a.severity,
        status: a.status,
        timestamp: a.detectedAt || a.createdAt,
        sourceIp: a.sourceIp,
        destinationIp: a.destinationIp,
        mitreId: a.mitreId,
      })),
      ...insights.alerts.map<FeedItem>(a => ({
        kind: 'alert',
        id: a.id,
        title: a.title,
        description: a.description,
        severity: (a.severity as unknown) as string,
        status: (a.status as unknown) as string,
        timestamp: a.createdAt,
        sourceIp: a.sourceIp,
        destinationIp: a.destinationIp,
      })),
    ].sort((a, b) => {
      const ta = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const tb = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return tb - ta;
    });

    const counts = {
      total: items.length,
      critical: items.filter(i => (i.severity || '').toUpperCase() === 'CRITICAL').length,
      high: items.filter(i => (i.severity || '').toUpperCase() === 'HIGH').length,
      open: items.filter(i => {
        const s = (i.status || '').toUpperCase();
        return s !== 'RESOLVED' && s !== 'CLOSED' && s !== 'FALSE_POSITIVE';
      }).length,
    };

    return (
      <div className="p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-bold">
            Alerts & Insights for {selected.name}
            {selected.ipAddress ? ` (${selected.ipAddress})` : ''}
          </h3>
          <div className="flex items-center gap-2 text-sm">
            <span className="px-3 py-1 rounded bg-gray-100 text-gray-700 font-medium">
              {counts.total} total
            </span>
            <span className="px-3 py-1 rounded bg-red-100 text-red-700 font-medium">
              {counts.critical} critical
            </span>
            <span className="px-3 py-1 rounded bg-orange-100 text-orange-700 font-medium">
              {counts.high} high
            </span>
            <span className="px-3 py-1 rounded bg-blue-100 text-blue-700 font-medium">
              {counts.open} open
            </span>
          </div>
        </div>

        {items.length === 0 ? (
          <div className="border rounded-lg p-8 text-center text-gray-500">
            <div className="text-3xl mb-2">✓</div>
            <p className="text-sm">
              No alerts or anomalies recorded for this asset.
            </p>
          </div>
        ) : (
          <div className="border rounded-lg divide-y">
            {items.map(it => (
              <div
                key={`${it.kind}-${it.id}`}
                className="p-4 hover:bg-gray-50 transition-colors"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`px-2 py-0.5 text-xs rounded uppercase font-medium ${severityBadge(
                          it.severity
                        )}`}
                      >
                        {it.severity || 'INFO'}
                      </span>
                      <span
                        className={`px-2 py-0.5 text-xs rounded uppercase ${
                          it.kind === 'anomaly'
                            ? 'bg-purple-100 text-purple-700'
                            : 'bg-indigo-100 text-indigo-700'
                        }`}
                      >
                        {it.kind}
                      </span>
                      {it.status && (
                        <span className="px-2 py-0.5 text-xs rounded bg-gray-100 text-gray-700">
                          {it.status.replace(/_/g, ' ')}
                        </span>
                      )}
                      {it.mitreId && (
                        <span className="px-2 py-0.5 text-xs rounded bg-yellow-50 text-yellow-800 border border-yellow-200">
                          MITRE: {it.mitreId}
                        </span>
                      )}
                    </div>
                    <h4 className="font-medium mt-1">{it.title}</h4>
                    {it.description && (
                      <p className="text-sm text-gray-600 mt-1 line-clamp-2">
                        {it.description}
                      </p>
                    )}
                    <div className="text-xs text-gray-500 mt-2 flex flex-wrap gap-3">
                      {it.sourceIp && (
                        <span>
                          src <span className="font-mono">{it.sourceIp}</span>
                        </span>
                      )}
                      {it.destinationIp && (
                        <span>
                          → dst <span className="font-mono">{it.destinationIp}</span>
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="text-xs text-gray-500 whitespace-nowrap">
                    {it.timestamp ? formatDate(it.timestamp) : '-'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  // ---------------------------------------------------------------------
  // OT Activity - DPI events, function-code distribution, communication peers
  // ---------------------------------------------------------------------

  const renderOtActivity = () => {
    if (!selected) return null;

    const ip = selected.ipAddress?.trim();

    // Window selector - always visible
    const windowSelector = (
      <div className="flex items-center gap-2">
        <span className="text-xs text-gray-500">Time range:</span>
        {(['24h', '7d', '30d'] as const).map(w => (
          <button
            key={w}
            onClick={() => setOtWindow(w)}
            className={`px-3 py-1 text-xs rounded-full border ${
              otWindow === w
                ? 'bg-purple-600 text-white border-purple-600'
                : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
            }`}
          >
            {w === '24h' ? 'Last 24h' : w === '7d' ? 'Last 7 days' : 'Last 30 days'}
          </button>
        ))}
      </div>
    );

    if (!ip) {
      return (
        <div className="p-8 text-center text-gray-500">
          <div className="text-3xl mb-2">ℹ️</div>
          <p className="mb-2">
            This asset has no <strong>IP address</strong> set.
          </p>
          <p className="text-sm">
            OT Activity correlates asset traffic by IP. Add the IP in the Device
            Information tab, then return here.
          </p>
        </div>
      );
    }

    if (isLoadingOtActivity) {
      return (
        <div className="p-8 text-center">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600 mb-3" />
          <p className="text-gray-600 text-sm">
            Loading DPI events for <span className="font-mono">{ip}</span>…
          </p>
        </div>
      );
    }

    if (otActivityError) {
      return (
        <div className="p-6 text-center">
          <p className="text-red-500 mb-2">Error: {otActivityError}</p>
          <p className="text-xs text-gray-500">
            OT Activity relies on DPI events parsed from uploaded pcap files.
            Upload a pcap in the Network Topology page to populate this view.
          </p>
        </div>
      );
    }

    // --- Empty state: no events at all ---
    if (otEvents.length === 0 && otStats.length === 0 && otPeers.length === 0) {
      return (
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-800">
              OT Activity for {selected.name}
            </h3>
            {windowSelector}
          </div>
          <div className="p-8 text-center text-gray-500 border border-dashed border-gray-300 rounded-lg">
            <div className="text-3xl mb-2">📭</div>
            <p className="mb-1">
              No DPI activity recorded for{' '}
              <span className="font-mono">{ip}</span> in the selected window.
            </p>
            <p className="text-sm">
              Upload a pcap on the Network Topology page that includes traffic to or
              from this asset, or widen the time range above.
            </p>
          </div>
        </div>
      );
    }

    // --- Derived: protocol breakdown from events ---
    const protocolCounts = new Map<string, number>();
    const writeCount = otEvents.filter(e => e.isWrite).length;
    const exceptionCount = otEvents.filter(e => e.isException).length;
    for (const e of otEvents) {
      const p = e.protocol || 'UNKNOWN';
      protocolCounts.set(p, (protocolCounts.get(p) ?? 0) + 1);
    }
    const protocolList = Array.from(protocolCounts.entries()).sort((a, b) => b[1] - a[1]);

    // --- Derived: peer counts aggregated by other-side IP ---
    const peerMap = new Map<string, { direction: 'in' | 'out' | 'both'; count: number; protocols: Set<string> }>();
    for (const p of otPeers) {
      const other = p.sourceIp === ip ? p.destinationIp : p.sourceIp;
      const dir: 'in' | 'out' = p.sourceIp === ip ? 'out' : 'in';
      const existing = peerMap.get(other);
      if (existing) {
        existing.count += p.count;
        existing.protocols.add(p.protocol);
        existing.direction = existing.direction === dir ? dir : 'both';
      } else {
        peerMap.set(other, {
          direction: dir,
          count: p.count,
          protocols: new Set([p.protocol]),
        });
      }
    }
    const peerList = Array.from(peerMap.entries())
      .map(([peerIp, v]) => ({ peerIp, ...v, protocols: Array.from(v.protocols) }))
      .sort((a, b) => b.count - a.count);

    // --- Top function codes for the stats panel ---
    const topStats = [...otStats].sort((a, b) => b.count - a.count).slice(0, 10);
    const totalStatCount = otStats.reduce((sum, s) => sum + s.count, 0);

    const protoColor = (p: string): string => {
      switch (p.toUpperCase()) {
        case 'MODBUS': return 'bg-blue-100 text-blue-700 border-blue-200';
        case 'S7COMM': return 'bg-indigo-100 text-indigo-700 border-indigo-200';
        case 'IEC104': return 'bg-teal-100 text-teal-700 border-teal-200';
        default: return 'bg-gray-100 text-gray-700 border-gray-200';
      }
    };

    return (
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-800">
              OT Activity for {selected.name}
            </h3>
            <p className="text-xs text-gray-500">
              Deep-packet inspection stream for <span className="font-mono">{ip}</span>
            </p>
          </div>
          {windowSelector}
        </div>

        {/* Summary chips */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="p-3 bg-white border rounded-lg">
            <div className="text-xs text-gray-500 uppercase">Events</div>
            <div className="text-2xl font-semibold text-gray-800">{otEvents.length}</div>
          </div>
          <div className="p-3 bg-white border rounded-lg">
            <div className="text-xs text-gray-500 uppercase">Write ops</div>
            <div className="text-2xl font-semibold text-amber-600">{writeCount}</div>
          </div>
          <div className="p-3 bg-white border rounded-lg">
            <div className="text-xs text-gray-500 uppercase">Exceptions</div>
            <div className="text-2xl font-semibold text-red-600">{exceptionCount}</div>
          </div>
          <div className="p-3 bg-white border rounded-lg">
            <div className="text-xs text-gray-500 uppercase">Peers</div>
            <div className="text-2xl font-semibold text-gray-800">{peerList.length}</div>
          </div>
        </div>

        {/* Protocol distribution */}
        {protocolList.length > 0 && (
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2">
              Protocols observed
            </h4>
            <div className="flex flex-wrap gap-2">
              {protocolList.map(([proto, count]) => (
                <span
                  key={proto}
                  className={`px-3 py-1 text-xs rounded-full border ${protoColor(proto)}`}
                >
                  {proto} · {count}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Two-column: function-code stats + communication peers */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Function codes */}
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2">
              Top function codes
            </h4>
            {topStats.length === 0 ? (
              <p className="text-sm text-gray-500 italic">
                No dissector-level statistics in this window.
              </p>
            ) : (
              <div className="bg-white border rounded-lg divide-y">
                {topStats.map((s, idx) => {
                  const pct = totalStatCount > 0 ? (s.count / totalStatCount) * 100 : 0;
                  return (
                    <div key={`${s.protocol}-${s.functionCode}-${idx}`} className="p-3">
                      <div className="flex items-center justify-between text-sm mb-1">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 text-xs rounded border ${protoColor(s.protocol)}`}
                          >
                            {s.protocol}
                          </span>
                          <span className="font-mono text-gray-600">{s.functionCode}</span>
                          <span className="text-gray-800">
                            {s.functionName || '-'}
                          </span>
                        </div>
                        <span className="text-gray-600 font-medium">{s.count}</span>
                      </div>
                      <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-purple-500"
                          style={{ width: `${pct.toFixed(1)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Peers */}
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2">
              Communication peers
            </h4>
            {peerList.length === 0 ? (
              <p className="text-sm text-gray-500 italic">
                No peer IPs in the selected window.
              </p>
            ) : (
              <div className="bg-white border rounded-lg divide-y">
                {peerList.slice(0, 10).map(p => (
                  <div key={p.peerIp} className="p-3 flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <span
                        title={
                          p.direction === 'out'
                            ? `${ip} → ${p.peerIp}`
                            : p.direction === 'in'
                            ? `${p.peerIp} → ${ip}`
                            : 'bidirectional'
                        }
                        className="text-gray-400 font-mono"
                      >
                        {p.direction === 'out' ? '→' : p.direction === 'in' ? '←' : '↔'}
                      </span>
                      <span className="font-mono">{p.peerIp}</span>
                      <div className="flex gap-1">
                        {p.protocols.map(proto => (
                          <span
                            key={proto}
                            className={`px-1.5 py-0.5 text-[10px] rounded border ${protoColor(proto)}`}
                          >
                            {proto}
                          </span>
                        ))}
                      </div>
                    </div>
                    <span className="text-gray-600 font-medium">{p.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Recent events timeline */}
        <div>
          <h4 className="text-sm font-medium text-gray-700 mb-2">
            Recent events <span className="text-xs text-gray-400">(latest 100)</span>
          </h4>
          {otEvents.length === 0 ? (
            <p className="text-sm text-gray-500 italic">
              No dissected events in the selected window.
            </p>
          ) : (
            <div className="bg-white border rounded-lg overflow-hidden">
              <table className="min-w-full text-sm">
                <thead className="bg-gray-50 text-gray-600">
                  <tr>
                    <th className="text-left px-3 py-2 font-medium">Time</th>
                    <th className="text-left px-3 py-2 font-medium">Src → Dst</th>
                    <th className="text-left px-3 py-2 font-medium">Protocol</th>
                    <th className="text-left px-3 py-2 font-medium">Function</th>
                    <th className="text-left px-3 py-2 font-medium">Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {otEvents.slice(0, 20).map(ev => {
                    const isIncoming = ev.destinationIp === ip;
                    return (
                      <tr
                        key={ev.id}
                        className={ev.isException ? 'bg-red-50' : ev.isWrite ? 'bg-amber-50' : ''}
                      >
                        <td className="px-3 py-2 text-gray-500 whitespace-nowrap">
                          {formatDate(ev.eventTime)}
                        </td>
                        <td className="px-3 py-2 font-mono text-xs">
                          <span className={isIncoming ? 'text-gray-400' : 'font-semibold'}>
                            {ev.sourceIp}
                          </span>
                          <span className="text-gray-400 mx-1">→</span>
                          <span className={isIncoming ? 'font-semibold' : 'text-gray-400'}>
                            {ev.destinationIp}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <span
                            className={`px-2 py-0.5 text-xs rounded border ${protoColor(ev.protocol)}`}
                          >
                            {ev.protocol}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <span className="font-mono text-xs text-gray-600">
                            {ev.functionCode || '-'}
                          </span>
                          {ev.functionName && (
                            <span className="ml-2 text-gray-700">{ev.functionName}</span>
                          )}
                          {ev.isException && (
                            <span className="ml-2 px-1.5 py-0.5 text-[10px] bg-red-100 text-red-700 rounded">
                              EXC
                            </span>
                          )}
                          {ev.isWrite && (
                            <span className="ml-2 px-1.5 py-0.5 text-[10px] bg-amber-100 text-amber-700 rounded">
                              WRITE
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2 text-gray-600 text-xs">
                          {ev.summary || '-'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {otEvents.length > 20 && (
                <div className="px-3 py-2 text-xs text-gray-500 bg-gray-50 text-center">
                  Showing 20 of {otEvents.length} events, widen the time range for more.
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderDataSources = () => {
    if (!selected) return null;

    const ip = selected.ipAddress?.trim() || '';

    // Source-status helper - green if we have evidence, gray otherwise
    const sourceChip = (label: string, active: boolean, detail?: string) => (
      <div
        className={`flex items-center justify-between px-3 py-2 rounded border ${
          active
            ? 'bg-green-50 border-green-200 text-green-800'
            : 'bg-gray-50 border-gray-200 text-gray-500'
        }`}
      >
        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${active ? 'bg-green-500' : 'bg-gray-400'}`}
            aria-hidden="true"
          />
          <span className="text-sm font-medium">{label}</span>
        </div>
        {detail && <span className="text-xs">{detail}</span>}
      </div>
    );

    // ----- system-level booleans
    const honeypotActive =
      !!dataSources.honeypotStats &&
      Object.keys(dataSources.honeypotStats).length > 0;
    const conpotRunning = !!dataSources.conpotStatus?.isRunning;
    const conpotSimulated = !!dataSources.conpotStatus?.simulationMode;
    const dpiActive = dataSources.totalDpiEvents > 0;

    // ----- asset-scoped booleans
    const assetSeenByDpi = dataSources.assetDpiSessions.length > 0;
    const assetSeenByHoneypot = dataSources.assetHoneypotLogs.length > 0;
    const isManuallyEntered =
      !!selected.createdBy &&
      selected.createdBy !== 'system' &&
      selected.createdBy !== 'pcap-discovery';

    return (
      <div className="space-y-6">
        {dataSourcesError && (
          <div className="p-3 bg-red-50 border border-red-200 rounded text-red-800 text-sm">
            {dataSourcesError}
          </div>
        )}

        {isLoadingDataSources && (
          <div className="p-4 text-gray-500 text-sm">Loading data sources…</div>
        )}

        {/* ===================================================================
            TOP, System-wide data sources
        =================================================================== */}
        <div className="bg-white border border-gray-200 rounded-lg">
          <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-gray-900">
                System-wide data sources
              </h3>
              <p className="text-xs text-gray-500 mt-0.5">
                Connectors that feed OTShield with telemetry across the entire
                deployment.
              </p>
            </div>
          </div>
          <div className="p-4 space-y-4">
            {/* Source status chips */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
              {sourceChip(
                'PCAP / DPI dissector',
                dpiActive,
                dpiActive
                  ? `${dataSources.totalDpiEvents.toLocaleString()} events`
                  : 'no events'
              )}
              {sourceChip(
                'Honeypot',
                honeypotActive,
                honeypotActive ? 'reporting' : 'no data'
              )}
              {sourceChip(
                'ICS decoy',
                conpotRunning,
                conpotRunning
                  ? conpotSimulated
                    ? 'sim mode'
                    : 'live'
                  : 'stopped'
              )}
              {sourceChip(
                'Anomaly engine',
                dpiActive,
                dpiActive ? 'inline w/ DPI' : 'idle'
              )}
            </div>

            {/* Decoy detail row */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
              <div className="p-3 bg-gray-50 rounded border border-gray-200">
                <div className="text-xs text-gray-500 uppercase tracking-wide">
                  Decoy logs collected
                </div>
                <div className="text-lg font-semibold text-gray-900 mt-0.5">
                  {dataSources.conpotLogCount.toLocaleString()}
                </div>
              </div>
              <div className="p-3 bg-gray-50 rounded border border-gray-200">
                <div className="text-xs text-gray-500 uppercase tracking-wide">
                  Pcap sessions in DPI store
                </div>
                <div className="text-lg font-semibold text-gray-900 mt-0.5">
                  {dataSources.dpiSessions.length.toLocaleString()}
                </div>
              </div>
              <div className="p-3 bg-gray-50 rounded border border-gray-200">
                <div className="text-xs text-gray-500 uppercase tracking-wide">
                  Total DPI events (recent)
                </div>
                <div className="text-lg font-semibold text-gray-900 mt-0.5">
                  {dataSources.totalDpiEvents.toLocaleString()}
                </div>
              </div>
            </div>

            {/* Pcap session table, global */}
            {dataSources.dpiSessions.length > 0 && (
              <div className="border border-gray-200 rounded overflow-hidden">
                <div className="px-3 py-2 bg-gray-50 border-b border-gray-200 text-xs font-medium text-gray-700 uppercase tracking-wide">
                  Recent pcap sessions
                </div>
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 text-xs text-gray-500">
                    <tr>
                      <th className="px-3 py-1.5 text-left font-medium">Session ID</th>
                      <th className="px-3 py-1.5 text-right font-medium">Events</th>
                      <th className="px-3 py-1.5 text-left font-medium">First seen</th>
                      <th className="px-3 py-1.5 text-left font-medium">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dataSources.dpiSessions.slice(0, 8).map(s => (
                      <tr key={s.id} className="border-t border-gray-100">
                        <td className="px-3 py-1.5 font-mono text-xs text-gray-700 truncate max-w-[260px]">
                          {s.id}
                        </td>
                        <td className="px-3 py-1.5 text-right text-gray-900">
                          {s.eventCount.toLocaleString()}
                        </td>
                        <td className="px-3 py-1.5 text-gray-500 text-xs">
                          {formatDate(s.firstSeen)}
                        </td>
                        <td className="px-3 py-1.5 text-gray-500 text-xs">
                          {formatDate(s.lastSeen)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {dataSources.dpiSessions.length > 8 && (
                  <div className="px-3 py-1.5 text-xs text-gray-500 bg-gray-50 text-center border-t border-gray-200">
                    Showing 8 of {dataSources.dpiSessions.length} sessions.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ===================================================================
            BOTTOM, Asset provenance: what reported THIS asset?
        =================================================================== */}
        <div className="bg-white border border-gray-200 rounded-lg">
          <div className="px-4 py-3 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-900">
              Provenance for{' '}
              <span className="font-mono text-purple-700">
                {selected.name || ip || selected.id}
              </span>
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Where the data about this specific asset came from.
            </p>
          </div>
          <div className="p-4 space-y-4">
            {/* Provenance chips */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
              {sourceChip(
                'PCAP / DPI',
                assetSeenByDpi,
                assetSeenByDpi
                  ? `${dataSources.assetDpiSessions.length} session(s)`
                  : 'never observed'
              )}
              {sourceChip(
                'Honeypot hits',
                assetSeenByHoneypot,
                assetSeenByHoneypot
                  ? `${dataSources.assetHoneypotLogs.length} attack(s)`
                  : 'no attacks'
              )}
              {sourceChip(
                'Manual entry',
                isManuallyEntered,
                isManuallyEntered ? selected.createdBy || 'user' : 'auto-discovered'
              )}
              {sourceChip(
                'Asset registry',
                true,
                selected.createdAt ? formatDate(selected.createdAt) : 'tracked'
              )}
            </div>

            {/* First / last seen on this asset's wire */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
              <div className="p-3 bg-gray-50 rounded border border-gray-200">
                <div className="text-xs text-gray-500 uppercase tracking-wide">
                  First DPI event for this IP
                </div>
                <div className="text-sm font-medium text-gray-900 mt-0.5">
                  {dataSources.assetFirstDpiEvent?.eventTime
                    ? formatDate(dataSources.assetFirstDpiEvent.eventTime)
                    : '-'}
                </div>
                {dataSources.assetFirstDpiEvent && (
                  <div className="text-xs text-gray-500 mt-1">
                    {dataSources.assetFirstDpiEvent.protocol}
                    {dataSources.assetFirstDpiEvent.functionName
                      ? ` · ${dataSources.assetFirstDpiEvent.functionName}`
                      : ''}
                  </div>
                )}
              </div>
              <div className="p-3 bg-gray-50 rounded border border-gray-200">
                <div className="text-xs text-gray-500 uppercase tracking-wide">
                  Last DPI event for this IP
                </div>
                <div className="text-sm font-medium text-gray-900 mt-0.5">
                  {dataSources.assetLastDpiEvent?.eventTime
                    ? formatDate(dataSources.assetLastDpiEvent.eventTime)
                    : '-'}
                </div>
                {dataSources.assetLastDpiEvent && (
                  <div className="text-xs text-gray-500 mt-1">
                    {dataSources.assetLastDpiEvent.protocol}
                    {dataSources.assetLastDpiEvent.functionName
                      ? ` · ${dataSources.assetLastDpiEvent.functionName}`
                      : ''}
                  </div>
                )}
              </div>
            </div>

            {/* Registry / lifecycle metadata */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-sm">
              <div className="p-3 bg-gray-50 rounded border border-gray-200">
                <div className="text-xs text-gray-500 uppercase tracking-wide">
                  Created
                </div>
                <div className="text-sm font-medium text-gray-900 mt-0.5">
                  {selected.createdAt ? formatDate(selected.createdAt) : '-'}
                </div>
                {selected.createdBy && (
                  <div className="text-xs text-gray-500 mt-1">
                    by {selected.createdBy}
                  </div>
                )}
              </div>
              <div className="p-3 bg-gray-50 rounded border border-gray-200">
                <div className="text-xs text-gray-500 uppercase tracking-wide">
                  Last updated
                </div>
                <div className="text-sm font-medium text-gray-900 mt-0.5">
                  {selected.updatedAt ? formatDate(selected.updatedAt) : '-'}
                </div>
                {selected.updatedBy && (
                  <div className="text-xs text-gray-500 mt-1">
                    by {selected.updatedBy}
                  </div>
                )}
              </div>
              <div className="p-3 bg-gray-50 rounded border border-gray-200">
                <div className="text-xs text-gray-500 uppercase tracking-wide">
                  First seen
                </div>
                <div className="text-sm font-medium text-gray-900 mt-0.5">
                  {selected.firstSeen ? formatDate(selected.firstSeen) : '-'}
                </div>
              </div>
              <div className="p-3 bg-gray-50 rounded border border-gray-200">
                <div className="text-xs text-gray-500 uppercase tracking-wide">
                  Last seen
                </div>
                <div className="text-sm font-medium text-gray-900 mt-0.5">
                  {selected.lastSeen ? formatDate(selected.lastSeen) : '-'}
                </div>
              </div>
            </div>

            {/* Asset's pcap session breakdown */}
            {dataSources.assetDpiSessions.length > 0 && (
              <div className="border border-gray-200 rounded overflow-hidden">
                <div className="px-3 py-2 bg-gray-50 border-b border-gray-200 text-xs font-medium text-gray-700 uppercase tracking-wide">
                  Pcap sessions that reported this asset
                </div>
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 text-xs text-gray-500">
                    <tr>
                      <th className="px-3 py-1.5 text-left font-medium">Session ID</th>
                      <th className="px-3 py-1.5 text-right font-medium">Events</th>
                      <th className="px-3 py-1.5 text-left font-medium">First seen</th>
                      <th className="px-3 py-1.5 text-left font-medium">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dataSources.assetDpiSessions.slice(0, 8).map(s => (
                      <tr key={s.id} className="border-t border-gray-100">
                        <td className="px-3 py-1.5 font-mono text-xs text-gray-700 truncate max-w-[260px]">
                          {s.id}
                        </td>
                        <td className="px-3 py-1.5 text-right text-gray-900">
                          {s.eventCount.toLocaleString()}
                        </td>
                        <td className="px-3 py-1.5 text-gray-500 text-xs">
                          {formatDate(s.firstSeen)}
                        </td>
                        <td className="px-3 py-1.5 text-gray-500 text-xs">
                          {formatDate(s.lastSeen)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Honeypot attacks targeting this IP */}
            {dataSources.assetHoneypotLogs.length > 0 && (
              <div className="border border-gray-200 rounded overflow-hidden">
                <div className="px-3 py-2 bg-gray-50 border-b border-gray-200 text-xs font-medium text-gray-700 uppercase tracking-wide">
                  Recent honeypot attacks from this asset
                </div>
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 text-xs text-gray-500">
                    <tr>
                      <th className="px-3 py-1.5 text-left font-medium">Time</th>
                      <th className="px-3 py-1.5 text-left font-medium">Protocol</th>
                      <th className="px-3 py-1.5 text-left font-medium">Type</th>
                      <th className="px-3 py-1.5 text-left font-medium">Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dataSources.assetHoneypotLogs.slice(0, 10).map(h => (
                      <tr key={String(h.id)} className="border-t border-gray-100">
                        <td className="px-3 py-1.5 text-gray-500 text-xs">
                          {formatDate(h.timestamp)}
                        </td>
                        <td className="px-3 py-1.5 text-gray-700">{h.protocol}</td>
                        <td className="px-3 py-1.5 text-gray-700">
                          {h.attackType || '-'}
                        </td>
                        <td className="px-3 py-1.5">
                          {h.severity ? (
                            <span
                              className={`inline-block px-2 py-0.5 rounded text-xs ${severityBadge(
                                h.severity
                              )}`}
                            >
                              {h.severity}
                            </span>
                          ) : (
                            <span className="text-gray-400 text-xs">-</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Empty state, no data from any asset-scoped source */}
            {!isLoadingDataSources &&
              !assetSeenByDpi &&
              !assetSeenByHoneypot &&
              !isManuallyEntered && (
                <div className="p-3 text-sm text-gray-500 bg-gray-50 border border-gray-200 rounded">
                  No DPI events, honeypot hits, or manual entries are linked to this
                  asset yet. Once a pcap covering its IP is analyzed it will show up
                  here.
                </div>
              )}
          </div>
        </div>
      </div>
    );
  };

  const renderLocation = () => {
    if (!selected) return null;

    const ip = selected.ipAddress?.trim() || '';
    const level = selected.purdueLevel;

    // --- Derive IEC 62443 zone from Purdue level + location/department hints.
    // Kept inline (doesn't import the topology helper) so Location works
    // even if the topology service schema changes.
    const hint = `${selected.location || ''} ${selected.department || ''}`.toUpperCase();
    let zoneLabel = 'Enterprise & Operations';
    let zoneAccent = 'text-blue-700 bg-blue-50 border-blue-200';
    if (hint.includes('DMZ') || hint.includes('PERIMETER')) {
      zoneLabel = 'Industrial DMZ';
      zoneAccent = 'text-amber-700 bg-amber-50 border-amber-200';
    } else if (hint.includes('EXTERNAL') || hint.includes('INTERNET')) {
      zoneLabel = 'Untrusted External';
      zoneAccent = 'text-red-700 bg-red-50 border-red-200';
    } else if (hint.includes('FIELD') || hint.includes('PLANT FLOOR')) {
      zoneLabel = 'Plant Floor / Field';
      zoneAccent = 'text-green-700 bg-green-50 border-green-200';
    } else if (hint.includes('CONTROL ROOM') || hint.includes('SCADA')) {
      zoneLabel = 'Control & Supervisory';
      zoneAccent = 'text-indigo-700 bg-indigo-50 border-indigo-200';
    } else if (
      hint.includes('ENTERPRISE') ||
      hint.includes('CORPORATE') ||
      hint.includes('OFFICE')
    ) {
      zoneLabel = 'Enterprise & Operations';
      zoneAccent = 'text-blue-700 bg-blue-50 border-blue-200';
    } else if (level === 'LEVEL_0') {
      zoneLabel = 'Plant Floor / Field';
      zoneAccent = 'text-green-700 bg-green-50 border-green-200';
    } else if (level === 'LEVEL_1' || level === 'LEVEL_2') {
      zoneLabel = 'Control & Supervisory';
      zoneAccent = 'text-indigo-700 bg-indigo-50 border-indigo-200';
    } else if (level === 'LEVEL_3' || level === 'LEVEL_4') {
      zoneLabel = 'Enterprise & Operations';
      zoneAccent = 'text-blue-700 bg-blue-50 border-blue-200';
    } else if (level === 'LEVEL_5') {
      zoneLabel = 'Industrial DMZ / External';
      zoneAccent = 'text-amber-700 bg-amber-50 border-amber-200';
    }

    // --- Purdue band visualization (0 at bottom … 5 at top)
    const bands: Array<{ id: PurdueLevel; label: string; color: string }> = [
      { id: 'LEVEL_5', label: 'L5, Internet DMZ', color: 'bg-red-100 border-red-300' },
      { id: 'LEVEL_4', label: 'L4, Enterprise', color: 'bg-blue-100 border-blue-300' },
      { id: 'LEVEL_3', label: 'L3, Operations', color: 'bg-blue-50 border-blue-200' },
      { id: 'LEVEL_2', label: 'L2, Supervisory', color: 'bg-indigo-50 border-indigo-200' },
      { id: 'LEVEL_1', label: 'L1, Basic Control', color: 'bg-indigo-100 border-indigo-300' },
      { id: 'LEVEL_0', label: 'L0, Process / Field', color: 'bg-green-100 border-green-300' },
    ];

    // --- Partition peers into inbound / outbound
    const inbound = locationPeers.filter(p => p.direction === 'in');
    const outbound = locationPeers.filter(p => p.direction === 'out');

    const peerRow = (p: LocationPeer) => (
      <tr key={`${p.ip}-${p.protocol}-${p.direction}`} className="border-t border-gray-100">
        <td className="px-3 py-1.5">
          <div className="font-mono text-xs text-gray-700">{p.ip}</div>
          {p.peerName && (
            <div className="text-xs text-gray-500">{p.peerName}</div>
          )}
        </td>
        <td className="px-3 py-1.5 text-gray-700 text-sm">{p.protocol}</td>
        <td className="px-3 py-1.5 text-right text-gray-900 text-sm">
          {p.count.toLocaleString()}
        </td>
        <td className="px-3 py-1.5">
          {p.isKnownAsset ? (
            <span className="inline-block px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-800 border border-purple-200">
              {p.peerZone ? `known · ${p.peerZone}` : 'known'}
            </span>
          ) : (
            <span className="inline-block px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700 border border-gray-200">
              external
            </span>
          )}
        </td>
      </tr>
    );

    return (
      <div className="space-y-6">
        {locationError && (
          <div className="p-3 bg-red-50 border border-red-200 rounded text-red-800 text-sm">
            {locationError}
          </div>
        )}

        {/* --- Summary card --- */}
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-sm">
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                IP address
              </div>
              <div className="text-sm font-mono font-medium text-gray-900 mt-0.5">
                {ip || '-'}
              </div>
            </div>
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                Purdue level
              </div>
              <div className="text-sm font-medium text-gray-900 mt-0.5">
                {purdueLevelLabel(level)}
              </div>
            </div>
            <div className={`p-3 rounded border ${zoneAccent}`}>
              <div className="text-xs uppercase tracking-wide opacity-80">
                IEC 62443 zone
              </div>
              <div className="text-sm font-semibold mt-0.5">{zoneLabel}</div>
            </div>
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                Physical location
              </div>
              <div className="text-sm font-medium text-gray-900 mt-0.5">
                {selected.location || '-'}
              </div>
              {selected.department && (
                <div className="text-xs text-gray-500 mt-1">
                  {selected.department}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* --- Purdue band visualization --- */}
        <div className="bg-white border border-gray-200 rounded-lg">
          <div className="px-4 py-3 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-900">
              Purdue model position
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              This asset sits at the highlighted band.
            </p>
          </div>
          <div className="p-4 space-y-1">
            {bands.map(b => {
              const isMe = b.id === level;
              return (
                <div
                  key={b.id}
                  className={`px-3 py-2 border rounded flex items-center justify-between ${
                    b.color
                  } ${isMe ? 'ring-2 ring-purple-500' : 'opacity-60'}`}
                >
                  <span className="text-sm font-medium text-gray-800">
                    {b.label}
                  </span>
                  {isMe && (
                    <span className="text-xs font-semibold text-purple-700">
                      ◀ this asset
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* --- Network neighbors --- */}
        <div className="bg-white border border-gray-200 rounded-lg">
          <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-gray-900">
                Network neighbors
              </h3>
              <p className="text-xs text-gray-500 mt-0.5">
                IPs this asset has communicated with (from observed DPI traffic).
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs text-gray-500">
              <span>
                <span className="font-semibold text-gray-900">{outbound.length}</span>{' '}
                outbound
              </span>
              <span>
                <span className="font-semibold text-gray-900">{inbound.length}</span>{' '}
                inbound
              </span>
            </div>
          </div>

          {isLoadingLocation ? (
            <div className="p-4 text-gray-500 text-sm">Loading neighbors…</div>
          ) : locationPeers.length === 0 ? (
            <div className="p-4 text-sm text-gray-500">
              No DPI traffic has been observed to or from {ip || 'this asset'} yet.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-0 md:gap-4 p-4">
              {/* Outbound */}
              <div className="border border-gray-200 rounded overflow-hidden mb-4 md:mb-0">
                <div className="px-3 py-2 bg-gray-50 border-b border-gray-200 text-xs font-medium text-gray-700 uppercase tracking-wide">
                  Outbound ({outbound.length})
                </div>
                {outbound.length === 0 ? (
                  <div className="px-3 py-2 text-sm text-gray-500">-</div>
                ) : (
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 text-xs text-gray-500">
                      <tr>
                        <th className="px-3 py-1.5 text-left font-medium">Peer</th>
                        <th className="px-3 py-1.5 text-left font-medium">Proto</th>
                        <th className="px-3 py-1.5 text-right font-medium">PDUs</th>
                        <th className="px-3 py-1.5 text-left font-medium">Type</th>
                      </tr>
                    </thead>
                    <tbody>{outbound.slice(0, 15).map(peerRow)}</tbody>
                  </table>
                )}
              </div>

              {/* Inbound */}
              <div className="border border-gray-200 rounded overflow-hidden">
                <div className="px-3 py-2 bg-gray-50 border-b border-gray-200 text-xs font-medium text-gray-700 uppercase tracking-wide">
                  Inbound ({inbound.length})
                </div>
                {inbound.length === 0 ? (
                  <div className="px-3 py-2 text-sm text-gray-500">-</div>
                ) : (
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 text-xs text-gray-500">
                      <tr>
                        <th className="px-3 py-1.5 text-left font-medium">Peer</th>
                        <th className="px-3 py-1.5 text-left font-medium">Proto</th>
                        <th className="px-3 py-1.5 text-right font-medium">PDUs</th>
                        <th className="px-3 py-1.5 text-left font-medium">Type</th>
                      </tr>
                    </thead>
                    <tbody>{inbound.slice(0, 15).map(peerRow)}</tbody>
                  </table>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderNetworkSecurity = () => {
    if (!selected) return null;

    const ip = selected.ipAddress?.trim() || '';
    const level = selected.purdueLevel;

    // ---- Self Purdue level as a numeric band (0..5)
    const selfBand = (() => {
      if (!level) return null;
      const m = /LEVEL_(\d)/.exec(level);
      return m ? parseInt(m[1], 10) : null;
    })();

    // Purdue-level → zone number (higher = more trusted upstream)
    const levelToZone = (lvl?: PurdueLevel | null): string => {
      if (!lvl) return 'Unknown';
      if (lvl === 'LEVEL_0') return 'Field';
      if (lvl === 'LEVEL_1' || lvl === 'LEVEL_2') return 'Control';
      if (lvl === 'LEVEL_3' || lvl === 'LEVEL_4') return 'Enterprise';
      if (lvl === 'LEVEL_5') return 'DMZ/External';
      return 'Unknown';
    };

    // ---- Partition peers for segmentation math
    const knownPeers = locationPeers.filter(p => p.isKnownAsset);
    const externalPeers = locationPeers.filter(p => !p.isKnownAsset);

    // Identify cross-zone edges: peer whose asset-level differs materially
    // from self's band. We compute it by looking up the asset by IP.
    const assetByIp = new Map<string, AssetDTO>();
    for (const a of assets) {
      const aip = a.ipAddress?.trim();
      if (aip) assetByIp.set(aip, a);
    }
    const crossZoneEdges = knownPeers.filter(p => {
      const peerAsset = assetByIp.get(p.ip);
      if (!peerAsset || !peerAsset.purdueLevel || selfBand == null) return false;
      const m = /LEVEL_(\d)/.exec(peerAsset.purdueLevel);
      if (!m) return false;
      const peerBand = parseInt(m[1], 10);
      return Math.abs(peerBand - selfBand) >= 2;
    });

    // ---- Protocol exposure mix
    const protoMix = new Map<string, number>();
    for (const p of locationPeers) {
      protoMix.set(p.protocol, (protoMix.get(p.protocol) || 0) + p.count);
    }
    const protoRows = Array.from(protoMix.entries())
      .map(([proto, count]) => ({ proto, count }))
      .sort((a, b) => b.count - a.count);
    const totalPdu = protoRows.reduce((s, r) => s + r.count, 0);

    // ---- Anomaly rules that fired on THIS asset
    const assetAnomalies = insights.anomalies.filter(
      a => a.sourceIp === ip || a.destinationIp === ip
    );
    const ruleHits = new Map<string, number>();
    for (const a of assetAnomalies) {
      const key = a.anomalyType || 'UNKNOWN';
      ruleHits.set(key, (ruleHits.get(key) || 0) + 1);
    }
    const ruleRows = Array.from(ruleHits.entries())
      .map(([rule, count]) => ({ rule, count }))
      .sort((a, b) => b.count - a.count);

    // ---- Posture score - simple composite, 0 (bad) → 100 (good)
    const posture = (() => {
      let score = 100;
      // Each cross-zone edge is worth ~12 off
      score -= Math.min(40, crossZoneEdges.length * 12);
      // External peers chip away more aggressively
      score -= Math.min(30, externalPeers.length * 6);
      // Active anomalies sting hard
      const activeAnoms = assetAnomalies.filter(a => a.isActive).length;
      score -= Math.min(40, activeAnoms * 8);
      if (score < 0) score = 0;
      if (score > 100) score = 100;
      return score;
    })();

    const postureTier =
      posture >= 80
        ? { label: 'Good', color: 'text-green-700', bg: 'bg-green-100' }
        : posture >= 60
        ? { label: 'Fair', color: 'text-yellow-700', bg: 'bg-yellow-100' }
        : posture >= 40
        ? { label: 'Weak', color: 'text-orange-700', bg: 'bg-orange-100' }
        : { label: 'Poor', color: 'text-red-700', bg: 'bg-red-100' };

    return (
      <div className="space-y-6">
        {(locationError || insightsError) && (
          <div className="p-3 bg-red-50 border border-red-200 rounded text-red-800 text-sm">
            {locationError || insightsError}
          </div>
        )}

        {/* --- Posture summary --- */}
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className={`p-3 rounded border border-gray-200 ${postureTier.bg}`}>
              <div className="text-xs text-gray-600 uppercase tracking-wide">
                Posture
              </div>
              <div className={`text-2xl font-bold mt-0.5 ${postureTier.color}`}>
                {posture}
                <span className="text-sm font-normal ml-1">/ 100</span>
              </div>
              <div className={`text-xs font-medium ${postureTier.color}`}>
                {postureTier.label}
              </div>
            </div>
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                Cross-zone edges
              </div>
              <div className="text-2xl font-bold text-gray-900 mt-0.5">
                {crossZoneEdges.length}
              </div>
              <div className="text-xs text-gray-500">peers ≥ 2 Purdue levels away</div>
            </div>
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                External peers
              </div>
              <div className="text-2xl font-bold text-gray-900 mt-0.5">
                {externalPeers.length}
              </div>
              <div className="text-xs text-gray-500">not in asset inventory</div>
            </div>
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                Active anomalies
              </div>
              <div className="text-2xl font-bold text-gray-900 mt-0.5">
                {assetAnomalies.filter(a => a.isActive).length}
              </div>
              <div className="text-xs text-gray-500">
                of {assetAnomalies.length} total on this asset
              </div>
            </div>
          </div>
        </div>

        {/* --- Segmentation: cross-zone talkers --- */}
        <div className="bg-white border border-gray-200 rounded-lg">
          <div className="px-4 py-3 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-900">
              Segmentation posture
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Peers at a distant Purdue level, typically IT↔OT conduits that
              should go through a firewall / DMZ.
            </p>
          </div>
          <div className="p-4">
            {isLoadingLocation ? (
              <div className="text-sm text-gray-500">Loading neighbors…</div>
            ) : crossZoneEdges.length === 0 ? (
              <div className="text-sm text-gray-500">
                No cross-zone traffic detected. This asset only talks to peers
                within 1 Purdue level of its own ({levelToZone(level)}).
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead className="bg-gray-50 text-xs text-gray-500">
                  <tr>
                    <th className="px-3 py-1.5 text-left font-medium">Peer</th>
                    <th className="px-3 py-1.5 text-left font-medium">
                      Peer zone
                    </th>
                    <th className="px-3 py-1.5 text-left font-medium">Direction</th>
                    <th className="px-3 py-1.5 text-left font-medium">Proto</th>
                    <th className="px-3 py-1.5 text-right font-medium">PDUs</th>
                  </tr>
                </thead>
                <tbody>
                  {crossZoneEdges.slice(0, 10).map(p => {
                    const peerAsset = assetByIp.get(p.ip);
                    return (
                      <tr
                        key={`${p.ip}-${p.protocol}-${p.direction}`}
                        className="border-t border-gray-100"
                      >
                        <td className="px-3 py-1.5">
                          <div className="font-mono text-xs text-gray-700">
                            {p.ip}
                          </div>
                          {p.peerName && (
                            <div className="text-xs text-gray-500">{p.peerName}</div>
                          )}
                        </td>
                        <td className="px-3 py-1.5 text-gray-700">
                          {levelToZone(peerAsset?.purdueLevel)}
                        </td>
                        <td className="px-3 py-1.5">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-xs ${
                              p.direction === 'out'
                                ? 'bg-blue-100 text-blue-800 border border-blue-200'
                                : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                            }`}
                          >
                            {p.direction === 'out' ? '→ outbound' : '← inbound'}
                          </span>
                        </td>
                        <td className="px-3 py-1.5 text-gray-700">{p.protocol}</td>
                        <td className="px-3 py-1.5 text-right text-gray-900">
                          {p.count.toLocaleString()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* --- Exposure: protocol mix + known/external ratio --- */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-white border border-gray-200 rounded-lg">
            <div className="px-4 py-3 border-b border-gray-200">
              <h3 className="text-sm font-semibold text-gray-900">
                Protocol exposure
              </h3>
              <p className="text-xs text-gray-500 mt-0.5">
                What protocols carry this asset&apos;s traffic.
              </p>
            </div>
            <div className="p-4">
              {protoRows.length === 0 ? (
                <div className="text-sm text-gray-500">
                  No protocol activity observed yet.
                </div>
              ) : (
                <div className="space-y-2">
                  {protoRows.map(r => {
                    const pct = totalPdu > 0 ? (r.count / totalPdu) * 100 : 0;
                    return (
                      <div key={r.proto}>
                        <div className="flex justify-between text-xs mb-0.5">
                          <span className="font-medium text-gray-700">
                            {r.proto}
                          </span>
                          <span className="text-gray-500">
                            {r.count.toLocaleString()} PDUs · {pct.toFixed(1)}%
                          </span>
                        </div>
                        <div className="h-2 rounded bg-gray-100 overflow-hidden">
                          <div
                            className="h-full bg-purple-500"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          <div className="bg-white border border-gray-200 rounded-lg">
            <div className="px-4 py-3 border-b border-gray-200">
              <h3 className="text-sm font-semibold text-gray-900">
                Peer trust mix
              </h3>
              <p className="text-xs text-gray-500 mt-0.5">
                Ratio of peers that are in the asset inventory vs. unknown IPs.
              </p>
            </div>
            <div className="p-4">
              {locationPeers.length === 0 ? (
                <div className="text-sm text-gray-500">No peers observed yet.</div>
              ) : (
                <>
                  <div className="flex items-end gap-4 mb-3">
                    <div className="flex-1">
                      <div className="text-xs text-gray-500 uppercase tracking-wide">
                        Known assets
                      </div>
                      <div className="text-2xl font-bold text-purple-700">
                        {knownPeers.length}
                      </div>
                    </div>
                    <div className="flex-1">
                      <div className="text-xs text-gray-500 uppercase tracking-wide">
                        External IPs
                      </div>
                      <div className="text-2xl font-bold text-gray-700">
                        {externalPeers.length}
                      </div>
                    </div>
                  </div>
                  <div className="h-3 rounded bg-gray-100 overflow-hidden flex">
                    <div
                      className="h-full bg-purple-500"
                      style={{
                        width: `${
                          (knownPeers.length /
                            Math.max(1, knownPeers.length + externalPeers.length)) *
                          100
                        }%`,
                      }}
                    />
                    <div
                      className="h-full bg-gray-400"
                      style={{
                        width: `${
                          (externalPeers.length /
                            Math.max(1, knownPeers.length + externalPeers.length)) *
                          100
                        }%`,
                      }}
                    />
                  </div>
                  <div className="mt-1 text-xs text-gray-500 flex justify-between">
                    <span>
                      <span className="inline-block w-2 h-2 bg-purple-500 rounded-sm mr-1" />
                      Known
                    </span>
                    <span>
                      <span className="inline-block w-2 h-2 bg-gray-400 rounded-sm mr-1" />
                      External
                    </span>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>

        {/* --- Anomaly rules that have fired --- */}
        <div className="bg-white border border-gray-200 rounded-lg">
          <div className="px-4 py-3 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-900">
              Anomaly rules fired on this asset
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Rule hits grouped by type (unauthorized-write, rare-function,
              exception-response, …).
            </p>
          </div>
          <div className="p-4">
            {isLoadingInsights ? (
              <div className="text-sm text-gray-500">Loading rule hits…</div>
            ) : ruleRows.length === 0 ? (
              <div className="text-sm text-gray-500">
                No anomaly rules have fired for this asset yet, either the
                traffic is benign or the engine hasn&apos;t seen its pcap yet.
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead className="bg-gray-50 text-xs text-gray-500">
                  <tr>
                    <th className="px-3 py-1.5 text-left font-medium">Rule / type</th>
                    <th className="px-3 py-1.5 text-right font-medium">Hits</th>
                    <th className="px-3 py-1.5 text-left font-medium">
                      Latest severity
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {ruleRows.map(r => {
                    // Find latest anomaly of this type
                    const latest = assetAnomalies
                      .filter(a => (a.anomalyType || 'UNKNOWN') === r.rule)
                      .sort((a, b) =>
                        (b.detectedAt || '').localeCompare(a.detectedAt || '')
                      )[0];
                    return (
                      <tr key={r.rule} className="border-t border-gray-100">
                        <td className="px-3 py-1.5 text-gray-800">{r.rule}</td>
                        <td className="px-3 py-1.5 text-right text-gray-900">
                          {r.count}
                        </td>
                        <td className="px-3 py-1.5">
                          {latest?.severity ? (
                            <span
                              className={`inline-block px-2 py-0.5 rounded text-xs ${severityBadge(
                                latest.severity
                              )}`}
                            >
                              {latest.severity}
                            </span>
                          ) : (
                            <span className="text-gray-400 text-xs">-</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderUtilization = () => {
    if (!selected) return null;

    const ip = selected.ipAddress?.trim() || '';

    // ---- Window label
    const windowLabel =
      utilWindow === '24h' ? 'last 24 hours' : utilWindow === '7d' ? 'last 7 days' : 'last 30 days';

    // ---- Protocol mix (by PDU count)
    const protoMix = new Map<string, number>();
    for (const e of utilEvents) {
      protoMix.set(e.protocol, (protoMix.get(e.protocol) || 0) + 1);
    }
    const protoRows = Array.from(protoMix.entries())
      .map(([proto, count]) => ({ proto, count }))
      .sort((a, b) => b.count - a.count);
    const totalPdu = utilEvents.length;

    // ---- Read / write split
    let readCount = 0;
    let writeCount = 0;
    let otherCount = 0;
    for (const e of utilEvents) {
      if (e.isWrite === true) writeCount += 1;
      else if (e.pduKind === 'read') readCount += 1;
      else otherCount += 1;
    }

    // ---- Busiest peers
    const peerMix = new Map<string, number>();
    for (const e of utilEvents) {
      const peer = e.sourceIp === ip ? e.destinationIp : e.sourceIp;
      if (peer) peerMix.set(peer, (peerMix.get(peer) || 0) + 1);
    }
    const peerRows = Array.from(peerMix.entries())
      .map(([peer, count]) => ({ peer, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // ---- Hourly / daily histogram
    const bucketMs = utilWindow === '24h' ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
    const now = Date.now();
    const windowMs =
      utilWindow === '24h' ? 24 * 60 * 60 * 1000 : utilWindow === '7d' ? 7 * 24 * 60 * 60 * 1000 : 30 * 24 * 60 * 60 * 1000;
    const bucketCount = Math.ceil(windowMs / bucketMs);
    const buckets: number[] = new Array(bucketCount).fill(0);
    for (const e of utilEvents) {
      if (!e.eventTime) continue;
      const t = new Date(e.eventTime).getTime();
      if (Number.isNaN(t)) continue;
      const idx = Math.floor((now - t) / bucketMs);
      if (idx >= 0 && idx < bucketCount) buckets[bucketCount - 1 - idx] += 1;
    }
    const maxBucket = Math.max(1, ...buckets);

    // ---- Exception / error rate
    const excCount = utilEvents.filter(e => e.isException === true).length;

    // ---- Event rate: average PDUs per hour
    const ratePerHour = totalPdu / Math.max(1, windowMs / (60 * 60 * 1000));

    const windowButton = (w: UtilWindow, label: string) => (
      <button
        key={w}
        type="button"
        onClick={() => setUtilWindow(w)}
        className={`px-3 py-1 text-xs rounded border ${
          utilWindow === w
            ? 'bg-purple-600 text-white border-purple-600'
            : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
        }`}
      >
        {label}
      </button>
    );

    return (
      <div className="space-y-6">
        {utilError && (
          <div className="p-3 bg-red-50 border border-red-200 rounded text-red-800 text-sm">
            {utilError}
          </div>
        )}

        {/* --- Window selector + summary --- */}
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-gray-900">
              Utilization ({windowLabel})
            </h3>
            <div className="flex gap-1">
              {windowButton('24h', '24h')}
              {windowButton('7d', '7d')}
              {windowButton('30d', '30d')}
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                Total PDUs
              </div>
              <div className="text-2xl font-bold text-gray-900 mt-0.5">
                {totalPdu.toLocaleString()}
              </div>
            </div>
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                Avg rate
              </div>
              <div className="text-2xl font-bold text-gray-900 mt-0.5">
                {ratePerHour >= 10
                  ? ratePerHour.toFixed(0)
                  : ratePerHour.toFixed(1)}
              </div>
              <div className="text-xs text-gray-500">PDUs / hour</div>
            </div>
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                Unique peers
              </div>
              <div className="text-2xl font-bold text-gray-900 mt-0.5">
                {peerMix.size}
              </div>
            </div>
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                Exceptions
              </div>
              <div
                className={`text-2xl font-bold mt-0.5 ${
                  excCount > 0 ? 'text-red-700' : 'text-gray-900'
                }`}
              >
                {excCount}
              </div>
              <div className="text-xs text-gray-500">
                {totalPdu > 0
                  ? `${((excCount / totalPdu) * 100).toFixed(1)}% of PDUs`
                  : '-'}
              </div>
            </div>
          </div>
        </div>

        {/* --- Activity histogram --- */}
        <div className="bg-white border border-gray-200 rounded-lg">
          <div className="px-4 py-3 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-900">
              Activity over time
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              {utilWindow === '24h'
                ? 'PDU count per hour'
                : 'PDU count per day (oldest → newest)'}
            </p>
          </div>
          <div className="p-4">
            {isLoadingUtil ? (
              <div className="text-sm text-gray-500">Loading activity…</div>
            ) : totalPdu === 0 ? (
              <div className="text-sm text-gray-500">
                No DPI events for {ip || 'this asset'} in the {windowLabel}.
              </div>
            ) : (
              <div className="flex items-end gap-0.5 h-32">
                {buckets.map((v, i) => {
                  const h = (v / maxBucket) * 100;
                  return (
                    <div
                      key={i}
                      className="flex-1 bg-purple-400 hover:bg-purple-600 rounded-sm relative group"
                      style={{ height: `${Math.max(2, h)}%` }}
                      title={`${v} PDU(s)`}
                    >
                      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block bg-gray-900 text-white text-xs px-1.5 py-0.5 rounded whitespace-nowrap">
                        {v}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* --- Protocol mix + read/write split --- */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-white border border-gray-200 rounded-lg">
            <div className="px-4 py-3 border-b border-gray-200">
              <h3 className="text-sm font-semibold text-gray-900">
                Protocol mix
              </h3>
            </div>
            <div className="p-4">
              {protoRows.length === 0 ? (
                <div className="text-sm text-gray-500">No traffic observed.</div>
              ) : (
                <div className="space-y-2">
                  {protoRows.map(r => {
                    const pct = totalPdu > 0 ? (r.count / totalPdu) * 100 : 0;
                    return (
                      <div key={r.proto}>
                        <div className="flex justify-between text-xs mb-0.5">
                          <span className="font-medium text-gray-700">
                            {r.proto}
                          </span>
                          <span className="text-gray-500">
                            {r.count.toLocaleString()} · {pct.toFixed(1)}%
                          </span>
                        </div>
                        <div className="h-2 rounded bg-gray-100 overflow-hidden">
                          <div
                            className="h-full bg-indigo-500"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          <div className="bg-white border border-gray-200 rounded-lg">
            <div className="px-4 py-3 border-b border-gray-200">
              <h3 className="text-sm font-semibold text-gray-900">
                Read / write split
              </h3>
              <p className="text-xs text-gray-500 mt-0.5">
                Write-heavy traffic on an L0/L1 device usually warrants a closer
                look.
              </p>
            </div>
            <div className="p-4">
              {totalPdu === 0 ? (
                <div className="text-sm text-gray-500">No PDUs to classify.</div>
              ) : (
                <>
                  <div className="grid grid-cols-3 gap-3 mb-3">
                    <div>
                      <div className="text-xs text-gray-500 uppercase tracking-wide">
                        Reads
                      </div>
                      <div className="text-xl font-bold text-blue-700">
                        {readCount.toLocaleString()}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-gray-500 uppercase tracking-wide">
                        Writes
                      </div>
                      <div className="text-xl font-bold text-red-700">
                        {writeCount.toLocaleString()}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-gray-500 uppercase tracking-wide">
                        Other
                      </div>
                      <div className="text-xl font-bold text-gray-700">
                        {otherCount.toLocaleString()}
                      </div>
                    </div>
                  </div>
                  <div className="h-3 rounded bg-gray-100 overflow-hidden flex">
                    <div
                      className="h-full bg-blue-500"
                      style={{ width: `${(readCount / totalPdu) * 100}%` }}
                    />
                    <div
                      className="h-full bg-red-500"
                      style={{ width: `${(writeCount / totalPdu) * 100}%` }}
                    />
                    <div
                      className="h-full bg-gray-400"
                      style={{ width: `${(otherCount / totalPdu) * 100}%` }}
                    />
                  </div>
                  <div className="mt-1 text-xs text-gray-500 flex justify-between">
                    <span>
                      <span className="inline-block w-2 h-2 bg-blue-500 rounded-sm mr-1" />
                      read
                    </span>
                    <span>
                      <span className="inline-block w-2 h-2 bg-red-500 rounded-sm mr-1" />
                      write
                    </span>
                    <span>
                      <span className="inline-block w-2 h-2 bg-gray-400 rounded-sm mr-1" />
                      other
                    </span>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>

        {/* --- Busiest peers --- */}
        <div className="bg-white border border-gray-200 rounded-lg">
          <div className="px-4 py-3 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-900">
              Busiest peers
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Top 10 IPs this asset exchanged PDUs with in the {windowLabel}.
            </p>
          </div>
          <div className="p-4">
            {peerRows.length === 0 ? (
              <div className="text-sm text-gray-500">No peer traffic observed.</div>
            ) : (
              <table className="w-full text-sm">
                <thead className="bg-gray-50 text-xs text-gray-500">
                  <tr>
                    <th className="px-3 py-1.5 text-left font-medium">Peer IP</th>
                    <th className="px-3 py-1.5 text-right font-medium">PDUs</th>
                    <th className="px-3 py-1.5 text-left font-medium">Share</th>
                  </tr>
                </thead>
                <tbody>
                  {peerRows.map(r => {
                    const pct = totalPdu > 0 ? (r.count / totalPdu) * 100 : 0;
                    return (
                      <tr key={r.peer} className="border-t border-gray-100">
                        <td className="px-3 py-1.5 font-mono text-xs text-gray-700">
                          {r.peer}
                        </td>
                        <td className="px-3 py-1.5 text-right text-gray-900">
                          {r.count.toLocaleString()}
                        </td>
                        <td className="px-3 py-1.5">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-2 rounded bg-gray-100 overflow-hidden">
                              <div
                                className="h-full bg-emerald-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                            <span className="text-xs text-gray-500 w-12 text-right">
                              {pct.toFixed(1)}%
                            </span>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderHistory = () => {
    if (!selected) return null;

    const ip = selected.ipAddress?.trim() || '';

    // ---- Timeline entry types
    type TimelineKind =
      | 'lifecycle-created'
      | 'lifecycle-updated'
      | 'dpi-first'
      | 'dpi-last'
      | 'dpi-event'
      | 'anomaly'
      | 'alert';
    interface TimelineEntry {
      id: string;
      kind: TimelineKind;
      timestamp: string;
      title: string;
      subtitle?: string;
      severity?: string;
      icon: string; // emoji / short text
      color: string; // tailwind tint for the dot
    }

    const entries: TimelineEntry[] = [];

    // --- Lifecycle
    if (selected.createdAt) {
      entries.push({
        id: `lc-created-${selected.id}`,
        kind: 'lifecycle-created',
        timestamp: selected.createdAt,
        title: 'Asset created in inventory',
        subtitle: selected.createdBy ? `by ${selected.createdBy}` : undefined,
        icon: '＋',
        color: 'bg-green-500',
      });
    }
    if (selected.updatedAt && selected.updatedAt !== selected.createdAt) {
      entries.push({
        id: `lc-updated-${selected.id}`,
        kind: 'lifecycle-updated',
        timestamp: selected.updatedAt,
        title: 'Asset record updated',
        subtitle: selected.updatedBy ? `by ${selected.updatedBy}` : undefined,
        icon: '✎',
        color: 'bg-blue-500',
      });
    }

    // --- DPI first / last seen (reuse dataSources if available)
    if (dataSources.assetFirstDpiEvent?.eventTime) {
      const e = dataSources.assetFirstDpiEvent;
      entries.push({
        id: `dpi-first-${e.id}`,
        kind: 'dpi-first',
        timestamp: e.eventTime,
        title: `First DPI event (${e.protocol})`,
        subtitle: e.functionName || e.summary || undefined,
        icon: '▶',
        color: 'bg-emerald-500',
      });
    }
    if (
      dataSources.assetLastDpiEvent?.eventTime &&
      dataSources.assetLastDpiEvent.id !== dataSources.assetFirstDpiEvent?.id
    ) {
      const e = dataSources.assetLastDpiEvent;
      entries.push({
        id: `dpi-last-${e.id}`,
        kind: 'dpi-last',
        timestamp: e.eventTime,
        title: `Most recent DPI event (${e.protocol})`,
        subtitle: e.functionName || e.summary || undefined,
        icon: '⏹',
        color: 'bg-emerald-400',
      });
    }

    // --- Recent DPI events (top ~20 to keep the list readable)
    for (const e of historyDpi.slice(0, 20)) {
      if (!e.eventTime) continue;
      // Skip the first/last if they already exist
      if (
        e.id === dataSources.assetFirstDpiEvent?.id ||
        e.id === dataSources.assetLastDpiEvent?.id
      ) {
        continue;
      }
      const direction = e.sourceIp === ip ? '→' : '←';
      const peer = e.sourceIp === ip ? e.destinationIp : e.sourceIp;
      entries.push({
        id: `dpi-${e.id}`,
        kind: 'dpi-event',
        timestamp: e.eventTime,
        title: `${e.protocol} ${direction} ${peer}`,
        subtitle: e.functionName || e.summary || undefined,
        icon: '·',
        color: 'bg-gray-400',
      });
    }

    // --- Anomalies (reuse insights)
    for (const a of insights.anomalies) {
      if (!a.detectedAt) continue;
      entries.push({
        id: `anom-${a.id}`,
        kind: 'anomaly',
        timestamp: a.detectedAt,
        title: a.title || a.anomalyType || 'Anomaly detected',
        subtitle: a.anomalyType,
        severity: a.severity,
        icon: '⚠',
        color:
          a.severity === 'CRITICAL'
            ? 'bg-red-600'
            : a.severity === 'HIGH'
            ? 'bg-orange-500'
            : a.severity === 'MEDIUM'
            ? 'bg-yellow-500'
            : 'bg-blue-500',
      });
    }

    // --- Alerts (reuse insights)
    for (const al of insights.alerts) {
      const ts = al.createdAt;
      if (!ts) continue;
      entries.push({
        id: `alert-${al.id}`,
        kind: 'alert',
        timestamp: String(ts),
        title: al.title || al.type || 'Alert',
        subtitle: al.type,
        severity: al.severity,
        icon: '!',
        color:
          al.severity === 'CRITICAL'
            ? 'bg-red-600'
            : al.severity === 'HIGH'
            ? 'bg-orange-500'
            : 'bg-amber-500',
      });
    }

    // --- Sort newest first
    entries.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));

    // --- Kind filter
    const counts = {
      lifecycle:
        entries.filter(
          e => e.kind === 'lifecycle-created' || e.kind === 'lifecycle-updated'
        ).length,
      dpi: entries.filter(
        e =>
          e.kind === 'dpi-first' || e.kind === 'dpi-last' || e.kind === 'dpi-event'
      ).length,
      anomaly: entries.filter(e => e.kind === 'anomaly').length,
      alert: entries.filter(e => e.kind === 'alert').length,
    };

    return (
      <div className="space-y-6">
        {historyError && (
          <div className="p-3 bg-red-50 border border-red-200 rounded text-red-800 text-sm">
            {historyError}
          </div>
        )}

        {/* --- Summary chips --- */}
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                Lifecycle
              </div>
              <div className="text-2xl font-bold text-gray-900 mt-0.5">
                {counts.lifecycle}
              </div>
            </div>
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                DPI events
              </div>
              <div className="text-2xl font-bold text-gray-900 mt-0.5">
                {counts.dpi}
              </div>
            </div>
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                Anomalies
              </div>
              <div className="text-2xl font-bold text-gray-900 mt-0.5">
                {counts.anomaly}
              </div>
            </div>
            <div className="p-3 bg-gray-50 rounded border border-gray-200">
              <div className="text-xs text-gray-500 uppercase tracking-wide">
                Alerts
              </div>
              <div className="text-2xl font-bold text-gray-900 mt-0.5">
                {counts.alert}
              </div>
            </div>
          </div>
        </div>

        {/* --- Timeline --- */}
        <div className="bg-white border border-gray-200 rounded-lg">
          <div className="px-4 py-3 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-900">
              Event timeline
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Newest first. Includes lifecycle, DPI traffic, anomalies, and
              alerts for this asset.
            </p>
          </div>
          <div className="p-4">
            {isLoadingHistory || isLoadingInsights ? (
              <div className="text-sm text-gray-500">Loading history…</div>
            ) : entries.length === 0 ? (
              <div className="text-sm text-gray-500">
                No history yet, this asset has no lifecycle events, DPI
                observations, anomalies, or alerts on record.
              </div>
            ) : (
              <ol className="relative border-l-2 border-gray-200 ml-2">
                {entries.map(e => (
                  <li key={e.id} className="mb-4 ml-4">
                    <span
                      className={`absolute -left-[11px] w-5 h-5 rounded-full border-2 border-white flex items-center justify-center text-[10px] text-white font-bold ${e.color}`}
                    >
                      {e.icon}
                    </span>
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <div className="text-sm font-medium text-gray-900">
                          {e.title}
                        </div>
                        {e.subtitle && (
                          <div className="text-xs text-gray-500 truncate">
                            {e.subtitle}
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        {e.severity && (
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-xs ${severityBadge(
                              e.severity
                            )}`}
                          >
                            {e.severity}
                          </span>
                        )}
                        <span className="text-xs text-gray-500 whitespace-nowrap">
                          {formatDate(e.timestamp)}
                        </span>
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderVulnerabilities = () => {
    if (!selected) return null;
    if (isLoadingVulnerabilities) {
      return (
        <div className="p-8 text-center">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mb-3" />
          <p className="text-gray-600 text-sm">
            Searching CVE database for {selected.manufacturer || '(no manufacturer)'}…
          </p>
        </div>
      );
    }
    if (vulnerabilitiesError) {
      return (
        <div className="p-6 text-center">
          <p className="text-red-500 mb-2">Error: {vulnerabilitiesError}</p>
          <p className="text-xs text-gray-500">
            The backend queries NVD and CIRCL Vulnerability-Lookup, with a built-in
            offline catalog as a last resort. Outbound network blocks or rate-limits
            on the server will surface here.
          </p>
        </div>
      );
    }

    if (!selected.manufacturer || !selected.manufacturer.trim()) {
      return (
        <div className="p-8 text-center text-gray-500">
          <div className="text-3xl mb-2">ℹ️</div>
          <p className="mb-2">
            This asset has no <strong>manufacturer</strong> set.
          </p>
          <p className="text-sm">
            CVE lookup uses the manufacturer name as a keyword. Switch to the
            <strong> Device Information</strong> tab, click <strong>✎ Edit</strong>,
            set the manufacturer, and come back.
          </p>
        </div>
      );
    }

    // Classify + filter + sort
    const classified = vulnerabilities.map(v => ({
      ...v,
      tier: cvssToTier(v.severity),
      cvss: (() => {
        const n = Number(v.severity);
        return Number.isNaN(n) ? null : n;
      })(),
    }));

    const searchLower = vulnSearch.trim().toLowerCase();
    const filtered = classified.filter(v => {
      if (vulnFilter !== 'ALL' && v.tier !== vulnFilter) return false;
      if (!searchLower) return true;
      return (
        v.id.toLowerCase().includes(searchLower) ||
        (v.title || '').toLowerCase().includes(searchLower)
      );
    });

    const sorted = [...filtered].sort((a, b) => {
      let cmp = 0;
      if (vulnSortKey === 'severity') {
        cmp = VULN_TIER_RANK[a.tier] - VULN_TIER_RANK[b.tier];
        if (cmp === 0) cmp = (a.cvss ?? -1) - (b.cvss ?? -1);
      } else if (vulnSortKey === 'publishedDate') {
        const ta = a.publishedDate ? new Date(a.publishedDate).getTime() : 0;
        const tb = b.publishedDate ? new Date(b.publishedDate).getTime() : 0;
        cmp = ta - tb;
      } else {
        cmp = a.id.localeCompare(b.id, undefined, { numeric: true });
      }
      return vulnSortDir === 'asc' ? cmp : -cmp;
    });

    const counts = {
      total: classified.length,
      critical: classified.filter(v => v.tier === 'CRITICAL').length,
      high: classified.filter(v => v.tier === 'HIGH').length,
      medium: classified.filter(v => v.tier === 'MEDIUM').length,
      low: classified.filter(v => v.tier === 'LOW').length,
      unknown: classified.filter(v => v.tier === 'UNKNOWN').length,
    };

    const toggleSort = (key: typeof vulnSortKey) => {
      if (vulnSortKey === key) {
        setVulnSortDir(prev => (prev === 'asc' ? 'desc' : 'asc'));
      } else {
        setVulnSortKey(key);
        setVulnSortDir(key === 'id' ? 'asc' : 'desc');
      }
    };

    const SortTh: React.FC<{ k: typeof vulnSortKey; label: string; align?: 'left' | 'right' }> = ({
      k, label, align,
    }) => (
      <th
        onClick={() => toggleSort(k)}
        className={`px-4 py-2 cursor-pointer select-none ${align === 'right' ? 'text-right' : 'text-left'}`}
      >
        <span className="inline-flex items-center gap-1">
          {label}
          {vulnSortKey === k && (
            <span className="text-xs">{vulnSortDir === 'asc' ? '▲' : '▼'}</span>
          )}
        </span>
      </th>
    );

    const FilterPill: React.FC<{
      tier: VulnSeverityTier | 'ALL';
      label: string;
      count: number;
      activeClass: string;
    }> = ({ tier, label, count, activeClass }) => {
      const active = vulnFilter === tier;
      return (
        <button
          onClick={() => setVulnFilter(tier)}
          className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
            active
              ? activeClass
              : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
          }`}
        >
          {label} <span className="opacity-70">({count})</span>
        </button>
      );
    };

    return (
      <div className="p-4">
        <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
          <div>
            <h3 className="text-xl font-bold">
              Vulnerabilities for {selected.name}
            </h3>
            <p className="text-sm text-gray-500">
              Manufacturer: <span className="font-medium">{selected.manufacturer}</span>
              {' · '}Source: CIRCL CVE Search
            </p>
          </div>
          <div className="flex items-center gap-2">
            <input
              value={vulnSearch}
              onChange={e => setVulnSearch(e.target.value)}
              placeholder="Filter by CVE id or keyword…"
              className="border border-gray-300 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 w-64"
            />
          </div>
        </div>

        <div className="flex items-center gap-2 mb-4 flex-wrap">
          <FilterPill tier="ALL" label="All" count={counts.total} activeClass="bg-blue-600 text-white" />
          <FilterPill tier="CRITICAL" label="Critical" count={counts.critical} activeClass="bg-red-600 text-white" />
          <FilterPill tier="HIGH" label="High" count={counts.high} activeClass="bg-orange-500 text-white" />
          <FilterPill tier="MEDIUM" label="Medium" count={counts.medium} activeClass="bg-yellow-500 text-white" />
          <FilterPill tier="LOW" label="Low" count={counts.low} activeClass="bg-green-600 text-white" />
          {counts.unknown > 0 && (
            <FilterPill tier="UNKNOWN" label="Unknown" count={counts.unknown} activeClass="bg-gray-600 text-white" />
          )}
        </div>

        {classified.length === 0 ? (
          <div className="border rounded-lg p-8 text-center text-gray-500">
            <div className="text-3xl mb-2">✓</div>
            <p className="text-sm">
              No vulnerabilities returned for manufacturer{' '}
              <span className="font-medium">{selected.manufacturer}</span>.
            </p>
            <p className="text-xs text-gray-400 mt-1">
              Try a more specific or canonical manufacturer name (e.g. "siemens", "schneider").
            </p>
          </div>
        ) : sorted.length === 0 ? (
          <div className="border rounded-lg p-6 text-center text-gray-500">
            No CVEs match the current filter.
          </div>
        ) : (
          <div className="overflow-x-auto border rounded-lg">
            <table className="min-w-full bg-white">
              <thead className="bg-gray-50 text-xs uppercase text-gray-500">
                <tr>
                  <SortTh k="id" label="CVE ID" />
                  <th className="px-4 py-2 text-left">Summary</th>
                  <SortTh k="severity" label="Severity" />
                  <SortTh k="publishedDate" label="Published" />
                  <th className="px-4 py-2 text-left">Link</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map(v => {
                  const published =
                    v.publishedDate && !Number.isNaN(new Date(v.publishedDate).getTime())
                      ? new Date(v.publishedDate).toLocaleDateString()
                      : v.publishedDate || '-';
                  return (
                    <tr key={v.id} className="border-t hover:bg-gray-50 align-top">
                      <td className="px-4 py-2 font-mono text-xs whitespace-nowrap">
                        {v.id}
                      </td>
                      <td className="px-4 py-2 text-sm text-gray-700 max-w-xl">
                        <div className="line-clamp-3" title={v.title}>
                          {v.title || <span className="text-gray-400">-</span>}
                        </div>
                      </td>
                      <td className="px-4 py-2 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 text-xs rounded font-semibold ${severityBadge(
                            v.tier
                          )}`}
                        >
                          {v.tier}
                        </span>
                        {v.cvss !== null && (
                          <span className="ml-2 text-xs text-gray-500">
                            CVSS {v.cvss.toFixed(1)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-sm text-gray-600 whitespace-nowrap">
                        {published}
                      </td>
                      <td className="px-4 py-2 whitespace-nowrap">
                        <a
                          href={v.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:text-blue-800 underline text-sm"
                        >
                          MITRE ↗
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <p className="text-xs text-gray-400 mt-3">
          Showing {sorted.length} of {classified.length} CVEs. Severity tiers use CVSS v3
          thresholds (≥9 critical, ≥7 high, ≥4 medium, &gt;0 low).
        </p>
      </div>
    );
  };

  const renderTabContent = () => {
    if (isLoading) {
      return (
        <div className="flex items-center justify-center p-8">
          <div className="text-center">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mb-4" />
            <p className="text-gray-600 text-lg">Loading assets from backend…</p>
          </div>
        </div>
      );
    }
    if (loadError) {
      return (
        <div className="p-6 text-center">
          <p className="text-red-500 mb-3">{loadError}</p>
          <button
            onClick={loadAssets}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Retry
          </button>
        </div>
      );
    }
    if (assets.length === 0) {
      return (
        <div className="flex items-center justify-center p-8">
          <div className="text-center">
            <div className="w-16 h-16 mx-auto mb-4 text-gray-400">
              <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                />
              </svg>
            </div>
            <p className="text-gray-600 text-lg mb-2">No assets yet</p>
            <p className="text-gray-500 text-sm">
              Upload a PCAP file, assets are auto-discovered from observed traffic.
            </p>
          </div>
        </div>
      );
    }
    if (!selected) {
      return (
        <div className="p-4 text-gray-500">Select an asset from the list above.</div>
      );
    }

    switch (activeTab) {
      case 'Device Information':
        return renderDeviceInformation();
      case 'Risk':
        return renderRisk();
      case 'Vulnerabilities':
        return renderVulnerabilities();
      case 'Alerts & Insights':
        return renderAlertsInsights();
      case 'OT Activity':
        return renderOtActivity();
      case 'Data Sources':
        return renderDataSources();
      case 'Location':
        return renderLocation();
      case 'Network Security':
        return renderNetworkSecurity();
      case 'Utilization':
        return renderUtilization();
      case 'History':
        return renderHistory();
      default:
        return (
          <div className="p-6 text-gray-500">
            <p className="mb-2">
              <strong>{activeTab}</strong>, backend wiring coming in a later phase.
            </p>
            <p className="text-sm">
              This tab will be powered by real backend data (DPI events, alerts, observed
              connections, audit log, etc.) once Phase 2–5 of the rewrite ships.
            </p>
          </div>
        );
    }
  };

  return (
    <div className="space-y-6">
      <div
        className="relative overflow-hidden rounded-2xl p-8 md:p-10 text-white"
        style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #4c1d95 45%, #7c3aed 100%)' }}
      >
        <div className="absolute -top-20 -right-20 w-80 h-80 rounded-full" style={{ background: 'radial-gradient(closest-side, rgba(236,72,153,0.35), transparent)' }} />
        <div className="absolute -bottom-24 -left-10 w-72 h-72 rounded-full" style={{ background: 'radial-gradient(closest-side, rgba(168,85,247,0.35), transparent)' }} />
        <div className="relative">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 backdrop-blur-sm ring-1 ring-white/20 text-xs font-medium tracking-wide">
            <svg className="w-4 h-4 text-pink-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            OT ASSET INVENTORY
          </div>
          <h1 className="mt-4 text-3xl md:text-4xl font-bold leading-tight">
            Assets & devices
            <span className="block text-violet-100/90 font-medium text-lg md:text-xl mt-2">
              Real PLCs, RTUs, HMIs, engineering workstations and their current security posture.
            </span>
          </h1>
        </div>
      </div>

      {renderDeviceList()}

      <div className="bg-white rounded-2xl ring-1 ring-slate-200/70 shadow-sm overflow-hidden">
        <div className="border-b border-slate-200/70 bg-slate-50/50">
          <nav className="flex flex-wrap">
            {TABS.map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-4 px-6 text-sm font-medium transition ${
                  activeTab === tab
                    ? 'border-b-2 border-violet-500 text-violet-700 bg-white'
                    : 'text-slate-500 hover:text-violet-600 hover:bg-white/60'
                }`}
              >
                {tab}
              </button>
            ))}
          </nav>
        </div>
        <div className="p-4">{renderTabContent()}</div>
      </div>

      {/* keep logout handler referenced so linter doesn't complain;
          the actual logout button lives in the shared layout */}
      <button type="button" onClick={handleLogout} className="hidden" aria-hidden="true" />
    </div>
  );
};

export default Assets;
