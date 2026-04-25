import api from './api';
import anomalyService, { Anomaly } from './anomalyService';
import dpiService from './dpiService';

/**
 * Topology service - derives a live network graph (nodes + edges) from
 * the existing assets and anomalies APIs. No new backend endpoint required.
 *
 * Node  = Asset (or unknown IP seen in an anomaly but not in asset inventory)
 * Edge  = Observed communication between two IPs (currently sourced from
 *         anomaly records; each edge is colored by the highest severity
 *         anomaly observed between those two endpoints).
 */

// --- Types coming back from the backend -------------------------------------

export interface BackendAsset {
  id: string;
  name?: string;
  ipAddress?: string;
  macAddress?: string;
  assetType?: string;
  assetCategory?: string;
  purdueLevel?: string; // enum: LEVEL_0 .. LEVEL_5
  manufacturer?: string;
  model?: string;
  hostname?: string;
  location?: string;
  department?: string;
  criticalityLevel?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  riskScore?: number;
  vulnerabilityCount?: number;
  isActive?: boolean;
  isOnline?: boolean;
}

export interface PageResponse<T> {
  content: T[];
  totalElements?: number;
  totalPages?: number;
  size?: number;
  number?: number;
}

// --- Graph model that the UI consumes ---------------------------------------

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'NONE';

/**
 * IEC 62443 inspired security zones - coarser grouping than Purdue levels,
 * used for segmentation visualization. A zone groups one or more Purdue
 * levels that share the same trust boundary.
 */
export type ZoneId =
  | 'EXTERNAL'    // untrusted Internet
  | 'DMZ'         // industrial DMZ / perimeter
  | 'ENTERPRISE'  // corporate IT + operations (L3-L4)
  | 'CONTROL'     // supervisory + basic control (L1-L2)
  | 'FIELD';      // field devices (L0)

export interface ZoneDef {
  id: ZoneId;
  label: string;
  short: string;
  /** Background tint used when drawing the zone rectangle */
  background: string;
  /** Stroke color for zone border and label badge */
  accent: string;
  /** Purdue levels that map to this zone (used for auto-assignment) */
  purdueLevels: number[];
}

export const ZONES: Record<ZoneId, ZoneDef> = {
  EXTERNAL:   { id: 'EXTERNAL',   label: 'Untrusted External',       short: 'External',      background: 'rgba(239, 68, 68, 0.08)',  accent: '#DC2626', purdueLevels: [5] },
  DMZ:        { id: 'DMZ',        label: 'Industrial DMZ',           short: 'DMZ',           background: 'rgba(245, 158, 11, 0.10)', accent: '#D97706', purdueLevels: [5] },
  ENTERPRISE: { id: 'ENTERPRISE', label: 'Enterprise & Operations',  short: 'Enterprise',    background: 'rgba(59, 130, 246, 0.08)', accent: '#2563EB', purdueLevels: [3, 4] },
  CONTROL:    { id: 'CONTROL',    label: 'Control & Supervisory',    short: 'Control',       background: 'rgba(99, 102, 241, 0.08)', accent: '#4F46E5', purdueLevels: [1, 2] },
  FIELD:      { id: 'FIELD',      label: 'Plant Floor / Field',      short: 'Field',         background: 'rgba(16, 185, 129, 0.09)', accent: '#059669', purdueLevels: [0] },
};

export const ZONE_ORDER: ZoneId[] = ['EXTERNAL', 'DMZ', 'ENTERPRISE', 'CONTROL', 'FIELD'];

export interface TopologyNode {
  id: string;                // unique; uses asset.id when available, otherwise `ip:<ip>`
  label: string;             // short label for graph
  ip?: string;
  purdueLevel: number;       // 0..5; used for hierarchical layout
  zone: ZoneId;              // IEC 62443 zone this node belongs to
  criticality: Severity;     // drives color
  isOnline: boolean;
  isKnown: boolean;          // false when only observed via anomaly
  asset?: BackendAsset;      // raw asset payload for the side panel
  anomalyCount: number;      // anomalies this node is involved in
  worstSeverity: Severity;   // worst severity seen on any edge touching this node
}

/**
 * Phase-2 analytics attached to every edge. Drives:
 *  - "NEW" badge for communications never seen during baseline
 *  - tooltip sparkline showing activity over the full time range
 *  - edge thickness proportional to windowCount
 */
export interface EdgeAnalytics {
  /** Events observed during the baseline period. */
  baselineCount: number;
  /** Events observed inside the currently-selected time window. */
  windowCount: number;
  /** Events across the entire dataset. */
  totalCount: number;
  /** Bucket counts across fullRange (length === sparkline bin count). */
  sparkline: number[];
  /** True when this comm appears in the selected window but never during baseline. */
  isNewInWindow: boolean;
  firstSeenAt?: number;
  lastSeenAt?: number;
  /** [start, end) bucket indices inside `sparkline` that fall within the baseline period. */
  baselineBucketRange?: [number, number];
  /** [start, end) bucket indices inside `sparkline` that fall within the selected window. */
  windowBucketRange?: [number, number];
}

export interface TopologyEdge {
  id: string;
  source: string;            // node id
  target: string;            // node id
  severity: Severity;        // worst severity between the two endpoints
  anomalyIds: string[];      // anomaly records that contributed
  protocols: string[];
  count: number;
  isBaseline?: boolean;      // true for non-anomalous baseline comms (dashed, gray)
  isConduit?: boolean;       // true if source/target are in different zones
  analytics?: EdgeAnalytics; // optional Phase-2 analytics
}

export interface TopologyGraph {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  generatedAt: string;
  isDemo?: boolean;
  scenario?: {
    title: string;
    summary: string;
    steps: string[];
  };
  stats: {
    assetCount: number;
    unknownIpCount: number;
    anomalousEdges: number;
  };
}

/**
 * A benign communication that we want to draw on the graph even though it is
 * not an anomaly (e.g. normal Modbus polling). These edges render as faint
 * dashed lines and do NOT increment a node's anomaly count.
 */
export interface BaselineConnection {
  sourceIp: string;
  destinationIp: string;
  protocol?: string;
}

// --- Helpers ----------------------------------------------------------------

const SEVERITY_RANK: Record<Severity, number> = {
  NONE: 0,
  INFO: 1,
  LOW: 2,
  MEDIUM: 3,
  HIGH: 4,
  CRITICAL: 5,
};

const worseSeverity = (a: Severity, b: Severity): Severity =>
  SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;

const normalizeSeverity = (s?: string): Severity => {
  if (!s) return 'NONE';
  const up = s.toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(up)) return up as Severity;
  return 'NONE';
};

const purdueLevelToNumber = (level?: string): number => {
  if (!level) return 3; // default: middle of the stack
  const match = level.match(/(\d)/);
  if (match) {
    const n = parseInt(match[1], 10);
    if (!Number.isNaN(n) && n >= 0 && n <= 5) return n;
  }
  const up = level.toUpperCase();
  if (up.includes('FIELD')) return 0;
  if (up.includes('CONTROL')) return 1;
  if (up.includes('SUPERVISORY') || up.includes('SCADA')) return 2;
  if (up.includes('MES') || up.includes('OPERATIONS')) return 3;
  if (up.includes('ENTERPRISE') || up.includes('ERP')) return 4;
  if (up.includes('DMZ') || up.includes('EXTERNAL')) return 5;
  return 3;
};

const criticalityToSeverity = (c?: string): Severity => {
  const up = (c || '').toUpperCase();
  if (up === 'CRITICAL') return 'CRITICAL';
  if (up === 'HIGH') return 'HIGH';
  if (up === 'MEDIUM') return 'MEDIUM';
  if (up === 'LOW') return 'LOW';
  return 'LOW';
};

/**
 * Derive a security zone for a node.
 *
 * Priority order:
 *  1. If the asset's `location` or `department` matches a zone keyword
 *     (e.g. "DMZ", "Control Room", "Plant Floor"), use that - operators
 *     sometimes tag assets with zone names directly.
 *  2. Otherwise derive from purdueLevel using ZONES[x].purdueLevels.
 *  3. Unknown/external IPs default to EXTERNAL.
 */
const deriveZone = (opts: {
  purdueLevel: number;
  asset?: BackendAsset;
  isKnown: boolean;
}): ZoneId => {
  if (!opts.isKnown) return 'EXTERNAL';

  const hint = `${opts.asset?.location || ''} ${opts.asset?.department || ''}`.toUpperCase();
  if (hint) {
    if (hint.includes('DMZ') || hint.includes('PERIMETER')) return 'DMZ';
    if (hint.includes('EXTERNAL') || hint.includes('INTERNET')) return 'EXTERNAL';
    if (hint.includes('FIELD') || hint.includes('PLANT FLOOR')) return 'FIELD';
    if (hint.includes('CONTROL ROOM') || hint.includes('SCADA')) return 'CONTROL';
    if (hint.includes('ENTERPRISE') || hint.includes('CORPORATE') || hint.includes('OFFICE')) return 'ENTERPRISE';
  }

  // Fall back to Purdue-level mapping
  for (const zid of ZONE_ORDER) {
    if (ZONES[zid].purdueLevels.includes(opts.purdueLevel)) return zid;
  }
  return 'ENTERPRISE';
};

const edgeKey = (a: string, b: string): string => {
  // undirected key so A->B and B->A collapse to one edge
  return a < b ? `${a}__${b}` : `${b}__${a}`;
};

// --- Raw dataset (used by UI for client-side time filtering) ---------------

export interface TopologyRawData {
  assets: BackendAsset[];
  anomalies: Anomaly[];
  baselineConnections: BaselineConnection[];
  scenario?: TopologyGraph['scenario'];
  isDemo: boolean;
  generatedAt: string;
  /**
   * Per-source counts + error flags so the UI can show a diagnostic panel
   * explaining *why* the graph looks the way it does (empty? demo? partial
   * failure?). Populated by `getRawData`; absent on direct `demoRawData()`.
   */
  diagnostics?: {
    assetCount: number;
    anomalyCount: number;
    observedConnectionCount: number;
    assetsError: boolean;
    anomaliesError: boolean;
    observedConnectionsError: boolean;
    fellBackToDemo: boolean;
    /** True when every real source is empty (but APIs succeeded). */
    allEmpty: boolean;
  };
}

// --- Demo fallback data -----------------------------------------------------

/** Returns the demo dataset in raw form so the UI can apply its own time filter. */
const demoRawData = (): TopologyRawData => {
  // --- Story -----------------------------------------------------------------
  // An external threat actor lands a phishing payload on a corporate
  // Engineering Workstation. From there the attacker pivots down the Purdue
  // stack - Historian → SCADA → HMI → PLC - and finally issues a malicious
  // write to a pump actuator. A secondary exfil channel sends Historian
  // data back out via HTTPS.
  //
  // Node count kept deliberately small (10) so the graph reads like a story
  // rather than a blizzard of endpoints.

  // Spread the 7 attack-chain timestamps over the last ~28 minutes so the
  // timeline histogram tells a story when the user scrubs back and forth.
  const now = Date.now();
  const minutesAgo = (m: number) => new Date(now - m * 60_000).toISOString();

  const assets: BackendAsset[] = [
    // --- DMZ zone ---------------------------------------------------------
    {
      id: 'fw-01', name: 'Perimeter Firewall', ipAddress: '192.168.100.1',
      purdueLevel: 'LEVEL_5', criticalityLevel: 'HIGH',
      manufacturer: 'Fortinet', model: 'FortiGate 200F', assetType: 'Firewall',
      location: 'DMZ Rack', department: 'IT Security',
      isOnline: true, riskScore: 35, vulnerabilityCount: 1,
    },
    // --- Enterprise zone (L3-L4) -----------------------------------------
    {
      id: 'ws-eng-01', name: 'Engineering Workstation', ipAddress: '10.20.5.42',
      purdueLevel: 'LEVEL_4', criticalityLevel: 'HIGH',
      manufacturer: 'Dell', model: 'OptiPlex 7090', assetType: 'Workstation',
      location: 'Corporate Office', department: 'Engineering',
      isOnline: true, riskScore: 71, vulnerabilityCount: 4,
    },
    {
      id: 'hist-01', name: 'PI Historian', ipAddress: '10.30.3.15',
      purdueLevel: 'LEVEL_3', criticalityLevel: 'HIGH',
      manufacturer: 'OSIsoft', model: 'PI Server 2018', assetType: 'Historian',
      location: 'Operations Data Center', department: 'Operations',
      isOnline: true, riskScore: 62, vulnerabilityCount: 2,
    },
    // --- Control zone (L1-L2) --------------------------------------------
    {
      id: 'scada-01', name: 'Wonderware SCADA', ipAddress: '10.40.2.10',
      purdueLevel: 'LEVEL_2', criticalityLevel: 'CRITICAL',
      manufacturer: 'AVEVA (Wonderware)', model: 'System Platform 2020', assetType: 'SCADA',
      location: 'Control Room', department: 'Operations',
      isOnline: true, riskScore: 88, vulnerabilityCount: 3,
    },
    {
      id: 'hmi-01', name: 'WinCC HMI', ipAddress: '10.40.2.51',
      purdueLevel: 'LEVEL_2', criticalityLevel: 'HIGH',
      manufacturer: 'Siemens', model: 'WinCC V7.5', assetType: 'HMI',
      location: 'Control Room', department: 'Operations',
      isOnline: true, riskScore: 66, vulnerabilityCount: 2,
    },
    {
      id: 'plc-01', name: 'S7-1500 Main PLC', ipAddress: '10.40.1.21',
      purdueLevel: 'LEVEL_1', criticalityLevel: 'CRITICAL',
      manufacturer: 'Siemens', model: 'S7-1500 CPU 1515', assetType: 'PLC',
      location: 'Control Cabinet A', department: 'Operations',
      isOnline: true, riskScore: 83, vulnerabilityCount: 2,
    },
    {
      id: 'rtu-01', name: 'RTU-01 (Substation)', ipAddress: '10.40.1.35',
      purdueLevel: 'LEVEL_1', criticalityLevel: 'HIGH',
      manufacturer: 'Schneider Electric', model: 'SCADAPack 474', assetType: 'RTU',
      location: 'Substation', department: 'Operations',
      isOnline: true, riskScore: 54, vulnerabilityCount: 1,
    },
    // --- Field zone (L0) --------------------------------------------------
    {
      id: 'sensor-01', name: 'Pressure Sensor P-101', ipAddress: '10.40.0.11',
      purdueLevel: 'LEVEL_0', criticalityLevel: 'MEDIUM',
      manufacturer: 'Endress+Hauser', model: 'Cerabar PMC71', assetType: 'Sensor',
      location: 'Plant Floor', department: 'Operations',
      isOnline: true, riskScore: 22, vulnerabilityCount: 0,
    },
    {
      id: 'pump-01', name: 'Cooling Pump Actuator', ipAddress: '10.40.0.21',
      purdueLevel: 'LEVEL_0', criticalityLevel: 'CRITICAL',
      manufacturer: 'Schneider Electric', model: 'Altivar 630', assetType: 'Pump Actuator',
      location: 'Plant Floor', department: 'Operations',
      isOnline: true, riskScore: 78, vulnerabilityCount: 1,
    },
  ];

  // External attacker (external IP is injected as an unknown node via the
  // anomaly chain; no asset record exists for it - that's the point).
  const ATTACKER = '185.10.22.77';

  // Attack chain - each step is an anomaly record. Timestamps are staggered
  // (~4-5 min apart) to give the timeline a meaningful distribution.
  const mkAnomaly = (m: number, a: Partial<Anomaly>): Anomaly => {
    const ts = minutesAgo(m);
    return {
      status: 'DETECTED',
      detectedAt: ts, createdAt: ts, createdBy: 'ids',
      isActive: true, isEscalated: false, isAcknowledged: false,
      isResolved: false, isFalsePositive: false,
      ...a,
    } as Anomaly;
  };

  const anomalies: Anomaly[] = [
    mkAnomaly(28, {
      id: 'demo-a1', title: 'Inbound C2 beacon from known-bad IP',
      anomalyType: 'C2_COMMS', severity: 'HIGH',
      sourceIp: ATTACKER, destinationIp: '10.20.5.42', protocol: 'HTTPS',
      isEscalated: true,
    }),
    mkAnomaly(23, {
      id: 'demo-a2', title: 'Lateral movement: Workstation → Historian',
      anomalyType: 'LATERAL_MOVEMENT', severity: 'HIGH',
      sourceIp: '10.20.5.42', destinationIp: '10.30.3.15', protocol: 'SMB',
    }),
    mkAnomaly(18, {
      id: 'demo-a3', title: 'Historian → SCADA OPC abuse',
      anomalyType: 'PROTOCOL_ABUSE', severity: 'HIGH',
      sourceIp: '10.30.3.15', destinationIp: '10.40.2.10', protocol: 'OPC-UA',
    }),
    mkAnomaly(14, {
      id: 'demo-a4', title: 'Suspicious command: SCADA → HMI',
      anomalyType: 'BEHAVIORAL', severity: 'MEDIUM',
      sourceIp: '10.40.2.10', destinationIp: '10.40.2.51', protocol: 'OPC',
    }),
    mkAnomaly(10, {
      id: 'demo-a5', title: 'Unauthorized S7 write to PLC',
      anomalyType: 'PROTOCOL_ABUSE', severity: 'CRITICAL',
      sourceIp: '10.40.2.51', destinationIp: '10.40.1.21', protocol: 'S7',
      isEscalated: true,
    }),
    mkAnomaly(6, {
      id: 'demo-a6', title: 'PLC → Pump: out-of-range setpoint',
      anomalyType: 'SAFETY_VIOLATION', severity: 'CRITICAL',
      sourceIp: '10.40.1.21', destinationIp: '10.40.0.21', protocol: 'Modbus',
      isEscalated: true,
    }),
    mkAnomaly(3, {
      id: 'demo-a7', title: 'Historian exfil to external host',
      anomalyType: 'DATA_EXFIL', severity: 'HIGH',
      sourceIp: '10.30.3.15', destinationIp: ATTACKER, protocol: 'HTTPS',
    }),
  ];

  // Benign baseline traffic - shows the operator what "normal" looks like.
  const baselineConnections: BaselineConnection[] = [
    { sourceIp: '10.40.0.11', destinationIp: '10.40.1.21', protocol: 'Modbus' },   // Sensor → PLC polling
    { sourceIp: '10.40.1.21', destinationIp: '10.40.2.10', protocol: 'OPC-UA' },   // PLC → SCADA telemetry
    { sourceIp: '10.40.1.35', destinationIp: '10.40.2.10', protocol: 'DNP3' },     // RTU → SCADA
    { sourceIp: '10.40.2.10', destinationIp: '10.30.3.15', protocol: 'OPC-UA' },   // SCADA → Historian archive
    { sourceIp: '192.168.100.1', destinationIp: '10.20.5.42', protocol: 'HTTPS' }, // Firewall → WS permitted
  ];

  const scenario: TopologyGraph['scenario'] = {
    title: 'Simulated Attack Chain - Phishing → ICS Pivot',
    summary:
      'An attacker at 185.10.22.77 gained initial access on an engineering workstation and ' +
      'moved laterally down the Purdue stack to manipulate a pump actuator. A secondary exfil ' +
      'channel is pulling historian data out over HTTPS.',
    steps: [
      '1. Initial access: C2 beacon from 185.10.22.77 on Engineering Workstation',
      '2. Lateral movement: Workstation → PI Historian via SMB',
      '3. Zone crossing: Historian → Wonderware SCADA via OPC-UA (Enterprise → Control)',
      '4. Command injection: SCADA → WinCC HMI, then HMI → S7-1500 PLC via S7',
      '5. Physical impact: PLC issues out-of-range setpoint to the Cooling Pump (Control → Field)',
      '6. Data exfiltration: PI Historian → 185.10.22.77 over HTTPS',
    ],
  };

  return {
    assets,
    anomalies,
    baselineConnections,
    scenario,
    isDemo: true,
    generatedAt: new Date().toISOString(),
  };
};

/** Convenience - build a full graph from the demo dataset (kept for callers
 *  that want a one-shot graph without time filtering). */
const demoGraph = (): TopologyGraph => {
  const raw = demoRawData();
  return buildGraph(raw.assets, raw.anomalies, {
    demo: raw.isDemo,
    scenario: raw.scenario,
    baselineConnections: raw.baselineConnections,
  });
};

// --- Graph construction -----------------------------------------------------

export interface BuildGraphOptions {
  demo?: boolean;
  scenario?: TopologyGraph['scenario'];
  baselineConnections?: BaselineConnection[];
  /**
   * Phase-2 analytics context. When provided, every edge gets an `analytics`
   * record with baseline/window counts, sparkline, and a `isNewInWindow`
   * flag. `anomalies` (the 2nd argument) is still expected to be pre-filtered
   * to the selected window - `analytics.allAnomalies` supplies the full
   * dataset used to compute baseline + sparkline.
   */
  analytics?: {
    allAnomalies: Anomaly[];
    baselineWindow: { start: number; end: number };
    selectedWindow: { start: number; end: number };
    fullRange: { start: number; end: number };
    sparklineBuckets?: number; // default 24
  };
}

export const buildGraph = (
  assets: BackendAsset[],
  anomalies: Anomaly[],
  opts: BuildGraphOptions = {}
): TopologyGraph => {
  const nodesByKey = new Map<string, TopologyNode>();
  const ipToNodeId = new Map<string, string>();

  // Seed nodes from the asset inventory
  for (const a of assets) {
    const nodeId = a.id || `asset:${a.ipAddress || a.name}`;
    const purdueLevel = purdueLevelToNumber(a.purdueLevel);
    const node: TopologyNode = {
      id: nodeId,
      label: a.name || a.hostname || a.ipAddress || nodeId,
      ip: a.ipAddress,
      purdueLevel,
      zone: deriveZone({ purdueLevel, asset: a, isKnown: true }),
      criticality: criticalityToSeverity(a.criticalityLevel),
      isOnline: Boolean(a.isOnline ?? a.isActive ?? true),
      isKnown: true,
      asset: a,
      anomalyCount: 0,
      worstSeverity: 'NONE',
    };
    nodesByKey.set(nodeId, node);
    if (a.ipAddress) ipToNodeId.set(a.ipAddress, nodeId);
  }

  // Derive edges from anomaly source→dest pairs
  const edgesByKey = new Map<string, TopologyEdge>();
  let unknownIpCount = 0;
  let anomalousEdges = 0;

  const ensureNodeForIp = (ip: string): string => {
    const existing = ipToNodeId.get(ip);
    if (existing) return existing;
    const nodeId = `ip:${ip}`;
    if (!nodesByKey.has(nodeId)) {
      nodesByKey.set(nodeId, {
        id: nodeId,
        label: ip,
        ip,
        purdueLevel: 5, // external/unknown floats on top layer
        zone: 'EXTERNAL',
        criticality: 'HIGH',
        isOnline: true,
        isKnown: false,
        anomalyCount: 0,
        worstSeverity: 'NONE',
      });
      unknownIpCount += 1;
    }
    ipToNodeId.set(ip, nodeId);
    return nodeId;
  };

  for (const an of anomalies) {
    if (!an.sourceIp || !an.destinationIp) continue;
    const src = ensureNodeForIp(an.sourceIp);
    const dst = ensureNodeForIp(an.destinationIp);
    if (src === dst) continue;

    const key = edgeKey(src, dst);
    const sev = normalizeSeverity(an.severity);
    const existing = edgesByKey.get(key);
    if (existing) {
      existing.count += 1;
      existing.severity = worseSeverity(existing.severity, sev);
      existing.anomalyIds.push(an.id);
      if (an.protocol && !existing.protocols.includes(an.protocol)) {
        existing.protocols.push(an.protocol);
      }
    } else {
      edgesByKey.set(key, {
        id: `e:${key}`,
        source: src,
        target: dst,
        severity: sev,
        anomalyIds: [an.id],
        protocols: an.protocol ? [an.protocol] : [],
        count: 1,
      });
      anomalousEdges += 1;
    }

    // Roll worst severity up to both endpoints
    const srcNode = nodesByKey.get(src);
    const dstNode = nodesByKey.get(dst);
    if (srcNode) {
      srcNode.anomalyCount += 1;
      srcNode.worstSeverity = worseSeverity(srcNode.worstSeverity, sev);
    }
    if (dstNode) {
      dstNode.anomalyCount += 1;
      dstNode.worstSeverity = worseSeverity(dstNode.worstSeverity, sev);
    }
  }

  // Add baseline (non-anomalous) connections - these show benign comms like
  // Sensor→PLC Modbus polling so the operator can see normal traffic flowing
  // underneath the red anomaly edges. They do NOT bump anomaly counts.
  if (opts.baselineConnections) {
    for (const bc of opts.baselineConnections) {
      if (!bc.sourceIp || !bc.destinationIp) continue;
      const src = ensureNodeForIp(bc.sourceIp);
      const dst = ensureNodeForIp(bc.destinationIp);
      if (src === dst) continue;
      const key = edgeKey(src, dst);
      const existing = edgesByKey.get(key);
      if (existing) {
        // Already an anomaly edge here - just merge protocol info.
        if (bc.protocol && !existing.protocols.includes(bc.protocol)) {
          existing.protocols.push(bc.protocol);
        }
        continue;
      }
      edgesByKey.set(key, {
        id: `e:${key}`,
        source: src,
        target: dst,
        severity: 'NONE',
        anomalyIds: [],
        protocols: bc.protocol ? [bc.protocol] : [],
        count: 0,
        isBaseline: true,
      });
    }
  }

  // Mark cross-zone edges as conduits (used by the Zones view to style them
  // distinctly and label them with the protocol).
  const nodesList = Array.from(nodesByKey.values());
  const edgesList = Array.from(edgesByKey.values());
  for (const e of edgesList) {
    const s = nodesByKey.get(e.source);
    const t = nodesByKey.get(e.target);
    if (s && t && s.zone !== t.zone) {
      e.isConduit = true;
    }
  }

  // --- Phase-2: attach analytics to each edge -----------------------------
  if (opts.analytics) {
    const { allAnomalies, baselineWindow, selectedWindow, fullRange } = opts.analytics;
    const SPARKLINE_BUCKETS = opts.analytics.sparklineBuckets ?? 24;
    const rangeSpan = Math.max(1, fullRange.end - fullRange.start);

    // Precompute which sparkline buckets belong to the baseline vs selected
    // window so the tooltip can paint them in distinct colors.
    const msToBucket = (ms: number): number => {
      const rel = (ms - fullRange.start) / rangeSpan;
      return Math.max(0, Math.min(SPARKLINE_BUCKETS, Math.round(rel * SPARKLINE_BUCKETS)));
    };
    const baselineBucketRange: [number, number] = [
      msToBucket(baselineWindow.start),
      msToBucket(baselineWindow.end),
    ];
    const windowBucketRange: [number, number] = [
      msToBucket(selectedWindow.start),
      msToBucket(selectedWindow.end),
    ];

    // Build a lookup from undirected edge key → aggregated analytics.
    // We use IPs (not node ids) to match what `edgeKey` logic does above.
    const analyticsByKey = new Map<string, EdgeAnalytics>();

    const resolveKeyFromIps = (srcIp?: string, dstIp?: string): string | null => {
      if (!srcIp || !dstIp) return null;
      const s = ipToNodeId.get(srcIp);
      const d = ipToNodeId.get(dstIp);
      if (!s || !d || s === d) return null;
      return edgeKey(s, d);
    };

    const getOrCreate = (key: string): EdgeAnalytics => {
      let rec = analyticsByKey.get(key);
      if (!rec) {
        rec = {
          baselineCount: 0,
          windowCount: 0,
          totalCount: 0,
          sparkline: new Array(SPARKLINE_BUCKETS).fill(0),
          isNewInWindow: false,
        };
        analyticsByKey.set(key, rec);
      }
      return rec;
    };

    for (const a of allAnomalies) {
      const key = resolveKeyFromIps(a.sourceIp, a.destinationIp);
      if (!key) continue;
      const rec = getOrCreate(key);
      const t = a.detectedAt ? new Date(a.detectedAt).getTime() : NaN;
      if (!Number.isFinite(t)) continue;

      rec.totalCount += 1;
      if (rec.firstSeenAt === undefined || t < rec.firstSeenAt) rec.firstSeenAt = t;
      if (rec.lastSeenAt === undefined || t > rec.lastSeenAt) rec.lastSeenAt = t;

      // bucket for sparkline
      const relative = (t - fullRange.start) / rangeSpan;
      const idx = Math.max(0, Math.min(SPARKLINE_BUCKETS - 1, Math.floor(relative * SPARKLINE_BUCKETS)));
      rec.sparkline[idx] += 1;

      if (t >= baselineWindow.start && t <= baselineWindow.end) rec.baselineCount += 1;
      if (t >= selectedWindow.start && t <= selectedWindow.end) rec.windowCount += 1;
    }

    // Attach to edges
    for (const e of edgesList) {
      const rec = analyticsByKey.get(e.id.replace(/^e:/, ''));
      if (rec) {
        rec.isNewInWindow = rec.windowCount > 0 && rec.baselineCount === 0;
        rec.baselineBucketRange = baselineBucketRange;
        rec.windowBucketRange = windowBucketRange;
        e.analytics = rec;
      } else if (e.isBaseline) {
        // Benign baseline comms (Sensor→PLC polling etc.) - treat as baseline
        // so they never get a "NEW" flag.
        e.analytics = {
          baselineCount: 1,
          windowCount: 0,
          totalCount: 1,
          sparkline: new Array(SPARKLINE_BUCKETS).fill(0),
          isNewInWindow: false,
          baselineBucketRange,
          windowBucketRange,
        };
      } else {
        e.analytics = {
          baselineCount: 0,
          windowCount: 0,
          totalCount: 0,
          sparkline: new Array(SPARKLINE_BUCKETS).fill(0),
          isNewInWindow: false,
          baselineBucketRange,
          windowBucketRange,
        };
      }
    }
  }

  return {
    nodes: nodesList,
    edges: edgesList,
    generatedAt: new Date().toISOString(),
    isDemo: opts.demo,
    scenario: opts.scenario,
    stats: {
      assetCount: assets.length,
      unknownIpCount,
      anomalousEdges,
    },
  };
};

// --- Public API -------------------------------------------------------------

export const topologyService = {
  /**
   * Fetch the raw dataset (assets + anomalies + baseline + optional scenario).
   * The UI consumes this and applies its own time-window filtering, then
   * calls `buildGraph()` to produce the visual graph. This lets the timeline
   * scrubber re-render cheaply without re-fetching from the server.
   */
  async getRawData(
    opts: {
      assetLimit?: number;
      anomalyLimit?: number;
      /**
       * When true, return the hardcoded attack-scenario dataset instead of
       * calling the backend. Use this for the Network Topology "Show demo
       * scenario" toggle.
       */
      forceDemo?: boolean;
    } = {}
  ): Promise<TopologyRawData> {
    const assetLimit = opts.assetLimit ?? 200;
    const anomalyLimit = opts.anomalyLimit ?? 500;

    if (opts.forceDemo) {
      return demoRawData();
    }

    // Track per-source errors so the UI can surface a clear diagnostic panel
    // ("assets 200 OK, anomalies 500, dpi 404") instead of silently falling
    // back to demo and leaving the operator wondering what happened.
    let assetsError = false;
    let anomaliesError = false;
    let observedConnectionsError = false;

    const [assetsRes, anomaliesRes, observedConns] = await Promise.all([
      api.get(`/api/assets`, { params: { page: 0, size: assetLimit } })
        .catch((err) => {
          assetsError = true;
          // eslint-disable-next-line no-console
          console.warn('[topologyService] /api/assets failed:', err);
          return { data: { content: [] as BackendAsset[] } };
        }),
      anomalyService.getRecentAnomalies(anomalyLimit).catch((err) => {
        anomaliesError = true;
        // eslint-disable-next-line no-console
        console.warn('[topologyService] getRecentAnomalies failed:', err);
        return [] as Anomaly[];
      }),
      // Try the aggregated endpoint first; if that 404s (old backend that
      // hasn't been redeployed yet), fall back to deriving pairs from the
      // paged /api/dpi/events endpoint which has been around longer. This
      // means topology will light up with real edges even before the backend
      // has the new `/observed-connections` endpoint.
      dpiService.observedConnections().catch(async (err) => {
        // eslint-disable-next-line no-console
        console.warn('[topologyService] /api/dpi/observed-connections failed, falling back to /api/dpi/events:', err);
        try {
          const page = await dpiService.search({ size: 1000 });
          const pairKey = (a: string, b: string, p: string) => `${a}__${b}__${p}`;
          const byKey = new Map<string, { sourceIp: string; destinationIp: string; protocol: string; count: number }>();
          for (const ev of page.content) {
            if (!ev.sourceIp || !ev.destinationIp) continue;
            const k = pairKey(ev.sourceIp, ev.destinationIp, ev.protocol || 'UNKNOWN');
            const existing = byKey.get(k);
            if (existing) {
              existing.count += 1;
            } else {
              byKey.set(k, {
                sourceIp: ev.sourceIp,
                destinationIp: ev.destinationIp,
                protocol: ev.protocol || 'UNKNOWN',
                count: 1,
              });
            }
          }
          return Array.from(byKey.values());
        } catch (fallbackErr) {
          observedConnectionsError = true;
          // eslint-disable-next-line no-console
          console.warn('[topologyService] /api/dpi/events fallback also failed:', fallbackErr);
          return [];
        }
      }),
    ]);

    const assetPayload = (assetsRes as { data: PageResponse<BackendAsset> | BackendAsset[] }).data;
    const assets: BackendAsset[] = Array.isArray(assetPayload)
      ? assetPayload
      : (assetPayload.content ?? []);

    const anomalies: Anomaly[] = Array.isArray(anomaliesRes) ? anomaliesRes : [];

    // Project observed DPI connections into baselineConnections so they
    // become real (non-anomalous) edges on the graph. Each pair renders
    // as a dashed line with its protocol label - exactly what we want
    // for visualising pcap-derived Modbus/S7 traffic.
    const baselineConnections: BaselineConnection[] = observedConns.map((c) => ({
      sourceIp: c.sourceIp,
      destinationIp: c.destinationIp,
      protocol: c.protocol,
    }));

    const allEmpty =
      assets.length === 0 && anomalies.length === 0 && baselineConnections.length === 0;
    const allFailed = assetsError && anomaliesError && observedConnectionsError;

    // CRITICAL: we NO LONGER fall back to demo just because the DB happens
    // to be empty. An empty graph is a valid state (fresh install, no pcap
    // uploaded yet) and silently showing fake attack scenarios made users
    // think they were looking at their real network. We only fall back when
    // *every* real source errored (network down, backend unreachable).
    if (allFailed) {
      const demo = demoRawData();
      return {
        ...demo,
        diagnostics: {
          assetCount: 0,
          anomalyCount: 0,
          observedConnectionCount: 0,
          assetsError: true,
          anomaliesError: true,
          observedConnectionsError: true,
          fellBackToDemo: true,
          allEmpty: false,
        },
      };
    }

    return {
      assets,
      anomalies,
      baselineConnections,
      isDemo: false,
      generatedAt: new Date().toISOString(),
      diagnostics: {
        assetCount: assets.length,
        anomalyCount: anomalies.length,
        observedConnectionCount: baselineConnections.length,
        assetsError,
        anomaliesError,
        observedConnectionsError,
        fellBackToDemo: false,
        allEmpty,
      },
    };
  },

  /**
   * One-shot graph fetch (no time filtering). Kept for any caller that does
   * not need the raw dataset.
   */
  async getTopology(
    opts: { assetLimit?: number; anomalyLimit?: number; forceDemo?: boolean } = {}
  ): Promise<TopologyGraph> {
    const raw = await this.getRawData(opts);
    return buildGraph(raw.assets, raw.anomalies, {
      demo: raw.isDemo,
      scenario: raw.scenario,
      baselineConnections: raw.baselineConnections,
    });
  },

  demoGraph,
  demoRawData,
};

export default topologyService;
