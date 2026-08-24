import api from './api';

// ---------- Types (mirror backend DTOs) ----------
//
// The attacker kill-chain / campaign timeline stitches every real signal we
// hold for one source IP - internet-exposed decoy hits, decoy-twin
// interactions, DPI events, anomalies, and opened cases - into a single
// chronological narrative, each step mapped to a MITRE ATT&CK for ICS phase.

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INFO';

/** Ordered kill-chain phases (a subset of MITRE ATT&CK for ICS tactics). */
export type KillChainPhase =
  | 'RECON'            // Discovery (T0846) - scanning / enumeration
  | 'INITIAL_ACCESS'   // Internet-exposed device reached (T0883)
  | 'DISCOVERY'        // Protocol / device-id probing on an internal target
  | 'LATERAL_MOVEMENT' // Reaching further into the OT segment
  | 'EXECUTION'        // Issuing control commands / function calls
  | 'IMPACT';          // Impair Process Control - writes to a real/decoy device (T0855, T0836)

/** Which telemetry store a timeline step came from. */
export type TimelineSource = 'HONEYPOT' | 'TWIN' | 'DPI' | 'ANOMALY' | 'CASE';

export interface TimelineEvent {
  timestamp: string;              // ISO-8601
  source: TimelineSource;
  phase: KillChainPhase;
  title: string;
  description?: string | null;
  protocol?: string | null;
  functionCode?: string | null;
  targetIp?: string | null;
  targetAsset?: string | null;    // resolved asset name/label when known
  mitreId?: string | null;
  mitreTechnique?: string | null;
  severity?: Severity | null;
  refId?: string | null;          // id of the underlying anomaly/case/event
}

export interface TargetedAsset {
  ip: string;
  name?: string | null;
  purdueLevel?: string | null;
  protocol?: string | null;
}

export interface AttackerTimeline {
  ip: string;
  country?: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  totalEvents: number;
  reachedPhases: KillChainPhase[]; // distinct phases the attacker reached, in order
  highestSeverity: Severity | null;
  targetedAssets: TargetedAsset[];
  caseNumbers: string[];           // cases already opened for this IP
  events: TimelineEvent[];         // chronological (oldest -> newest)
}

/** One row in the "top attackers" / campaigns list. */
export interface AttackerSummary {
  ip: string;
  country?: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  eventCount: number;
  reachedPhases: KillChainPhase[];
  highestSeverity: Severity | null;
  targetedAssetCount: number;
  breached: boolean;               // did they reach IMPACT (a decoy/real write)
}

// Canonical phase order + display labels for the UI progress bar.
export const KILL_CHAIN_ORDER: KillChainPhase[] = [
  'RECON', 'INITIAL_ACCESS', 'DISCOVERY', 'LATERAL_MOVEMENT', 'EXECUTION', 'IMPACT',
];

export const PHASE_LABEL: Record<KillChainPhase, string> = {
  RECON: 'Recon',
  INITIAL_ACCESS: 'Initial Access',
  DISCOVERY: 'Discovery',
  LATERAL_MOVEMENT: 'Lateral Movement',
  EXECUTION: 'Execution',
  IMPACT: 'Impact',
};

export const attackerService = {
  /** Ranked list of attacker IPs with their kill-chain reach (for a campaigns page). */
  listAttackers: async (limit = 25): Promise<AttackerSummary[]> => {
    const res = await api.get<AttackerSummary[]>('/api/attackers', { params: { limit } });
    return res.data;
  },

  /** Full stitched timeline for one attacker IP. */
  getTimeline: async (ip: string): Promise<AttackerTimeline> => {
    const res = await api.get<AttackerTimeline>(`/api/attackers/${encodeURIComponent(ip)}/timeline`);
    return res.data;
  },
};
