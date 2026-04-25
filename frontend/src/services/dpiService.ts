import api from './api';

/**
 * Client for `/api/dpi/*` - the Deep-Packet-Inspection surface fed by the
 * Modbus / S7Comm dissectors during PCAP analysis. Used by the Network
 * Topology detail panels and the Dashboard DPI modal.
 */

export interface DpiEvent {
  id: string;
  eventTime: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number | null;
  destinationPort?: number | null;
  protocol: string;
  functionCode?: string | null;
  functionName?: string | null;
  pduKind?: string | null;
  isWrite?: boolean | null;
  isException?: boolean | null;
  registerAddress?: string | null;
  area?: string | null;
  value?: string | null;
  summary?: string | null;
  /** Only set by the single-event detail endpoint. */
  dpiFieldsJson?: string | null;
  pcapSessionId?: string | null;
}

export interface FunctionCodeStat {
  protocol: string;
  functionCode: string;
  functionName: string | null;
  count: number;
}

/**
 * A distinct src↔dst pair observed in the dissector stream, with its
 * protocol and PDU count. Used by topologyService to draw real edges on
 * the Network Topology page.
 */
export interface ObservedConnection {
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  count: number;
}

export interface SpringPage<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  number: number;   // current page (0-based)
  size: number;
  first: boolean;
  last: boolean;
}

export interface DpiSearchParams {
  /** Exact source IP filter. */
  sourceIp?: string;
  /** Exact destination IP filter. */
  destinationIp?: string;
  /** Matches events where IP appears as either src OR dst. */
  ip?: string;
  /** MODBUS / S7COMM / IEC104 / … */
  protocol?: string;
  /** read / write / other. */
  pduKind?: string;
  /** ISO-8601 local date-time, e.g. `"2024-04-20T12:00:00"`. */
  from?: string;
  to?: string;
  page?: number;
  size?: number;
}

export interface StatsParams {
  sourceIp?: string;
  destinationIp?: string;
  from?: string;
  to?: string;
}

/**
 * Drop undefined/empty/null query fields so axios doesn't send
 * `?sourceIp=undefined` to the backend (which would then 400 or behave
 * oddly on the `isBlank()` check).
 */
const clean = (o: Record<string, unknown>): Record<string, unknown> => {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    if (v === undefined || v === null || v === '') continue;
    out[k] = v;
  }
  return out;
};

export const dpiService = {
  /**
   * Flexible search - returns a Spring Data Page of DpiEvents. Every filter
   * is optional; call with `{}` to get the most recent events globally.
   */
  async search(params: DpiSearchParams = {}): Promise<SpringPage<DpiEvent>> {
    const res = await api.get<SpringPage<DpiEvent>>('/api/dpi/events', {
      params: clean(params as Record<string, unknown>),
    });
    return res.data;
  },

  /** Single-event detail, including full dpiFieldsJson for the UI modal. */
  async getById(id: string): Promise<DpiEvent> {
    const res = await api.get<DpiEvent>(`/api/dpi/events/${encodeURIComponent(id)}`);
    return res.data;
  },

  /**
   * Function-code histogram for a specific src↔dst pair, or global when
   * both endpoints are omitted. Feeds the "rare command" badge on the
   * Network Topology edge tooltip.
   */
  async functionStats(params: StatsParams = {}): Promise<FunctionCodeStat[]> {
    const res = await api.get<FunctionCodeStat[]>('/api/dpi/function-stats', {
      params: clean(params as Record<string, unknown>),
    });
    return res.data;
  },

  /** Per-node function-code histogram (traffic where the IP appears either side). */
  async nodeStats(ip: string, from?: string, to?: string): Promise<FunctionCodeStat[]> {
    const res = await api.get<FunctionCodeStat[]>('/api/dpi/stats/node', {
      params: clean({ ip, from, to }),
    });
    return res.data;
  },

  /**
   * Last N DPI events touching the given IP - convenience wrapper around
   * {@link search} used by the node detail panel.
   */
  async recentForNode(ip: string, limit = 10): Promise<DpiEvent[]> {
    const page = await dpiService.search({ ip, size: limit });
    return page.content;
  },

  /**
   * Last N DPI events for a specific conduit (src↔dst pair), used by the
   * edge detail panel.
   */
  async recentForEdge(sourceIp: string, destinationIp: string, limit = 10): Promise<DpiEvent[]> {
    const page = await dpiService.search({ sourceIp, destinationIp, size: limit });
    return page.content;
  },

  /**
   * Every distinct src↔dst pair observed in the dissector stream. Drives
   * the real-traffic edges on the Network Topology page - replaces the
   * hardcoded demo scenario whenever the DPI table has any data.
   */
  async observedConnections(from?: string, to?: string): Promise<ObservedConnection[]> {
    const res = await api.get<ObservedConnection[]>('/api/dpi/observed-connections', {
      params: clean({ from, to }),
    });
    return res.data;
  },
};

export default dpiService;
