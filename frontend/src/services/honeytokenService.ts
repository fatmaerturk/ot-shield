import api from './api';

// ---------- Types (mirror backend) ----------

export type HoneytokenType =
  | 'CREDENTIAL'
  | 'API_KEY'
  | 'CONNECTION_STRING'
  | 'URL_BEACON'
  | 'FILE_BEACON';

export interface Honeytoken {
  id: string;
  type: HoneytokenType;
  label: string;
  note?: string | null;
  tokenValue: string;
  matchValue?: string | null;
  createdAt: string;
  trips: number;
  lastTrippedAt?: string | null;
  lastSourceIp?: string | null;
}

export interface HoneytokenTrip {
  id: number;
  tokenId: string;
  tokenLabel: string;
  tokenType: string;
  method: 'CALLBACK' | 'CREDENTIAL_REPLAY' | string;
  sourceIp: string;
  userAgent?: string | null;
  detail?: string | null;
  ts: string;
}

export interface HoneytokenStats {
  totalTokens: number;
  trippedTokens: number;
  totalTrips: number;
  lastTrippedAt: string | null;
}

/**
 * Host a planted beacon calls home to. Defaults to the local backend; when
 * planting for real, the operator swaps this for their public / tunnel host.
 */
export const BEACON_BASE = 'http://localhost:8080';

export const honeytokenService = {
  list: (): Promise<Honeytoken[]> =>
    api.get<Honeytoken[]>('/api/honeytoken').then((r) => r.data),

  create: (type: HoneytokenType, label: string, note?: string): Promise<Honeytoken> =>
    api.post<Honeytoken>('/api/honeytoken', { type, label, note }).then((r) => r.data),

  remove: (id: string): Promise<{ deleted: boolean }> =>
    api.delete<{ deleted: boolean }>(`/api/honeytoken/${encodeURIComponent(id)}`).then((r) => r.data),

  trips: (): Promise<HoneytokenTrip[]> =>
    api.get<HoneytokenTrip[]>('/api/honeytoken/trips').then((r) => r.data),

  stats: (): Promise<HoneytokenStats> =>
    api.get<HoneytokenStats>('/api/honeytoken/stats').then((r) => r.data),

  beaconUrl: (id: string): string => `${BEACON_BASE}/api/honeytoken/hit/${id}`,
};
