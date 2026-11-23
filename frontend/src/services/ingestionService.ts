import api from './api';

/** One sensor's rolled-up status over the backend's retained ingest window. */
export interface SensorStat {
  sensorId: string;
  host: string;
  iface: string;
  remoteIp: string;
  online: boolean;
  lastSeen: number;        // epoch ms
  uploads: number;
  packets: number;
  bytes: number;
  packetsLastMin: number;
  packets5m: number;
  lastFilename: string;
  lastPackets: number;
  lastParsed: boolean;
}

export interface IngestionSummary {
  sensors: SensorStat[];
  totalSensors: number;
  onlineSensors: number;
  packetsPerMin: number;
  windowPackets: number;
  windowBytes: number;
  windowEvents: number;
  retainedMax: number;
}

/** One recorded upload in the recent-ingest feed. */
export interface IngestEvent {
  ts: number;              // epoch ms
  sensorId: string;
  host: string;
  iface: string;
  remoteIp: string;
  filename: string;
  bytes: number;
  packets: number;
  parsed: boolean;
}

/**
 * Live-ingestion monitoring. Every value is derived from real
 * {@code POST /api/upload/pcap} uploads - no fabricated telemetry.
 */
export const ingestionService = {
  async getSummary(): Promise<IngestionSummary> {
    const { data } = await api.get('/api/ingestion/summary');
    return data;
  },
  async getRecent(limit = 50): Promise<IngestEvent[]> {
    const { data } = await api.get(`/api/ingestion/recent?limit=${limit}`);
    return data;
  },
};
