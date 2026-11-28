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
  newAssets: number;       // assets this sensor's captures discovered (window)
  newAnomalies: number;    // anomalies this sensor's captures raised (window)
  protocols: string[];     // OT/IT protocols this sensor's traffic carried
}

export interface IngestionSummary {
  sensors: SensorStat[];
  totalSensors: number;
  onlineSensors: number;
  packetsPerMin: number;
  windowPackets: number;
  windowBytes: number;
  windowAssets: number;    // assets discovered across all captures (window)
  windowAnomalies: number; // anomalies raised across all captures (window)
  protocols: string[];     // distinct protocols seen across all sensors (window)
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
  newAssets: number;       // assets this capture discovered
  newAnomalies: number;    // anomalies this capture raised
  protocols: string[];     // protocols observed in this capture
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
