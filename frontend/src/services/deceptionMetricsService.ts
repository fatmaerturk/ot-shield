import api from './api';

export interface NameCount {
  name: string;
  count: number;
}

export interface DeceptionMetrics {
  headline: {
    interactionsAbsorbed: number;
    uniqueAttackers: number;
    credentialsHarvested: number;
    decoysActive: number;
    luresPlanted: number;
    luresTripped: number;
    casesFromDeception: number;
    lureFalsePositiveRate: number;
  };
  engagement: {
    avgInteractionsPerAttacker: number;
    avgDwellSeconds: number;
    returningAttackers: number;
    deepestEngagement: number;
  };
  coverage: {
    protocolsCovered: number;
    countriesSeen: number;
  };
  lures: {
    planted: number;
    tripped: number;
    tripRatePct: number;
    beaconTrips: number;
    replayTrips: number;
    avgTimeToTripSeconds: number | null;
  };
  breakdown: {
    topProtocols: NameCount[];
    topAttackTypes: NameCount[];
    topCountries: NameCount[];
    topDecoys: NameCount[];
  };
  trend: NameCount[];
  analyzedWindow: number;
}

export const deceptionMetricsService = {
  get: (): Promise<DeceptionMetrics> =>
    api.get<DeceptionMetrics>('/api/deception/metrics').then((r) => r.data),
};
