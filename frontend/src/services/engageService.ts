import api from './api';

// ---------- Types (mirror backend) ----------

export type EngageStatus = 'ACTIVE' | 'AVAILABLE';

export interface EngageActivity {
  goal: string;
  approach: string;
  activity: string;
  otShieldFeature: string;
  description: string;
  status: EngageStatus;
  evidenceCount: number;
  evidence: string;
}

export interface EngageGoalSummary {
  total: number;
  active: number;
}

export interface EngageMatrix {
  framework: string;
  goals: string[];
  activities: EngageActivity[];
  summary: {
    totalActivities: number;
    activeActivities: number;
    coveragePct: number;
    byGoal: Record<string, EngageGoalSummary>;
  };
}

export const engageService = {
  matrix: (): Promise<EngageMatrix> =>
    api.get<EngageMatrix>('/api/engage/matrix').then((r) => r.data),
};
