import api from './api';

// ---------- Types (mirror the backend posture map) ----------
export type IecStatus = 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT' | 'NOT_ASSESSED';

export interface IecEnhancement {
  id: string;
  title: string;
  sl: number;
  status: IecStatus;
}

export interface IecRequirement {
  id: string;            // e.g. "SR 1.1"
  title: string;
  appliesFrom: number;   // lowest SL the base requirement applies at
  status: IecStatus;
  evidence: string;
  enhancements: IecEnhancement[];
}

export interface IecFR {
  fr: string;            // "FR1".."FR7"
  code: string;          // "IAC","UC",...
  name: string;
  description: string;
  total: number;
  compliant: number;
  partial: number;
  notAssessed: number;
  coveragePct: number;
  achievedSL: number;
  targetSL: number;
  requirements: IecRequirement[];
}

export interface IecZone {
  level: string;
  name: string;
  assetCount: number;
  backedUp: number;
  suggestedTargetSL: number;
}

export interface IecSLDef { sl: number; name: string; description: string; }
export interface IecPart { part: string; title: string; focus: boolean; }

export interface IecPosture {
  organization: { name: string; sector: string; standard: string; targetSL: number };
  overall: {
    coveragePct: number;
    achievedSL: number;
    targetSL: number;
    classification: string;
    totalRequirements: number;
    compliant: number;
    partial: number;
    notAssessed: number;
  };
  securityLevels: IecSLDef[];
  standardParts: IecPart[];
  foundationalRequirements: IecFR[];
  zones: IecZone[];
}

export const iec62443Service = {
  getPosture: async (): Promise<IecPosture> => {
    const res = await api.get<IecPosture>('/api/compliance/iec62443/posture');
    return res.data;
  },
};
