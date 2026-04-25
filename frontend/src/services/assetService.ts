import api from './api';

// ---------------------------------------------------------------------------
// Backend enums (mirror of com.safetech.otshield.model.Asset.* enums)
// ---------------------------------------------------------------------------

export type AssetType =
  | 'PLC'
  | 'HMI'
  | 'RTU'
  | 'IED'
  | 'DCS'
  | 'SCADA_SERVER'
  | 'ENGINEERING_WORKSTATION'
  | 'OPERATOR_WORKSTATION'
  | 'HISTORIAN'
  | 'GATEWAY'
  | 'FIREWALL'
  | 'SWITCH'
  | 'ROUTER'
  | 'SENSOR'
  | 'ACTUATOR'
  | 'OTHER';

export type AssetCategory =
  | 'CONTROL_SYSTEM'
  | 'NETWORK_INFRASTRUCTURE'
  | 'SAFETY_SYSTEM'
  | 'MONITORING_SYSTEM'
  | 'OTHER';

export type PurdueLevel =
  | 'LEVEL_0'
  | 'LEVEL_1'
  | 'LEVEL_2'
  | 'LEVEL_3'
  | 'LEVEL_4'
  | 'LEVEL_5';

export type CriticalityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type BackupStatus =
  | 'UP_TO_DATE'
  | 'OUTDATED'
  | 'NEVER_BACKED_UP'
  | 'NOT_APPLICABLE';

export type MonitoringStatus =
  | 'MONITORED'
  | 'PARTIALLY_MONITORED'
  | 'NOT_MONITORED'
  | 'NOT_APPLICABLE';

// ---------------------------------------------------------------------------
// AssetDTO - mirrors com.safetech.otshield.dto.AssetDTO
// ---------------------------------------------------------------------------

export interface AssetDTO {
  id: string;
  name: string;
  description?: string;
  ipAddress?: string;
  macAddress?: string;
  assetType?: AssetType;
  assetCategory?: AssetCategory;
  purdueLevel?: PurdueLevel;
  manufacturer?: string;
  model?: string;
  serialNumber?: string;
  firmwareVersion?: string;
  operatingSystem?: string;
  osVersion?: string;
  hostname?: string;
  domain?: string;
  location?: string;
  department?: string;
  owner?: string;
  responsiblePerson?: string;
  contactEmail?: string;
  contactPhone?: string;
  purchaseDate?: string;        // ISO local date-time
  warrantyExpiry?: string;
  lastMaintenance?: string;
  nextMaintenance?: string;
  criticalityLevel?: CriticalityLevel;
  riskScore?: number;
  vulnerabilityCount?: number;
  patchLevel?: string;
  backupStatus?: BackupStatus;
  monitoringStatus?: MonitoringStatus;
  isActive?: boolean;
  isOnline?: boolean;
  lastSeen?: string;
  firstSeen?: string;
  createdAt?: string;
  updatedAt?: string;
  createdBy?: string;
  updatedBy?: string;
  tags?: string[];
  notes?: string;
  customFields?: string;
}

export interface SpringPage<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  number: number;
  size: number;
  first: boolean;
  last: boolean;
}

export interface AssetSearchParams {
  page?: number;
  size?: number;
  sortBy?: string;
  sortDir?: 'asc' | 'desc';
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

const PURDUE_LABEL: Record<PurdueLevel, string> = {
  LEVEL_0: 'Level 0 - Process',
  LEVEL_1: 'Level 1 - Basic Control',
  LEVEL_2: 'Level 2 - Supervisory',
  LEVEL_3: 'Level 3 - Operations',
  LEVEL_4: 'Level 4 - Enterprise',
  LEVEL_5: 'Level 5 - Internet DMZ',
};

export const purdueLevelLabel = (lvl?: PurdueLevel | null): string =>
  lvl ? PURDUE_LABEL[lvl] ?? lvl : 'Unknown';

export const purdueLevelShort = (lvl?: PurdueLevel | null): string => {
  if (!lvl) return 'L?';
  const m = /LEVEL_(\d)/.exec(lvl);
  return m ? `L${m[1]}` : lvl;
};

const CRITICALITY_LABEL: Record<CriticalityLevel, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
};

export const criticalityLabel = (c?: CriticalityLevel | null): string =>
  c ? CRITICALITY_LABEL[c] ?? c : 'Unknown';

export const ASSET_TYPE_OPTIONS: AssetType[] = [
  'PLC', 'HMI', 'RTU', 'IED', 'DCS',
  'SCADA_SERVER', 'ENGINEERING_WORKSTATION', 'OPERATOR_WORKSTATION',
  'HISTORIAN', 'GATEWAY', 'FIREWALL', 'SWITCH', 'ROUTER',
  'SENSOR', 'ACTUATOR', 'OTHER',
];

export const PURDUE_LEVEL_OPTIONS: PurdueLevel[] = [
  'LEVEL_0', 'LEVEL_1', 'LEVEL_2', 'LEVEL_3', 'LEVEL_4', 'LEVEL_5',
];

export const CRITICALITY_OPTIONS: CriticalityLevel[] = [
  'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO',
];

// ---------------------------------------------------------------------------
// REST client
// ---------------------------------------------------------------------------

export const assetService = {
  /** Spring-paged listing. Pass a large `size` to grab everything in one shot. */
  list: async (params: AssetSearchParams = {}): Promise<SpringPage<AssetDTO>> => {
    const merged: AssetSearchParams = {
      page: 0,
      size: 200,
      sortBy: 'name',
      sortDir: 'asc',
      ...params,
    };
    const res = await api.get<SpringPage<AssetDTO>>('/api/assets', {
      params: merged,
    });
    return res.data;
  },

  /** Convenience - flatten paging and return just the array. */
  listAll: async (size: number = 500): Promise<AssetDTO[]> => {
    const page = await assetService.list({ page: 0, size });
    return Array.isArray(page?.content) ? page.content : [];
  },

  getById: async (id: string): Promise<AssetDTO> => {
    const res = await api.get<AssetDTO>(`/api/assets/${id}`);
    return res.data;
  },

  create: async (asset: Partial<AssetDTO>): Promise<AssetDTO> => {
    const res = await api.post<AssetDTO>('/api/assets', asset);
    return res.data;
  },

  update: async (id: string, asset: Partial<AssetDTO>): Promise<AssetDTO> => {
    const res = await api.put<AssetDTO>(`/api/assets/${id}`, asset);
    return res.data;
  },

  remove: async (id: string): Promise<void> => {
    await api.delete(`/api/assets/${id}`);
  },

  highRisk: async (): Promise<AssetDTO[]> => {
    const res = await api.get<AssetDTO[]>('/api/assets/high-risk');
    return Array.isArray(res.data) ? res.data : [];
  },

  online: async (): Promise<AssetDTO[]> => {
    const res = await api.get<AssetDTO[]>('/api/assets/online');
    return Array.isArray(res.data) ? res.data : [];
  },
};

export default assetService;
