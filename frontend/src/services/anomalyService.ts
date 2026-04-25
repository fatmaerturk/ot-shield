import api from './api';

// Anomaly interfaces
export interface Anomaly {
  id: string;
  title: string;
  description?: string;
  anomalyType: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  status: 'DETECTED' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'ESCALATED' | 'RESOLVED' | 'FALSE_POSITIVE' | 'IGNORED' | 'CLOSED';
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  assetType?: string;
  assetCategory?: string;
  purdueLevel?: string;
  manufacturer?: string;
  model?: string;
  hostname?: string;
  location?: string;
  department?: string;
  evidence?: string;
  mitigationSteps?: string;
  recommendations?: string;
  confidenceScore?: number;
  riskScore?: number;
  falsePositiveProbability?: number;
  mitreTactic?: string;
  mitreTechnique?: string;
  mitreId?: string;
  tags?: string[];
  indicators?: string[];
  customFields?: string;
  detectedAt: string;
  resolvedAt?: string;
  acknowledgedAt?: string;
  escalatedAt?: string;
  createdAt: string;
  updatedAt?: string;
  createdBy: string;
  updatedBy?: string;
  assignedTo?: string;
  resolvedBy?: string;
  notes?: string;
  isActive: boolean;
  isEscalated: boolean;
  isAcknowledged: boolean;
  isResolved: boolean;
  isFalsePositive: boolean;
}

export interface AnomalyStatistics {
  total: number;
  detected: number;
  acknowledged: number;
  investigating: number;
  escalated: number;
  resolved: number;
  falsePositive: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  active: number;
}

export interface AnomalyFilters {
  title?: string;
  sourceIp?: string;
  destinationIp?: string;
  protocol?: string;
  assetType?: string;
  purdueLevel?: string;
  severity?: string;
  status?: string;
  anomalyType?: string;
  isActive?: boolean;
}

export interface AnomalySearchParams extends AnomalyFilters {
  page?: number;
  size?: number;
  sortBy?: string;
  sortDir?: 'asc' | 'desc';
}

// Anomaly API service
export const anomalyService = {
  // Get all anomalies with pagination
  getAnomalies: async (params: AnomalySearchParams = {}) => {
    const response = await api.get('/api/anomalies', { params });
    return response.data;
  },

  // Get anomaly by ID
  getAnomalyById: async (id: string) => {
    const response = await api.get(`/api/anomalies/${id}`);
    return response.data;
  },

  // Create new anomaly
  createAnomaly: async (anomaly: Partial<Anomaly>) => {
    const response = await api.post('/api/anomalies', anomaly);
    return response.data;
  },

  // Update anomaly
  updateAnomaly: async (id: string, anomaly: Partial<Anomaly>) => {
    const response = await api.put(`/api/anomalies/${id}`, anomaly);
    return response.data;
  },

  // Delete anomaly
  deleteAnomaly: async (id: string) => {
    const response = await api.delete(`/api/anomalies/${id}`);
    return response.data;
  },

  // Acknowledge anomaly
  acknowledgeAnomaly: async (id: string) => {
    const response = await api.post(`/api/anomalies/${id}/acknowledge`);
    return response.data;
  },

  // Escalate anomaly
  escalateAnomaly: async (id: string) => {
    const response = await api.post(`/api/anomalies/${id}/escalate`);
    return response.data;
  },

  // Resolve anomaly
  resolveAnomaly: async (id: string, resolutionNotes: string) => {
    const response = await api.post(`/api/anomalies/${id}/resolve`, null, {
      params: { resolutionNotes }
    });
    return response.data;
  },

  // Mark as false positive
  markAsFalsePositive: async (id: string, reason: string) => {
    const response = await api.post(`/api/anomalies/${id}/false-positive`, null, {
      params: { reason }
    });
    return response.data;
  },

  // Get anomalies by status
  getAnomaliesByStatus: async (status: string) => {
    const response = await api.get(`/api/anomalies/status/${status}`);
    return response.data;
  },

  // Get anomalies by severity
  getAnomaliesBySeverity: async (severity: string) => {
    const response = await api.get(`/api/anomalies/severity/${severity}`);
    return response.data;
  },

  // Get anomalies by type
  getAnomaliesByType: async (type: string) => {
    const response = await api.get(`/api/anomalies/type/${type}`);
    return response.data;
  },

  // Get recent anomalies
  getRecentAnomalies: async (limit: number = 10) => {
    const response = await api.get('/api/anomalies/recent', {
      params: { limit }
    });
    return response.data;
  },

  // Get unresolved anomalies
  getUnresolvedAnomalies: async (limit: number = 10) => {
    const response = await api.get('/api/anomalies/unresolved', {
      params: { limit }
    });
    return response.data;
  },

  // Get escalated anomalies
  getEscalatedAnomalies: async (limit: number = 10) => {
    const response = await api.get('/api/anomalies/escalated', {
      params: { limit }
    });
    return response.data;
  },

  // Get top anomalies by risk score
  getTopAnomaliesByRiskScore: async (limit: number = 10, since?: string) => {
    const response = await api.get('/api/anomalies/top-risk', {
      params: { limit, since }
    });
    return response.data;
  },

  // Get anomalies by asset
  getAnomaliesByAsset: async (hostname?: string, ip?: string) => {
    const response = await api.get('/api/anomalies/asset', {
      params: { hostname, ip }
    });
    return response.data;
  },

  // Get anomaly statistics
  getAnomalyStatistics: async () => {
    const response = await api.get('/api/anomalies/stats');
    return response.data;
  },

  // Get anomaly counts by type
  getAnomalyCountsByType: async () => {
    const response = await api.get('/api/anomalies/stats/by-type');
    return response.data;
  },

  // Get anomaly counts by severity
  getAnomalyCountsBySeverity: async () => {
    const response = await api.get('/api/anomalies/stats/by-severity');
    return response.data;
  },

  // Get anomaly counts by status
  getAnomalyCountsByStatus: async () => {
    const response = await api.get('/api/anomalies/stats/by-status');
    return response.data;
  },

  // Get anomaly count by date range
  getAnomalyCountByDateRange: async (startDate: string, endDate: string) => {
    const response = await api.get('/api/anomalies/stats/count-by-date-range', {
      params: { startDate, endDate }
    });
    return response.data;
  },

  // Bulk update status
  bulkUpdateStatus: async (anomalyIds: string[], status: string) => {
    const response = await api.post('/api/anomalies/bulk/update-status', null, {
      params: { anomalyIds, status }
    });
    return response.data;
  },

  // Bulk assign
  bulkAssign: async (anomalyIds: string[], assignedTo: string) => {
    const response = await api.post('/api/anomalies/bulk/assign', null, {
      params: { anomalyIds, assignedTo }
    });
    return response.data;
  },

  // Search anomalies
  searchAnomalies: async (filters: AnomalyFilters, page: number = 0, size: number = 10) => {
    const response = await api.get('/api/anomalies/search', {
      params: { ...filters, page, size }
    });
    return response.data;
  }
};

export default anomalyService; 