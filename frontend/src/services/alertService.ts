import api from './api';
import { 
  Alert, 
  AlertRule, 
  AlertComment, 
  AlertNotification, 
  AlertEscalation,
  AlertFilters,
  AlertSortConfig,
  AlertListResponse,
  AlertStatistics
} from '../types/alert';

// Alert Service
export const alertService = {
  // Get all alerts with pagination and filtering
  getAlerts: async (
    page: number = 0,
    size: number = 20,
    sortBy: string = 'createdAt',
    sortDir: string = 'DESC',
    filters?: AlertFilters
  ): Promise<AlertListResponse> => {
    const params = new URLSearchParams({
      page: page.toString(),
      size: size.toString(),
      sortBy,
      sortDir
    });

    if (filters) {
      if (filters.severity?.length) {
        filters.severity.forEach(s => params.append('severity', s));
      }
      if (filters.status?.length) {
        filters.status.forEach(s => params.append('status', s));
      }
      if (filters.type?.length) {
        filters.type.forEach(t => params.append('type', t));
      }
      if (filters.assignedTo) {
        params.append('assignedTo', filters.assignedTo);
      }
      if (filters.source) {
        params.append('source', filters.source);
      }
      if (filters.dateRange) {
        params.append('startDate', filters.dateRange.start);
        params.append('endDate', filters.dateRange.end);
      }
      if (filters.tags?.length) {
        filters.tags.forEach(tag => params.append('tags', tag));
      }
      if (filters.riskScore) {
        params.append('minRiskScore', filters.riskScore.min.toString());
        params.append('maxRiskScore', filters.riskScore.max.toString());
      }
    }

    const response = await api.get<AlertListResponse>(`/api/alerts?${params}`);
    return response.data;
  },

  // Get alert by ID
  getAlertById: async (id: string): Promise<Alert> => {
    const response = await api.get<Alert>(`/api/alerts/${id}`);
    return response.data;
  },

  // Create new alert
  createAlert: async (alert: Partial<Alert>): Promise<Alert> => {
    const response = await api.post<Alert>('/api/alerts', alert);
    return response.data;
  },

  // Update alert
  updateAlert: async (id: string, alert: Partial<Alert>): Promise<Alert> => {
    const response = await api.put<Alert>(`/api/alerts/${id}`, alert);
    return response.data;
  },

  // Delete alert
  deleteAlert: async (id: string): Promise<void> => {
    await api.delete(`/api/alerts/${id}`);
  },

  // Get alerts by status
  getAlertsByStatus: async (status: string, page: number = 0, size: number = 20): Promise<AlertListResponse> => {
    const params = new URLSearchParams({
      page: page.toString(),
      size: size.toString()
    });
    const response = await api.get<AlertListResponse>(`/api/alerts/status/${status}?${params}`);
    return response.data;
  },

  // Get alerts by severity
  getAlertsBySeverity: async (severity: string, page: number = 0, size: number = 20): Promise<AlertListResponse> => {
    const params = new URLSearchParams({
      page: page.toString(),
      size: size.toString()
    });
    const response = await api.get<AlertListResponse>(`/api/alerts/severity/${severity}?${params}`);
    return response.data;
  },

  // Get alerts by type
  getAlertsByType: async (type: string, page: number = 0, size: number = 20): Promise<AlertListResponse> => {
    const params = new URLSearchParams({
      page: page.toString(),
      size: size.toString()
    });
    const response = await api.get<AlertListResponse>(`/api/alerts/type/${type}?${params}`);
    return response.data;
  },

  // Search alerts
  searchAlerts: async (searchTerm: string, page: number = 0, size: number = 20): Promise<AlertListResponse> => {
    const params = new URLSearchParams({
      searchTerm,
      page: page.toString(),
      size: size.toString()
    });
    const response = await api.get<AlertListResponse>(`/api/alerts/search?${params}`);
    return response.data;
  },

  // Get alerts by source
  getAlertsBySource: async (source: string): Promise<Alert[]> => {
    const response = await api.get<Alert[]>(`/api/alerts/source/${source}`);
    return response.data;
  },

  // Get alerts by IP address
  getAlertsByIpAddress: async (ip: string): Promise<Alert[]> => {
    const response = await api.get<Alert[]>(`/api/alerts/ip/${ip}`);
    return response.data;
  },

  // Get alerts by date range
  getAlertsByDateRange: async (startDate: string, endDate: string): Promise<Alert[]> => {
    const params = new URLSearchParams({ startDate, endDate });
    const response = await api.get<Alert[]>(`/api/alerts/date-range?${params}`);
    return response.data;
  },

  // Get alerts assigned to user
  getAlertsByAssignedTo: async (assignedTo: string): Promise<Alert[]> => {
    const response = await api.get<Alert[]>(`/api/alerts/assigned/${assignedTo}`);
    return response.data;
  },

  // Get unassigned alerts
  getUnassignedAlerts: async (): Promise<Alert[]> => {
    const response = await api.get<Alert[]>('/api/alerts/unassigned');
    return response.data;
  },

  // Get alerts by tag
  getAlertsByTag: async (tag: string): Promise<Alert[]> => {
    const response = await api.get<Alert[]>(`/api/alerts/tag/${tag}`);
    return response.data;
  },

  // Get high risk alerts
  getHighRiskAlerts: async (minScore: number = 7): Promise<Alert[]> => {
    const params = new URLSearchParams({ minScore: minScore.toString() });
    const response = await api.get<Alert[]>(`/api/alerts/high-risk?${params}`);
    return response.data;
  },

  // Get recent alerts
  getRecentAlerts: async (): Promise<Alert[]> => {
    const response = await api.get<Alert[]>('/api/alerts/recent');
    return response.data;
  },

  // Assign alert
  assignAlert: async (id: string, assignedTo: string, assignedBy: string): Promise<Alert> => {
    const response = await api.post<Alert>(`/api/alerts/${id}/assign`, {
      assignedTo,
      assignedBy
    });
    return response.data;
  },

  // Acknowledge alert
  acknowledgeAlert: async (id: string, acknowledgedBy: string): Promise<Alert> => {
    const response = await api.post<Alert>(`/api/alerts/${id}/acknowledge`, {
      acknowledgedBy
    });
    return response.data;
  },

  // Mark as false positive
  markAsFalsePositive: async (id: string, markedBy: string): Promise<Alert> => {
    const response = await api.post<Alert>(`/api/alerts/${id}/false-positive`, {
      markedBy
    });
    return response.data;
  },

  // Resolve alert
  resolveAlert: async (id: string, resolvedBy: string, mitigationNotes?: string): Promise<Alert> => {
    const response = await api.post<Alert>(`/api/alerts/${id}/resolve`, {
      resolvedBy,
      mitigationNotes
    });
    return response.data;
  },

  // Get alert statistics
  getAlertStatistics: async (): Promise<AlertStatistics> => {
    const response = await api.get<AlertStatistics>('/api/alerts/statistics');
    return response.data;
  }
};

// Alert Rule Service
export const alertRuleService = {
  // Get all alert rules
  getAlertRules: async (
    page: number = 0,
    size: number = 20,
    sortBy: string = 'createdAt',
    sortDir: string = 'DESC'
  ): Promise<AlertListResponse> => {
    const params = new URLSearchParams({
      page: page.toString(),
      size: size.toString(),
      sortBy,
      sortDir
    });
    const response = await api.get<AlertListResponse>(`/api/alert-rules?${params}`);
    return response.data;
  },

  // Get alert rule by ID
  getAlertRuleById: async (id: string): Promise<AlertRule> => {
    const response = await api.get<AlertRule>(`/api/alert-rules/${id}`);
    return response.data;
  },

  // Get alert rule by name
  getAlertRuleByName: async (name: string): Promise<AlertRule> => {
    const response = await api.get<AlertRule>(`/api/alert-rules/name/${name}`);
    return response.data;
  },

  // Create alert rule
  createAlertRule: async (rule: Partial<AlertRule>): Promise<AlertRule> => {
    const response = await api.post<AlertRule>('/api/alert-rules', rule);
    return response.data;
  },

  // Update alert rule
  updateAlertRule: async (id: string, rule: Partial<AlertRule>): Promise<AlertRule> => {
    const response = await api.put<AlertRule>(`/api/alert-rules/${id}`, rule);
    return response.data;
  },

  // Delete alert rule
  deleteAlertRule: async (id: string): Promise<void> => {
    await api.delete(`/api/alert-rules/${id}`);
  },

  // Get enabled rules
  getEnabledRules: async (): Promise<AlertRule[]> => {
    const response = await api.get<AlertRule[]>('/api/alert-rules/enabled');
    return response.data;
  },

  // Get disabled rules
  getDisabledRules: async (): Promise<AlertRule[]> => {
    const response = await api.get<AlertRule[]>('/api/alert-rules/disabled');
    return response.data;
  },

  // Get rules by severity
  getRulesBySeverity: async (severity: string): Promise<AlertRule[]> => {
    const response = await api.get<AlertRule[]>(`/api/alert-rules/severity/${severity}`);
    return response.data;
  },

  // Get rules by type
  getRulesByType: async (type: string): Promise<AlertRule[]> => {
    const response = await api.get<AlertRule[]>(`/api/alert-rules/type/${type}`);
    return response.data;
  },

  // Get rules by category
  getRulesByCategory: async (category: string): Promise<AlertRule[]> => {
    const response = await api.get<AlertRule[]>(`/api/alert-rules/category/${category}`);
    return response.data;
  },

  // Search rules
  searchRules: async (searchTerm: string, page: number = 0, size: number = 20): Promise<AlertListResponse> => {
    const params = new URLSearchParams({
      searchTerm,
      page: page.toString(),
      size: size.toString()
    });
    const response = await api.get<AlertListResponse>(`/api/alert-rules/search?${params}`);
    return response.data;
  },

  // Enable rule
  enableRule: async (id: string): Promise<AlertRule> => {
    const response = await api.post<AlertRule>(`/api/alert-rules/${id}/enable`);
    return response.data;
  },

  // Disable rule
  disableRule: async (id: string): Promise<AlertRule> => {
    const response = await api.post<AlertRule>(`/api/alert-rules/${id}/disable`);
    return response.data;
  },

  // Get rule statistics
  getRuleStatistics: async (): Promise<any> => {
    const response = await api.get('/api/alert-rules/statistics');
    return response.data;
  }
};

// Alert Comment Service
export const alertCommentService = {
  // Get all comments
  getComments: async (
    page: number = 0,
    size: number = 20,
    sortBy: string = 'createdAt',
    sortDir: string = 'DESC'
  ): Promise<AlertListResponse> => {
    const params = new URLSearchParams({
      page: page.toString(),
      size: size.toString(),
      sortBy,
      sortDir
    });
    const response = await api.get<AlertListResponse>(`/api/alert-comments?${params}`);
    return response.data;
  },

  // Get comment by ID
  getCommentById: async (id: string): Promise<AlertComment> => {
    const response = await api.get<AlertComment>(`/api/alert-comments/${id}`);
    return response.data;
  },

  // Create comment
  createComment: async (comment: Partial<AlertComment>): Promise<AlertComment> => {
    const response = await api.post<AlertComment>('/api/alert-comments', comment);
    return response.data;
  },

  // Update comment
  updateComment: async (id: string, comment: Partial<AlertComment>): Promise<AlertComment> => {
    const response = await api.put<AlertComment>(`/api/alert-comments/${id}`, comment);
    return response.data;
  },

  // Delete comment
  deleteComment: async (id: string): Promise<void> => {
    await api.delete(`/api/alert-comments/${id}`);
  },

  // Get comments by alert ID
  getCommentsByAlertId: async (alertId: string, page: number = 0, size: number = 20): Promise<AlertListResponse> => {
    const params = new URLSearchParams({
      page: page.toString(),
      size: size.toString()
    });
    const response = await api.get<AlertListResponse>(`/api/alert-comments/alert/${alertId}?${params}`);
    return response.data;
  },

  // Get comments by user
  getCommentsByUser: async (createdBy: string): Promise<AlertComment[]> => {
    const response = await api.get<AlertComment[]>(`/api/alert-comments/user/${createdBy}`);
    return response.data;
  },

  // Get internal comments
  getInternalComments: async (): Promise<AlertComment[]> => {
    const response = await api.get<AlertComment[]>('/api/alert-comments/internal');
    return response.data;
  },

  // Get external comments
  getExternalComments: async (): Promise<AlertComment[]> => {
    const response = await api.get<AlertComment[]>('/api/alert-comments/external');
    return response.data;
  },

  // Get comments by type
  getCommentsByType: async (commentType: string): Promise<AlertComment[]> => {
    const response = await api.get<AlertComment[]>(`/api/alert-comments/type/${commentType}`);
    return response.data;
  },

  // Search comments
  searchComments: async (searchTerm: string, page: number = 0, size: number = 20): Promise<AlertListResponse> => {
    const params = new URLSearchParams({
      searchTerm,
      page: page.toString(),
      size: size.toString()
    });
    const response = await api.get<AlertListResponse>(`/api/alert-comments/search?${params}`);
    return response.data;
  },

  // Get latest comments for alert
  getLatestCommentsByAlertId: async (alertId: string, limit: number = 10): Promise<AlertComment[]> => {
    const params = new URLSearchParams({ limit: limit.toString() });
    const response = await api.get<AlertComment[]>(`/api/alert-comments/alert/${alertId}/latest?${params}`);
    return response.data;
  },

  // Get comments with attachments
  getCommentsWithAttachments: async (): Promise<AlertComment[]> => {
    const response = await api.get<AlertComment[]>('/api/alert-comments/with-attachments');
    return response.data;
  },

  // Add quick comment
  addQuickComment: async (
    alertId: string,
    commentText: string,
    createdBy: string,
    isInternal: boolean = false,
    commentType: string = 'GENERAL'
  ): Promise<AlertComment> => {
    const response = await api.post<AlertComment>(`/api/alert-comments/alert/${alertId}/quick`, {
      commentText,
      createdBy,
      isInternal,
      commentType
    });
    return response.data;
  },

  // Get comment statistics
  getCommentStatistics: async (): Promise<any> => {
    const response = await api.get('/api/alert-comments/statistics');
    return response.data;
  }
};

// Alert Notification Service
export const alertNotificationService = {
  // Get all notifications
  getNotifications: async (
    page: number = 0,
    size: number = 20,
    sortBy: string = 'createdAt',
    sortDir: string = 'DESC'
  ): Promise<AlertListResponse> => {
    const params = new URLSearchParams({
      page: page.toString(),
      size: size.toString(),
      sortBy,
      sortDir
    });
    const response = await api.get<AlertListResponse>(`/api/alert-notifications?${params}`);
    return response.data;
  },

  // Get notification by ID
  getNotificationById: async (id: string): Promise<AlertNotification> => {
    const response = await api.get<AlertNotification>(`/api/alert-notifications/${id}`);
    return response.data;
  },

  // Create notification
  createNotification: async (notification: Partial<AlertNotification>): Promise<AlertNotification> => {
    const response = await api.post<AlertNotification>('/api/alert-notifications', notification);
    return response.data;
  },

  // Update notification
  updateNotification: async (id: string, notification: Partial<AlertNotification>): Promise<AlertNotification> => {
    const response = await api.put<AlertNotification>(`/api/alert-notifications/${id}`, notification);
    return response.data;
  },

  // Delete notification
  deleteNotification: async (id: string): Promise<void> => {
    await api.delete(`/api/alert-notifications/${id}`);
  },

  // Get notifications by alert ID
  getNotificationsByAlertId: async (alertId: string): Promise<AlertNotification[]> => {
    const response = await api.get<AlertNotification[]>(`/api/alert-notifications/alert/${alertId}`);
    return response.data;
  },

  // Get notifications by status
  getNotificationsByStatus: async (status: string): Promise<AlertNotification[]> => {
    const response = await api.get<AlertNotification[]>(`/api/alert-notifications/status/${status}`);
    return response.data;
  },

  // Get pending notifications
  getPendingNotifications: async (): Promise<AlertNotification[]> => {
    const response = await api.get<AlertNotification[]>('/api/alert-notifications/pending');
    return response.data;
  },

  // Mark notification as sent
  markAsSent: async (id: string): Promise<AlertNotification> => {
    const response = await api.post<AlertNotification>(`/api/alert-notifications/${id}/mark-sent`);
    return response.data;
  },

  // Mark notification as delivered
  markAsDelivered: async (id: string): Promise<AlertNotification> => {
    const response = await api.post<AlertNotification>(`/api/alert-notifications/${id}/mark-delivered`);
    return response.data;
  },

  // Get notification statistics
  getNotificationStatistics: async (): Promise<any> => {
    const response = await api.get('/api/alert-notifications/statistics');
    return response.data;
  }
}; 