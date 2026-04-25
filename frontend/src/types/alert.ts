// Alert Types matching backend DTOs
export interface Alert {
  id: string;
  title: string;
  description: string;
  source: string;
  destinationIp?: string;
  sourceIp?: string;
  severity: AlertSeverity;
  status: AlertStatus;
  type: AlertType;
  assignedTo?: string;
  assignedBy?: string;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: string;
  falsePositive: boolean;
  riskScore: number;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  resolvedAt?: string;
  mitigationNotes?: string;
  evidence?: string;
  correlationId?: string;
  ruleId?: string;
}

export enum AlertSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export enum AlertStatus {
  NEW = 'NEW',
  ACKNOWLEDGED = 'ACKNOWLEDGED',
  IN_PROGRESS = 'IN_PROGRESS',
  RESOLVED = 'RESOLVED',
  FALSE_POSITIVE = 'FALSE_POSITIVE',
  CLOSED = 'CLOSED'
}

export enum AlertType {
  INTRUSION_DETECTION = 'INTRUSION_DETECTION',
  MALWARE_DETECTION = 'MALWARE_DETECTION',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  POLICY_VIOLATION = 'POLICY_VIOLATION',
  SYSTEM_ANOMALY = 'SYSTEM_ANOMALY',
  NETWORK_ANOMALY = 'NETWORK_ANOMALY',
  USER_ANOMALY = 'USER_ANOMALY',
  THREAT_INTELLIGENCE = 'THREAT_INTELLIGENCE',
  COMPLIANCE_VIOLATION = 'COMPLIANCE_VIOLATION',
  SECURITY_INCIDENT = 'SECURITY_INCIDENT'
}

// Alert Rule Types
export interface AlertRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: AlertSeverity;
  type: AlertType;
  enabled: boolean;
  conditions: string;
  actions: string[];
  threshold: number;
  timeWindow: number;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  tags: string[];
  priority: number;
  source: string;
}

// Alert Comment Types
export interface AlertComment {
  id: string;
  alertId: string;
  commentText: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  isInternal: boolean;
  commentType: CommentType;
  attachments?: string[];
}

export enum CommentType {
  GENERAL = 'GENERAL',
  INVESTIGATION = 'INVESTIGATION',
  RESOLUTION = 'RESOLUTION',
  ESCALATION = 'ESCALATION',
  NOTIFICATION = 'NOTIFICATION'
}

// Alert Notification Types
export interface AlertNotification {
  id: string;
  alertId: string;
  notificationType: NotificationType;
  recipient: string;
  channel: NotificationChannel;
  status: NotificationStatus;
  sentAt?: string;
  deliveredAt?: string;
  readAt?: string;
  content: string;
  subject?: string;
  priority: NotificationPriority;
  retryCount: number;
  maxRetries: number;
  createdAt: string;
  updatedAt: string;
}

export enum NotificationType {
  EMAIL = 'EMAIL',
  SMS = 'SMS',
  SLACK = 'SLACK',
  WEBHOOK = 'WEBHOOK',
  PUSH = 'PUSH',
  IN_APP = 'IN_APP'
}

export enum NotificationChannel {
  EMAIL = 'EMAIL',
  SMS = 'SMS',
  SLACK = 'SLACK',
  WEBHOOK = 'WEBHOOK',
  PUSH = 'PUSH',
  IN_APP = 'IN_APP'
}

export enum NotificationStatus {
  PENDING = 'PENDING',
  SENT = 'SENT',
  DELIVERED = 'DELIVERED',
  READ = 'READ',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED'
}

export enum NotificationPriority {
  LOW = 'LOW',
  NORMAL = 'NORMAL',
  HIGH = 'HIGH',
  URGENT = 'URGENT'
}

// Alert Escalation Types
export interface AlertEscalation {
  id: string;
  alertId: string;
  escalationLevel: number;
  escalatedTo: string;
  escalatedFrom: string;
  escalationTime: string;
  responseTime?: string;
  resolutionTime?: string;
  status: EscalationStatus;
  escalationReason: string;
  notes?: string;
  autoEscalate: boolean;
  escalationPolicy: string;
  timeoutMinutes: number;
  createdAt: string;
  updatedAt: string;
}

export enum EscalationStatus {
  PENDING = 'PENDING',
  ACTIVE = 'ACTIVE',
  RESPONDED = 'RESPONDED',
  RESOLVED = 'RESOLVED',
  TIMEOUT = 'TIMEOUT',
  CANCELLED = 'CANCELLED'
}

// Filter and Search Types
export interface AlertFilters {
  severity?: AlertSeverity[];
  status?: AlertStatus[];
  type?: AlertType[];
  assignedTo?: string;
  source?: string;
  dateRange?: {
    start: string;
    end: string;
  };
  tags?: string[];
  riskScore?: {
    min: number;
    max: number;
  };
}

export interface AlertSortConfig {
  field: keyof Alert;
  direction: 'asc' | 'desc';
}

// API Response Types
export interface AlertListResponse {
  content: Alert[];
  totalElements: number;
  totalPages: number;
  size: number;
  number: number;
  first: boolean;
  last: boolean;
}

export interface AlertStatistics {
  totalAlerts: number;
  newAlerts: number;
  acknowledgedAlerts: number;
  resolvedAlerts: number;
  criticalAlerts: number;
  highAlerts: number;
  unassignedAlerts: number;
  falsePositives: number;
} 