// Define the AuditRecord interface for TypeScript
export interface AuditRecord {
  id: number;
  username: string;
  actionType: string;
  details: string;
  timestamp: string;
} 