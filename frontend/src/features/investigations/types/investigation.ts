export type InvestigationStatus =
  | "open"
  | "in_progress"
  | "escalated"
  | "closed"
  | "archived";

export type InvestigationVerdict =
  | "true_positive"
  | "false_positive"
  | "benign"
  | "inconclusive"
  | "pending";

export type InvestigationSeverity = "critical" | "high" | "medium" | "low";

export interface MITRETechnique {
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
  alertCount: number;
  severity: InvestigationSeverity;
}

export interface SuspiciousEntity {
  type: "host" | "user" | "ip" | "process" | "file" | "domain";
  value: string;
  riskScore: number;    // 0-100
  reason: string;
}

export interface DetectedBehavior {
  id: string;
  name: string;
  description: string;
  severity: InvestigationSeverity;
  techniqueId?: string;
  techniqueName?: string;
  confidence: number;   // 0-100
  matchedAt: string;
}

export interface AIAnalysis {
  verdict: InvestigationVerdict;
  confidence: number;
  reasoning: string;    // markdown text
  attackChain: string;
  suspiciousEntities: SuspiciousEntity[];
  detectedBehaviors: DetectedBehavior[];
  recommendedActions: string[];
  riskScore: number;    // 0-100
  analyzedAt: string;
}

export interface OnlineAnalyst {
  id: string;
  name: string;
  avatarColor: string;
  activeSection: string;
  lastSeen: string;
}

export interface CollaborationState {
  presentAnalysts: OnlineAnalyst[];
  lastActivity: string;
}

export interface AnalystActivity {
  id: string;
  analystId: string;
  analystName: string;
  action: string;
  details: Record<string, unknown>;
  timestamp: string;
}

export interface Investigation {
  id: string;
  tenantId: string;
  title: string;
  description: string;
  severity: InvestigationSeverity;
  status: InvestigationStatus;
  verdict: InvestigationVerdict;
  assignedTo?: string;
  assignedToName?: string;
  alertCount: number;
  alertIds: string[];
  entityCount: number;
  affectedHosts: string[];
  affectedUsers: string[];
  mitreTechniques: MITRETechnique[];
  aiAnalysis?: AIAnalysis;
  recentActivity: AnalystActivity[];
  createdAt: string;
  updatedAt: string;
  closedAt?: string;
}

export interface InvestigationNote {
  id: string;
  investigationId: string;
  authorId: string;
  authorName: string;
  content: string;
  createdAt: string;
  updatedAt: string;
}

// ─── Placeholders ─────────────────────────────────────────────────────────────

export const PLACEHOLDER_INVESTIGATION: Investigation = {
  id: "",
  tenantId: "",
  title: "Loading investigation...",
  description: "",
  severity: "medium",
  status: "open",
  verdict: "pending",
  alertCount: 0,
  alertIds: [],
  entityCount: 0,
  affectedHosts: [],
  affectedUsers: [],
  mitreTechniques: [],
  recentActivity: [],
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};
