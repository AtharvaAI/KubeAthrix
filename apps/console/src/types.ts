export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "in_review" | "remediating" | "resolved" | "suppressed";
export type Fixability =
  | "safe_deterministic"
  | "dry_run_then_gated"
  | "human_approved_only"
  | "informational_no_fix";

export interface ResourceRef {
  apiVersion: string;
  kind: string;
  namespace?: string;
  name: string;
}

export interface Evidence {
  summary: string;
  details: string;
  sourceId: string;
  observedAt: string;
}

export interface Finding {
  id: string;
  source: string;
  title: string;
  severity: Severity;
  evidence: Evidence[];
  resources: ResourceRef[];
  blastRadius: string;
  fixability: Fixability;
  status: FindingStatus;
  correlationGroup: string;
  riskScore: number;
  remediationState: string;
  recommendedAction: string;
  createdAt: string;
  updatedAt: string;
}

export interface Dashboard {
  totalFindings: number;
  openCritical: number;
  pendingApprovals: number;
  activeRemediations: number;
  meanRiskScore: number;
  findingsBySeverity: Record<string, number>;
  findingsBySource: Record<string, number>;
  remediationByState: Record<string, number>;
  protectedNamespaces: number;
  bundledEnginesOnline: number;
}

export interface TypedAction {
  type: string;
  target: ResourceRef;
  description: string;
  params?: Record<string, string>;
}

export interface RemediationPlan {
  id: string;
  findingId: string;
  rootCause: string;
  actions: TypedAction[];
  riskTier: "A" | "B" | "C" | "D";
  dryRunResult: {
    passed: boolean;
    message: string;
  };
  verificationSteps: string[];
  rollbackSteps: string[];
  approvalPolicy: {
    required: boolean;
    categories?: string[];
  };
  status: string;
  createdAt: string;
}

export interface AuditEvent {
  id: string;
  actor: string;
  action: string;
  subject: string;
  message: string;
  createdAt: string;
}

export interface Integration {
  name: string;
  type: string;
  enabled: boolean;
  status: string;
}

export interface ModelProviderSettings {
  providers: Array<{
    name: string;
    type: string;
    model: string;
    apiKeySecretRef?: {
      name: string;
      key: string;
    };
    externalSecretRef?: {
      store: string;
      path: string;
      key: string;
    };
  }>;
}
