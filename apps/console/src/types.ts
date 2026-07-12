export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "in_review" | "remediating" | "resolved" | "suppressed" | "expired";
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
	correlationKeys?: { workload?: string; namespace?: string; identity?: string; networkExposure?: string; image?: string };
  riskScore: number;
	riskExplanation?: { version: string; baseScore: number; factors: Array<{ name: string; points: number; reason: string }>; finalScore: number };
  remediationState: string;
  recommendedAction: string;
  createdAt: string;
  updatedAt: string;
}

export interface FindingException {
	id: string;
	scope: string;
	owner: string;
	reason: string;
	expiresAt: string;
	status: "active" | "expired";
	createdAt: string;
	updatedAt: string;
}

export interface Dashboard {
  totalFindings: number;
  openCritical: number;
  pendingApprovals: number;
  activeRemediations: number;
  verifiedRemediations: number;
  findingsWithSafeFix: number;
  riskReduced: number;
  evidenceFreshness: string;
  meanRiskScore: number;
  findingsBySeverity: Record<string, number>;
  findingsBySource: Record<string, number>;
  remediationByState: Record<string, number>;
  protectedNamespaces: number;
  bundledEnginesOnline: number;
  cluster: ClusterInventory;
  scan: ScanSummary;
  compliance: ComplianceControl[];
  experiments: ChaosExperiment[];
}

export interface ClusterInventory {
  nodes: number;
  readyNodes: number;
  namespaces: number;
  pods: number;
  runningPods: number;
  pendingPods: number;
  deployments: number;
  statefulSets: number;
  daemonSets: number;
  services: number;
  ingresses: number;
  jobs: number;
  configMaps: number;
  secrets: number;
  serviceAccounts: number;
  roles: number;
  roleBindings: number;
  clusterRoles: number;
  clusterRoleBindings: number;
  networkPolicies: number;
  resourceQuotas: number;
  limitRanges: number;
  persistentVolumeClaims: number;
  podDisruptionBudgets: number;
  horizontalPodAutoscalers: number;
  events: number;
}

export interface ScanSummary {
  lastRunAt: string;
  resourcesScanned: number;
  policyChecks: number;
  permissionChecks: number;
  configurationChecks: number;
  complianceControls: number;
  passedControls: number;
  failedControls: number;
}

export interface ComplianceControl {
  id: string;
  framework: string;
  title: string;
  status: "pass" | "fail" | string;
  severity: Severity;
  evidence: string;
}

export interface ChaosExperiment {
  id: string;
  name: string;
  category: string;
  target: string;
  status: string;
  engine: string;
  description: string;
  preflight: string[];
  manifest: string;
}

export interface ChaosExperimentRun {
  id: string;
  experimentId: string;
  status: string;
  message: string;
  manifest: string;
  resource: ResourceRef;
  targetSelector: Record<string, string>;
  targetCount: number;
  durationSeconds: number;
  requestedBy: string;
  approvedBy?: string;
  approvalReason?: string;
  abortedBy?: string;
  failureReason?: string;
  recoveryStatus?: string;
  recoveryMessage?: string;
  version: number;
  createdAt: string;
  updatedAt: string;
  approvalExpiresAt?: string;
  injectionDeadline?: string;
  startedAt?: string;
  finishedAt?: string;
  cleanupDeadline?: string;
  recoveryDeadline?: string;
}

export interface TypedAction {
  type: string;
  target: ResourceRef;
  description: string;
  params?: Record<string, string>;
}

export interface RemediationPlan {
  id: string;
  catalogVersion: string;
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
    decision?: "pending" | "approved" | "rejected" | "expired";
    categories?: string[];
  };
  status: string;
  createdAt: string;
}

export interface EvidenceCitation {
  sourceId: string;
  summary: string;
  resource: string;
  observedAt: string;
}

export interface RemediationPreview {
  findingId: string;
  summary: string;
  candidate: RemediationPlan;
  evidenceCitations: EvidenceCitation[];
  promptEvidenceHash: string;
  deterministicFallback: boolean;
  safetyNotes: string[];
  generatedAt: string;
}

export interface PlannedManifest {
  actionType: string;
  target: ResourceRef;
  writeMode: string;
  riskTier: string;
  approvalRequired: boolean;
  requiredPermissions: string[];
  verificationChecks: string[];
  rollbackProcedure: string[];
  idempotencyBehavior: string;
  failureHandling: string;
  diff: string;
  manifest: string;
}

export interface RemediationDiff {
  planId: string;
  mode: string;
  summary: string;
  manifests: PlannedManifest[];
}

export interface ApprovalRequest {
  id: string;
  subjectRef: string;
  requestedAction: string;
  requester: string;
  approver?: string;
  status: "pending" | "approved" | "rejected" | "expired";
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
  decisionReason?: string;
}

export interface AuditEvent {
  id: string;
  actor: string;
  action: string;
  subject: string;
  message: string;
  createdAt: string;
}

export interface EvidenceBundle {
  scope: string;
  generatedAt: string;
  summary: Record<string, number>;
  findings: Finding[];
  plans: RemediationPlan[];
  runs: RemediationRun[];
  chaosRuns: ChaosExperimentRun[];
  auditEvents: AuditEvent[];
}

export interface RemediationRun {
  id: string;
  planId: string;
  state: string;
  actionStatuses: Array<{ actionType: string; state: string; message: string }>;
  validationResult: string;
  rollbackMetadata: string;
  createdAt: string;
  updatedAt: string;
}

export interface Integration {
  name: string;
  type: string;
  enabled: boolean;
  status: string;
}

export interface IntegrationHealth {
  name: string;
  type: string;
  enabled: boolean;
  status: string;
  health: string;
  dataLastSeen: string;
  permissions: string[];
  supportedVersions: string[];
  setupGaps: string[];
  errorState?: string;
  findingsCount: number;
  checkedAt: string;
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
