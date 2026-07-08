import type { AuditEvent, Dashboard, Finding, Integration, ModelProviderSettings } from "./types";

const now = new Date("2026-07-08T12:00:00Z").toISOString();

export const demoFindings: Finding[] = [
  {
    id: "finding-public-rbac-image",
    source: "correlator",
    title: "Public workload combines broad RBAC, stale image, and missing network policy",
    severity: "critical",
    evidence: [
      {
        summary: "Public LoadBalancer exposure",
        details: "checkout-api accepts ingress from 0.0.0.0/0.",
        sourceId: "kubescape/network",
        observedAt: now
      },
      {
        summary: "Secret read path",
        details: "RoleBinding grants list/watch on secrets in payments.",
        sourceId: "kyverno/rbac",
        observedAt: now
      }
    ],
    resources: [
      { apiVersion: "apps/v1", kind: "Deployment", namespace: "payments", name: "checkout-api" },
      { apiVersion: "v1", kind: "Service", namespace: "payments", name: "checkout-api" }
    ],
    blastRadius: "Internet-facing payment API with namespace secret visibility and critical image exposure.",
    fixability: "human_approved_only",
    status: "open",
    correlationGroup: "payments-checkout-exposure",
    riskScore: 97,
    remediationState: "approval_required",
    recommendedAction: "Review network, RBAC, and image trust changes before rollout.",
    createdAt: now,
    updatedAt: now
  },
  {
    id: "finding-missing-probes-pdb",
    source: "kubeathrix",
    title: "Critical API lacks readiness probes and disruption protection",
    severity: "high",
    evidence: [
      {
        summary: "No readiness probe",
        details: "tenant-router cannot prove request-serving health during rollout.",
        sourceId: "kubeathrix/reliability",
        observedAt: now
      }
    ],
    resources: [{ apiVersion: "apps/v1", kind: "Deployment", namespace: "platform", name: "tenant-router" }],
    blastRadius: "Tenant routing can flap during node maintenance.",
    fixability: "dry_run_then_gated",
    status: "in_review",
    correlationGroup: "platform-tenant-router-resilience",
    riskScore: 82,
    remediationState: "dry_run_ready",
    recommendedAction: "Create a readiness probe and PDB after dry-run validation.",
    createdAt: now,
    updatedAt: now
  },
  {
    id: "finding-namespace-quota",
    source: "kyverno",
    title: "Developer namespace has no ResourceQuota or LimitRange",
    severity: "medium",
    evidence: [
      {
        summary: "Unbounded namespace",
        details: "team-labs has no ResourceQuota or LimitRange.",
        sourceId: "kyverno/policyreport",
        observedAt: now
      }
    ],
    resources: [{ apiVersion: "v1", kind: "Namespace", name: "team-labs" }],
    blastRadius: "A runaway workload can starve shared nodes.",
    fixability: "safe_deterministic",
    status: "open",
    correlationGroup: "team-labs-resource-hygiene",
    riskScore: 61,
    remediationState: "autofix_available",
    recommendedAction: "Apply namespace-scoped quota and default request limits.",
    createdAt: now,
    updatedAt: now
  },
  {
    id: "finding-runtime-shell",
    source: "falco",
    title: "Interactive shell opened in production workload",
    severity: "high",
    evidence: [
      {
        summary: "Unexpected shell spawned",
        details: "bash was executed inside prod/catalog-api by kubectl exec.",
        sourceId: "falco/runtime",
        observedAt: now
      }
    ],
    resources: [{ apiVersion: "v1", kind: "Pod", namespace: "prod", name: "catalog-api-657ccd4f9d-q2k84" }],
    blastRadius: "Runtime activity may indicate manual debugging or compromise.",
    fixability: "informational_no_fix",
    status: "open",
    correlationGroup: "prod-catalog-runtime",
    riskScore: 76,
    remediationState: "triage_required",
    recommendedAction: "Verify actor, correlate with deployment window, and consider containment policy.",
    createdAt: now,
    updatedAt: now
  }
];

export const demoDashboard: Dashboard = {
  totalFindings: 4,
  openCritical: 1,
  pendingApprovals: 1,
  activeRemediations: 0,
  meanRiskScore: 79,
  findingsBySeverity: { critical: 1, high: 2, medium: 1 },
  findingsBySource: { correlator: 1, kubeathrix: 1, kyverno: 1, falco: 1 },
  remediationByState: { approval_required: 1, dry_run_ready: 1, autofix_available: 1, triage_required: 1 },
  protectedNamespaces: 4,
  bundledEnginesOnline: 3
};

export const demoIntegrations: Integration[] = [
  { name: "Trivy Operator", type: "scanner", enabled: true, status: "online" },
  { name: "Kyverno", type: "policy", enabled: true, status: "online" },
  { name: "Kubescape", type: "scanner", enabled: true, status: "online" },
  { name: "Falco", type: "runtime", enabled: false, status: "stubbed" },
  { name: "Tetragon", type: "runtime", enabled: false, status: "stubbed" },
  { name: "Chaos Mesh", type: "verification", enabled: false, status: "stubbed" },
  { name: "LitmusChaos", type: "verification", enabled: false, status: "stubbed" }
];

export const demoAuditEvents: AuditEvent[] = [
  {
    id: "audit-001",
    actor: "system",
    action: "finding.normalized",
    subject: "finding-public-rbac-image",
    message: "Correlated Kubescape, Kyverno, and Trivy evidence into one issue.",
    createdAt: now
  },
  {
    id: "audit-002",
    actor: "platform-sre",
    action: "remediation.plan.created",
    subject: "finding-missing-probes-pdb",
    message: "Created typed reliability remediation plan.",
    createdAt: now
  }
];

export const demoModelProviders: ModelProviderSettings = {
  providers: [
    {
      name: "primary",
      type: "openai-compatible",
      model: "gpt-5",
      apiKeySecretRef: { name: "kubeathrix-llm", key: "api-key" }
    }
  ]
};
