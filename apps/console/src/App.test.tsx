import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";

const finding = {
  id: "finding-public-rbac-image",
  source: "kubeathrix-scan",
  title: "Public workload combines broad RBAC, stale image, and missing network policy",
  severity: "critical",
  evidence: [
    {
      summary: "Public LoadBalancer exposure",
      details: "checkout-api accepts ingress from 0.0.0.0/0.",
      sourceId: "kubeathrix/live-scan",
      observedAt: "2026-07-08T12:00:00Z"
    }
  ],
  resources: [{ apiVersion: "apps/v1", kind: "Deployment", namespace: "payments", name: "checkout-api" }],
  blastRadius: "Internet-facing payment API with namespace secret visibility.",
  fixability: "human_approved_only",
  status: "open",
  correlationGroup: "payments-checkout-exposure",
  riskScore: 97,
  remediationState: "approval_required",
  recommendedAction: "Review network, RBAC, and image trust changes before rollout.",
  createdAt: "2026-07-08T12:00:00Z",
  updatedAt: "2026-07-08T12:00:00Z"
};

function dashboardPayload() {
  return {
    totalFindings: 1,
    openCritical: 1,
    pendingApprovals: 1,
    activeRemediations: 0,
    verifiedRemediations: 0,
    findingsWithSafeFix: 0,
    riskReduced: 0,
    evidenceFreshness: "fresh",
    meanRiskScore: 97,
    findingsBySeverity: { critical: 1 },
    findingsBySource: { "kubeathrix-scan": 1 },
    remediationByState: { approval_required: 1 },
    protectedNamespaces: 1,
    bundledEnginesOnline: 1,
    cluster: {
      nodes: 2,
      readyNodes: 2,
      namespaces: 3,
      pods: 8,
      runningPods: 7,
      pendingPods: 1,
      deployments: 2,
      statefulSets: 0,
      daemonSets: 2,
      services: 3,
      ingresses: 1,
      jobs: 0,
      configMaps: 8,
      secrets: 6,
      serviceAccounts: 5,
      roles: 2,
      roleBindings: 2,
      clusterRoles: 12,
      clusterRoleBindings: 6,
      networkPolicies: 1,
      resourceQuotas: 1,
      limitRanges: 1,
      persistentVolumeClaims: 0,
      podDisruptionBudgets: 1,
      horizontalPodAutoscalers: 1,
      events: 12
    },
    scan: {
      lastRunAt: "2026-07-08T12:00:00Z",
      resourcesScanned: 76,
      policyChecks: 8,
      permissionChecks: 22,
      configurationChecks: 18,
      complianceControls: 2,
      passedControls: 1,
      failedControls: 1
    },
    compliance: [
      {
        id: "KA-K8S-010",
        framework: "Traffic exposure",
        title: "Ingress and Service exposure are explicitly controlled",
        status: "fail",
        severity: "high",
        evidence: "External traffic paths should be reviewed and encrypted."
      }
    ],
    experiments: [
      {
        id: "pod-delete-resilience",
        name: "Pod delete resilience",
        category: "availability",
        target: "Deployment pods",
        status: "ready",
        engine: "litmus",
        description: "Deletes one matching pod and verifies recovery.",
        preflight: ["Target deployment has at least two replicas."],
        manifest: "apiVersion: litmuschaos.io/v1alpha1\nkind: ChaosEngine\nmetadata:\n  name: kubeathrix-pod-delete\n  namespace: default"
      }
    ]
  };
}

function planPayload() {
  return {
    id: "plan-finding-public-rbac-image-001",
    findingId: finding.id,
    rootCause: "Structured plan generated from scanner evidence.",
    actions: [
      {
        type: "propose_security_hardening",
        target: finding.resources[0],
        description: finding.recommendedAction,
        params: { dryRun: "required" }
      }
    ],
    riskTier: "C",
    dryRunResult: { passed: true, message: "server-side dry-run queued" },
    verificationSteps: ["Re-scan source engines"],
    rollbackSteps: ["Restore pre-change snapshot"],
    approvalPolicy: { required: true, categories: ["network", "iam"] },
    status: "proposed",
    createdAt: "2026-07-08T12:00:00Z"
  };
}

function managedResourcePayload() {
  return {
    enabled: true,
    observedAt: "2026-07-08T12:00:00Z",
    resources: [{
      id: "iam.aws.example.io/v1beta1/roles/payments/checkout-role",
      apiGroup: "iam.aws.example.io",
      version: "v1beta1",
      plural: "roles",
      apiVersion: "iam.aws.example.io/v1beta1",
      kind: "Role",
      namespace: "payments",
      name: "checkout-role",
      uid: "role-uid",
      generation: 4,
      externalId: "arn:aws:iam::123456789012:role/checkout-role",
      status: { ready: true, synced: true, stalled: false, state: "Ready", observedGeneration: 4 },
      provenance: { system: "argocd", controller: "argocd-application-controller", sourceRef: "platform/iam/checkout-role.yaml", gitOps: true, signals: ["argocd tracking label"] }
    }],
    relationships: [],
    findings: [],
    warnings: []
  };
}

function mockApi(modelSettingsAllowed = true, managedResourcesAllowed = true) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? "GET";
	  if (url.endsWith("/auth/config")) return Promise.resolve(Response.json({ mode: "development", issuerURL: "", clientID: "" }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(Response.json(dashboardPayload()));
      if (url.endsWith("/api/findings")) return Promise.resolve(Response.json({ items: [finding] }));
      if (url.endsWith("/api/exceptions")) return Promise.resolve(Response.json({ items: [] }));
      if (url.endsWith("/api/audit-events")) return Promise.resolve(Response.json({ items: [] }));
      if (url.endsWith("/api/integrations")) {
        return Promise.resolve(Response.json({ items: [{ name: "Kyverno", type: "policy", enabled: true, status: "configured" }] }));
      }
      if (url.endsWith("/api/integrations/Kyverno/health")) {
        return Promise.resolve(Response.json({ name: "Kyverno", type: "policy", enabled: true, status: "configured", health: "healthy", dataLastSeen: "2026-07-08T12:00:00Z", permissions: ["Read policyreports"], setupGaps: [], checkedAt: "2026-07-08T12:00:00Z" }));
      }
      if (url.endsWith("/api/managed-resources")) {
        if (!managedResourcesAllowed) return Promise.resolve(Response.json({ error: { code: "permission_denied", message: "cluster scope required" } }, { status: 403 }));
        return Promise.resolve(Response.json(managedResourcePayload()));
      }
      if (url.endsWith("/api/settings/model-providers")) {
        if (!modelSettingsAllowed) return Promise.resolve(Response.json({ error: { code: "permission_denied", message: "insufficient permissions" } }, { status: 403 }));
        return Promise.resolve(Response.json({ providers: [{ name: "primary", type: "openai-compatible", model: "gpt-5", apiKeySecretRef: { name: "kubeathrix-llm", key: "api-key" } }] }));
      }
	  if (url.endsWith("/api/experiments")) return Promise.resolve(Response.json({ items: dashboardPayload().experiments }));
	  if (url.endsWith("/api/experiment-runs")) return Promise.resolve(Response.json({ items: [] }));
      if (url.endsWith("/api/remediation-plans") && method === "POST") return Promise.resolve(Response.json(planPayload(), { status: 201 }));
      if (url.endsWith("/api/approvals/approval-plan-finding-public-rbac-image-001/approve") && method === "POST") {
        return Promise.resolve(Response.json({ id: "approval-plan-finding-public-rbac-image-001", subjectRef: "plan-finding-public-rbac-image-001", status: "approved" }));
      }
      if (url.endsWith("/api/remediation-plans/plan-finding-public-rbac-image-001/execute") && method === "POST") {
        return Promise.resolve(Response.json({
          id: "run-plan-finding-public-rbac-image-001",
          planId: "plan-finding-public-rbac-image-001",
          state: "execution_requested",
          actionStatuses: [],
          validationResult: "execution request persisted",
          rollbackMetadata: "no snapshot yet",
          createdAt: "2026-07-08T12:00:00Z",
          updatedAt: "2026-07-08T12:00:00Z"
        }, { status: 202 }));
      }
      if (url.endsWith("/api/remediation-plans/plan-finding-public-rbac-image-001/diff")) {
        return Promise.resolve(Response.json({ planId: "plan-finding-public-rbac-image-001", mode: "typed-server-side-dry-run", summary: "1 typed action prepared.", manifests: [{ actionType: "propose_security_hardening", target: finding.resources[0], writeMode: "gitops-proposal", diff: "Prepare network policy proposal.", manifest: "" }] }));
      }
      return Promise.resolve(Response.json({ error: "not found" }, { status: 404 }));
    })
  );
}

describe("KubeAthrix console", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the operator dashboard with live API metrics", async () => {
    mockApi();
    render(<App />);

    expect(await screen.findByText("Correlated cluster risk")).toBeInTheDocument();
    expect(await screen.findByText("KubeAthrix")).toBeInTheDocument();
    expect(await screen.findByText("Open critical")).toBeInTheDocument();
  });

  it("creates a typed remediation plan from the findings workflow", async () => {
    mockApi();
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: /Findings/i }));
    await user.click(await screen.findByRole("button", { name: /Generate typed plan/i }));

    expect(await screen.findByText("Find, explain, fix, verify, prove")).toBeInTheDocument();
	expect(await screen.findByText("Approval required")).toBeInTheDocument();
  });

  it("shows approved and execution-requested plan states instead of pending approval", async () => {
    mockApi();
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: /Findings/i }));
    await user.click(await screen.findByRole("button", { name: /Generate typed plan/i }));
    await screen.findByText("Approval required");

    await user.type(screen.getByLabelText(/Approval decision reason/i), "reviewed");
    await user.click(screen.getByRole("button", { name: "Approve" }));

    expect(await screen.findByText("Approved; not executed")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Execute" }));

    expect(await screen.findByText("Execution requested")).toBeInTheDocument();
  });

  it("keeps viewer data usable when administrator-only settings are denied", async () => {
    mockApi(false);
    render(<App />);

    expect(await screen.findByText("Correlated cluster risk")).toBeInTheDocument();
    expect(screen.queryByText("API unavailable")).not.toBeInTheDocument();
  });

  it("shows managed resources as read-only source-of-truth inventory", async () => {
    mockApi();
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: /Managed resources/i }));

    expect(await screen.findByText("Role/checkout-role")).toBeInTheDocument();
    expect(screen.getByText("platform/iam/checkout-role.yaml")).toBeInTheDocument();
    expect(screen.getByText("GitOps")).toBeInTheDocument();
    expect(screen.getByText(/every managed-resource change remains human-reviewed and proposal-only/i)).toBeInTheDocument();
  });

  it("keeps the console usable when managed-resource inventory is forbidden", async () => {
    mockApi(true, false);
    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByText("Correlated cluster risk")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Managed resources/i }));

    expect(await screen.findByText("Managed-resource inventory is not available to this identity")).toBeInTheDocument();
    expect(screen.queryByText("API unavailable")).not.toBeInTheDocument();
  });
});
