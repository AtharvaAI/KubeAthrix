import { expect, test, type Page } from "@playwright/test";

const finding = {
  id: "finding-public-rbac-image",
  source: "correlator",
  title: "Public workload combines broad RBAC, stale image, and missing network policy",
  severity: "critical",
  evidence: [
    {
      summary: "Public LoadBalancer exposure",
      details: "checkout-api accepts ingress from 0.0.0.0/0.",
      sourceId: "kubescape/network",
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

async function mockApi(page: Page) {
	await page.route("**/auth/config", async (route) => route.fulfill({ json: { mode: "development", issuerURL: "", clientID: "" } }));
  await page.route("**/api/dashboard", async (route) =>
    route.fulfill({
      json: {
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
        findingsBySource: { correlator: 1 },
        remediationByState: { approval_required: 1 },
        protectedNamespaces: 1,
        bundledEnginesOnline: 3,
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
      }
    })
  );
  await page.route("**/api/findings", async (route) => route.fulfill({ json: { items: [finding] } }));
  await page.route("**/api/exceptions", async (route) => route.fulfill({ json: { items: [] } }));
  await page.route("**/api/audit-events", async (route) => route.fulfill({ json: { items: [] } }));
  await page.route("**/api/integrations", async (route) =>
    route.fulfill({
      json: {
        items: [
          { name: "Trivy Operator", type: "scanner", enabled: true, status: "online" },
          { name: "Kyverno", type: "policy", enabled: true, status: "online" },
          { name: "Kubescape", type: "scanner", enabled: true, status: "online" }
        ]
      }
    })
  );
  await page.route("**/api/integrations/*/health", async (route) =>
    route.fulfill({
      json: {
        name: "Kyverno",
        type: "policy",
        enabled: true,
        status: "online",
        health: "healthy",
        dataLastSeen: "2026-07-08T12:00:00Z",
        permissions: ["Read policyreports"],
        setupGaps: [],
        checkedAt: "2026-07-08T12:00:00Z"
      }
    })
  );
  await page.route("**/api/settings/model-providers", async (route) =>
    route.fulfill({
      json: {
        providers: [
          {
            name: "primary",
            type: "openai-compatible",
            model: "gpt-5",
            apiKeySecretRef: { name: "kubeathrix-llm", key: "api-key" }
          }
        ]
      }
    })
  );
  await page.route("**/api/experiments", async (route) =>
    route.fulfill({
      json: {
        items: [
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
      }
    })
  );
  await page.route("**/api/experiment-runs", async (route) => route.fulfill({ json: { items: [] } }));
  await page.route("**/api/remediation-plans", async (route) =>
    route.fulfill({
      status: 201,
      json: {
        id: "plan-finding-public-rbac-image-001",
        findingId: finding.id,
        rootCause: "Structured plan generated from correlated scanner evidence.",
        actions: [
          {
            type: "propose_security_hardening",
            target: finding.resources[0],
            description: finding.recommendedAction,
            params: { dryRun: "required" }
          }
        ],
        riskTier: "C",
        dryRunResult: { passed: true, message: "dry-run queued" },
        verificationSteps: ["Re-scan source engines"],
        rollbackSteps: ["Restore pre-change snapshot"],
        approvalPolicy: { required: true, categories: ["network", "iam"] },
        status: "proposed",
        createdAt: "2026-07-08T12:00:00Z"
      }
    })
  );
  await page.route("**/api/remediation-plans/plan-finding-public-rbac-image-001/diff", async (route) =>
    route.fulfill({
      json: {
        planId: "plan-finding-public-rbac-image-001",
        mode: "typed-server-side-dry-run",
        summary: "1 typed action prepared.",
        manifests: [
          {
            actionType: "propose_security_hardening",
            target: finding.resources[0],
            writeMode: "gitops-proposal",
            diff: "Prepare network policy proposal.",
            manifest: ""
          }
        ]
      }
    })
  );
}

test("dashboard and fix center are usable on desktop", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Correlated cluster risk")).toBeVisible();
  await page.getByRole("button", { name: /Findings/ }).click();
  await page.getByRole("button", { name: /Generate typed plan/ }).click();
  await expect(page.getByRole("heading", { name: "Fix Center" })).toBeVisible();
  await expect(page.getByText("Find, explain, fix, verify, prove")).toBeVisible();
});

test("mobile layout keeps navigation and text accessible", async ({ page }) => {
  await mockApi(page);
  await page.setViewportSize({ width: 390, height: 840 });
  await page.goto("/");
  await expect(page.getByText("Guardrail control plane")).toBeVisible();
  await page.getByRole("button", { name: /Integrations/ }).click();
  await expect(page.getByRole("heading", { name: "Integrations" })).toBeVisible();
  await expect(page.getByText("Trivy Operator")).toBeVisible();
});

test("OIDC Authorization Code with PKCE authenticates against the real API", async ({ page }) => {
  test.setTimeout(60_000);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sign in to KubeAthrix" })).toBeVisible();
  await page.getByRole("button", { name: "Sign in with OIDC" }).click();

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Cluster cockpit")).toBeVisible();
  const authenticatedHealth = await page.evaluate(async () => {
    const token = sessionStorage.getItem("kubeathrix.oidc.access_token");
    const response = await fetch("/api/health", { headers: { Authorization: `Bearer ${token}` } });
    return { status: response.status, payload: await response.json() };
  });
  expect(authenticatedHealth.status).toBe(200);
  expect(authenticatedHealth.payload).toMatchObject({ status: "ok", oidcConfigured: true, clusterId: "e2e" });
  expect(await page.evaluate(() => sessionStorage.getItem("kubeathrix.oidc.access_token")?.split(".").length)).toBe(3);
  expect(await page.evaluate(() => localStorage.length)).toBe(0);

  const signOut = page.getByRole("button", { name: "Sign out" });
  await expect(signOut).toBeVisible();
  await signOut.click();
  await expect(page.getByRole("heading", { name: "Sign in to KubeAthrix" })).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem("kubeathrix.oidc.access_token"))).toBeNull();
});
