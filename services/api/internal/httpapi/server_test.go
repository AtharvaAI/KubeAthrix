package httpapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/httpapi"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
)

func testServer() http.Handler {
	fixed := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	repo := store.NewMemoryStore(
		store.WithClock(func() time.Time { return fixed }),
		store.WithFindings(testFindings(fixed)),
		store.WithIntegrations([]core.Integration{
			{Name: "Trivy Operator", Type: "scanner", Enabled: true, Status: "configured"},
			{Name: "Kyverno", Type: "policy", Enabled: true, Status: "configured"},
			{Name: "Kubescape", Type: "scanner", Enabled: true, Status: "configured"},
		}),
	)
	return httpapi.NewServer(repo, httpapi.Config{DevAuthEnabled: true}).Routes()
}

func testFindings(now time.Time) []core.Finding {
	return []core.Finding{
		{
			ID:       "finding-public-rbac-image",
			Source:   "correlator",
			Title:    "Public workload combines broad RBAC, stale image, and missing network policy",
			Severity: core.SeverityCritical,
			Evidence: []core.Evidence{
				{Summary: "Service is exposed through a public LoadBalancer.", Details: "Service checkout-api accepts traffic from 0.0.0.0/0.", SourceID: "kubescape/network", ObservedAt: now.Add(-27 * time.Minute)},
				{Summary: "ServiceAccount can list secrets.", Details: "RoleBinding grants get/list/watch on secrets in payments.", SourceID: "kyverno/rbac", ObservedAt: now.Add(-25 * time.Minute)},
			},
			Resources: []core.ResourceRef{
				{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "payments", Name: "checkout-api"},
				{APIVersion: "v1", Kind: "Service", Namespace: "payments", Name: "checkout-api"},
			},
			BlastRadius:       "Internet-facing payment API with namespace secret visibility.",
			Fixability:        core.FixabilityHumanOnly,
			Status:            core.FindingOpen,
			CorrelationGroup:  "payments-checkout-exposure",
			RiskScore:         97,
			RemediationState:  "approval_required",
			RecommendedAction: "Review network, RBAC, and image trust changes before rollout.",
			CreatedAt:         now.Add(-45 * time.Minute),
			UpdatedAt:         now.Add(-23 * time.Minute),
		},
		{
			ID:       "finding-missing-probes-pdb",
			Source:   "kubeathrix",
			Title:    "Critical API lacks readiness probes and disruption protection",
			Severity: core.SeverityHigh,
			Evidence: []core.Evidence{
				{Summary: "Deployment has no readiness probe.", Details: "rollout-controller cannot confirm request-serving health.", SourceID: "kubeathrix/reliability", ObservedAt: now.Add(-18 * time.Minute)},
			},
			Resources:         []core.ResourceRef{{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "platform", Name: "tenant-router"}},
			BlastRadius:       "Tenant routing can flap during node maintenance.",
			Fixability:        core.FixabilityGated,
			Status:            core.FindingInReview,
			CorrelationGroup:  "platform-tenant-router-resilience",
			RiskScore:         82,
			RemediationState:  "dry_run_ready",
			RecommendedAction: "Create a readiness probe and PDB after dry-run validation.",
			CreatedAt:         now.Add(-2 * time.Hour),
			UpdatedAt:         now.Add(-18 * time.Minute),
		},
		{
			ID:                "finding-namespace-quota",
			Source:            "kyverno",
			Title:             "Developer namespace has no ResourceQuota or LimitRange",
			Severity:          core.SeverityMedium,
			Evidence:          []core.Evidence{{Summary: "Unbounded namespace", Details: "No ResourceQuota or LimitRange exists in team-labs.", SourceID: "kyverno/policyreport", ObservedAt: now.Add(-12 * time.Minute)}},
			Resources:         []core.ResourceRef{{APIVersion: "v1", Kind: "Namespace", Name: "team-labs"}},
			BlastRadius:       "A runaway workload can starve shared nodes.",
			Fixability:        core.FixabilityDeterministic,
			Status:            core.FindingOpen,
			CorrelationGroup:  "team-labs-resource-hygiene",
			RiskScore:         61,
			RemediationState:  "autofix_available",
			RecommendedAction: "Apply namespace-scoped quota and default request limits.",
			CreatedAt:         now.Add(-6 * time.Hour),
			UpdatedAt:         now.Add(-12 * time.Minute),
		},
		{
			ID:                "finding-runtime-shell",
			Source:            "falco",
			Title:             "Interactive shell opened in production workload",
			Severity:          core.SeverityHigh,
			Evidence:          []core.Evidence{{Summary: "Unexpected shell spawned.", Details: "bash was executed inside prod/catalog-api by kubectl exec.", SourceID: "falco/runtime", ObservedAt: now.Add(-4 * time.Minute)}},
			Resources:         []core.ResourceRef{{APIVersion: "v1", Kind: "Pod", Namespace: "prod", Name: "catalog-api-657ccd4f9d-q2k84"}},
			BlastRadius:       "Runtime activity may indicate manual debugging or compromise.",
			Fixability:        core.FixabilityInformational,
			Status:            core.FindingOpen,
			CorrelationGroup:  "prod-catalog-runtime",
			RiskScore:         76,
			RemediationState:  "triage_required",
			RecommendedAction: "Verify actor and correlate with deployment window.",
			CreatedAt:         now.Add(-8 * time.Minute),
			UpdatedAt:         now.Add(-4 * time.Minute),
		},
	}
}

func TestFindingFilters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/findings?severity=critical", nil)
	res := httptest.NewRecorder()
	testServer().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var payload struct {
		Items []core.Finding `json:"items"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) != 1 {
		t.Fatalf("expected 1 critical finding, got %d", len(payload.Items))
	}
	if payload.Items[0].Severity != core.SeverityCritical {
		t.Fatalf("unexpected severity %s", payload.Items[0].Severity)
	}
}

func TestDashboardAggregation(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	res := httptest.NewRecorder()
	testServer().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var dashboard core.Dashboard
	if err := json.NewDecoder(res.Body).Decode(&dashboard); err != nil {
		t.Fatal(err)
	}
	if dashboard.TotalFindings != 4 {
		t.Fatalf("expected 4 findings, got %d", dashboard.TotalFindings)
	}
	if dashboard.OpenCritical != 1 {
		t.Fatalf("expected 1 open critical, got %d", dashboard.OpenCritical)
	}
	if dashboard.BundledEnginesOnline != 3 {
		t.Fatalf("expected 3 bundled engines online, got %d", dashboard.BundledEnginesOnline)
	}
}

func TestCreatePlanUsesTypedActionsOnly(t *testing.T) {
	body := bytes.NewBufferString(`{"findingId":"finding-public-rbac-image","requestedBy":"platform-sre"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/remediation-plans", body)
	res := httptest.NewRecorder()
	testServer().ServeHTTP(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", res.Code, res.Body.String())
	}
	var plan core.RemediationPlan
	if err := json.NewDecoder(res.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("expected one typed action, got %d", len(plan.Actions))
	}
	actionType := plan.Actions[0].Type
	if strings.Contains(actionType, "shell") || strings.Contains(actionType, "kubectl") {
		t.Fatalf("unsafe action type %q", actionType)
	}
	if !plan.ApprovalPolicy.Required {
		t.Fatal("critical human-only remediation must require approval")
	}
}

func TestApprovalTransitionCreatesAuditEvent(t *testing.T) {
	handler := testServer()
	createBody := bytes.NewBufferString(`{"findingId":"finding-missing-probes-pdb","requestedBy":"platform-sre"}`)
	createReq := httptest.NewRequest(http.MethodPost, "/api/remediation-plans", createBody)
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRes.Code, createRes.Body.String())
	}
	var plan core.RemediationPlan
	if err := json.NewDecoder(createRes.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}

	approveBody := bytes.NewBufferString(`{"actor":"sre-lead","reason":"probe path confirmed in staging"}`)
	approveReq := httptest.NewRequest(http.MethodPost, "/api/approvals/approval-"+plan.ID+"/approve", approveBody)
	approveRes := httptest.NewRecorder()
	handler.ServeHTTP(approveRes, approveReq)
	if approveRes.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", approveRes.Code, approveRes.Body.String())
	}

	auditReq := httptest.NewRequest(http.MethodGet, "/api/audit-events", nil)
	auditRes := httptest.NewRecorder()
	handler.ServeHTTP(auditRes, auditReq)
	var auditPayload struct {
		Items []core.AuditEvent `json:"items"`
	}
	if err := json.NewDecoder(auditRes.Body).Decode(&auditPayload); err != nil {
		t.Fatal(err)
	}
	if len(auditPayload.Items) < 2 {
		t.Fatalf("expected plan and approval audit events, got %d", len(auditPayload.Items))
	}
	if auditPayload.Items[0].Action != "approval.approved" {
		t.Fatalf("expected latest audit to be approval.approved, got %s", auditPayload.Items[0].Action)
	}
}

func TestModelProviderRejectsInlineSecrets(t *testing.T) {
	body := bytes.NewBufferString(`{"providers":[{"name":"primary","type":"openai-compatible","model":"gpt-5","apiKey":"leaked"}]}`)
	req := httptest.NewRequest(http.MethodPut, "/api/settings/model-providers", body)
	res := httptest.NewRecorder()
	testServer().ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected strict decoder to reject inline apiKey, got %d", res.Code)
	}
}
