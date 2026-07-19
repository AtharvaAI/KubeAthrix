package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/auth"
	"github.com/atharvaai/kubeathrix/services/api/internal/cluster"
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
	return httpapi.NewServer(repo, httpapi.Config{InsecureDevAuth: true, AllowMemoryWorkflows: true}).Routes()
}

func jsonRequest(method, path string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, path, body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", fmt.Sprintf("test-key-%08d", testRequestSequence.Add(1)))
	return request
}

var testRequestSequence atomic.Uint64

type recordingProviderSecretWriter struct {
	namespace string
	name      string
	key       string
	value     []byte
}

func (w *recordingProviderSecretWriter) Upsert(_ context.Context, namespace, name, key string, value []byte) error {
	w.namespace, w.name, w.key = namespace, name, key
	w.value = append([]byte(nil), value...)
	return nil
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

func TestEmptyCollectionEndpointsReturnArrays(t *testing.T) {
	handler := httpapi.NewServer(
		store.NewMemoryStore(store.WithIntegrations(nil)),
		httpapi.Config{InsecureDevAuth: true, AllowMemoryWorkflows: true},
	).Routes()
	for _, path := range []string{"/api/findings", "/api/exceptions", "/api/audit-events", "/api/integrations"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
			}
			var payload struct {
				Items json.RawMessage `json:"items"`
			}
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if string(payload.Items) != "[]" {
				t.Fatalf("items must be an empty JSON array, got %s", payload.Items)
			}
		})
	}
}

func TestFindingPaginationSortingAndStructuredFilters(t *testing.T) {
	handler := testServer()
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/findings?namespace=payments&kind=Deployment&minRisk=80&sort=title&order=asc&limit=1", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", first.Code, first.Body.String())
	}
	var page core.FindingListResponse
	if err := json.NewDecoder(first.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("unexpected filtered page: %#v", page)
	}

	all := httptest.NewRecorder()
	handler.ServeHTTP(all, httptest.NewRequest(http.MethodGet, "/api/findings?limit=2&sort=updated&order=desc", nil))
	if err := json.NewDecoder(all.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 4 || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("unexpected first page: %#v", page)
	}
	next := httptest.NewRecorder()
	handler.ServeHTTP(next, httptest.NewRequest(http.MethodGet, "/api/findings?limit=2&sort=updated&order=desc&cursor="+page.NextCursor, nil))
	var second core.FindingListResponse
	if err := json.NewDecoder(next.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 2 || second.Items[0].ID == page.Items[0].ID {
		t.Fatalf("cursor did not advance: %#v", second)
	}
}

func TestFindingLifecycleAndExceptionAudit(t *testing.T) {
	handler := testServer()
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, jsonRequest(http.MethodPatch, "/api/findings/finding-namespace-quota/status", bytes.NewBufferString(`{"status":"in_review","reason":"triage owner assigned"}`)))
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("status transition failed: %d %s", statusResponse.Code, statusResponse.Body.String())
	}

	exceptionResponse := httptest.NewRecorder()
	handler.ServeHTTP(exceptionResponse, jsonRequest(http.MethodPost, "/api/exceptions", bytes.NewBufferString(`{"scope":"finding-namespace-quota","reason":"approved lab exception","expiresAt":"2026-07-09T12:00:00Z"}`)))
	if exceptionResponse.Code != http.StatusCreated {
		t.Fatalf("exception creation failed: %d %s", exceptionResponse.Code, exceptionResponse.Body.String())
	}
	var exception core.Exception
	if err := json.NewDecoder(exceptionResponse.Body).Decode(&exception); err != nil {
		t.Fatal(err)
	}
	if exception.Owner == "" || exception.Status != "active" {
		t.Fatalf("exception lacks derived owner/state: %#v", exception)
	}

	findingResponse := httptest.NewRecorder()
	handler.ServeHTTP(findingResponse, httptest.NewRequest(http.MethodGet, "/api/findings/finding-namespace-quota", nil))
	var finding core.Finding
	if err := json.NewDecoder(findingResponse.Body).Decode(&finding); err != nil {
		t.Fatal(err)
	}
	if finding.Status != core.FindingSuppressed {
		t.Fatalf("finding was not suppressed: %#v", finding)
	}

	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, httptest.NewRequest(http.MethodDelete, "/api/exceptions/"+exception.ID, nil))
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("exception deletion failed: %d %s", deleteResponse.Code, deleteResponse.Body.String())
	}
}

func TestMetricsEndpointIsAuthenticatedAndPrometheusFormatted(t *testing.T) {
	handler := testServer()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/health", nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/metrics", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "kubeathrix_http_requests_total") {
		t.Fatalf("unexpected metrics response: %d %s", response.Code, response.Body.String())
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
	if dashboard.PendingApprovals != 0 {
		t.Fatalf("expected no pending approvals before a plan is requested, got %d", dashboard.PendingApprovals)
	}
}

func TestDashboardCountsOnlyOpenApprovalRequests(t *testing.T) {
	handler := testServer()

	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, jsonRequest(http.MethodPost, "/api/remediation-plans", bytes.NewBufferString(`{"findingId":"finding-public-rbac-image"}`)))
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("expected create plan 201, got %d: %s", createResponse.Code, createResponse.Body.String())
	}
	var plan core.RemediationPlan
	if err := json.NewDecoder(createResponse.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}

	pendingResponse := httptest.NewRecorder()
	handler.ServeHTTP(pendingResponse, httptest.NewRequest(http.MethodGet, "/api/dashboard", nil))
	var pending core.Dashboard
	if err := json.NewDecoder(pendingResponse.Body).Decode(&pending); err != nil {
		t.Fatal(err)
	}
	if pending.PendingApprovals != 1 {
		t.Fatalf("expected one pending approval after plan creation, got %d", pending.PendingApprovals)
	}

	approveResponse := httptest.NewRecorder()
	handler.ServeHTTP(approveResponse, jsonRequest(http.MethodPost, "/api/approvals/approval-"+plan.ID+"/approve", bytes.NewBufferString(`{"reason":"reviewed"}`)))
	if approveResponse.Code != http.StatusOK {
		t.Fatalf("expected approval 200, got %d: %s", approveResponse.Code, approveResponse.Body.String())
	}

	approvedResponse := httptest.NewRecorder()
	handler.ServeHTTP(approvedResponse, httptest.NewRequest(http.MethodGet, "/api/dashboard", nil))
	var approved core.Dashboard
	if err := json.NewDecoder(approvedResponse.Body).Decode(&approved); err != nil {
		t.Fatal(err)
	}
	if approved.PendingApprovals != 0 {
		t.Fatalf("expected no pending approvals after approval, got %d", approved.PendingApprovals)
	}
}

func TestCreatePlanUsesTypedActionsOnly(t *testing.T) {
	body := bytes.NewBufferString(`{"findingId":"finding-public-rbac-image"}`)
	req := jsonRequest(http.MethodPost, "/api/remediation-plans", body)
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

func TestCreatePlanCanAttachAIAnalysisWithoutChangingActions(t *testing.T) {
	fixed := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	repo := store.NewMemoryStore(store.WithClock(func() time.Time { return fixed }), store.WithFindings(testFindings(fixed)))
	handler := httpapi.NewServer(repo, httpapi.Config{InsecureDevAuth: true, AllowMemoryWorkflows: true, AIAdvisor: fakeAIAdvisor{now: fixed}}).Routes()

	request := jsonRequest(http.MethodPost, "/api/remediation-plans", bytes.NewBufferString(`{"findingId":"finding-namespace-quota"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	var plan core.RemediationPlan
	if err := json.NewDecoder(response.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}
	if plan.AI == nil {
		t.Fatal("expected AI decision support on the plan")
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Type != "apply_resource_governance" {
		t.Fatalf("AI advisor must not replace typed actions: %#v", plan.Actions)
	}
}

func TestPlanPreviewDiffAndEvidenceBundle(t *testing.T) {
	handler := testServer()
	previewBody := bytes.NewBufferString(`{"findingId":"finding-namespace-quota"}`)
	previewReq := jsonRequest(http.MethodPost, "/api/remediation-plans/preview", previewBody)
	previewRes := httptest.NewRecorder()
	handler.ServeHTTP(previewRes, previewReq)
	if previewRes.Code != http.StatusOK {
		t.Fatalf("expected preview 200, got %d: %s", previewRes.Code, previewRes.Body.String())
	}
	var preview core.RemediationPreview
	if err := json.NewDecoder(previewRes.Body).Decode(&preview); err != nil {
		t.Fatal(err)
	}
	if preview.PromptEvidenceHash == "" || len(preview.EvidenceCitations) == 0 {
		t.Fatal("preview must include evidence hash and citations")
	}

	createBody := bytes.NewBufferString(`{"findingId":"finding-namespace-quota"}`)
	createReq := jsonRequest(http.MethodPost, "/api/remediation-plans", createBody)
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", createRes.Code, createRes.Body.String())
	}
	var plan core.RemediationPlan
	if err := json.NewDecoder(createRes.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}
	diffReq := httptest.NewRequest(http.MethodGet, "/api/remediation-plans/"+plan.ID+"/diff", nil)
	diffRes := httptest.NewRecorder()
	handler.ServeHTTP(diffRes, diffReq)
	if diffRes.Code != http.StatusOK {
		t.Fatalf("expected diff 200, got %d: %s", diffRes.Code, diffRes.Body.String())
	}
	var diff core.RemediationDiff
	if err := json.NewDecoder(diffRes.Body).Decode(&diff); err != nil {
		t.Fatal(err)
	}
	if len(diff.Manifests) == 0 || diff.Manifests[0].WriteMode == "" {
		t.Fatal("diff must expose planned manifests and write mode")
	}
	executeReq := jsonRequest(http.MethodPost, "/api/remediation-plans/"+plan.ID+"/execute", bytes.NewBufferString(`{}`))
	executeRes := httptest.NewRecorder()
	handler.ServeHTTP(executeRes, executeReq)
	if executeRes.Code != http.StatusAccepted {
		t.Fatalf("expected execute 202, got %d: %s", executeRes.Code, executeRes.Body.String())
	}
	bundleReq := httptest.NewRequest(http.MethodGet, "/api/evidence-bundles/"+plan.ID, nil)
	bundleRes := httptest.NewRecorder()
	handler.ServeHTTP(bundleRes, bundleReq)
	if bundleRes.Code != http.StatusOK {
		t.Fatalf("expected evidence bundle 200, got %d: %s", bundleRes.Code, bundleRes.Body.String())
	}
	var bundle core.EvidenceBundle
	if err := json.NewDecoder(bundleRes.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Summary["plans"] != 1 || bundle.Summary["auditEvents"] == 0 {
		t.Fatalf("expected plan and audit evidence, got %#v", bundle.Summary)
	}
}

type fakeAIAdvisor struct {
	now time.Time
}

func (a fakeAIAdvisor) Analyze(_ context.Context, _ core.Finding, _ core.RemediationPlan) (core.AIAnalysis, error) {
	return core.AIAnalysis{
		Provider:          "test",
		Model:             "stub",
		Mode:              "assistive",
		Summary:           "AI summary",
		RootCause:         "AI root cause",
		Impact:            "AI impact",
		RecommendedAction: "Use the typed action.",
		Confidence:        "high",
		SafetyNotes:       []string{"No direct mutation."},
		AutonomousPolicy:  "Typed actions only.",
		GeneratedAt:       a.now,
	}, nil
}

func TestExecuteRequiresApprovalForGatedPlan(t *testing.T) {
	handler := testServer()
	createBody := bytes.NewBufferString(`{"findingId":"finding-missing-probes-pdb"}`)
	createReq := jsonRequest(http.MethodPost, "/api/remediation-plans", createBody)
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRes.Code, createRes.Body.String())
	}
	var plan core.RemediationPlan
	if err := json.NewDecoder(createRes.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}
	executeReq := jsonRequest(http.MethodPost, "/api/remediation-plans/"+plan.ID+"/execute", bytes.NewBufferString(`{}`))
	executeRes := httptest.NewRecorder()
	handler.ServeHTTP(executeRes, executeReq)
	if executeRes.Code != http.StatusBadRequest {
		t.Fatalf("expected gated execute 400, got %d: %s", executeRes.Code, executeRes.Body.String())
	}
}

func TestFindingGroupingAndIntegrationHealth(t *testing.T) {
	handler := testServer()
	groupReq := httptest.NewRequest(http.MethodGet, "/api/findings?groupBy=namespace", nil)
	groupRes := httptest.NewRecorder()
	handler.ServeHTTP(groupRes, groupReq)
	if groupRes.Code != http.StatusOK {
		t.Fatalf("expected grouped findings 200, got %d: %s", groupRes.Code, groupRes.Body.String())
	}
	var grouped core.FindingListResponse
	if err := json.NewDecoder(groupRes.Body).Decode(&grouped); err != nil {
		t.Fatal(err)
	}
	if len(grouped.Groups) == 0 {
		t.Fatal("expected grouped finding response")
	}
	healthReq := httptest.NewRequest(http.MethodGet, "/api/integrations/Kyverno/health", nil)
	healthRes := httptest.NewRecorder()
	handler.ServeHTTP(healthRes, healthReq)
	if healthRes.Code != http.StatusOK {
		t.Fatalf("expected health 200, got %d: %s", healthRes.Code, healthRes.Body.String())
	}
	var health core.IntegrationHealth
	if err := json.NewDecoder(healthRes.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health.Health != "healthy" || len(health.Permissions) == 0 {
		t.Fatalf("unexpected integration health %#v", health)
	}
}

func TestApprovalTransitionCreatesAuditEvent(t *testing.T) {
	handler := testServer()
	createBody := bytes.NewBufferString(`{"findingId":"finding-missing-probes-pdb"}`)
	createReq := jsonRequest(http.MethodPost, "/api/remediation-plans", createBody)
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRes.Code, createRes.Body.String())
	}
	var plan core.RemediationPlan
	if err := json.NewDecoder(createRes.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}

	approveBody := bytes.NewBufferString(`{"reason":"probe path confirmed in staging"}`)
	approveReq := jsonRequest(http.MethodPost, "/api/approvals/approval-"+plan.ID+"/approve", approveBody)
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
	runRequest := httptest.NewRequest(http.MethodGet, "/api/remediation-runs/run-"+plan.ID, nil)
	runResponse := httptest.NewRecorder()
	handler.ServeHTTP(runResponse, runRequest)
	if runResponse.Code != http.StatusOK {
		t.Fatalf("expected run 200, got %d: %s", runResponse.Code, runResponse.Body.String())
	}
	var run core.RemediationRun
	if err := json.NewDecoder(runResponse.Body).Decode(&run); err != nil {
		t.Fatal(err)
	}
	if run.State == core.RunSucceeded || run.State == core.RunRunning || run.State == core.RunDryRunPassed {
		t.Fatalf("approval must not imply cluster execution or validation, got state %q", run.State)
	}
}

func TestModelProviderRejectsInlineSecrets(t *testing.T) {
	body := bytes.NewBufferString(`{"providers":[{"name":"primary","type":"openai-compatible","model":"gpt-5","apiKey":"leaked"}]}`)
	req := jsonRequest(http.MethodPut, "/api/settings/model-providers", body)
	res := httptest.NewRecorder()
	testServer().ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected strict decoder to reject inline apiKey, got %d", res.Code)
	}
}

func TestModelProviderSecretWriteIsAuditedWithoutEchoingValue(t *testing.T) {
	repo := store.NewMemoryStore()
	writer := &recordingProviderSecretWriter{}
	handler := httpapi.NewServer(repo, httpapi.Config{
		InsecureDevAuth: true, AllowMemoryWorkflows: true,
		ProviderSecrets: writer, ProviderSecretNS: "kubeathrix",
	}).Routes()
	request := jsonRequest(http.MethodPut, "/api/settings/model-providers/primary/secret", bytes.NewBufferString(`{"secretName":"provider-primary","key":"api-key","value":"top-secret-value"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "top-secret-value") {
		t.Fatal("secret value must never be returned")
	}
	if writer.namespace != "kubeathrix" || writer.name != "provider-primary" || writer.key != "api-key" || string(writer.value) != "top-secret-value" {
		t.Fatalf("unexpected secret write: %#v", writer)
	}
	events, err := repo.ListAuditEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "model-provider.secret.rotated" || events[0].Subject != "primary" || strings.Contains(events[0].Message, "top-secret-value") {
		t.Fatalf("unexpected audit event: %#v", events)
	}
}

func TestDashboardReturnsAPIBackedAgentStatus(t *testing.T) {
	repo := store.NewMemoryStore()
	if err := repo.RecordAuditEvent(context.Background(), core.AuditEvent{Actor: "operator", Action: "plan.created", Subject: "plan-1", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	handler := httpapi.NewServer(repo, httpapi.Config{
		InsecureDevAuth: true, AllowMemoryWorkflows: true,
		AutonomyMode: "guarded-auto", RuntimeIdentity: "sa/kubeathrix-api",
	}).Routes()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/dashboard", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var dashboard core.Dashboard
	if err := json.NewDecoder(response.Body).Decode(&dashboard); err != nil {
		t.Fatal(err)
	}
	if dashboard.Agent.AutonomyMode != "guarded-auto" || dashboard.Agent.RuntimeIdentity != "sa/kubeathrix-api" || dashboard.Agent.ActionsLast24H != 1 || dashboard.Agent.UptimeSeconds < 0 {
		t.Fatalf("unexpected agent status: %#v", dashboard.Agent)
	}
}

func TestChaosPreflightRunIsPersistedAndAudited(t *testing.T) {
	repo := store.NewMemoryStore()
	manager := cluster.NewChaosManager(repo, cluster.NewChaosPreflightRunner("sandbox"), false, nil)
	handler := httpapi.NewServer(repo, httpapi.Config{InsecureDevAuth: true, AllowMemoryWorkflows: true, ChaosManager: manager}).Routes()
	body := bytes.NewBufferString(`{"manifest":"apiVersion: chaos-mesh.org/v1alpha1\nkind: NetworkChaos\nmetadata:\n  name: latency\n  namespace: sandbox\nspec:\n  action: delay\n  direction: to\n  mode: one\n  selector:\n    namespaces: [sandbox]\n    labelSelectors:\n      app: checkout\n  delay:\n    latency: 100ms\n  duration: 60s"}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, jsonRequest(http.MethodPost, "/api/experiments/custom/runs", body))
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	var run core.ChaosExperimentRun
	if err := json.NewDecoder(response.Body).Decode(&run); err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosPreflightValidated || run.RequestedBy == "" || run.Version != 1 {
		t.Fatalf("unexpected persisted preflight: %#v", run)
	}
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/experiment-runs/"+run.ID, nil))
	if get.Code != http.StatusOK {
		t.Fatalf("expected persisted run 200, got %d: %s", get.Code, get.Body.String())
	}
	events, err := repo.ListAuditEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "chaos.preflight.validated" {
		t.Fatalf("unexpected chaos audit events: %#v", events)
	}
}

func TestProtectedRoutesFailClosedAndProbesRemainAvailable(t *testing.T) {
	repo := store.NewMemoryStore()
	handler := httpapi.NewServer(repo, httpapi.Config{
		Authenticator:        auth.StaticVerifier{Principal: auth.DevelopmentPrincipal()},
		AllowMemoryWorkflows: true,
	}).Routes()

	protected := httptest.NewRecorder()
	handler.ServeHTTP(protected, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("expected protected route to return 401, got %d: %s", protected.Code, protected.Body.String())
	}
	if protected.Header().Get("X-Request-ID") == "" || protected.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("expected request ID and security headers on authentication failure")
	}

	for _, path := range []string{"/health/live", "/health/ready"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("expected public probe %s to return 200, got %d", path, response.Code)
		}
	}
}

func TestRoleAndNamespaceScopesAndDerivedActor(t *testing.T) {
	fixed := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	repo := store.NewMemoryStore(store.WithClock(func() time.Time { return fixed }), store.WithFindings(testFindings(fixed)))
	principal := auth.Principal{
		Subject:     "user-42",
		DisplayName: "platform-operator",
		Roles:       map[auth.Role]struct{}{auth.RoleOperator: {}},
		Namespaces:  map[string]struct{}{"payments": {}},
		Clusters:    map[string]struct{}{},
	}
	handler := httpapi.NewServer(repo, httpapi.Config{
		Authenticator:        auth.StaticVerifier{Principal: principal},
		ClusterID:            "cluster-a",
		AllowMemoryWorkflows: true,
	}).Routes()
	authorized := func(request *http.Request) *http.Request {
		request.Header.Set("Authorization", "Bearer test-token")
		return request
	}

	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, authorized(httptest.NewRequest(http.MethodGet, "/api/findings", nil)))
	if listResponse.Code != http.StatusOK {
		t.Fatalf("expected scoped finding list 200, got %d: %s", listResponse.Code, listResponse.Body.String())
	}
	var list core.FindingListResponse
	if err := json.NewDecoder(listResponse.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Resources[0].Namespace != "payments" {
		t.Fatalf("namespace scope leaked findings: %#v", list.Items)
	}

	dashboardResponse := httptest.NewRecorder()
	handler.ServeHTTP(dashboardResponse, authorized(httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)))
	if dashboardResponse.Code != http.StatusForbidden {
		t.Fatalf("expected cluster dashboard to require cluster scope, got %d", dashboardResponse.Code)
	}

	impersonationResponse := httptest.NewRecorder()
	impersonationRequest := jsonRequest(http.MethodPost, "/api/remediation-plans", bytes.NewBufferString(`{"findingId":"finding-public-rbac-image","requestedBy":"someone-else"}`))
	handler.ServeHTTP(impersonationResponse, authorized(impersonationRequest))
	if impersonationResponse.Code != http.StatusBadRequest {
		t.Fatalf("expected client requester field to be rejected, got %d: %s", impersonationResponse.Code, impersonationResponse.Body.String())
	}

	createResponse := httptest.NewRecorder()
	createRequest := jsonRequest(http.MethodPost, "/api/remediation-plans", bytes.NewBufferString(`{"findingId":"finding-public-rbac-image"}`))
	handler.ServeHTTP(createResponse, authorized(createRequest))
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("expected scoped operator to create a plan, got %d: %s", createResponse.Code, createResponse.Body.String())
	}
	events, err := repo.ListAuditEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Actor != principal.Actor() {
		t.Fatalf("expected actor to come from authenticated principal, got %#v", events)
	}
}

func TestViewerCannotCreatePlans(t *testing.T) {
	fixed := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	repo := store.NewMemoryStore(store.WithClock(func() time.Time { return fixed }), store.WithFindings(testFindings(fixed)))
	principal := auth.Principal{
		Subject:  "read-only-user",
		Roles:    map[auth.Role]struct{}{auth.RoleViewer: {}},
		Clusters: map[string]struct{}{"cluster-a": {}},
	}
	handler := httpapi.NewServer(repo, httpapi.Config{Authenticator: auth.StaticVerifier{Principal: principal}, ClusterID: "cluster-a", AllowMemoryWorkflows: true}).Routes()
	request := jsonRequest(http.MethodPost, "/api/remediation-plans", bytes.NewBufferString(`{"findingId":"finding-namespace-quota"}`))
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected viewer plan creation to return 403, got %d: %s", response.Code, response.Body.String())
	}
}

func TestRequestLimitsRateLimitsAndErrorEnvelope(t *testing.T) {
	handler := httpapi.NewServer(store.NewMemoryStore(), httpapi.Config{
		InsecureDevAuth:      true,
		AllowMemoryWorkflows: true,
		MaxRequestBytes:      32,
		RateLimitPerMinute:   2,
	}).Routes()

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", first.Code)
	}

	tooLargeRequest := jsonRequest(http.MethodPost, "/api/remediation-plans", bytes.NewBufferString(`{"findingId":"this-value-is-far-longer-than-the-request-limit"}`))
	tooLarge := httptest.NewRecorder()
	handler.ServeHTTP(tooLarge, tooLargeRequest)
	if tooLarge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected request limit 413, got %d: %s", tooLarge.Code, tooLarge.Body.String())
	}
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"requestId"`
		} `json:"error"`
	}
	if err := json.NewDecoder(tooLarge.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != "request_too_large" || envelope.Error.RequestID == "" {
		t.Fatalf("unexpected error envelope: %#v", envelope)
	}

	rateLimited := httptest.NewRecorder()
	handler.ServeHTTP(rateLimited, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if rateLimited.Code != http.StatusTooManyRequests {
		t.Fatalf("expected third request to be rate limited, got %d: %s", rateLimited.Code, rateLimited.Body.String())
	}
}

type recordingWorkflowClient struct {
	createdPlanID string
	createdActor  string
	run           core.RemediationRun
}

func (c *recordingWorkflowClient) ListFindings(context.Context) ([]core.Finding, error) {
	return nil, nil
}

func (c *recordingWorkflowClient) GetFinding(context.Context, string) (core.Finding, error) {
	return core.Finding{}, store.ErrNotFound
}

func (c *recordingWorkflowClient) ListRuns(context.Context) ([]core.RemediationRun, error) {
	if c.run.ID == "" {
		return nil, nil
	}
	return []core.RemediationRun{c.run}, nil
}

func (c *recordingWorkflowClient) RenderDiff(_ context.Context, plan core.RemediationPlan) (core.RemediationDiff, error) {
	return store.BuildRemediationDiff(plan), nil
}

func (c *recordingWorkflowClient) Health(context.Context) error { return nil }

func (c *recordingWorkflowClient) CreatePlan(_ context.Context, _ core.Finding, plan core.RemediationPlan, actor string) error {
	c.createdPlanID = plan.ID
	c.createdActor = actor
	return nil
}

func (c *recordingWorkflowClient) DecideApproval(_ context.Context, approvalID string, decision core.ApprovalStatus, actor, reason string) (core.ApprovalRequest, error) {
	return core.ApprovalRequest{ID: approvalID, Status: decision, Approver: actor, DecisionReason: reason}, nil
}

func (c *recordingWorkflowClient) RequestExecution(_ context.Context, planID, _ string) (core.RemediationRun, error) {
	return core.RemediationRun{ID: "run-" + planID, PlanID: planID, State: core.RunExecutionRequested}, nil
}

func (c *recordingWorkflowClient) RequestRollback(_ context.Context, runID, _ string) (core.RemediationRun, error) {
	run := c.run
	run.ID = runID
	run.State = core.RunRollbackRequested
	return run, nil
}

func (c *recordingWorkflowClient) GetRun(_ context.Context, runID string) (core.RemediationRun, error) {
	if c.run.ID == runID {
		return c.run, nil
	}
	return core.RemediationRun{}, store.ErrNotFound
}

func TestPlanCreationAndRunReadsUseKubernetesWorkflowClient(t *testing.T) {
	fixed := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	repo := store.NewMemoryStore(store.WithClock(func() time.Time { return fixed }), store.WithFindings(testFindings(fixed)))
	workflow := &recordingWorkflowClient{}
	handler := httpapi.NewServer(repo, httpapi.Config{InsecureDevAuth: true, WorkflowClient: workflow}).Routes()
	create := jsonRequest(http.MethodPost, "/api/remediation-plans", bytes.NewBufferString(`{"findingId":"finding-namespace-quota"}`))
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, create)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("expected plan create 201, got %d: %s", createResponse.Code, createResponse.Body.String())
	}
	var plan core.RemediationPlan
	if err := json.NewDecoder(createResponse.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}
	if workflow.createdPlanID != plan.ID || workflow.createdActor != auth.DevelopmentPrincipal().Actor() {
		t.Fatalf("plan was not persisted with derived actor: %#v", workflow)
	}
	workflow.run = core.RemediationRun{
		ID: "run-" + plan.ID, PlanID: plan.ID, State: core.RunSucceeded,
		ValidationResult: "cluster object read back and source finding no longer reproduced",
	}
	runResponse := httptest.NewRecorder()
	handler.ServeHTTP(runResponse, httptest.NewRequest(http.MethodGet, "/api/remediation-runs/"+workflow.run.ID, nil))
	if runResponse.Code != http.StatusOK {
		t.Fatalf("expected CRD-backed run 200, got %d: %s", runResponse.Code, runResponse.Body.String())
	}
	var run core.RemediationRun
	if err := json.NewDecoder(runResponse.Body).Decode(&run); err != nil {
		t.Fatal(err)
	}
	if run.State != core.RunSucceeded || run.ValidationResult != workflow.run.ValidationResult {
		t.Fatalf("API did not use authoritative workflow state: %#v", run)
	}
	rollbackRequest := jsonRequest(http.MethodPost, "/api/remediation-runs/"+workflow.run.ID+"/rollback", bytes.NewBufferString(`{}`))
	rollbackResponse := httptest.NewRecorder()
	handler.ServeHTTP(rollbackResponse, rollbackRequest)
	if rollbackResponse.Code != http.StatusAccepted {
		t.Fatalf("expected rollback request 202, got %d: %s", rollbackResponse.Code, rollbackResponse.Body.String())
	}
	var rollback core.RemediationRun
	if err := json.NewDecoder(rollbackResponse.Body).Decode(&rollback); err != nil {
		t.Fatal(err)
	}
	if rollback.State != core.RunRollbackRequested {
		t.Fatalf("rollback endpoint claimed an unsupported state: %#v", rollback)
	}
}

func TestPlanCreationIsIdempotentAndDetectsKeyReuse(t *testing.T) {
	fixed := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	repo := store.NewMemoryStore(store.WithClock(func() time.Time { return fixed }), store.WithFindings(testFindings(fixed)))
	handler := httpapi.NewServer(repo, httpapi.Config{InsecureDevAuth: true, AllowMemoryWorkflows: true}).Routes()
	create := func(findingID string) (int, core.RemediationPlan) {
		request := jsonRequest(http.MethodPost, "/api/remediation-plans", bytes.NewBufferString(`{"findingId":"`+findingID+`"}`))
		request.Header.Set("Idempotency-Key", "stable-request-key")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var plan core.RemediationPlan
		if response.Code == http.StatusCreated {
			if err := json.NewDecoder(response.Body).Decode(&plan); err != nil {
				t.Fatal(err)
			}
		}
		return response.Code, plan
	}
	firstStatus, first := create("finding-namespace-quota")
	secondStatus, second := create("finding-namespace-quota")
	if firstStatus != http.StatusCreated || secondStatus != http.StatusCreated || first.ID == "" || first.ID != second.ID {
		t.Fatalf("idempotent retry created different results: %d %#v / %d %#v", firstStatus, first, secondStatus, second)
	}
	events, err := repo.ListAuditEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("idempotent retry must not duplicate audit events, got %d", len(events))
	}
	conflictStatus, _ := create("finding-missing-probes-pdb")
	if conflictStatus != http.StatusConflict {
		t.Fatalf("expected reused key with different request to return 409, got %d", conflictStatus)
	}
}
