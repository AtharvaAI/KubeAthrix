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
	repo := store.NewMemoryStore(store.WithClock(func() time.Time { return fixed }), store.WithDemoData())
	return httpapi.NewServer(repo, httpapi.Config{DevAuthEnabled: true}).Routes()
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
