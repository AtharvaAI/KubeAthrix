package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/pkg/actioncatalog"
	"github.com/atharvaai/kubeathrix/services/api/internal/adapters"
	"github.com/atharvaai/kubeathrix/services/api/internal/auth"
	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/httpapi"
	"github.com/atharvaai/kubeathrix/services/api/internal/managedresources"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
)

type staticManagedResourceSource struct {
	snapshot managedresources.Snapshot
	err      error
}

type staticAdapterManager struct{ collection adapters.Collection }

func (s staticAdapterManager) Collect(context.Context) adapters.Collection { return s.collection }

func (s staticManagedResourceSource) Discover(context.Context) (managedresources.Snapshot, error) {
	return s.snapshot, s.err
}

func TestManagedResourcesDisabledReturnsExplicitEmptyState(t *testing.T) {
	handler := httpapi.NewServer(store.NewMemoryStore(), httpapi.Config{
		InsecureDevAuth:      true,
		AllowMemoryWorkflows: true,
	}).Routes()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/managed-resources", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Enabled       bool                            `json:"enabled"`
		Resources     []managedresources.Resource     `json:"resources"`
		Relationships []managedresources.Relationship `json:"relationships"`
		Findings      []core.Finding                  `json:"findings"`
		Warnings      []managedresources.Warning      `json:"warnings"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Enabled || payload.Resources == nil || payload.Relationships == nil || payload.Findings == nil || payload.Warnings == nil {
		t.Fatalf("disabled response must use explicit empty arrays: %#v", payload)
	}
}

func TestManagedResourcesHonorNamespaceScopeAndHideClusterWarnings(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	paymentRef := managedresources.ResourceReference{APIVersion: "iam.example.io/v1", Kind: "Role", Namespace: "payments", Name: "reader"}
	policyRef := managedresources.ResourceReference{APIVersion: "iam.example.io/v1", Kind: "Policy", Namespace: "payments", Name: "read-only"}
	platformRef := managedresources.ResourceReference{APIVersion: "iam.example.io/v1", Kind: "Role", Namespace: "platform", Name: "admin"}
	snapshot := managedresources.Snapshot{
		ObservedAt: now,
		Resources: []managedresources.Resource{
			{ID: "payments-role", APIVersion: paymentRef.APIVersion, Kind: paymentRef.Kind, Namespace: paymentRef.Namespace, Name: paymentRef.Name},
			{ID: "payments-policy", APIVersion: policyRef.APIVersion, Kind: policyRef.Kind, Namespace: policyRef.Namespace, Name: policyRef.Name},
			{ID: "platform-role", APIVersion: platformRef.APIVersion, Kind: platformRef.Kind, Namespace: platformRef.Namespace, Name: platformRef.Name},
			{ID: "cluster-policy", APIVersion: "iam.example.io/v1", Kind: "ClusterPolicy", Name: "organization"},
		},
		Relationships: []managedresources.Relationship{
			{From: paymentRef, To: policyRef, Type: managedresources.RelationshipReference},
			{From: paymentRef, To: platformRef, Type: managedresources.RelationshipReference},
		},
		Findings: []core.Finding{
			{ID: "payments-finding", Resources: []core.ResourceRef{{APIVersion: paymentRef.APIVersion, Kind: paymentRef.Kind, Namespace: paymentRef.Namespace, Name: paymentRef.Name}}},
			{ID: "platform-finding", Resources: []core.ResourceRef{{APIVersion: platformRef.APIVersion, Kind: platformRef.Kind, Namespace: platformRef.Namespace, Name: platformRef.Name}}},
		},
		Warnings: []managedresources.Warning{{APIGroup: "iam.example.io", Version: "v1", Resource: "roles", Code: "forbidden", Message: "cluster detail"}},
	}
	principal := auth.Principal{
		Subject:    "payments-viewer",
		Roles:      map[auth.Role]struct{}{auth.RoleViewer: {}},
		Namespaces: map[string]struct{}{"payments": {}},
		Clusters:   map[string]struct{}{},
	}
	handler := httpapi.NewServer(store.NewMemoryStore(), httpapi.Config{
		Authenticator:        auth.StaticVerifier{Principal: principal},
		ClusterID:            "cluster-a",
		AllowMemoryWorkflows: true,
		ManagedResources:     staticManagedResourceSource{snapshot: snapshot},
	}).Routes()
	request := httptest.NewRequest(http.MethodGet, "/api/managed-resources", nil)
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Enabled       bool                            `json:"enabled"`
		Resources     []managedresources.Resource     `json:"resources"`
		Relationships []managedresources.Relationship `json:"relationships"`
		Findings      []core.Finding                  `json:"findings"`
		Warnings      []managedresources.Warning      `json:"warnings"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Enabled || len(payload.Resources) != 2 || payload.Resources[0].Namespace != "payments" || payload.Resources[1].Namespace != "payments" {
		t.Fatalf("namespace resource scope was not enforced: %#v", payload.Resources)
	}
	if len(payload.Relationships) != 1 || payload.Relationships[0].To.Namespace != "payments" {
		t.Fatalf("relationship scope leaked data: %#v", payload.Relationships)
	}
	if len(payload.Findings) != 1 || payload.Findings[0].ID != "payments-finding" {
		t.Fatalf("finding scope leaked data: %#v", payload.Findings)
	}
	if len(payload.Warnings) != 0 {
		t.Fatalf("cluster-wide warnings must be hidden from namespace viewers: %#v", payload.Warnings)
	}
}

func TestManagedFindingCreatesInternalApprovalOnlyPlan(t *testing.T) {
	finding := core.Finding{
		ID:                "managed-resource-iam-wildcard-action-1234",
		Source:            "managed-resource",
		Title:             "Managed IAM policy allows wildcard actions",
		Resources:         []core.ResourceRef{{APIVersion: "iam.example.io/v1", Kind: "Role", Namespace: "payments", Name: "reader"}},
		Fixability:        core.FixabilityHumanOnly,
		Status:            core.FindingOpen,
		RiskScore:         94,
		RecommendedAction: "Replace wildcard actions through the owning source with approval.",
	}
	handler := httpapi.NewServer(store.NewMemoryStore(), httpapi.Config{
		InsecureDevAuth:      true,
		AllowMemoryWorkflows: true,
		AdapterManager:       staticAdapterManager{collection: adapters.Collection{Findings: []core.Finding{finding}}},
	}).Routes()
	request := httptest.NewRequest(http.MethodPost, "/api/remediation-plans", bytes.NewBufferString(`{"findingId":"managed-resource-iam-wildcard-action-1234"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "managed-plan-test-0001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	var plan core.RemediationPlan
	if err := json.NewDecoder(response.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Type != actioncatalog.ManagedResourceReviewAction {
		t.Fatalf("managed finding selected an unsafe action: %#v", plan.Actions)
	}
	if plan.RiskTier != core.RiskTierC || !plan.ApprovalPolicy.Required || plan.ApprovalPolicy.Decision != core.ApprovalPending {
		t.Fatalf("managed plan must remain pending human approval: %#v", plan)
	}
}
