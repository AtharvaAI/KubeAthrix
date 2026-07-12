package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/atharvaai/kubeathrix/services/api/internal/auth"
	"github.com/atharvaai/kubeathrix/services/api/internal/cluster"
	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/httpapi"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestChaosHTTPLifecycleDerivesDistinctActorsAndAbortsOwnedResource(t *testing.T) {
	ctx := context.Background()
	pod := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "checkout-0", "namespace": "default", "labels": map[string]any{"app": "checkout"}},
		"status":   map[string]any{"phase": "Running", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}},
	}}
	networkGVR := schema.GroupVersionResource{Group: "chaos-mesh.org", Version: "v1alpha1", Resource: "networkchaos"}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		{Group: "", Version: "v1", Resource: "pods"}: "PodList",
		networkGVR: "NetworkChaosList",
	}, pod)
	dryRunCreates := 0
	client.PrependReactor("create", "networkchaos", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create, ok := action.(k8stesting.CreateAction)
		// The dynamic fake does not honor DryRun and would persist those two
		// validation creates. The real API server does not.
		if ok && dryRunCreates < 2 {
			dryRunCreates++
			return true, create.GetObject().DeepCopyObject(), nil
		}
		return false, nil, nil
	})

	repository := store.NewMemoryStore()
	manager := cluster.NewChaosManager(repository, cluster.NewChaosRunnerFromClient(client, nil), true, nil)
	operator := auth.Principal{Subject: "operator-1", DisplayName: "operator", Roles: map[auth.Role]struct{}{auth.RoleOperator: {}}, Namespaces: map[string]struct{}{"default": {}}, Clusters: map[string]struct{}{}}
	approver := auth.Principal{Subject: "approver-1", DisplayName: "approver", Roles: map[auth.Role]struct{}{auth.RoleApprover: {}}, Namespaces: map[string]struct{}{"default": {}}, Clusters: map[string]struct{}{}}
	verifier := tokenMapVerifier{principals: map[string]auth.Principal{"operator-token": operator, "approver-token": approver}}
	handler := httpapi.NewServer(repository, httpapi.Config{Authenticator: verifier, ClusterID: "cluster-a", AllowMemoryWorkflows: true, ChaosManager: manager}).Routes()

	manifest := "apiVersion: chaos-mesh.org/v1alpha1\nkind: NetworkChaos\nmetadata:\n  name: latency\n  namespace: default\nspec:\n  action: delay\n  direction: to\n  mode: one\n  selector:\n    namespaces: [default]\n    labelSelectors:\n      app: checkout\n  delay:\n    latency: 100ms\n  duration: 60s"
	requestRun := chaosRequest(http.MethodPost, "/api/experiments/custom/runs", map[string]string{"manifest": manifest}, "operator-token")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, requestRun)
	if created.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", created.Code, created.Body.String())
	}
	var run core.ChaosExperimentRun
	if err := json.NewDecoder(created.Body).Decode(&run); err != nil {
		t.Fatal(err)
	}
	if run.RequestedBy != operator.Actor() || run.Status != core.ChaosPendingApproval {
		t.Fatalf("request actor or state was not derived correctly: %#v", run)
	}

	selfApproval := httptest.NewRecorder()
	handler.ServeHTTP(selfApproval, chaosRequest(http.MethodPost, "/api/experiment-runs/"+run.ID+"/approve", map[string]string{"reason": "self"}, "operator-token"))
	if selfApproval.Code != http.StatusForbidden {
		t.Fatalf("operator without approver role should receive 403, got %d", selfApproval.Code)
	}
	approved := httptest.NewRecorder()
	handler.ServeHTTP(approved, chaosRequest(http.MethodPost, "/api/experiment-runs/"+run.ID+"/approve", map[string]string{"reason": "maintenance window"}, "approver-token"))
	if approved.Code != http.StatusOK {
		t.Fatalf("expected approval 200, got %d: %s", approved.Code, approved.Body.String())
	}
	executed := httptest.NewRecorder()
	handler.ServeHTTP(executed, chaosRequest(http.MethodPost, "/api/experiment-runs/"+run.ID+"/execute", nil, "operator-token"))
	if executed.Code != http.StatusAccepted {
		stored, _ := repository.GetChaosRun(ctx, run.ID)
		_, reconcileErr := manager.Get(ctx, run.ID)
		t.Fatalf("expected execute 202, got %d: %s; stored run: %#v; reconcile error: %v", executed.Code, executed.Body.String(), stored, reconcileErr)
	}
	aborted := httptest.NewRecorder()
	handler.ServeHTTP(aborted, chaosRequest(http.MethodPost, "/api/experiment-runs/"+run.ID+"/abort", map[string]string{"reason": "latency SLO"}, "operator-token"))
	if aborted.Code != http.StatusOK {
		t.Fatalf("expected abort 200, got %d: %s", aborted.Code, aborted.Body.String())
	}
	if err := json.NewDecoder(aborted.Body).Decode(&run); err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosAborted || run.AbortedBy != operator.Actor() {
		t.Fatalf("abort actor or state was not persisted: %#v", run)
	}
	if _, err := client.Resource(networkGVR).Namespace("default").Get(ctx, "latency", metav1.GetOptions{}); err == nil {
		t.Fatal("HTTP abort left the owned chaos resource behind")
	}

	selfRequested := httptest.NewRecorder()
	handler.ServeHTTP(selfRequested, chaosRequest(http.MethodPost, "/api/experiments/custom/runs", map[string]string{"manifest": manifest}, "approver-token"))
	if selfRequested.Code != http.StatusCreated {
		t.Fatalf("approver should inherit operator request access, got %d", selfRequested.Code)
	}
	var selfRun core.ChaosExperimentRun
	if err := json.NewDecoder(selfRequested.Body).Decode(&selfRun); err != nil {
		t.Fatal(err)
	}
	selfDecision := httptest.NewRecorder()
	handler.ServeHTTP(selfDecision, chaosRequest(http.MethodPost, "/api/experiment-runs/"+selfRun.ID+"/approve", map[string]string{"reason": "self approval"}, "approver-token"))
	if selfDecision.Code != http.StatusBadRequest {
		t.Fatalf("same authenticated actor approved its own chaos request: %d %s", selfDecision.Code, selfDecision.Body.String())
	}
}

type tokenMapVerifier struct {
	principals map[string]auth.Principal
}

func (v tokenMapVerifier) Verify(_ context.Context, rawToken string) (auth.Principal, error) {
	principal, ok := v.principals[rawToken]
	if !ok {
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	return principal, nil
}

func chaosRequest(method, path string, payload map[string]string, token string) *http.Request {
	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		encoded, _ := json.Marshal(payload)
		body = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, body)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	return request
}
