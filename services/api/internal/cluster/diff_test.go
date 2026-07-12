package cluster

import (
	"context"
	"strings"
	"testing"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestRenderDiffResolvesExactLiveTargets(t *testing.T) {
	namespace := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": "team-labs", "labels": map[string]any{"owner": "platform"}},
	}}
	deployment := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "router", "namespace": "team-labs"},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{"app": "router"}},
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": "router", "image": "example/router@sha256:abc"},
					},
				},
			},
		},
	}}
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), namespace, deployment)
	workflow := NewWorkflowClientFromDynamic(client, "kubeathrix", nil)
	workload := core.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "team-labs", Name: "router"}
	plan := core.RemediationPlan{
		ID: "plan-exact-diff", CatalogVersion: "v1",
		Actions: []core.TypedAction{
			{Type: "patch_pod_security_labels", Target: core.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: "team-labs"}, Params: map[string]string{"enforce": "baseline", "audit": "restricted", "warn": "restricted"}},
			{Type: "patch_workload_resources", Target: workload, Params: map[string]string{"cpuRequest": "100m", "memoryRequest": "128Mi", "cpuLimit": "500m", "memoryLimit": "512Mi"}},
			{Type: "create_pdb", Target: workload, Params: map[string]string{"minAvailable": "1"}},
		},
	}
	diff, err := workflow.RenderDiff(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Manifests) != 3 {
		t.Fatalf("expected three exact manifests, got %d", len(diff.Manifests))
	}
	for _, manifest := range diff.Manifests {
		if manifest.Manifest == "" || manifest.Diff == "" {
			t.Fatalf("action %s has no exact preview: %#v", manifest.ActionType, manifest)
		}
	}
	if !strings.Contains(diff.Manifests[1].Diff, `containers["router"]`) || !strings.Contains(diff.Manifests[2].Manifest, `"app": "router"`) {
		t.Fatalf("live container or PDB selector was not resolved: %#v", diff.Manifests)
	}
	if strings.Contains(diff.Manifests[2].Manifest, `"matchLabels": {}`) {
		t.Fatal("PDB preview must never contain an empty selector")
	}
}
