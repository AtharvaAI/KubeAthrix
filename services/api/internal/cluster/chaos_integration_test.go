package cluster

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// TestChaosMeshLifecycleIntegration is intentionally opt-in because it injects
// a real, bounded fault. It must run only against a disposable cluster with
// Chaos Mesh installed. The namespace created here is deleted on completion.
func TestChaosMeshLifecycleIntegration(t *testing.T) {
	if os.Getenv("KUBEATHRIX_CHAOS_E2E") != "true" {
		t.Skip("set KUBEATHRIX_CHAOS_E2E=true only for a disposable Chaos Mesh cluster")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	namespace := fmt.Sprintf("kubeathrix-chaos-e2e-%d", time.Now().Unix())
	t.Setenv("KUBEATHRIX_CHAOS_NAMESPACE_ALLOWLIST", namespace)
	runner, err := NewChaosRunner()
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Health(ctx); err != nil {
		t.Fatalf("Chaos Mesh is not ready: %v", err)
	}

	namespaces := runner.client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"})
	_, err = namespaces.Create(ctx, &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": namespace},
	}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		_ = namespaces.Delete(cleanupCtx, namespace, metav1.DeleteOptions{})
	}()

	pods := runner.client.Resource(podsResource).Namespace(namespace)
	_, err = pods.Create(ctx, &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "target", "namespace": namespace, "labels": map[string]any{"app": "kubeathrix-chaos-e2e"}},
		"spec": map[string]any{"containers": []any{map[string]any{
			"name": "target", "image": "registry.k8s.io/pause:3.10.1",
		}}},
	}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, 2*time.Second, func() (bool, error) {
		pod, getErr := pods.Get(ctx, "target", metav1.GetOptions{})
		return getErr == nil && chaosTargetPodReady(pod), getErr
	}, "target pod never became Running and Ready")

	manifest := fmt.Sprintf(`apiVersion: chaos-mesh.org/v1alpha1
kind: StressChaos
metadata:
  name: kubeathrix-cpu
  namespace: %s
spec:
  mode: one
  selector:
    namespaces: [%s]
    labelSelectors:
      app: kubeathrix-chaos-e2e
  stressors:
    cpu:
      workers: 1
      load: 20
  duration: 10s`, namespace, namespace)
	repository := store.NewMemoryStore()
	manager := NewChaosManager(repository, runner, true, nil)
	run, err := manager.Request(ctx, "real-cpu-stress", manifest, "integration-requester")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Approve(ctx, run.ID, "integration-approver", "isolated cluster verification")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Execute(ctx, run.ID, "integration-operator")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosExecutionRequested {
		t.Fatalf("creation without controller proof was reported as %s", run.Status)
	}
	waitFor(t, ctx, time.Second, func() (bool, error) {
		var getErr error
		run, getErr = manager.Get(ctx, run.ID)
		return getErr == nil && run.Status == core.ChaosRunning, getErr
	}, "Chaos Mesh never proved injection with AllInjected=True")
	waitFor(t, ctx, time.Second, func() (bool, error) {
		var getErr error
		run, getErr = manager.Get(ctx, run.ID)
		return getErr == nil && run.Status == core.ChaosSucceeded, getErr
	}, "chaos resource cleanup and target recovery were not proven")
	if run.RecoveryStatus != "healthy" || run.FinishedAt == nil {
		t.Fatalf("unexpected terminal recovery evidence: %#v", run)
	}
}

func waitFor(t *testing.T, ctx context.Context, interval time.Duration, check func() (bool, error), failure string) {
	t.Helper()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ok, err := check()
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(failure)
		case <-ticker.C:
		}
	}
}
