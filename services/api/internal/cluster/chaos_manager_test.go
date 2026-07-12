package cluster

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestChaosManagerApprovalExecutionCleanupAndRecovery(t *testing.T) {
	manager, runner, repository, clock := testChaosManager(t)
	ctx := context.Background()
	run, err := manager.Request(ctx, "network-latency-service", validChaosManifest, "requester")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosPendingApproval || run.Version != 1 || run.TargetCount != 1 {
		t.Fatalf("unexpected requested run: %#v", run)
	}
	if _, err := manager.Approve(ctx, run.ID, "requester", "self approval"); err == nil {
		t.Fatal("requester was allowed to approve their own chaos run")
	}
	run, err = manager.Approve(ctx, run.ID, "approver", "maintenance window open")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosApproved {
		t.Fatalf("expected approved, got %s", run.Status)
	}
	run, err = manager.Execute(ctx, run.ID, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosExecutionRequested || run.InjectionDeadline == nil {
		t.Fatalf("resource creation was incorrectly reported as running: %#v", run)
	}
	markChaosInjected(t, runner, run)
	run, err = manager.Get(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosRunning || run.StartedAt == nil {
		t.Fatalf("AllInjected=True did not produce a cluster-backed running state: %#v", run)
	}
	resource, err := runner.resourceForRun(run)
	if err != nil {
		t.Fatal(err)
	}
	created, err := resource.Get(ctx, run.Resource.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if created.GetLabels()["security.kubeathrix.io/chaos-run"] != run.ID {
		t.Fatal("created chaos resource is missing its run ownership label")
	}

	*clock = clock.Add(61 * time.Second)
	if _, err := manager.Get(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	run, err = manager.Get(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosSucceeded || run.RecoveryStatus != "healthy" || run.FinishedAt == nil {
		t.Fatalf("cleanup and recovery were not proven: %#v", run)
	}
	if _, err := resource.Get(ctx, run.Resource.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("chaos resource still exists after cleanup")
	}

	events, err := repository.ListAuditEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{
		"chaos.approval.requested": false, "chaos.approved": false, "chaos.execution.requested": false,
		"chaos.execution.started": false, "chaos.cleanup.requested": false, "chaos.cleanup.completed": false, "chaos.succeeded": false,
	}
	for _, event := range events {
		if _, ok := required[event.Action]; ok {
			required[event.Action] = true
		}
	}
	for action, seen := range required {
		if !seen {
			t.Fatalf("missing audit event %s", action)
		}
	}
}

func TestChaosManagerAbortDeletesResource(t *testing.T) {
	manager, runner, _, _ := testChaosManager(t)
	ctx := context.Background()
	run, err := manager.Request(ctx, "network-latency-service", validChaosManifest, "requester")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Approve(ctx, run.ID, "approver", "approved")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Execute(ctx, run.ID, "operator")
	if err != nil {
		t.Fatal(err)
	}
	markChaosInjected(t, runner, run)
	run, err = manager.Get(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Abort(ctx, run.ID, "operator", "service degradation")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosAborted || run.AbortedBy != "operator" {
		t.Fatalf("unexpected aborted run: %#v", run)
	}
	resource, _ := runner.resourceForRun(run)
	if _, err := resource.Get(ctx, run.Resource.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("aborted chaos resource still exists")
	}
}

func TestChaosManagerDoesNotReportSuccessWhenResourceDisappearsEarly(t *testing.T) {
	manager, runner, _, clock := testChaosManager(t)
	ctx := context.Background()
	run, err := manager.Request(ctx, "network-latency-service", validChaosManifest, "requester")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Approve(ctx, run.ID, "approver", "approved")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Execute(ctx, run.ID, "operator")
	if err != nil {
		t.Fatal(err)
	}
	markChaosInjected(t, runner, run)
	run, err = manager.Get(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	resource, _ := runner.resourceForRun(run)
	if err := resource.Delete(ctx, run.Resource.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(10 * time.Second)
	run, err = manager.Get(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status == core.ChaosVerifying {
		run, err = manager.Get(ctx, run.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if run.Status != core.ChaosFailed || run.FinishedAt == nil {
		t.Fatalf("early resource disappearance was not terminal failure: %#v", run)
	}
}

func TestChaosManagerRecoveryTimeoutIsFailure(t *testing.T) {
	manager, runner, _, clock := testChaosManager(t)
	ctx := context.Background()
	run, err := manager.Request(ctx, "network-latency-service", validChaosManifest, "requester")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Approve(ctx, run.ID, "approver", "approved")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Execute(ctx, run.ID, "operator")
	if err != nil {
		t.Fatal(err)
	}
	markChaosInjected(t, runner, run)
	run, err = manager.Get(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	pods := runner.client.Resource(podsResource).Namespace("sandbox")
	pod, err := pods.Get(ctx, "checkout-0", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedSlice(pod.Object, []any{map[string]any{"type": "Ready", "status": "False"}}, "status", "conditions")
	if _, err := pods.Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(61 * time.Second)
	if _, err := manager.Get(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	run, err = manager.Get(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosVerifying {
		t.Fatalf("expected recovery polling, got %s", run.Status)
	}
	*clock = clock.Add(chaosRecoveryWindow + chaosCleanupGrace + time.Second)
	run, err = manager.Get(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosFailed || run.RecoveryStatus != "unhealthy" {
		t.Fatalf("unhealthy target was not a terminal recovery failure: %#v", run)
	}
}

func TestChaosManagerExpiresApprovalWithoutCreatingResource(t *testing.T) {
	manager, runner, _, clock := testChaosManager(t)
	ctx := context.Background()
	run, err := manager.Request(ctx, "network-latency-service", validChaosManifest, "requester")
	if err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(chaosApprovalTTL + time.Second)
	run, err = manager.Get(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosExpired {
		t.Fatalf("expected expired approval, got %s", run.Status)
	}
	resource, _ := runner.resourceForRun(run)
	if _, err := resource.Get(ctx, run.Resource.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("expired run created a chaos resource")
	}
}

func TestChaosManagerInjectionTimeoutCleansUpAndNeverReportsSuccess(t *testing.T) {
	manager, runner, _, clock := testChaosManager(t)
	ctx := context.Background()
	run, err := manager.Request(ctx, "network-latency-service", validChaosManifest, "requester")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Approve(ctx, run.ID, "approver", "approved")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Execute(ctx, run.ID, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != core.ChaosExecutionRequested {
		t.Fatalf("expected injection polling, got %s", run.Status)
	}
	*clock = clock.Add(chaosInjectionWindow + time.Second)
	for range 3 {
		run, err = manager.Get(ctx, run.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if run.Status != core.ChaosFailed || run.RecoveryStatus != "healthy" || run.FailureReason == "" {
		t.Fatalf("unproven injection was not cleaned up as a terminal failure: %#v", run)
	}
	resource, _ := runner.resourceForRun(run)
	if _, err := resource.Get(ctx, run.Resource.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("injection timeout left the chaos resource behind")
	}
}

func TestChaosObservationRequiresControllerProofAndSurfacesApplyFailure(t *testing.T) {
	manager, runner, _, _ := testChaosManager(t)
	ctx := context.Background()
	run, err := manager.Request(ctx, "network-latency-service", validChaosManifest, "requester")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Approve(ctx, run.ID, "approver", "approved")
	if err != nil {
		t.Fatal(err)
	}
	run, err = manager.Execute(ctx, run.ID, "operator")
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runner.Observe(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	if observation.AllInjected || observation.Failed {
		t.Fatalf("empty controller status produced false proof: %#v", observation)
	}
	resource, _ := runner.resourceForRun(run)
	object, err := resource.Get(ctx, run.Resource.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedSlice(object.Object, []any{map[string]any{
		"events": []any{map[string]any{"type": "Failed", "operation": "Apply", "message": "unable to inject target"}},
	}}, "status", "experiment", "containerRecords"); err != nil {
		t.Fatal(err)
	}
	if _, err := resource.Update(ctx, object, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	observation, err = runner.Observe(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Failed || !strings.Contains(observation.Message, "unable to inject target") {
		t.Fatalf("controller apply failure was not surfaced: %#v", observation)
	}
}

func testChaosManager(t *testing.T) (*ChaosManager, *ChaosRunner, *store.MemoryStore, *time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	pod := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "checkout-0", "namespace": "sandbox", "labels": map[string]any{"app": "checkout"}},
		"status":   map[string]any{"phase": "Running", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}},
	}}
	listKinds := map[schema.GroupVersionResource]string{
		podsResource: "PodList",
		allowedChaosResources[schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "NetworkChaos"}]: "NetworkChaosList",
	}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, pod)
	runner := NewChaosRunnerFromClient(client, func() time.Time { return now })
	runner.allowedNamespaces = map[string]struct{}{"sandbox": {}}
	runner.serverSideDryRun = false
	repository := store.NewMemoryStore(store.WithClock(func() time.Time { return now }))
	manager := NewChaosManager(repository, runner, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manager.now = func() time.Time { return now }
	return manager, runner, repository, &now
}

func markChaosInjected(t *testing.T, runner *ChaosRunner, run core.ChaosExperimentRun) {
	t.Helper()
	resource, err := runner.resourceForRun(run)
	if err != nil {
		t.Fatal(err)
	}
	object, err := resource.Get(context.Background(), run.Resource.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedSlice(object.Object, []any{map[string]any{
		"type": "AllInjected", "status": "True", "reason": "AllTargetsInjected",
	}}, "status", "conditions"); err != nil {
		t.Fatal(err)
	}
	if _, err := resource.Update(context.Background(), object, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}
