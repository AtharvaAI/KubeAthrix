package controllers

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRemediationPlanReconcilerAppliesResourceGovernance(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	scheme.AddKnownTypeWithName(RemediationPlanGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(RemediationRunGVK, &unstructured.Unstructured{})

	plan := NewRemediationPlanObject(types.NamespacedName{Namespace: "kubeathrix", Name: "plan-team-labs-001"})
	plan.SetGeneration(2)
	plan.Object["spec"] = map[string]any{
		"findingRef": map[string]any{"name": "finding-namespace-quota"},
		"riskTier":   "A",
		"actions": []any{
			map[string]any{
				"type": "apply_resource_governance",
				"target": map[string]any{
					"apiVersion": "v1",
					"kind":       "Namespace",
					"name":       "team-labs",
				},
				"description": "Apply scoped ResourceQuota and LimitRange defaults",
			},
		},
		"dryRunResult":      map[string]any{"passed": true, "message": "server-side dry-run queued"},
		"approvalPolicy":    map[string]any{"required": false},
		"rootCause":         "namespace lacks resource governance",
		"verificationSteps": []any{"re-scan"},
		"rollbackSteps":     []any{"delete generated defaults"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(plan).
		WithStatusSubresource(plan, NewRemediationRunObject(types.NamespacedName{})).
		Build()

	reconciler := &RemediationPlanReconciler{
		Client: c,
		Scheme: scheme,
		Clock: func() time.Time {
			return time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
		},
	}
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "kubeathrix", Name: "plan-team-labs-001"}})
	if err != nil {
		t.Fatal(err)
	}

	quota := &corev1.ResourceQuota{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "team-labs", Name: "kubeathrix-defaults"}, quota); err != nil {
		t.Fatal(err)
	}
	limitRange := &corev1.LimitRange{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "team-labs", Name: "kubeathrix-defaults"}, limitRange); err != nil {
		t.Fatal(err)
	}
	updated := NewRemediationPlanObject(types.NamespacedName{Namespace: "kubeathrix", Name: "plan-team-labs-001"})
	if err := c.Get(ctx, client.ObjectKeyFromObject(updated), updated); err != nil {
		t.Fatal(err)
	}
	phase, _, _ := unstructured.NestedString(updated.Object, "status", "phase")
	if phase != "Applied" {
		t.Fatalf("expected Applied phase, got %q", phase)
	}
	run := NewRemediationRunObject(types.NamespacedName{Namespace: "kubeathrix", Name: "run-plan-team-labs-001"})
	if err := c.Get(ctx, client.ObjectKeyFromObject(run), run); err != nil {
		t.Fatal(err)
	}
	state, _, _ := unstructured.NestedString(run.Object, "status", "state")
	if state != "succeeded" {
		t.Fatalf("expected run state succeeded, got %q", state)
	}
}
