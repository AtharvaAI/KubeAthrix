package controllers

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFindingReconcilerWritesObservedStatus(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(FindingGVK, &unstructured.Unstructured{})

	finding := NewFindingObject(types.NamespacedName{Namespace: "kubeathrix", Name: "quota-missing"})
	finding.SetGeneration(3)
	finding.Object["spec"] = map[string]any{
		"source":   "kyverno",
		"severity": "medium",
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(finding).
		WithStatusSubresource(finding).
		Build()

	reconciler := &FindingReconciler{
		Client: client,
		Scheme: scheme,
		Clock: func() time.Time {
			return time.Date(2026, 7, 8, 12, 30, 0, 0, time.UTC)
		},
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "kubeathrix", Name: "quota-missing"}})
	if err != nil {
		t.Fatal(err)
	}

	updated := NewFindingObject(types.NamespacedName{Namespace: "kubeathrix", Name: "quota-missing"})
	if err := client.Get(ctx, types.NamespacedName{Namespace: "kubeathrix", Name: "quota-missing"}, updated); err != nil {
		t.Fatal(err)
	}
	phase, _, _ := unstructured.NestedString(updated.Object, "status", "phase")
	if phase != "Observed" {
		t.Fatalf("expected Observed phase, got %q", phase)
	}
	observedGeneration, _, _ := unstructured.NestedInt64(updated.Object, "status", "observedGeneration")
	if observedGeneration != 3 {
		t.Fatalf("expected observed generation 3, got %d", observedGeneration)
	}
}
