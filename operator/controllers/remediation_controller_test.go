package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	scheme.AddKnownTypeWithName(FindingGVK, &unstructured.Unstructured{})

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
		"dryRunResult":       map[string]any{"passed": true, "message": "server-side dry-run queued"},
		"approvalPolicy":     map[string]any{"required": false},
		"executionRequested": true,
		"rootCause":          "namespace lacks resource governance",
		"verificationSteps":  []any{"re-scan"},
		"rollbackSteps":      []any{"delete generated defaults"},
	}
	finding := NewFindingObject(types.NamespacedName{Namespace: "kubeathrix", Name: "finding-namespace-quota"})
	finding.Object["spec"] = map[string]any{"source": "kubeathrix-native", "severity": "medium"}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(plan, finding).
		WithStatusSubresource(plan, NewRemediationRunObject(types.NamespacedName{}), finding).
		Build()

	reconciler := &RemediationPlanReconciler{
		Client:          c,
		Scheme:          scheme,
		MutationEnabled: true,
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
	updatedFinding := NewFindingObject(types.NamespacedName{Namespace: "kubeathrix", Name: "finding-namespace-quota"})
	if err := c.Get(ctx, client.ObjectKeyFromObject(updatedFinding), updatedFinding); err != nil {
		t.Fatal(err)
	}
	findingPhase, _, _ := unstructured.NestedString(updatedFinding.Object, "status", "phase")
	if findingPhase != "Resolved" {
		t.Fatalf("expected verified source finding to resolve, got %q", findingPhase)
	}
}

func TestRemediationPlanReconcilerDoesNotMutatePreparedPlan(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	scheme.AddKnownTypeWithName(RemediationPlanGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(RemediationRunGVK, &unstructured.Unstructured{})
	plan := NewRemediationPlanObject(types.NamespacedName{Namespace: "kubeathrix", Name: "plan-not-requested"})
	plan.Object["spec"] = map[string]any{
		"findingRef": map[string]any{"name": "finding-namespace-quota"},
		"riskTier":   "A",
		"actions": []any{map[string]any{
			"type":        "apply_resource_governance",
			"target":      map[string]any{"apiVersion": "v1", "kind": "Namespace", "name": "team-labs"},
			"description": "Apply scoped ResourceQuota and LimitRange defaults",
		}},
		"approvalPolicy":     map[string]any{"required": false},
		"executionRequested": false,
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(plan).WithStatusSubresource(plan, NewRemediationRunObject(types.NamespacedName{})).Build()
	reconciler := &RemediationPlanReconciler{Client: c, Scheme: scheme, MutationEnabled: true}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "kubeathrix", Name: "plan-not-requested"}}); err != nil {
		t.Fatal(err)
	}
	quota := &corev1.ResourceQuota{}
	err := c.Get(ctx, client.ObjectKey{Namespace: "team-labs", Name: "kubeathrix-defaults"}, quota)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("prepared plan must not mutate cluster state, got error %v and object %#v", err, quota)
	}
	updated := NewRemediationPlanObject(types.NamespacedName{Namespace: "kubeathrix", Name: "plan-not-requested"})
	if err := c.Get(ctx, client.ObjectKeyFromObject(updated), updated); err != nil {
		t.Fatal(err)
	}
	phase, _, _ := unstructured.NestedString(updated.Object, "status", "phase")
	if phase != "Prepared" {
		t.Fatalf("expected Prepared phase without execution request, got %q", phase)
	}
}

func TestSafeTypedExecutorsApplyAndVerifyExactClusterObjects(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := policyv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	replicas := int32(2)
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-labs"}}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "router", Namespace: "team-labs"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "router"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "router"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "router", Image: "example/router@sha256:abc"}}},
			},
		},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 0, UpdatedReplicas: 2, AvailableReplicas: 2, ReadyReplicas: 2},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(namespace, deployment).Build()
	reconciler := &RemediationPlanReconciler{Client: c, Scheme: scheme, MutationEnabled: true}
	actions := []map[string]any{
		{
			"type":   "patch_pod_security_labels",
			"target": map[string]any{"apiVersion": "v1", "kind": "Namespace", "name": "team-labs"},
			"params": map[string]any{"enforce": "baseline", "audit": "restricted", "warn": "restricted"},
		},
		{
			"type":   "patch_workload_resources",
			"target": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "namespace": "team-labs", "name": "router"},
			"params": map[string]any{"cpuRequest": "100m", "memoryRequest": "128Mi", "cpuLimit": "500m", "memoryLimit": "512Mi"},
		},
		{
			"type":   "patch_workload_probes",
			"target": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "namespace": "team-labs", "name": "router"},
			"params": map[string]any{"configured": "true", "container": "router", "port": "8080", "readinessPath": "/ready", "livenessPath": "/live"},
		},
		{
			"type":   "create_pdb",
			"target": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "namespace": "team-labs", "name": "router"},
			"params": map[string]any{"minAvailable": "1"},
		},
	}
	for _, action := range actions {
		message, err := reconciler.executeTypedAction(ctx, action, false)
		if err != nil && !(action["type"] == "create_pdb" && errors.Is(err, errVerificationPending)) {
			t.Fatalf("execute %s: %v", action["type"], err)
		}
		if err == nil && message == "" {
			t.Fatalf("executor %s returned no verification evidence", action["type"])
		}
	}
	updatedNamespace := &corev1.Namespace{}
	if err := c.Get(ctx, client.ObjectKey{Name: "team-labs"}, updatedNamespace); err != nil {
		t.Fatal(err)
	}
	if updatedNamespace.Labels["pod-security.kubernetes.io/enforce"] != "baseline" {
		t.Fatal("Pod Security labels were not applied")
	}
	updatedDeployment := &appsv1.Deployment{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "team-labs", Name: "router"}, updatedDeployment); err != nil {
		t.Fatal(err)
	}
	container := updatedDeployment.Spec.Template.Spec.Containers[0]
	if container.Resources.Requests.Cpu().IsZero() || container.Resources.Limits.Memory().IsZero() || container.ReadinessProbe == nil || container.LivenessProbe == nil {
		t.Fatalf("workload action did not persist resources and probes: %#v", container)
	}
	pdb := &policyv1.PodDisruptionBudget{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "team-labs", Name: "router-kubeathrix"}, pdb); err != nil {
		t.Fatal(err)
	}
	if pdb.Spec.Selector == nil || pdb.Spec.Selector.MatchLabels["app"] != "router" {
		t.Fatalf("PDB did not use the exact workload selector: %#v", pdb.Spec.Selector)
	}
}

func TestPodSecurityExecutorProtectsSystemNamespaces(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kubeSystem := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kubeSystem).Build()
	reconciler := &RemediationPlanReconciler{Client: c, Scheme: scheme, MutationEnabled: true}
	action := map[string]any{
		"type":   "patch_pod_security_labels",
		"target": map[string]any{"apiVersion": "v1", "kind": "Namespace", "name": "kube-system"},
		"params": map[string]any{"enforce": "baseline"},
	}
	if _, err := reconciler.executeTypedAction(context.Background(), action, false); err == nil {
		t.Fatal("expected system namespace mutation to be rejected")
	}
}

func TestRollbackRestoresExistingObjectsAndDeletesRunCreatedObjects(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	teamNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-labs", Labels: map[string]string{"owner": "platform"}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(teamNamespace).Build()
	reconciler := &RemediationPlanReconciler{Client: c, Scheme: scheme, MutationEnabled: true}
	plan := NewRemediationPlanObject(types.NamespacedName{Namespace: "kubeathrix", Name: "plan-rollback-test"})
	labelAction := map[string]any{
		"type":   "patch_pod_security_labels",
		"target": map[string]any{"apiVersion": "v1", "kind": "Namespace", "name": "team-labs"},
		"params": map[string]any{"enforce": "baseline", "audit": "restricted", "warn": "restricted"},
	}
	governanceAction := map[string]any{
		"type":   "apply_resource_governance",
		"target": map[string]any{"apiVersion": "v1", "kind": "Namespace", "name": "team-labs"},
	}
	for _, action := range []map[string]any{labelAction, governanceAction} {
		if _, err := reconciler.ensureActionSnapshot(ctx, plan, action); err != nil {
			t.Fatalf("capture snapshot: %v", err)
		}
		if _, err := reconciler.executeTypedAction(ctx, action, false); err != nil {
			t.Fatalf("apply action before rollback: %v", err)
		}
	}
	result := reconciler.reconcileRollback(ctx, plan)
	if result.runState != "rolled_back" || result.phase != "RolledBack" {
		t.Fatalf("rollback did not complete: %#v", result)
	}
	restoredNamespace := &corev1.Namespace{}
	if err := c.Get(ctx, client.ObjectKey{Name: "team-labs"}, restoredNamespace); err != nil {
		t.Fatal(err)
	}
	if len(restoredNamespace.Labels) != 1 || restoredNamespace.Labels["owner"] != "platform" {
		t.Fatalf("namespace labels were not restored exactly: %#v", restoredNamespace.Labels)
	}
	for _, object := range []client.Object{&corev1.ResourceQuota{}, &corev1.LimitRange{}} {
		err := c.Get(ctx, client.ObjectKey{Namespace: "team-labs", Name: "kubeathrix-defaults"}, object)
		if !apierrors.IsNotFound(err) {
			t.Fatalf("run-created object %T was not deleted during rollback: %v", object, err)
		}
	}
}
