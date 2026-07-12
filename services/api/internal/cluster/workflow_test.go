package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestWorkflowClientPersistsPlanApprovalAndExecutionState(t *testing.T) {
	ctx := context.Background()
	fixed := time.Date(2026, 7, 11, 18, 30, 0, 0, time.UTC)
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	client := NewWorkflowClientFromDynamic(dynamicClient, "kubeathrix", func() time.Time { return fixed })
	finding := core.Finding{
		ID: "finding-platform-probes", Source: "kubeathrix-native", Title: "Workload has no probes",
		Severity: core.SeverityHigh, Fixability: core.FixabilityGated, Status: core.FindingOpen,
		Resources:   []core.ResourceRef{{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "platform", Name: "router"}},
		Evidence:    []core.Evidence{{Summary: "probe missing", SourceID: "native/platform/router", ObservedAt: fixed}},
		BlastRadius: "router availability", CorrelationGroup: "platform-router", RiskScore: 80,
		RemediationState: "approval_required", RecommendedAction: "add configured probes",
	}
	plan := core.RemediationPlan{
		ID: "plan-finding-platform-probes-001", FindingID: finding.ID, RootCause: "probe configuration is absent",
		Actions:  []core.TypedAction{{Type: "patch_workload_probes", Target: finding.Resources[0], Description: "patch configured probes"}},
		RiskTier: core.RiskTierB, ApprovalPolicy: core.ApprovalPolicy{Required: true, Decision: core.ApprovalPending},
		VerificationSteps: []string{"read workload"}, RollbackSteps: []string{"restore snapshot"}, Status: "proposed", CreatedAt: fixed,
	}
	actor := "platform-operator (user-42)"
	if err := client.CreatePlan(ctx, finding, plan, actor); err != nil {
		t.Fatal(err)
	}
	if err := client.CreatePlan(ctx, finding, plan, actor); err != nil {
		t.Fatalf("idempotent retry failed: %v", err)
	}
	planObject, err := dynamicClient.Resource(planResource).Namespace("kubeathrix").Get(ctx, ObjectName(plan.ID), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	requested, _, _ := unstructured.NestedBool(planObject.Object, "spec", "executionRequested")
	if requested {
		t.Fatal("new plan must not request execution")
	}
	approvalID := "approval-" + plan.ID
	approvalObject, err := dynamicClient.Resource(approvalResource).Namespace("kubeathrix").Get(ctx, ObjectName(approvalID), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	decision, _, _ := unstructured.NestedString(approvalObject.Object, "spec", "decision")
	if decision != "pending" {
		t.Fatalf("expected pending approval CRD, got %q", decision)
	}

	approval, err := client.DecideApproval(ctx, approvalID, core.ApprovalApproved, "sre-lead (user-7)", "validated in staging")
	if err != nil {
		t.Fatal(err)
	}
	if approval.Status != core.ApprovalApproved || approval.Approver != "sre-lead (user-7)" {
		t.Fatalf("unexpected approval result: %#v", approval)
	}
	planObject, err = dynamicClient.Resource(planResource).Namespace("kubeathrix").Get(ctx, ObjectName(plan.ID), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	planDecision, _, _ := unstructured.NestedString(planObject.Object, "spec", "approvalPolicy", "decision")
	if planDecision != "approved" {
		t.Fatalf("expected plan approval decision to be persisted, got %q", planDecision)
	}

	run, err := client.RequestExecution(ctx, plan.ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != core.RunExecutionRequested {
		t.Fatalf("request must not claim the controller is running, got %q", run.State)
	}
	planObject, err = dynamicClient.Resource(planResource).Namespace("kubeathrix").Get(ctx, ObjectName(plan.ID), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	requested, _, _ = unstructured.NestedBool(planObject.Object, "spec", "executionRequested")
	if !requested {
		t.Fatal("execution request was not persisted in the plan CRD")
	}
	runObject := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "security.kubeathrix.io/v1alpha1", "kind": "RemediationRun",
		"metadata": map[string]any{
			"name": ObjectName("run-" + plan.ID), "namespace": "kubeathrix",
			"annotations": map[string]any{apiIDAnnotation: "run-" + plan.ID, "security.kubeathrix.io/plan-id": plan.ID},
		},
		"spec": map[string]any{"planRef": map[string]any{"name": ObjectName(plan.ID), "namespace": "kubeathrix"}},
		"status": map[string]any{
			"state": "succeeded", "validationResult": "objects and rollout verified",
			"rollbackMetadata": "ConfigMap/kubeathrix/snapshot-plan",
		},
	}}
	if _, err := dynamicClient.Resource(runResource).Namespace("kubeathrix").Create(ctx, runObject, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	rollback, err := client.RequestRollback(ctx, "run-"+plan.ID, "platform-operator (user-42)")
	if err != nil {
		t.Fatal(err)
	}
	if rollback.State != core.RunRollbackRequested {
		t.Fatalf("expected rollback request state, got %q", rollback.State)
	}
	planObject, err = dynamicClient.Resource(planResource).Namespace("kubeathrix").Get(ctx, ObjectName(plan.ID), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rollbackRequested, _, _ := unstructured.NestedBool(planObject.Object, "spec", "rollbackRequested")
	if !rollbackRequested {
		t.Fatal("rollback request was not persisted in the plan CRD")
	}
}

func TestWorkflowClientPersistsAndDeletesException(t *testing.T) {
	ctx := context.Background()
	fixed := time.Date(2026, 7, 11, 18, 30, 0, 0, time.UTC)
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	client := NewWorkflowClientFromDynamic(dynamicClient, "kubeathrix", func() time.Time { return fixed })
	exception := core.Exception{ID: "exception-123", Scope: "finding-123", Owner: "operator (subject)", Reason: "maintenance window", ExpiresAt: fixed.Add(time.Hour), AuditMetadata: "authenticated", Status: "active", CreatedAt: fixed, UpdatedAt: fixed}
	if err := client.CreateException(ctx, exception); err != nil {
		t.Fatal(err)
	}
	object, err := dynamicClient.Resource(exceptionResource).Namespace("kubeathrix").Get(ctx, ObjectName(exception.ID), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := unstructured.NestedString(object.Object, "spec", "owner")
	if owner != exception.Owner {
		t.Fatalf("exception owner was not persisted: %q", owner)
	}
	if err := client.DeleteException(ctx, exception.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := dynamicClient.Resource(exceptionResource).Namespace("kubeathrix").Get(ctx, ObjectName(exception.ID), metav1.GetOptions{}); err == nil {
		t.Fatal("exception CRD was not deleted")
	}
}

func TestObjectNameIsStableAndDNSCompatible(t *testing.T) {
	input := "Finding/With A Very Long Name That Exceeds The Kubernetes DNS Label Limit By Quite A Few Characters Indeed"
	first := ObjectName(input)
	second := ObjectName(input)
	if first != second || len(first) > 63 {
		t.Fatalf("invalid stable object name %q / %q", first, second)
	}
	for _, character := range first {
		if !(character == '-' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9') {
			t.Fatalf("object name contains invalid character %q: %s", character, first)
		}
	}
}
