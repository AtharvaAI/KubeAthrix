package controllers

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var RemediationPlanGVK = schema.GroupVersionKind{
	Group:   "security.kubeathrix.io",
	Version: "v1alpha1",
	Kind:    "RemediationPlan",
}

var RemediationRunGVK = schema.GroupVersionKind{
	Group:   "security.kubeathrix.io",
	Version: "v1alpha1",
	Kind:    "RemediationRun",
}

type RemediationPlanReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Clock  func() time.Time
}

// +kubebuilder:rbac:groups=security.kubeathrix.io,resources=remediationplans;remediationruns,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security.kubeathrix.io,resources=remediationplans/status;remediationruns/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.kubeathrix.io,resources=remediationplans/finalizers;remediationruns/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=resourcequotas;limitranges,verbs=get;list;watch;create;update;patch

func (r *RemediationPlanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	plan := NewRemediationPlanObject(req.NamespacedName)
	if err := r.Get(ctx, req.NamespacedName, plan); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if controllerutil.AddFinalizer(plan, "remediation.security.kubeathrix.io/audit") {
		if err := r.Update(ctx, plan); err != nil {
			return ctrl.Result{}, err
		}
	}

	now := time.Now().UTC()
	if r.Clock != nil {
		now = r.Clock().UTC()
	}
	result := r.reconcilePlanActions(ctx, plan)
	if err := r.writePlanStatus(ctx, plan, result, now); err != nil {
		logger.Error(err, "failed to update remediation plan status")
		return ctrl.Result{}, err
	}
	if err := r.upsertRun(ctx, plan, result, now); err != nil {
		logger.Error(err, "failed to upsert remediation run")
		return ctrl.Result{}, err
	}
	logger.Info("reconciled remediation plan", "plan", req.NamespacedName.String(), "phase", result.phase)
	return ctrl.Result{}, nil
}

func (r *RemediationPlanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(NewRemediationPlanObject(types.NamespacedName{})).
		Complete(r)
}

type planResult struct {
	phase              string
	runState           string
	message            string
	diffSummary        string
	verificationResult string
	rollbackRef        string
	lastError          string
	actionStatuses     []any
}

func (r *RemediationPlanReconciler) reconcilePlanActions(ctx context.Context, plan *unstructured.Unstructured) planResult {
	approvalRequired, _, _ := unstructured.NestedBool(plan.Object, "spec", "approvalPolicy", "required")
	dryRunPassed, _, _ := unstructured.NestedBool(plan.Object, "spec", "dryRunResult", "passed")
	actions, _, _ := unstructured.NestedSlice(plan.Object, "spec", "actions")
	result := planResult{
		phase:              "Prepared",
		runState:           "dry_run_passed",
		message:            "typed actions prepared for controller reconciliation",
		diffSummary:        fmt.Sprintf("%d typed action(s) inspected", len(actions)),
		verificationResult: "source engines must be re-scanned after execution",
		rollbackRef:        "pre-change snapshot required before mutating write",
	}
	if approvalRequired {
		result.phase = "PendingApproval"
		result.runState = "pending_approval"
		result.message = "approval gate is still required"
		result.verificationResult = "waiting for explicit approval"
		return result
	}
	if !dryRunPassed {
		result.phase = "DryRunFailed"
		result.runState = "failed"
		result.message = "dry-run result is not passing"
		result.lastError = "plan spec.dryRunResult.passed is false"
		return result
	}

	applied := 0
	for _, raw := range actions {
		action, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		actionType, _, _ := unstructured.NestedString(action, "type")
		status := map[string]any{"actionType": actionType, "state": "prepared", "message": "typed action prepared; no arbitrary command path exists"}
		if actionType == "apply_resource_governance" {
			namespace, err := targetNamespace(action)
			if err != nil {
				status["state"] = "failed"
				status["message"] = err.Error()
				result.phase = "Failed"
				result.runState = "failed"
				result.lastError = err.Error()
				result.actionStatuses = append(result.actionStatuses, status)
				return result
			}
			if err := r.applyResourceGovernance(ctx, namespace); err != nil {
				status["state"] = "failed"
				status["message"] = err.Error()
				result.phase = "Failed"
				result.runState = "failed"
				result.lastError = err.Error()
				result.actionStatuses = append(result.actionStatuses, status)
				return result
			}
			applied++
			status["state"] = "succeeded"
			status["message"] = "ResourceQuota and LimitRange reconciled"
		}
		result.actionStatuses = append(result.actionStatuses, status)
	}
	if applied > 0 {
		result.phase = "Applied"
		result.runState = "succeeded"
		result.message = fmt.Sprintf("%d low-risk typed action(s) applied", applied)
		result.verificationResult = "resource governance objects reconciled; re-scan required for proof"
	}
	return result
}

func (r *RemediationPlanReconciler) applyResourceGovernance(ctx context.Context, namespace string) error {
	if namespace == "" {
		return fmt.Errorf("namespace target is required for resource governance")
	}
	quota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: "kubeathrix-defaults", Namespace: namespace},
		Spec: corev1.ResourceQuotaSpec{Hard: corev1.ResourceList{
			corev1.ResourceRequestsCPU:    resource.MustParse("4"),
			corev1.ResourceRequestsMemory: resource.MustParse("8Gi"),
		}},
	}
	if err := r.upsertObject(ctx, quota); err != nil {
		return err
	}
	limitRange := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Name: "kubeathrix-defaults", Namespace: namespace},
		Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
			Type: corev1.LimitTypeContainer,
			DefaultRequest: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Default: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("512Mi"),
			},
		}}},
	}
	return r.upsertObject(ctx, limitRange)
}

func (r *RemediationPlanReconciler) upsertObject(ctx context.Context, obj client.Object) error {
	current := obj.DeepCopyObject().(client.Object)
	err := r.Get(ctx, client.ObjectKeyFromObject(obj), current)
	if apierrors.IsNotFound(err) {
		return r.Create(ctx, obj)
	}
	if err != nil {
		return err
	}
	obj.SetResourceVersion(current.GetResourceVersion())
	return r.Update(ctx, obj)
}

func (r *RemediationPlanReconciler) writePlanStatus(ctx context.Context, plan *unstructured.Unstructured, result planResult, now time.Time) error {
	status := map[string]any{
		"phase":              result.phase,
		"observedGeneration": plan.GetGeneration(),
		"lastTransitionTime": now.Format(time.RFC3339),
		"message":            result.message,
		"diffSummary":        result.diffSummary,
		"approvalRef":        "approval-" + plan.GetName(),
		"runRef":             "run-" + plan.GetName(),
		"verificationResult": result.verificationResult,
		"rollbackRef":        result.rollbackRef,
	}
	if result.lastError != "" {
		status["lastError"] = result.lastError
	}
	dryRun, ok, _ := unstructured.NestedMap(plan.Object, "spec", "dryRunResult")
	if ok {
		status["dryRunResult"] = dryRun
	}
	plan.Object["status"] = status
	return r.Status().Update(ctx, plan)
}

func (r *RemediationPlanReconciler) upsertRun(ctx context.Context, plan *unstructured.Unstructured, result planResult, now time.Time) error {
	runName := "run-" + plan.GetName()
	run := NewRemediationRunObject(types.NamespacedName{Namespace: plan.GetNamespace(), Name: runName})
	err := r.Get(ctx, client.ObjectKeyFromObject(run), run)
	if apierrors.IsNotFound(err) {
		run.Object["spec"] = map[string]any{"planRef": map[string]any{"name": plan.GetName(), "namespace": plan.GetNamespace()}}
		if err := r.Create(ctx, run); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	status := map[string]any{
		"state":              result.runState,
		"actionStatuses":     result.actionStatuses,
		"validationResult":   result.message,
		"rollbackMetadata":   result.rollbackRef,
		"observedGeneration": run.GetGeneration(),
		"lastTransitionTime": now.Format(time.RFC3339),
	}
	run.Object["status"] = status
	return r.Status().Update(ctx, run)
}

func targetNamespace(action map[string]any) (string, error) {
	target, ok, _ := unstructured.NestedMap(action, "target")
	if !ok {
		return "", fmt.Errorf("action target is required")
	}
	kind, _, _ := unstructured.NestedString(target, "kind")
	name, _, _ := unstructured.NestedString(target, "name")
	namespace, _, _ := unstructured.NestedString(target, "namespace")
	if kind == "Namespace" {
		return name, nil
	}
	if namespace != "" {
		return namespace, nil
	}
	return "", fmt.Errorf("namespace could not be derived from target")
}

func NewRemediationPlanObject(name types.NamespacedName) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(RemediationPlanGVK)
	obj.SetNamespace(name.Namespace)
	obj.SetName(name.Name)
	return obj
}

func NewRemediationRunObject(name types.NamespacedName) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(RemediationRunGVK)
	obj.SetNamespace(name.Namespace)
	obj.SetName(name.Name)
	return obj
}
