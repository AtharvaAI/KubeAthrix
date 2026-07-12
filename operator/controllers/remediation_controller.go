package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/atharvaai/kubeathrix/pkg/actioncatalog"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
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

var errVerificationPending = errors.New("verification is pending cluster reconciliation")

type RemediationPlanReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	Clock           func() time.Time
	MutationEnabled bool
}

// +kubebuilder:rbac:groups=security.kubeathrix.io,resources=remediationplans;remediationruns,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security.kubeathrix.io,resources=remediationplans/status;remediationruns/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.kubeathrix.io,resources=remediationplans/finalizers;remediationruns/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=resourcequotas;limitranges,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch

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
	rollbackRequested, _, _ := unstructured.NestedBool(plan.Object, "spec", "rollbackRequested")
	var result planResult
	if rollbackRequested {
		phase, _, _ := unstructured.NestedString(plan.Object, "status", "phase")
		observed, _, _ := unstructured.NestedInt64(plan.Object, "status", "observedGeneration")
		if phase == "RolledBack" && observed == plan.GetGeneration() {
			return ctrl.Result{}, nil
		}
		result = r.reconcileRollback(ctx, plan)
	} else {
		result = r.reconcilePlanActions(ctx, plan)
	}
	if err := r.writePlanStatus(ctx, plan, result, now); err != nil {
		logger.Error(err, "failed to update remediation plan status")
		return ctrl.Result{}, err
	}
	if err := r.upsertRun(ctx, plan, result, now); err != nil {
		logger.Error(err, "failed to upsert remediation run")
		return ctrl.Result{}, err
	}
	if err := r.updateFindingStatus(ctx, plan, result, now); err != nil {
		logger.Error(err, "failed to update source finding status")
		return ctrl.Result{}, err
	}
	logger.Info("reconciled remediation plan", "plan", req.NamespacedName.String(), "phase", result.phase)
	if result.requeueAfter > 0 {
		return ctrl.Result{RequeueAfter: result.requeueAfter}, nil
	}
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
	dryRunPassed       bool
	dryRunMessage      string
	requeueAfter       time.Duration
}

func (r *RemediationPlanReconciler) reconcilePlanActions(ctx context.Context, plan *unstructured.Unstructured) planResult {
	approvalRequired, _, _ := unstructured.NestedBool(plan.Object, "spec", "approvalPolicy", "required")
	approvalDecision, _, _ := unstructured.NestedString(plan.Object, "spec", "approvalPolicy", "decision")
	executionRequested, _, _ := unstructured.NestedBool(plan.Object, "spec", "executionRequested")
	actions, _, _ := unstructured.NestedSlice(plan.Object, "spec", "actions")
	result := planResult{
		phase:              "Prepared",
		runState:           "prepared",
		message:            "typed actions prepared; execution has not been requested",
		diffSummary:        fmt.Sprintf("%d typed action(s) inspected", len(actions)),
		verificationResult: "no verification performed because execution has not been requested",
		rollbackRef:        "pre-change snapshot required before mutating write",
		dryRunMessage:      "server-side dry-run has not been performed",
	}
	if approvalRequired && approvalDecision == "rejected" {
		result.phase = "Rejected"
		result.runState = "failed"
		result.message = "approval was rejected; execution is blocked"
		result.verificationResult = "no cluster write attempted"
		return result
	}
	if approvalRequired && approvalDecision != "approved" {
		result.phase = "PendingApproval"
		result.runState = "pending_approval"
		result.message = "approval gate is still required"
		result.verificationResult = "waiting for explicit approval"
		return result
	}
	if approvalRequired && approvalDecision == "approved" && !executionRequested {
		result.phase = "Approved"
		result.runState = "approved"
		result.message = "approval recorded; execution has not been requested"
		result.verificationResult = "no dry-run or cluster write performed"
		return result
	}
	if !executionRequested {
		return result
	}

	applied := 0
	dryRunCount := 0
	proposalOnly := 0
	for _, raw := range actions {
		action, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		actionType, _, _ := unstructured.NestedString(action, "type")
		status := map[string]any{"actionType": actionType, "state": "prepared", "message": "typed action prepared; no arbitrary command path exists"}
		target, _, _ := unstructured.NestedMap(action, "target")
		apiVersion, _, _ := unstructured.NestedString(target, "apiVersion")
		kind, _, _ := unstructured.NestedString(target, "kind")
		params, _, _ := unstructured.NestedStringMap(action, "params")
		catalogEntry := actioncatalog.Action{Type: actionType, APIVersion: apiVersion, Kind: kind, Params: params}
		if _, err := actioncatalog.ValidateProposal(catalogEntry); err != nil {
			status["state"] = "failed"
			status["message"] = err.Error()
			result.phase = "Failed"
			result.runState = "failed"
			result.lastError = err.Error()
			result.actionStatuses = append(result.actionStatuses, status)
			return result
		}
		if actioncatalog.ExecutionModeFor(catalogEntry) != actioncatalog.ModeDirect {
			proposalOnly++
			status["state"] = "proposal_only"
			status["message"] = "the action registry does not permit direct execution"
			result.actionStatuses = append(result.actionStatuses, status)
			continue
		}
		if _, err := actioncatalog.Validate(catalogEntry); err != nil {
			proposalOnly++
			status["state"] = "proposal_only"
			status["message"] = err.Error()
			result.actionStatuses = append(result.actionStatuses, status)
			continue
		}
		if _, err := r.executeTypedAction(ctx, action, true); err != nil {
			status["state"] = "failed"
			status["message"] = "server-side dry-run failed: " + err.Error()
			result.phase = "DryRunFailed"
			result.runState = "failed"
			result.lastError = status["message"].(string)
			result.dryRunMessage = result.lastError
			result.actionStatuses = append(result.actionStatuses, status)
			return result
		}
		dryRunCount++
		status["state"] = "dry_run_passed"
		status["message"] = "Kubernetes server-side dry-run passed"
		if !r.MutationEnabled {
			result.actionStatuses = append(result.actionStatuses, status)
			continue
		}
		snapshotRef, err := r.ensureActionSnapshot(ctx, plan, action)
		if err != nil {
			status["state"] = "failed"
			status["message"] = "snapshot failed: " + err.Error()
			result.phase = "SnapshotFailed"
			result.runState = "failed"
			result.lastError = status["message"].(string)
			result.actionStatuses = append(result.actionStatuses, status)
			return result
		}
		result.rollbackRef = snapshotRef
		verification, err := r.executeTypedAction(ctx, action, false)
		if err != nil {
			if errors.Is(err, errVerificationPending) {
				status["state"] = "verifying"
				status["message"] = err.Error()
				result.phase = "Verifying"
				result.runState = "verifying"
				result.message = "cluster write completed; waiting for controller and health verification"
				result.verificationResult = err.Error()
				result.dryRunPassed = true
				result.dryRunMessage = fmt.Sprintf("Kubernetes server-side dry-run passed for %d action(s)", dryRunCount)
				result.requeueAfter = 5 * time.Second
				result.actionStatuses = append(result.actionStatuses, status)
				return result
			}
			status["state"] = "failed"
			status["message"] = err.Error()
			result.phase = "VerificationFailed"
			result.runState = "failed"
			result.lastError = err.Error()
			result.actionStatuses = append(result.actionStatuses, status)
			return result
		}
		applied++
		status["state"] = "succeeded"
		status["message"] = verification
		result.actionStatuses = append(result.actionStatuses, status)
	}
	if applied > 0 {
		result.phase = "Applied"
		result.runState = "succeeded"
		result.message = fmt.Sprintf("%d low-risk typed action(s) applied", applied)
		result.verificationResult = "all mutated objects were read back from the Kubernetes API and matched the typed action; source re-scan is still required"
		result.dryRunPassed = true
		result.dryRunMessage = fmt.Sprintf("Kubernetes server-side dry-run passed for %d action(s)", dryRunCount)
	} else if dryRunCount > 0 {
		result.phase = "DryRunPassed"
		result.runState = "dry_run_passed"
		result.message = "server-side dry-run passed; mutating remediation is disabled"
		result.verificationResult = "no cluster mutation was attempted"
		result.dryRunPassed = true
		result.dryRunMessage = fmt.Sprintf("Kubernetes server-side dry-run passed for %d action(s)", dryRunCount)
	} else if proposalOnly > 0 {
		result.phase = "ProposalOnly"
		result.runState = "proposal_only"
		result.message = "all actions are proposal-only because no executor is registered"
		result.verificationResult = "no cluster mutation or verification was attempted"
	}
	return result
}

func (r *RemediationPlanReconciler) applyResourceGovernance(ctx context.Context, namespace string, dryRun bool) error {
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
	if err := r.upsertObject(ctx, quota, dryRun); err != nil {
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
	return r.upsertObject(ctx, limitRange, dryRun)
}

func (r *RemediationPlanReconciler) executeTypedAction(ctx context.Context, action map[string]any, dryRun bool) (string, error) {
	actionType, _, _ := unstructured.NestedString(action, "type")
	switch actionType {
	case "apply_resource_governance":
		namespace, err := targetNamespace(action)
		if err != nil {
			return "", err
		}
		if err := r.applyResourceGovernance(ctx, namespace, dryRun); err != nil {
			return "", err
		}
		if dryRun {
			return "Kubernetes server-side dry-run passed for ResourceQuota and LimitRange", nil
		}
		if err := r.verifyResourceGovernance(ctx, namespace); err != nil {
			return "", fmt.Errorf("post-write verification failed: %w", err)
		}
		return "ResourceQuota and LimitRange were read back and match the planned governance profile", nil
	case "patch_pod_security_labels":
		return r.executePodSecurityLabels(ctx, action, dryRun)
	case "patch_workload_resources":
		return r.executeWorkloadResources(ctx, action, dryRun)
	case "create_pdb":
		return r.executePDB(ctx, action, dryRun)
	case "patch_workload_probes":
		return r.executeWorkloadProbes(ctx, action, dryRun)
	default:
		return "", fmt.Errorf("no direct executor registered for action %s", actionType)
	}
}

func (r *RemediationPlanReconciler) executePodSecurityLabels(ctx context.Context, action map[string]any, dryRun bool) (string, error) {
	namespace, err := targetNamespace(action)
	if err != nil {
		return "", err
	}
	if protectedNamespace(namespace) {
		return "", fmt.Errorf("namespace %s is protected from Pod Security label mutation", namespace)
	}
	params, _, _ := unstructured.NestedStringMap(action, "params")
	desired := map[string]string{
		"pod-security.kubernetes.io/enforce": valueOr(params["enforce"], "baseline"),
		"pod-security.kubernetes.io/audit":   valueOr(params["audit"], "restricted"),
		"pod-security.kubernetes.io/warn":    valueOr(params["warn"], "restricted"),
	}
	object := &corev1.Namespace{}
	if err := r.Get(ctx, types.NamespacedName{Name: namespace}, object); err != nil {
		return "", err
	}
	labels := object.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	for key, value := range desired {
		labels[key] = value
	}
	object.SetLabels(labels)
	if dryRun {
		if err := r.Update(ctx, object, client.DryRunAll); err != nil {
			return "", err
		}
		return "Kubernetes server-side dry-run passed for exact namespace label patch", nil
	}
	if err := r.Update(ctx, object); err != nil {
		return "", err
	}
	verified := &corev1.Namespace{}
	if err := r.Get(ctx, types.NamespacedName{Name: namespace}, verified); err != nil {
		return "", err
	}
	for key, value := range desired {
		if verified.Labels[key] != value {
			return "", fmt.Errorf("namespace label %s was not persisted", key)
		}
	}
	return "Pod Security labels were read back from the Namespace and match the plan", nil
}

func (r *RemediationPlanReconciler) executeWorkloadResources(ctx context.Context, action map[string]any, dryRun bool) (string, error) {
	params, _, _ := unstructured.NestedStringMap(action, "params")
	quantities := map[corev1.ResourceName]resource.Quantity{}
	for name, value := range map[corev1.ResourceName]string{
		corev1.ResourceCPU: params["cpuRequest"], corev1.ResourceMemory: params["memoryRequest"],
	} {
		quantity, err := resource.ParseQuantity(value)
		if err != nil || quantity.Sign() <= 0 {
			return "", fmt.Errorf("invalid request quantity for %s", name)
		}
		quantities[corev1.ResourceName("request."+string(name))] = quantity
	}
	for name, value := range map[corev1.ResourceName]string{
		corev1.ResourceCPU: params["cpuLimit"], corev1.ResourceMemory: params["memoryLimit"],
	} {
		quantity, err := resource.ParseQuantity(value)
		if err != nil || quantity.Sign() <= 0 {
			return "", fmt.Errorf("invalid limit quantity for %s", name)
		}
		quantities[corev1.ResourceName("limit."+string(name))] = quantity
	}
	mutate := func(spec *corev1.PodSpec) error {
		containers := append(spec.InitContainers, spec.Containers...)
		for index := range containers {
			if containers[index].Resources.Requests == nil {
				containers[index].Resources.Requests = corev1.ResourceList{}
			}
			if containers[index].Resources.Limits == nil {
				containers[index].Resources.Limits = corev1.ResourceList{}
			}
			setIfMissing(containers[index].Resources.Requests, corev1.ResourceCPU, quantities["request.cpu"])
			setIfMissing(containers[index].Resources.Requests, corev1.ResourceMemory, quantities["request.memory"])
			setIfMissing(containers[index].Resources.Limits, corev1.ResourceCPU, quantities["limit.cpu"])
			setIfMissing(containers[index].Resources.Limits, corev1.ResourceMemory, quantities["limit.memory"])
		}
		copy(spec.InitContainers, containers[:len(spec.InitContainers)])
		copy(spec.Containers, containers[len(spec.InitContainers):])
		return nil
	}
	if err := r.updateWorkload(ctx, action, dryRun, mutate); err != nil {
		return "", err
	}
	if dryRun {
		return "Kubernetes server-side dry-run passed for named workload containers", nil
	}
	if err := r.verifyWorkload(ctx, action, func(spec *corev1.PodSpec) error {
		for _, container := range append(spec.InitContainers, spec.Containers...) {
			for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
				if _, ok := container.Resources.Requests[name]; !ok {
					return fmt.Errorf("container %s is still missing request %s", container.Name, name)
				}
				if _, ok := container.Resources.Limits[name]; !ok {
					return fmt.Errorf("container %s is still missing limit %s", container.Name, name)
				}
			}
		}
		return nil
	}); err != nil {
		return "", err
	}
	if err := r.verifyWorkloadRollout(ctx, action); err != nil {
		return "", err
	}
	return "Workload resource requests and limits were read back for every container", nil
}

func (r *RemediationPlanReconciler) executeWorkloadProbes(ctx context.Context, action map[string]any, dryRun bool) (string, error) {
	params, _, _ := unstructured.NestedStringMap(action, "params")
	if params["configured"] != "true" {
		return "", fmt.Errorf("probe execution requires configured=true")
	}
	containerName := params["container"]
	port := intstr.Parse(params["port"])
	readinessPath := params["readinessPath"]
	livenessPath := params["livenessPath"]
	mutate := func(spec *corev1.PodSpec) error {
		for index := range spec.Containers {
			if spec.Containers[index].Name != containerName {
				continue
			}
			if spec.Containers[index].ReadinessProbe == nil {
				spec.Containers[index].ReadinessProbe = safeHTTPProbe(readinessPath, port, params)
			}
			if spec.Containers[index].LivenessProbe == nil {
				spec.Containers[index].LivenessProbe = safeHTTPProbe(livenessPath, port, params)
			}
			return nil
		}
		return fmt.Errorf("configured container %s does not exist", containerName)
	}
	if err := r.updateWorkload(ctx, action, dryRun, mutate); err != nil {
		return "", err
	}
	if dryRun {
		return "Kubernetes server-side dry-run passed for explicit probe configuration", nil
	}
	if err := r.verifyWorkload(ctx, action, func(spec *corev1.PodSpec) error {
		for _, container := range spec.Containers {
			if container.Name == containerName {
				if !probeMatches(container.ReadinessProbe, readinessPath, port) || !probeMatches(container.LivenessProbe, livenessPath, port) {
					return fmt.Errorf("configured probes were not persisted for container %s", containerName)
				}
				return nil
			}
		}
		return fmt.Errorf("configured container %s does not exist", containerName)
	}); err != nil {
		return "", err
	}
	if err := r.verifyWorkloadRollout(ctx, action); err != nil {
		return "", err
	}
	return "Explicit readiness and liveness probes were read back from the workload template", nil
}

func (r *RemediationPlanReconciler) executePDB(ctx context.Context, action map[string]any, dryRun bool) (string, error) {
	target, key, err := actionTarget(action)
	if err != nil {
		return "", err
	}
	selector := map[string]string{}
	switch target.Kind {
	case "Deployment":
		workload := &appsv1.Deployment{}
		if err := r.Get(ctx, key, workload); err != nil {
			return "", err
		}
		selector = workload.Spec.Selector.MatchLabels
	case "StatefulSet":
		workload := &appsv1.StatefulSet{}
		if err := r.Get(ctx, key, workload); err != nil {
			return "", err
		}
		selector = workload.Spec.Selector.MatchLabels
	default:
		return "", fmt.Errorf("PDB action does not support %s", target.Kind)
	}
	if len(selector) == 0 {
		return "", fmt.Errorf("refusing to create a PDB with an empty workload selector")
	}
	params, _, _ := unstructured.NestedStringMap(action, "params")
	minimum := intstr.Parse(params["minAvailable"])
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: target.Name + "-kubeathrix", Namespace: target.Namespace},
		Spec:       policyv1.PodDisruptionBudgetSpec{MinAvailable: &minimum, Selector: &metav1.LabelSelector{MatchLabels: selector}},
	}
	if err := r.upsertObject(ctx, pdb, dryRun); err != nil {
		return "", err
	}
	if dryRun {
		return "Kubernetes server-side dry-run passed for a non-empty exact PDB selector", nil
	}
	verified := &policyv1.PodDisruptionBudget{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: pdb.Namespace, Name: pdb.Name}, verified); err != nil {
		return "", err
	}
	if verified.Spec.Selector == nil || len(verified.Spec.Selector.MatchLabels) == 0 || verified.Spec.MinAvailable == nil || verified.Spec.MinAvailable.String() != minimum.String() {
		return "", fmt.Errorf("PodDisruptionBudget does not match the planned selector and threshold")
	}
	if verified.Status.ExpectedPods == 0 {
		return "", fmt.Errorf("%w: PodDisruptionBudget controller has not observed matching pods", errVerificationPending)
	}
	return "PodDisruptionBudget was read back with the exact workload selector and threshold", nil
}

func (r *RemediationPlanReconciler) upsertObject(ctx context.Context, obj client.Object, dryRun bool) error {
	labels := obj.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	labels["app.kubernetes.io/managed-by"] = "kubeathrix"
	obj.SetLabels(labels)
	current := obj.DeepCopyObject().(client.Object)
	err := r.Get(ctx, client.ObjectKeyFromObject(obj), current)
	if apierrors.IsNotFound(err) {
		if dryRun {
			return r.Create(ctx, obj, client.DryRunAll)
		}
		return r.Create(ctx, obj)
	}
	if err != nil {
		return err
	}
	if current.GetLabels()["app.kubernetes.io/managed-by"] != "kubeathrix" {
		return fmt.Errorf("refusing to take ownership of existing %T %s", obj, client.ObjectKeyFromObject(obj))
	}
	obj.SetResourceVersion(current.GetResourceVersion())
	if dryRun {
		return r.Update(ctx, obj, client.DryRunAll)
	}
	return r.Update(ctx, obj)
}

func (r *RemediationPlanReconciler) verifyResourceGovernance(ctx context.Context, namespace string) error {
	quota := &corev1.ResourceQuota{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "kubeathrix-defaults"}, quota); err != nil {
		return fmt.Errorf("read ResourceQuota: %w", err)
	}
	cpu, hasCPU := quota.Spec.Hard[corev1.ResourceRequestsCPU]
	memory, hasMemory := quota.Spec.Hard[corev1.ResourceRequestsMemory]
	if !hasCPU || !hasMemory || cpu.Cmp(resource.MustParse("4")) != 0 || memory.Cmp(resource.MustParse("8Gi")) != 0 {
		return fmt.Errorf("ResourceQuota does not match the planned limits")
	}
	limitRange := &corev1.LimitRange{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "kubeathrix-defaults"}, limitRange); err != nil {
		return fmt.Errorf("read LimitRange: %w", err)
	}
	if len(limitRange.Spec.Limits) != 1 {
		return fmt.Errorf("LimitRange does not contain the planned defaults")
	}
	return nil
}

type remediationTarget struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
}

func actionTarget(action map[string]any) (remediationTarget, types.NamespacedName, error) {
	target, ok, _ := unstructured.NestedMap(action, "target")
	if !ok {
		return remediationTarget{}, types.NamespacedName{}, fmt.Errorf("action target is required")
	}
	result := remediationTarget{}
	result.APIVersion, _, _ = unstructured.NestedString(target, "apiVersion")
	result.Kind, _, _ = unstructured.NestedString(target, "kind")
	result.Namespace, _, _ = unstructured.NestedString(target, "namespace")
	result.Name, _, _ = unstructured.NestedString(target, "name")
	if result.Name == "" || result.Kind == "" || result.APIVersion == "" {
		return remediationTarget{}, types.NamespacedName{}, fmt.Errorf("action target must include apiVersion, kind, and name")
	}
	if result.Kind != "Namespace" && result.Namespace == "" {
		return remediationTarget{}, types.NamespacedName{}, fmt.Errorf("namespaced action target requires namespace")
	}
	return result, types.NamespacedName{Namespace: result.Namespace, Name: result.Name}, nil
}

func (r *RemediationPlanReconciler) updateWorkload(ctx context.Context, action map[string]any, dryRun bool, mutate func(*corev1.PodSpec) error) error {
	target, key, err := actionTarget(action)
	if err != nil {
		return err
	}
	var object client.Object
	switch target.Kind {
	case "Deployment":
		object = &appsv1.Deployment{}
	case "StatefulSet":
		object = &appsv1.StatefulSet{}
	case "DaemonSet":
		object = &appsv1.DaemonSet{}
	default:
		return fmt.Errorf("unsupported workload kind %s", target.Kind)
	}
	if err := r.Get(ctx, key, object); err != nil {
		return err
	}
	spec, err := workloadPodSpec(object)
	if err != nil {
		return err
	}
	if err := mutate(spec); err != nil {
		return err
	}
	if dryRun {
		return r.Update(ctx, object, client.DryRunAll)
	}
	return r.Update(ctx, object)
}

func (r *RemediationPlanReconciler) verifyWorkload(ctx context.Context, action map[string]any, verify func(*corev1.PodSpec) error) error {
	target, key, err := actionTarget(action)
	if err != nil {
		return err
	}
	var object client.Object
	switch target.Kind {
	case "Deployment":
		object = &appsv1.Deployment{}
	case "StatefulSet":
		object = &appsv1.StatefulSet{}
	case "DaemonSet":
		object = &appsv1.DaemonSet{}
	default:
		return fmt.Errorf("unsupported workload kind %s", target.Kind)
	}
	if err := r.Get(ctx, key, object); err != nil {
		return err
	}
	spec, err := workloadPodSpec(object)
	if err != nil {
		return err
	}
	return verify(spec)
}

func (r *RemediationPlanReconciler) verifyWorkloadRollout(ctx context.Context, action map[string]any) error {
	target, key, err := actionTarget(action)
	if err != nil {
		return err
	}
	switch target.Kind {
	case "Deployment":
		workload := &appsv1.Deployment{}
		if err := r.Get(ctx, key, workload); err != nil {
			return err
		}
		desired := int32(1)
		if workload.Spec.Replicas != nil {
			desired = *workload.Spec.Replicas
		}
		if workload.Status.ObservedGeneration < workload.Generation || workload.Status.UpdatedReplicas < desired || workload.Status.AvailableReplicas < desired {
			return fmt.Errorf("%w: Deployment rollout is not yet available", errVerificationPending)
		}
	case "StatefulSet":
		workload := &appsv1.StatefulSet{}
		if err := r.Get(ctx, key, workload); err != nil {
			return err
		}
		desired := int32(1)
		if workload.Spec.Replicas != nil {
			desired = *workload.Spec.Replicas
		}
		if workload.Status.ObservedGeneration < workload.Generation || workload.Status.ReadyReplicas < desired || workload.Status.UpdatedReplicas < desired {
			return fmt.Errorf("%w: StatefulSet rollout is not yet ready", errVerificationPending)
		}
	case "DaemonSet":
		workload := &appsv1.DaemonSet{}
		if err := r.Get(ctx, key, workload); err != nil {
			return err
		}
		if workload.Status.ObservedGeneration < workload.Generation || workload.Status.DesiredNumberScheduled == 0 || workload.Status.UpdatedNumberScheduled < workload.Status.DesiredNumberScheduled || workload.Status.NumberAvailable < workload.Status.DesiredNumberScheduled {
			return fmt.Errorf("%w: DaemonSet rollout is not yet ready", errVerificationPending)
		}
	}
	return nil
}

func workloadPodSpec(object client.Object) (*corev1.PodSpec, error) {
	switch workload := object.(type) {
	case *appsv1.Deployment:
		return &workload.Spec.Template.Spec, nil
	case *appsv1.StatefulSet:
		return &workload.Spec.Template.Spec, nil
	case *appsv1.DaemonSet:
		return &workload.Spec.Template.Spec, nil
	default:
		return nil, fmt.Errorf("unsupported workload object %T", object)
	}
}

func setIfMissing(values corev1.ResourceList, name corev1.ResourceName, quantity resource.Quantity) {
	if _, ok := values[name]; !ok {
		values[name] = quantity.DeepCopy()
	}
}

func safeHTTPProbe(path string, port intstr.IntOrString, params map[string]string) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: path, Port: port}},
		InitialDelaySeconds: boundedInt(params["initialDelaySeconds"], 5, 0, 300),
		PeriodSeconds:       boundedInt(params["periodSeconds"], 10, 2, 300),
		TimeoutSeconds:      boundedInt(params["timeoutSeconds"], 2, 1, 30),
		FailureThreshold:    boundedInt(params["failureThreshold"], 3, 1, 10),
		SuccessThreshold:    1,
	}
}

func probeMatches(probe *corev1.Probe, path string, port intstr.IntOrString) bool {
	return probe != nil && probe.HTTPGet != nil && probe.HTTPGet.Path == path && probe.HTTPGet.Port == port
}

func boundedInt(raw string, fallback, minimum, maximum int32) int32 {
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || value < int64(minimum) || value > int64(maximum) {
		return fallback
	}
	return int32(value)
}

func protectedNamespace(namespace string) bool {
	if namespace == "kube-system" || namespace == "kube-public" || namespace == "kube-node-lease" {
		return true
	}
	return strings.HasPrefix(namespace, "openshift-")
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

type snapshotItem struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Namespace  string         `json:"namespace,omitempty"`
	Name       string         `json:"name"`
	Existed    bool           `json:"existed"`
	Object     map[string]any `json:"object,omitempty"`
}

func (r *RemediationPlanReconciler) ensureActionSnapshot(ctx context.Context, plan *unstructured.Unstructured, action map[string]any) (string, error) {
	configMapName := childName("snapshot-", plan.GetName())
	configMap := &corev1.ConfigMap{}
	key := snapshotKey(action)
	err := r.Get(ctx, types.NamespacedName{Namespace: plan.GetNamespace(), Name: configMapName}, configMap)
	if err == nil {
		if _, ok := configMap.Data[key]; ok {
			return "ConfigMap/" + plan.GetNamespace() + "/" + configMapName + "#" + key, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return "", err
	} else {
		configMap = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Name: configMapName, Namespace: plan.GetNamespace(),
			Labels: map[string]string{"app.kubernetes.io/managed-by": "kubeathrix", "security.kubeathrix.io/plan": plan.GetName()},
		}, Data: map[string]string{}}
	}
	items, err := r.snapshotItemsForAction(ctx, action)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	if len(payload) > 900*1024 {
		return "", fmt.Errorf("snapshot exceeds the safe ConfigMap payload limit")
	}
	if configMap.Data == nil {
		configMap.Data = map[string]string{}
	}
	configMap.Data[key] = string(payload)
	if configMap.ResourceVersion == "" {
		if err := r.Create(ctx, configMap); err != nil {
			return "", err
		}
	} else if err := r.Update(ctx, configMap); err != nil {
		return "", err
	}
	return "ConfigMap/" + plan.GetNamespace() + "/" + configMapName + "#" + key, nil
}

func (r *RemediationPlanReconciler) snapshotItemsForAction(ctx context.Context, action map[string]any) ([]snapshotItem, error) {
	actionType, _, _ := unstructured.NestedString(action, "type")
	target, key, err := actionTarget(action)
	if err != nil {
		return nil, err
	}
	refs := []remediationTarget{target}
	switch actionType {
	case "apply_resource_governance":
		namespace, err := targetNamespace(action)
		if err != nil {
			return nil, err
		}
		refs = []remediationTarget{
			{APIVersion: "v1", Kind: "ResourceQuota", Namespace: namespace, Name: "kubeathrix-defaults"},
			{APIVersion: "v1", Kind: "LimitRange", Namespace: namespace, Name: "kubeathrix-defaults"},
		}
	case "create_pdb":
		refs = []remediationTarget{{APIVersion: "policy/v1", Kind: "PodDisruptionBudget", Namespace: target.Namespace, Name: target.Name + "-kubeathrix"}}
	case "patch_pod_security_labels":
		refs = []remediationTarget{{APIVersion: "v1", Kind: "Namespace", Name: target.Name}}
	case "patch_workload_resources", "patch_workload_probes":
		_ = key
	default:
		return nil, fmt.Errorf("action %s does not support snapshots", actionType)
	}
	items := make([]snapshotItem, 0, len(refs))
	for _, ref := range refs {
		object := &unstructured.Unstructured{}
		object.SetAPIVersion(ref.APIVersion)
		object.SetKind(ref.Kind)
		err := r.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, object)
		if apierrors.IsNotFound(err) {
			items = append(items, snapshotItem{APIVersion: ref.APIVersion, Kind: ref.Kind, Namespace: ref.Namespace, Name: ref.Name, Existed: false})
			continue
		}
		if err != nil {
			return nil, err
		}
		sanitizeObject(object)
		items = append(items, snapshotItem{APIVersion: ref.APIVersion, Kind: ref.Kind, Namespace: ref.Namespace, Name: ref.Name, Existed: true, Object: object.Object})
	}
	return items, nil
}

func (r *RemediationPlanReconciler) reconcileRollback(ctx context.Context, plan *unstructured.Unstructured) planResult {
	result := planResult{
		phase: "RollingBack", runState: "running", message: "restoring pre-change snapshots",
		verificationResult: "rollback verification is in progress", dryRunMessage: "not applicable to rollback",
	}
	configMapName := childName("snapshot-", plan.GetName())
	configMap := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: plan.GetNamespace(), Name: configMapName}, configMap); err != nil {
		result.phase, result.runState, result.lastError = "RollbackFailed", "failed", "load rollback snapshot: "+err.Error()
		result.message = result.lastError
		return result
	}
	keys := make([]string, 0, len(configMap.Data))
	for key := range configMap.Data {
		keys = append(keys, key)
	}
	for _, key := range keys {
		var items []snapshotItem
		if err := json.Unmarshal([]byte(configMap.Data[key]), &items); err != nil {
			result.phase, result.runState, result.lastError = "RollbackFailed", "failed", "decode rollback snapshot: "+err.Error()
			result.message = result.lastError
			return result
		}
		for _, item := range items {
			if err := r.restoreSnapshotItem(ctx, item); err != nil {
				result.phase, result.runState, result.lastError = "RollbackFailed", "failed", err.Error()
				result.message = result.lastError
				return result
			}
			result.actionStatuses = append(result.actionStatuses, map[string]any{"actionType": "rollback", "state": "rolled_back", "message": item.Kind + "/" + item.Name + " restored and verified"})
		}
	}
	result.phase = "RolledBack"
	result.runState = "rolled_back"
	result.message = fmt.Sprintf("restored and verified %d snapshot set(s)", len(keys))
	result.verificationResult = "restored objects were read back or created objects were confirmed deleted"
	result.rollbackRef = "ConfigMap/" + plan.GetNamespace() + "/" + configMapName
	return result
}

func (r *RemediationPlanReconciler) restoreSnapshotItem(ctx context.Context, item snapshotItem) error {
	current := &unstructured.Unstructured{}
	current.SetAPIVersion(item.APIVersion)
	current.SetKind(item.Kind)
	key := types.NamespacedName{Namespace: item.Namespace, Name: item.Name}
	err := r.Get(ctx, key, current)
	if !item.Existed {
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.GetLabels()["app.kubernetes.io/managed-by"] != "kubeathrix" {
			return fmt.Errorf("refusing to delete non-KubeAthrix object %s/%s during rollback", item.Kind, item.Name)
		}
		if err := r.Delete(ctx, current); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		check := &unstructured.Unstructured{}
		check.SetAPIVersion(item.APIVersion)
		check.SetKind(item.Kind)
		if err := r.Get(ctx, key, check); !apierrors.IsNotFound(err) {
			return fmt.Errorf("rollback deletion was not observed for %s/%s", item.Kind, item.Name)
		}
		return nil
	}
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		restored := &unstructured.Unstructured{Object: item.Object}
		if err := r.Create(ctx, restored); err != nil {
			return err
		}
	} else {
		restored := &unstructured.Unstructured{Object: item.Object}
		restored.SetResourceVersion(current.GetResourceVersion())
		if err := r.Update(ctx, restored); err != nil {
			return err
		}
	}
	verified := &unstructured.Unstructured{}
	verified.SetAPIVersion(item.APIVersion)
	verified.SetKind(item.Kind)
	if err := r.Get(ctx, key, verified); err != nil {
		return err
	}
	expected := &unstructured.Unstructured{Object: item.Object}
	if objectState(verified) != objectState(expected) {
		return fmt.Errorf("restored object %s/%s does not match the snapshot", item.Kind, item.Name)
	}
	return nil
}

func sanitizeObject(object *unstructured.Unstructured) {
	delete(object.Object, "status")
	metadata, _, _ := unstructured.NestedMap(object.Object, "metadata")
	for _, key := range []string{"resourceVersion", "uid", "generation", "creationTimestamp", "managedFields", "selfLink"} {
		delete(metadata, key)
	}
	_ = unstructured.SetNestedMap(object.Object, metadata, "metadata")
}

func objectState(object *unstructured.Unstructured) string {
	spec, _, _ := unstructured.NestedFieldNoCopy(object.Object, "spec")
	labels := object.GetLabels()
	payload, _ := json.Marshal(map[string]any{"spec": spec, "labels": labels})
	return string(payload)
}

func snapshotKey(action map[string]any) string {
	payload, _ := json.Marshal(action)
	hash := sha256.Sum256(payload)
	actionType, _, _ := unstructured.NestedString(action, "type")
	return strings.ReplaceAll(actionType, "_", "-") + "-" + hex.EncodeToString(hash[:])[:12] + ".json"
}

func childName(prefix, parent string) string {
	value := prefix + parent
	if len(value) <= 63 {
		return value
	}
	hash := sha256.Sum256([]byte(value))
	return strings.Trim(value[:50], "-") + "-" + hex.EncodeToString(hash[:])[:12]
}

func (r *RemediationPlanReconciler) writePlanStatus(ctx context.Context, plan *unstructured.Unstructured, result planResult, now time.Time) error {
	runName, _, _ := unstructured.NestedString(plan.Object, "spec", "runName")
	if runName == "" {
		runName = "run-" + plan.GetName()
	}
	status := map[string]any{
		"phase":              result.phase,
		"observedGeneration": plan.GetGeneration(),
		"lastTransitionTime": now.Format(time.RFC3339),
		"message":            result.message,
		"diffSummary":        result.diffSummary,
		"approvalRef":        "approval-" + plan.GetName(),
		"runRef":             runName,
		"verificationResult": result.verificationResult,
		"rollbackRef":        result.rollbackRef,
	}
	if result.lastError != "" {
		status["lastError"] = result.lastError
	}
	status["dryRunResult"] = map[string]any{"passed": result.dryRunPassed, "message": result.dryRunMessage}
	plan.Object["status"] = status
	return r.Status().Update(ctx, plan)
}

func (r *RemediationPlanReconciler) upsertRun(ctx context.Context, plan *unstructured.Unstructured, result planResult, now time.Time) error {
	runName, _, _ := unstructured.NestedString(plan.Object, "spec", "runName")
	if runName == "" {
		runName = "run-" + plan.GetName()
	}
	run := NewRemediationRunObject(types.NamespacedName{Namespace: plan.GetNamespace(), Name: runName})
	err := r.Get(ctx, client.ObjectKeyFromObject(run), run)
	if apierrors.IsNotFound(err) {
		run.Object["spec"] = map[string]any{"planRef": map[string]any{"name": plan.GetName(), "namespace": plan.GetNamespace()}}
		if planID := plan.GetAnnotations()["security.kubeathrix.io/api-id"]; planID != "" {
			run.SetAnnotations(map[string]string{
				"security.kubeathrix.io/api-id":  "run-" + planID,
				"security.kubeathrix.io/plan-id": planID,
			})
		}
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

func (r *RemediationPlanReconciler) updateFindingStatus(ctx context.Context, plan *unstructured.Unstructured, result planResult, now time.Time) error {
	findingName, _, _ := unstructured.NestedString(plan.Object, "spec", "findingRef", "name")
	findingNamespace, _, _ := unstructured.NestedString(plan.Object, "spec", "findingRef", "namespace")
	if findingName == "" {
		return nil
	}
	if findingNamespace == "" {
		findingNamespace = plan.GetNamespace()
	}
	finding := NewFindingObject(types.NamespacedName{Namespace: findingNamespace, Name: findingName})
	if err := r.Get(ctx, client.ObjectKeyFromObject(finding), finding); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	phase := "InReview"
	remediationState := result.runState
	switch result.runState {
	case "succeeded":
		phase = "Resolved"
		remediationState = "verified_resolved"
	case "verifying", "running":
		phase = "Remediating"
	case "rolled_back":
		phase = "Open"
		remediationState = "rolled_back"
	case "prepared", "pending_approval", "approved", "proposal_only", "dry_run_passed":
		return nil
	}
	status := map[string]any{
		"phase": phase, "remediationState": remediationState,
		"verificationResult": result.verificationResult,
		"observedGeneration": finding.GetGeneration(), "lastTransitionTime": now.Format(time.RFC3339),
	}
	if result.lastError != "" {
		status["lastError"] = result.lastError
	}
	finding.Object["status"] = status
	return r.Status().Update(ctx, finding)
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
