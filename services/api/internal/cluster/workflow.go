package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/retry"
)

var (
	ErrWorkflowNotFound = errors.New("workflow object not found")
	ErrWorkflowConflict = errors.New("workflow object conflict")
)

var (
	findingResource   = schema.GroupVersionResource{Group: "security.kubeathrix.io", Version: "v1alpha1", Resource: "findings"}
	planResource      = schema.GroupVersionResource{Group: "security.kubeathrix.io", Version: "v1alpha1", Resource: "remediationplans"}
	approvalResource  = schema.GroupVersionResource{Group: "security.kubeathrix.io", Version: "v1alpha1", Resource: "approvalrequests"}
	runResource       = schema.GroupVersionResource{Group: "security.kubeathrix.io", Version: "v1alpha1", Resource: "remediationruns"}
	exceptionResource = schema.GroupVersionResource{Group: "security.kubeathrix.io", Version: "v1alpha1", Resource: "exceptions"}
)

const (
	apiIDAnnotation     = "security.kubeathrix.io/api-id"
	findingIDAnnotation = "security.kubeathrix.io/finding-id"
	actorAnnotation     = "security.kubeathrix.io/actor"
)

type WorkflowClient struct {
	client    dynamic.Interface
	namespace string
	now       func() time.Time
}

func (c *WorkflowClient) CreateException(ctx context.Context, exception core.Exception) error {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "security.kubeathrix.io/v1alpha1", "kind": "Exception",
		"metadata": map[string]any{"name": ObjectName(exception.ID), "namespace": c.namespace, "annotations": map[string]any{apiIDAnnotation: exception.ID}},
		"spec":     map[string]any{"scope": exception.Scope, "owner": exception.Owner, "reason": exception.Reason, "expiresAt": exception.ExpiresAt.UTC().Format(time.RFC3339), "auditMetadata": exception.AuditMetadata},
	}}
	_, err := c.client.Resource(exceptionResource).Namespace(c.namespace).Create(ctx, object, metav1.CreateOptions{FieldManager: "kubeathrix-api"})
	if apierrors.IsAlreadyExists(err) {
		current, getErr := c.client.Resource(exceptionResource).Namespace(c.namespace).Get(ctx, object.GetName(), metav1.GetOptions{})
		if getErr != nil {
			return workflowError(getErr)
		}
		if annotationOr(current, apiIDAnnotation, "") == exception.ID {
			return nil
		}
	}
	return workflowError(err)
}

func (c *WorkflowClient) SetFindingStatus(ctx context.Context, finding core.Finding, status core.FindingStatus, actor, reason string) error {
	finding.Status = status
	finding.UpdatedAt = c.now().UTC()
	if err := c.upsertFinding(ctx, finding); err != nil {
		return err
	}
	resource := c.client.Resource(findingResource).Namespace(c.namespace)
	name := ObjectName(finding.ID)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		object, err := resource.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return workflowError(err)
		}
		annotations := object.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[actorAnnotation] = actor
		annotations["security.kubeathrix.io/status-reason"] = reason
		object.SetAnnotations(annotations)
		if err := unstructured.SetNestedField(object.Object, string(status), "spec", "findingStatus"); err != nil {
			return err
		}
		_, err = resource.Update(ctx, object, metav1.UpdateOptions{FieldManager: "kubeathrix-api"})
		return err
	})
}

func (c *WorkflowClient) DeleteException(ctx context.Context, id string) error {
	err := c.client.Resource(exceptionResource).Namespace(c.namespace).Delete(ctx, ObjectName(id), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return workflowError(err)
}

func NewWorkflowClient(namespace string) (*WorkflowClient, error) {
	config, err := kubeConfig()
	if err != nil {
		return nil, err
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return NewWorkflowClientFromDynamic(client, namespace, nil), nil
}

func NewWorkflowClientFromDynamic(client dynamic.Interface, namespace string, now func() time.Time) *WorkflowClient {
	if namespace == "" {
		namespace = "kubeathrix"
	}
	if now == nil {
		now = time.Now
	}
	return &WorkflowClient{client: client, namespace: namespace, now: now}
}

func (c *WorkflowClient) Health(ctx context.Context) error {
	_, err := c.client.Resource(planResource).Namespace(c.namespace).List(ctx, metav1.ListOptions{Limit: 1})
	return err
}

func (c *WorkflowClient) ListFindings(ctx context.Context) ([]core.Finding, error) {
	list, err := c.client.Resource(findingResource).Namespace(c.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, workflowError(err)
	}
	findings := make([]core.Finding, 0, len(list.Items))
	for index := range list.Items {
		finding, err := findingFromObject(&list.Items[index])
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func (c *WorkflowClient) GetFinding(ctx context.Context, findingID string) (core.Finding, error) {
	object, err := c.client.Resource(findingResource).Namespace(c.namespace).Get(ctx, ObjectName(findingID), metav1.GetOptions{})
	if err != nil {
		return core.Finding{}, workflowError(err)
	}
	return findingFromObject(object)
}

func (c *WorkflowClient) CreatePlan(ctx context.Context, finding core.Finding, plan core.RemediationPlan, actor string) error {
	if finding.ID == "" || plan.ID == "" || plan.FindingID != finding.ID {
		return fmt.Errorf("invalid finding or remediation plan identity")
	}
	if err := c.upsertFinding(ctx, finding); err != nil {
		return fmt.Errorf("persist Finding CRD: %w", err)
	}
	actions, err := jsonValue(plan.Actions)
	if err != nil {
		return err
	}
	verificationSteps, err := jsonValue(plan.VerificationSteps)
	if err != nil {
		return err
	}
	rollbackSteps, err := jsonValue(plan.RollbackSteps)
	if err != nil {
		return err
	}
	approvalPolicy, err := jsonMap(plan.ApprovalPolicy)
	if err != nil {
		return err
	}
	dryRunResult, err := jsonMap(plan.DryRunResult)
	if err != nil {
		return err
	}
	planSpec := map[string]any{
		"findingRef":         map[string]any{"name": ObjectName(finding.ID), "namespace": c.namespace},
		"rootCause":          plan.RootCause,
		"actions":            actions,
		"riskTier":           string(plan.RiskTier),
		"catalogVersion":     plan.CatalogVersion,
		"dryRunResult":       dryRunResult,
		"verificationSteps":  verificationSteps,
		"rollbackSteps":      rollbackSteps,
		"approvalPolicy":     approvalPolicy,
		"executionRequested": false,
		"runName":            ObjectName("run-" + plan.ID),
	}
	if plan.AI != nil {
		aiAnalysis, mapErr := jsonMap(plan.AI)
		if mapErr != nil {
			return mapErr
		}
		planSpec["ai"] = aiAnalysis
	}
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "security.kubeathrix.io/v1alpha1",
		"kind":       "RemediationPlan",
		"metadata": map[string]any{
			"name":      ObjectName(plan.ID),
			"namespace": c.namespace,
			"annotations": map[string]any{
				apiIDAnnotation:     plan.ID,
				findingIDAnnotation: finding.ID,
				actorAnnotation:     actor,
			},
		},
		"spec": planSpec,
	}}
	if err := c.createIdempotent(ctx, planResource, object, plan.ID); err != nil {
		return fmt.Errorf("persist RemediationPlan CRD: %w", err)
	}
	if plan.ApprovalPolicy.Required {
		approval := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "security.kubeathrix.io/v1alpha1",
			"kind":       "ApprovalRequest",
			"metadata": map[string]any{
				"name":        ObjectName("approval-" + plan.ID),
				"namespace":   c.namespace,
				"annotations": map[string]any{apiIDAnnotation: "approval-" + plan.ID, actorAnnotation: actor},
			},
			"spec": map[string]any{
				"subjectRef":      ObjectName(plan.ID),
				"requestedAction": primaryActionDescription(plan),
				"requester":       actor,
				"expiresAt":       c.now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
				"decision":        "pending",
			},
		}}
		if err := c.createIdempotent(ctx, approvalResource, approval, "approval-"+plan.ID); err != nil {
			return fmt.Errorf("persist ApprovalRequest CRD: %w", err)
		}
	}
	return nil
}

func (c *WorkflowClient) DecideApproval(ctx context.Context, approvalID string, decision core.ApprovalStatus, actor, reason string) (core.ApprovalRequest, error) {
	if decision != core.ApprovalApproved && decision != core.ApprovalRejected {
		return core.ApprovalRequest{}, fmt.Errorf("unsupported approval decision %q", decision)
	}
	name := ObjectName(approvalID)
	var updated *unstructured.Unstructured
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		object, err := c.client.Resource(approvalResource).Namespace(c.namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		current, _, _ := unstructured.NestedString(object.Object, "spec", "decision")
		if current != "" && current != "pending" && current != string(decision) {
			return fmt.Errorf("%w: approval is already %s", ErrWorkflowConflict, current)
		}
		if err := unstructured.SetNestedField(object.Object, string(decision), "spec", "decision"); err != nil {
			return err
		}
		if err := unstructured.SetNestedField(object.Object, actor, "spec", "decidedBy"); err != nil {
			return err
		}
		if err := unstructured.SetNestedField(object.Object, reason, "spec", "decisionReason"); err != nil {
			return err
		}
		if err := unstructured.SetNestedField(object.Object, c.now().UTC().Format(time.RFC3339), "spec", "decidedAt"); err != nil {
			return err
		}
		updated, err = c.client.Resource(approvalResource).Namespace(c.namespace).Update(ctx, object, metav1.UpdateOptions{FieldManager: "kubeathrix-api"})
		return err
	})
	if err != nil {
		return core.ApprovalRequest{}, workflowError(err)
	}
	planName, _, _ := unstructured.NestedString(updated.Object, "spec", "subjectRef")
	if planName != "" {
		if err := c.setPlanApprovalDecision(ctx, planName, decision); err != nil {
			return core.ApprovalRequest{}, err
		}
	}
	return approvalFromObject(updated), nil
}

func (c *WorkflowClient) RequestExecution(ctx context.Context, planID, actor string) (core.RemediationRun, error) {
	name := ObjectName(planID)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		object, err := c.client.Resource(planResource).Namespace(c.namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		required, _, _ := unstructured.NestedBool(object.Object, "spec", "approvalPolicy", "required")
		decision, _, _ := unstructured.NestedString(object.Object, "spec", "approvalPolicy", "decision")
		if required && decision != string(core.ApprovalApproved) {
			return fmt.Errorf("%w: approval is still required", ErrWorkflowConflict)
		}
		if err := unstructured.SetNestedField(object.Object, true, "spec", "executionRequested"); err != nil {
			return err
		}
		if err := unstructured.SetNestedField(object.Object, actor, "spec", "executionRequestedBy"); err != nil {
			return err
		}
		if err := unstructured.SetNestedField(object.Object, c.now().UTC().Format(time.RFC3339), "spec", "executionRequestedAt"); err != nil {
			return err
		}
		_, err = c.client.Resource(planResource).Namespace(c.namespace).Update(ctx, object, metav1.UpdateOptions{FieldManager: "kubeathrix-api"})
		return err
	})
	if err != nil {
		return core.RemediationRun{}, workflowError(err)
	}
	now := c.now().UTC()
	return core.RemediationRun{
		ID:               "run-" + planID,
		PlanID:           planID,
		State:            core.RunExecutionRequested,
		ValidationResult: "execution request is persisted in the RemediationPlan CRD; controller status is pending",
		RollbackMetadata: "no snapshot exists until the controller begins a mutating action",
		CreatedAt:        now,
		UpdatedAt:        now,
	}, nil
}

func (c *WorkflowClient) RequestRollback(ctx context.Context, runID, actor string) (core.RemediationRun, error) {
	run, err := c.GetRun(ctx, runID)
	if err != nil {
		return core.RemediationRun{}, err
	}
	if run.State != core.RunSucceeded && run.State != core.RunFailed && run.State != core.RunVerifying {
		return core.RemediationRun{}, fmt.Errorf("%w: run state %s is not eligible for rollback", ErrWorkflowConflict, run.State)
	}
	planName := ObjectName(run.PlanID)
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		object, err := c.client.Resource(planResource).Namespace(c.namespace).Get(ctx, planName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if err := unstructured.SetNestedField(object.Object, true, "spec", "rollbackRequested"); err != nil {
			return err
		}
		if err := unstructured.SetNestedField(object.Object, actor, "spec", "rollbackRequestedBy"); err != nil {
			return err
		}
		if err := unstructured.SetNestedField(object.Object, c.now().UTC().Format(time.RFC3339), "spec", "rollbackRequestedAt"); err != nil {
			return err
		}
		_, err = c.client.Resource(planResource).Namespace(c.namespace).Update(ctx, object, metav1.UpdateOptions{FieldManager: "kubeathrix-api"})
		return err
	})
	if err != nil {
		return core.RemediationRun{}, workflowError(err)
	}
	run.State = core.RunRollbackRequested
	run.UpdatedAt = c.now().UTC()
	run.ValidationResult = "rollback request is persisted in the RemediationPlan CRD; controller restoration is pending"
	return run, nil
}

func (c *WorkflowClient) GetRun(ctx context.Context, runID string) (core.RemediationRun, error) {
	object, err := c.client.Resource(runResource).Namespace(c.namespace).Get(ctx, ObjectName(runID), metav1.GetOptions{})
	if err != nil {
		return core.RemediationRun{}, workflowError(err)
	}
	planName, _, _ := unstructured.NestedString(object.Object, "spec", "planRef", "name")
	planID := object.GetAnnotations()["security.kubeathrix.io/plan-id"]
	if planID == "" {
		planID = planName
	}
	if planName != "" {
		if plan, getErr := c.client.Resource(planResource).Namespace(c.namespace).Get(ctx, planName, metav1.GetOptions{}); getErr == nil {
			if value := plan.GetAnnotations()[apiIDAnnotation]; value != "" {
				planID = value
			}
		}
	}
	state, _, _ := unstructured.NestedString(object.Object, "status", "state")
	validation, _, _ := unstructured.NestedString(object.Object, "status", "validationResult")
	rollback, _, _ := unstructured.NestedString(object.Object, "status", "rollbackMetadata")
	statuses, _, _ := unstructured.NestedSlice(object.Object, "status", "actionStatuses")
	actionStatuses := make([]core.ActionStatus, 0, len(statuses))
	for _, raw := range statuses {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		actionType, _, _ := unstructured.NestedString(item, "actionType")
		actionState, _, _ := unstructured.NestedString(item, "state")
		message, _, _ := unstructured.NestedString(item, "message")
		actionStatuses = append(actionStatuses, core.ActionStatus{ActionType: actionType, State: actionState, Message: message})
	}
	return core.RemediationRun{
		ID:               annotationOr(object, apiIDAnnotation, runID),
		PlanID:           planID,
		State:            core.RunState(state),
		ActionStatuses:   actionStatuses,
		ValidationResult: validation,
		RollbackMetadata: rollback,
		CreatedAt:        object.GetCreationTimestamp().Time,
		UpdatedAt:        transitionTime(object),
	}, nil
}

func (c *WorkflowClient) ListApprovals(ctx context.Context) ([]core.ApprovalRequest, error) {
	list, err := c.client.Resource(approvalResource).Namespace(c.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, workflowError(err)
	}
	approvals := make([]core.ApprovalRequest, 0, len(list.Items))
	for index := range list.Items {
		approvals = append(approvals, approvalFromObject(&list.Items[index]))
	}
	return approvals, nil
}

func (c *WorkflowClient) ListRuns(ctx context.Context) ([]core.RemediationRun, error) {
	list, err := c.client.Resource(runResource).Namespace(c.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, workflowError(err)
	}
	runs := make([]core.RemediationRun, 0, len(list.Items))
	for index := range list.Items {
		apiID := annotationOr(&list.Items[index], apiIDAnnotation, list.Items[index].GetName())
		run, err := c.GetRun(ctx, apiID)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, nil
}

func (c *WorkflowClient) upsertFinding(ctx context.Context, finding core.Finding) error {
	evidence, err := jsonValue(finding.Evidence)
	if err != nil {
		return err
	}
	resources, err := jsonValue(finding.Resources)
	if err != nil {
		return err
	}
	correlationKeys, err := jsonObject(finding.CorrelationKeys)
	if err != nil {
		return err
	}
	riskExplanation, err := jsonObject(finding.RiskExplanation)
	if err != nil {
		return err
	}
	spec := map[string]any{
		"source": finding.Source, "title": finding.Title, "severity": string(finding.Severity),
		"evidence": evidence, "resources": resources, "blastRadius": finding.BlastRadius,
		"fixability": string(finding.Fixability), "findingStatus": string(finding.Status),
		"correlationGroup": finding.CorrelationGroup, "riskScore": int64(finding.RiskScore),
		"correlationKeys": correlationKeys, "riskExplanation": riskExplanation,
		"remediationState": finding.RemediationState, "recommendedAction": finding.RecommendedAction,
	}
	name := ObjectName(finding.ID)
	resource := c.client.Resource(findingResource).Namespace(c.namespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := resource.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			object := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "security.kubeathrix.io/v1alpha1", "kind": "Finding",
				"metadata": map[string]any{"name": name, "namespace": c.namespace, "annotations": map[string]any{apiIDAnnotation: finding.ID}},
				"spec":     spec,
			}}
			_, err = resource.Create(ctx, object, metav1.CreateOptions{FieldManager: "kubeathrix-api"})
			return err
		}
		if err != nil {
			return err
		}
		if annotationOr(current, apiIDAnnotation, "") != finding.ID {
			return ErrWorkflowConflict
		}
		current.Object["spec"] = spec
		_, err = resource.Update(ctx, current, metav1.UpdateOptions{FieldManager: "kubeathrix-api"})
		return err
	})
}

func (c *WorkflowClient) createIdempotent(ctx context.Context, resource schema.GroupVersionResource, object *unstructured.Unstructured, apiID string) error {
	objects := c.client.Resource(resource).Namespace(c.namespace)
	_, err := objects.Create(ctx, object, metav1.CreateOptions{FieldManager: "kubeathrix-api"})
	if !apierrors.IsAlreadyExists(err) {
		return err
	}
	existing, getErr := objects.Get(ctx, object.GetName(), metav1.GetOptions{})
	if getErr != nil {
		return getErr
	}
	if annotationOr(existing, apiIDAnnotation, "") != apiID {
		return ErrWorkflowConflict
	}
	return nil
}

func (c *WorkflowClient) setPlanApprovalDecision(ctx context.Context, planName string, decision core.ApprovalStatus) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		object, err := c.client.Resource(planResource).Namespace(c.namespace).Get(ctx, planName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if err := unstructured.SetNestedField(object.Object, string(decision), "spec", "approvalPolicy", "decision"); err != nil {
			return err
		}
		_, err = c.client.Resource(planResource).Namespace(c.namespace).Update(ctx, object, metav1.UpdateOptions{FieldManager: "kubeathrix-api"})
		return err
	})
}

func approvalFromObject(object *unstructured.Unstructured) core.ApprovalRequest {
	decision, _, _ := unstructured.NestedString(object.Object, "spec", "decision")
	subject, _, _ := unstructured.NestedString(object.Object, "spec", "subjectRef")
	action, _, _ := unstructured.NestedString(object.Object, "spec", "requestedAction")
	requester, _, _ := unstructured.NestedString(object.Object, "spec", "requester")
	approver, _, _ := unstructured.NestedString(object.Object, "spec", "decidedBy")
	reason, _, _ := unstructured.NestedString(object.Object, "spec", "decisionReason")
	expires, _, _ := unstructured.NestedString(object.Object, "spec", "expiresAt")
	expiresAt, _ := time.Parse(time.RFC3339, expires)
	updated := object.GetCreationTimestamp().Time
	if decidedAt, _, _ := unstructured.NestedString(object.Object, "spec", "decidedAt"); decidedAt != "" {
		updated, _ = time.Parse(time.RFC3339, decidedAt)
	}
	return core.ApprovalRequest{
		ID: annotationOr(object, apiIDAnnotation, object.GetName()), SubjectRef: subject,
		RequestedAction: action, Requester: requester, Approver: approver,
		Status: core.ApprovalStatus(decision), ExpiresAt: expiresAt,
		CreatedAt: object.GetCreationTimestamp().Time, UpdatedAt: updated, DecisionReason: reason,
	}
}

func findingFromObject(object *unstructured.Unstructured) (core.Finding, error) {
	spec, ok, err := unstructured.NestedMap(object.Object, "spec")
	if err != nil || !ok {
		return core.Finding{}, fmt.Errorf("Finding CRD %s has no spec", object.GetName())
	}
	payload, err := json.Marshal(spec)
	if err != nil {
		return core.Finding{}, err
	}
	var wire struct {
		Source            string               `json:"source"`
		Title             string               `json:"title"`
		Severity          core.Severity        `json:"severity"`
		Evidence          []core.Evidence      `json:"evidence"`
		Resources         []core.ResourceRef   `json:"resources"`
		BlastRadius       string               `json:"blastRadius"`
		Fixability        core.Fixability      `json:"fixability"`
		FindingStatus     core.FindingStatus   `json:"findingStatus"`
		CorrelationGroup  string               `json:"correlationGroup"`
		RiskScore         int                  `json:"riskScore"`
		CorrelationKeys   core.CorrelationKeys `json:"correlationKeys"`
		RiskExplanation   core.RiskExplanation `json:"riskExplanation"`
		RemediationState  string               `json:"remediationState"`
		RecommendedAction string               `json:"recommendedAction"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		return core.Finding{}, err
	}
	status := wire.FindingStatus
	if phase, _, _ := unstructured.NestedString(object.Object, "status", "phase"); phase != "" {
		switch phase {
		case "Resolved":
			status = core.FindingResolved
		case "Remediating":
			status = core.FindingRemediating
		case "InReview":
			status = core.FindingInReview
		case "Open":
			status = core.FindingOpen
		}
	}
	remediationState := wire.RemediationState
	if state, _, _ := unstructured.NestedString(object.Object, "status", "remediationState"); state != "" {
		remediationState = state
	}
	updatedAt := transitionTime(object)
	return core.Finding{
		ID: annotationOr(object, apiIDAnnotation, object.GetName()), Source: wire.Source, Title: wire.Title,
		Severity: wire.Severity, Evidence: wire.Evidence, Resources: wire.Resources, BlastRadius: wire.BlastRadius,
		Fixability: wire.Fixability, Status: status, CorrelationGroup: wire.CorrelationGroup, RiskScore: wire.RiskScore,
		CorrelationKeys: wire.CorrelationKeys, RiskExplanation: wire.RiskExplanation,
		RemediationState: remediationState, RecommendedAction: wire.RecommendedAction,
		CreatedAt: object.GetCreationTimestamp().Time, UpdatedAt: updatedAt,
	}, nil
}

func workflowError(err error) error {
	switch {
	case apierrors.IsNotFound(err):
		return fmt.Errorf("%w: %v", ErrWorkflowNotFound, err)
	case apierrors.IsConflict(err):
		return fmt.Errorf("%w: %v", ErrWorkflowConflict, err)
	default:
		return err
	}
}

func jsonValue(value any) ([]any, error) {
	bytes, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var result []any
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func jsonObject(value any) (map[string]any, error) {
	bytes, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func jsonMap(value any) (map[string]any, error) {
	bytes, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	result := map[string]any{}
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func annotationOr(object *unstructured.Unstructured, name, fallback string) string {
	if value := object.GetAnnotations()[name]; value != "" {
		return value
	}
	return fallback
}

func transitionTime(object *unstructured.Unstructured) time.Time {
	value, _, _ := unstructured.NestedString(object.Object, "status", "lastTransitionTime")
	parsed, err := time.Parse(time.RFC3339, value)
	if err == nil {
		return parsed
	}
	return object.GetCreationTimestamp().Time
}

func primaryActionDescription(plan core.RemediationPlan) string {
	if len(plan.Actions) > 0 {
		return plan.Actions[0].Description
	}
	return "Review remediation plan"
}

func ObjectName(value string) string {
	original := strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	previousDash := false
	for _, character := range original {
		valid := unicode.IsLower(character) || unicode.IsDigit(character)
		if valid {
			builder.WriteRune(character)
			previousDash = false
		} else if !previousDash && builder.Len() > 0 {
			builder.WriteByte('-')
			previousDash = true
		}
	}
	normalized := strings.Trim(builder.String(), "-")
	if normalized == "" {
		normalized = "workflow"
	}
	if len(normalized) <= 63 {
		return normalized
	}
	hash := sha256.Sum256([]byte(value))
	suffix := hex.EncodeToString(hash[:])[:12]
	return strings.Trim(normalized[:50], "-") + "-" + suffix
}
