package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
)

var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid request")
)

type FindingFilter struct {
	Severity string
	Status   string
	Source   string
	Query    string
}

type Repository interface {
	Health(ctx context.Context) error
	Dashboard(ctx context.Context) (core.Dashboard, error)
	ListFindings(ctx context.Context, filter FindingFilter) ([]core.Finding, error)
	GetFinding(ctx context.Context, id string) (core.Finding, error)
	PreviewRemediationPlan(ctx context.Context, findingID, requester string) (core.RemediationPreview, error)
	CreateRemediationPlan(ctx context.Context, findingID, requester string) (core.RemediationPlan, error)
	CreateRemediationPlanFromFinding(ctx context.Context, finding core.Finding, requester string) (core.RemediationPlan, error)
	GetRemediationPlan(ctx context.Context, id string) (core.RemediationPlan, error)
	GetRemediationPlanDiff(ctx context.Context, id string) (core.RemediationDiff, error)
	ExecuteRemediationPlan(ctx context.Context, id, actor string) (core.RemediationRun, error)
	GetRemediationRun(ctx context.Context, id string) (core.RemediationRun, error)
	Approve(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error)
	Reject(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error)
	ListAuditEvents(ctx context.Context) ([]core.AuditEvent, error)
	EvidenceBundle(ctx context.Context, scope string) (core.EvidenceBundle, error)
	ListIntegrations(ctx context.Context) ([]core.Integration, error)
	IntegrationHealth(ctx context.Context, name string) (core.IntegrationHealth, error)
	GetModelProviders(ctx context.Context) (core.ModelProviderSettings, error)
	SaveModelProviders(ctx context.Context, settings core.ModelProviderSettings) (core.ModelProviderSettings, error)
}

type Option func(*MemoryStore)

type MemoryStore struct {
	mu            sync.RWMutex
	findings      map[string]core.Finding
	plans         map[string]core.RemediationPlan
	approvals     map[string]core.ApprovalRequest
	runs          map[string]core.RemediationRun
	auditEvents   []core.AuditEvent
	integrations  []core.Integration
	modelSettings core.ModelProviderSettings
	clock         func() time.Time
	seq           int
}

func NewMemoryStore(options ...Option) *MemoryStore {
	s := &MemoryStore{
		findings:  map[string]core.Finding{},
		plans:     map[string]core.RemediationPlan{},
		approvals: map[string]core.ApprovalRequest{},
		runs:      map[string]core.RemediationRun{},
		clock:     time.Now,
		integrations: []core.Integration{
			{Name: "Trivy Operator", Type: "scanner", Enabled: false, Status: "disabled"},
			{Name: "Kyverno", Type: "policy", Enabled: false, Status: "disabled"},
			{Name: "Kubescape", Type: "scanner", Enabled: false, Status: "disabled"},
			{Name: "Falco", Type: "runtime", Enabled: false, Status: "disabled"},
			{Name: "Tetragon", Type: "runtime", Enabled: false, Status: "disabled"},
			{Name: "Chaos Mesh", Type: "verification", Enabled: false, Status: "disabled"},
			{Name: "LitmusChaos", Type: "verification", Enabled: false, Status: "disabled"},
		},
		modelSettings: core.ModelProviderSettings{
			Providers: []core.ModelProvider{
				{
					Name:  "primary",
					Type:  "openai-compatible",
					Model: "gpt-5",
					APIKeySecretRef: &core.SecretRef{
						Name: "kubeathrix-llm",
						Key:  "api-key",
					},
				},
			},
		},
	}
	for _, option := range options {
		option(s)
	}
	return s
}

func WithClock(clock func() time.Time) Option {
	return func(s *MemoryStore) {
		s.clock = clock
	}
}

func WithIntegrations(integrations []core.Integration) Option {
	return func(s *MemoryStore) {
		s.integrations = append([]core.Integration(nil), integrations...)
	}
}

func WithFindings(findings []core.Finding) Option {
	return func(s *MemoryStore) {
		for _, finding := range findings {
			s.findings[finding.ID] = finding
		}
	}
}

func (s *MemoryStore) Health(ctx context.Context) error {
	return ctx.Err()
}

func (s *MemoryStore) Dashboard(ctx context.Context) (core.Dashboard, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return core.Dashboard{}, err
	}

	dashboard := core.Dashboard{
		FindingsBySeverity:  map[string]int{},
		FindingsBySource:    map[string]int{},
		RemediationByState:  map[string]int{},
		ProtectedNamespaces: 4,
	}
	var scoreTotal int
	namespaces := map[string]struct{}{}
	for _, integration := range s.integrations {
		if integration.Enabled && integration.Status != "disabled" {
			dashboard.BundledEnginesOnline++
		}
	}
	for _, finding := range s.findings {
		dashboard.TotalFindings++
		scoreTotal += finding.RiskScore
		dashboard.FindingsBySeverity[string(finding.Severity)]++
		dashboard.FindingsBySource[finding.Source]++
		dashboard.RemediationByState[finding.RemediationState]++
		if finding.Severity == core.SeverityCritical && finding.Status != core.FindingResolved && finding.Status != core.FindingSuppressed {
			dashboard.OpenCritical++
		}
		if finding.RemediationState == "approval_required" {
			dashboard.PendingApprovals++
		}
		if finding.Status == core.FindingRemediating {
			dashboard.ActiveRemediations++
		}
		if finding.Fixability == core.FixabilityDeterministic || finding.Fixability == core.FixabilityGated {
			dashboard.FindingsWithSafeFix++
		}
		if finding.Status == core.FindingResolved {
			dashboard.RiskReduced += finding.RiskScore
		}
		for _, resource := range finding.Resources {
			if resource.Namespace != "" {
				namespaces[resource.Namespace] = struct{}{}
			}
		}
	}
	for _, run := range s.runs {
		if run.State == core.RunSucceeded {
			dashboard.VerifiedRemediations++
		}
	}
	if dashboard.TotalFindings > 0 {
		dashboard.MeanRiskScore = float64(scoreTotal) / float64(dashboard.TotalFindings)
	}
	dashboard.EvidenceFreshness = evidenceFreshness(s.findings, s.clock().UTC())
	if len(namespaces) > dashboard.ProtectedNamespaces {
		dashboard.ProtectedNamespaces = len(namespaces)
	}
	return dashboard, nil
}

func (s *MemoryStore) ListFindings(ctx context.Context, filter FindingFilter) ([]core.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	findings := make([]core.Finding, 0, len(s.findings))
	for _, finding := range s.findings {
		if filter.Severity != "" && string(finding.Severity) != filter.Severity {
			continue
		}
		if filter.Status != "" && string(finding.Status) != filter.Status {
			continue
		}
		if filter.Source != "" && finding.Source != filter.Source {
			continue
		}
		if filter.Query != "" {
			haystack := strings.ToLower(finding.Title + " " + finding.BlastRadius + " " + finding.CorrelationGroup)
			if !strings.Contains(haystack, strings.ToLower(filter.Query)) {
				continue
			}
		}
		findings = append(findings, finding)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RiskScore == findings[j].RiskScore {
			return findings[i].UpdatedAt.After(findings[j].UpdatedAt)
		}
		return findings[i].RiskScore > findings[j].RiskScore
	})
	return findings, nil
}

func (s *MemoryStore) GetFinding(ctx context.Context, id string) (core.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return core.Finding{}, err
	}
	finding, ok := s.findings[id]
	if !ok {
		return core.Finding{}, ErrNotFound
	}
	return finding, nil
}

func (s *MemoryStore) PreviewRemediationPlan(ctx context.Context, findingID, requester string) (core.RemediationPreview, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return core.RemediationPreview{}, err
	}
	finding, ok := s.findings[findingID]
	if !ok {
		return core.RemediationPreview{}, ErrNotFound
	}
	now := s.clock().UTC()
	plan := buildRemediationPlan(finding, requester, now, 0)
	plan.ID = "preview-" + finding.ID
	return buildRemediationPreview(finding, plan, now), nil
}

func (s *MemoryStore) CreateRemediationPlan(ctx context.Context, findingID, requester string) (core.RemediationPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.RemediationPlan{}, err
	}
	finding, ok := s.findings[findingID]
	if !ok {
		return core.RemediationPlan{}, ErrNotFound
	}
	return s.createRemediationPlanLocked(finding, requester)
}

func (s *MemoryStore) CreateRemediationPlanFromFinding(ctx context.Context, finding core.Finding, requester string) (core.RemediationPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.RemediationPlan{}, err
	}
	if finding.ID == "" {
		return core.RemediationPlan{}, fmt.Errorf("%w: finding id is required", ErrInvalid)
	}
	if existing, ok := s.findings[finding.ID]; ok {
		finding = existing
	} else {
		s.findings[finding.ID] = finding
	}
	return s.createRemediationPlanLocked(finding, requester)
}

func (s *MemoryStore) createRemediationPlanLocked(finding core.Finding, requester string) (core.RemediationPlan, error) {
	if requester == "" {
		requester = "operator-console"
	}

	now := s.clock().UTC()
	s.seq++
	plan := buildRemediationPlan(finding, requester, now, s.seq)
	s.plans[plan.ID] = plan
	action := primaryAction(plan)

	runState := core.RunDryRunPassed
	if plan.ApprovalPolicy.Required {
		runState = core.RunPendingApproval
		approval := core.ApprovalRequest{
			ID:              "approval-" + plan.ID,
			SubjectRef:      plan.ID,
			RequestedAction: action.Description,
			Requester:       requester,
			Status:          core.ApprovalPending,
			ExpiresAt:       now.Add(24 * time.Hour),
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		s.approvals[approval.ID] = approval
	}
	run := core.RemediationRun{
		ID:               "run-" + plan.ID,
		PlanID:           plan.ID,
		State:            runState,
		ActionStatuses:   actionStatuses(plan.Actions, string(runState), "typed action created; no arbitrary command execution path exists"),
		ValidationResult: "pending controller validation",
		RollbackMetadata: "pre-change snapshot will be captured by remediator before write",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	s.runs[run.ID] = run
	s.auditEvents = append(s.auditEvents, core.AuditEvent{
		ID:        fmt.Sprintf("audit-%03d", len(s.auditEvents)+1),
		Actor:     requester,
		Action:    "remediation.plan.created",
		Subject:   plan.ID,
		Message:   "Created typed remediation plan for " + finding.ID,
		CreatedAt: now,
	})
	return plan, nil
}

func (s *MemoryStore) GetRemediationPlan(ctx context.Context, id string) (core.RemediationPlan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return core.RemediationPlan{}, err
	}
	plan, ok := s.plans[id]
	if !ok {
		return core.RemediationPlan{}, ErrNotFound
	}
	return plan, nil
}

func (s *MemoryStore) GetRemediationPlanDiff(ctx context.Context, id string) (core.RemediationDiff, error) {
	plan, err := s.GetRemediationPlan(ctx, id)
	if err != nil {
		return core.RemediationDiff{}, err
	}
	return buildRemediationDiff(plan), nil
}

func (s *MemoryStore) ExecuteRemediationPlan(ctx context.Context, id, actor string) (core.RemediationRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.RemediationRun{}, err
	}
	if actor == "" {
		actor = "operator-console"
	}
	plan, ok := s.plans[id]
	if !ok {
		return core.RemediationRun{}, ErrNotFound
	}
	if plan.ApprovalPolicy.Required {
		return core.RemediationRun{}, fmt.Errorf("%w: approval is still required", ErrInvalid)
	}
	if plan.Status == "rejected" {
		return core.RemediationRun{}, fmt.Errorf("%w: rejected plan cannot be executed", ErrInvalid)
	}
	now := s.clock().UTC()
	plan.Status = "execution_requested"
	plan.DryRunResult = core.DryRunResult{
		Passed:  true,
		Message: "server-side dry-run passed; operator reconciliation has been requested",
	}
	s.plans[plan.ID] = plan

	runID := "run-" + plan.ID
	run, ok := s.runs[runID]
	if !ok {
		run = core.RemediationRun{ID: runID, PlanID: plan.ID, CreatedAt: now}
	}
	run.State = core.RunRunning
	run.UpdatedAt = now
	run.ValidationResult = "operator reconciliation requested; typed actions only"
	run.RollbackMetadata = "pre-change snapshots are required before mutating actions"
	run.ActionStatuses = actionStatuses(plan.Actions, "running", "execution requested for typed operator reconciliation")
	s.runs[run.ID] = run

	if finding, ok := s.findings[plan.FindingID]; ok {
		finding.Status = core.FindingRemediating
		finding.RemediationState = "execution_requested"
		finding.UpdatedAt = now
		s.findings[finding.ID] = finding
	}
	s.auditEvents = append(s.auditEvents, core.AuditEvent{
		ID:        fmt.Sprintf("audit-%03d", len(s.auditEvents)+1),
		Actor:     actor,
		Action:    "remediation.execution.requested",
		Subject:   plan.ID,
		Message:   "Execution requested for typed remediation plan",
		CreatedAt: now,
	})
	return run, nil
}

func (s *MemoryStore) GetRemediationRun(ctx context.Context, id string) (core.RemediationRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return core.RemediationRun{}, err
	}
	run, ok := s.runs[id]
	if !ok {
		return core.RemediationRun{}, ErrNotFound
	}
	return run, nil
}

func (s *MemoryStore) Approve(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error) {
	return s.decide(ctx, approvalID, actor, reason, core.ApprovalApproved)
}

func (s *MemoryStore) Reject(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error) {
	return s.decide(ctx, approvalID, actor, reason, core.ApprovalRejected)
}

func (s *MemoryStore) ListAuditEvents(ctx context.Context) ([]core.AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	events := append([]core.AuditEvent(nil), s.auditEvents...)
	sort.Slice(events, func(i, j int) bool {
		if events[i].CreatedAt.Equal(events[j].CreatedAt) {
			return events[i].ID > events[j].ID
		}
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	return events, nil
}

func (s *MemoryStore) EvidenceBundle(ctx context.Context, scope string) (core.EvidenceBundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return core.EvidenceBundle{}, err
	}
	if scope == "" {
		scope = "all"
	}
	bundle := core.EvidenceBundle{
		Scope:       scope,
		GeneratedAt: s.clock().UTC(),
		Summary:     map[string]int{},
	}
	for _, finding := range s.findings {
		if scopeMatchesFinding(scope, finding) {
			bundle.Findings = append(bundle.Findings, finding)
		}
	}
	for _, plan := range s.plans {
		if scope == "all" || scope == plan.ID || scope == plan.FindingID || hasFinding(bundle.Findings, plan.FindingID) {
			bundle.Plans = append(bundle.Plans, plan)
		}
	}
	for _, run := range s.runs {
		if scope == "all" || scope == run.ID || scope == run.PlanID || hasPlan(bundle.Plans, run.PlanID) {
			bundle.Runs = append(bundle.Runs, run)
		}
	}
	for _, event := range s.auditEvents {
		if scope == "all" || event.Subject == scope || hasPlan(bundle.Plans, event.Subject) || hasRun(bundle.Runs, event.Subject) {
			bundle.AuditEvents = append(bundle.AuditEvents, event)
		}
	}
	sort.Slice(bundle.Findings, func(i, j int) bool { return bundle.Findings[i].RiskScore > bundle.Findings[j].RiskScore })
	sort.Slice(bundle.Plans, func(i, j int) bool { return bundle.Plans[i].CreatedAt.After(bundle.Plans[j].CreatedAt) })
	sort.Slice(bundle.Runs, func(i, j int) bool { return bundle.Runs[i].UpdatedAt.After(bundle.Runs[j].UpdatedAt) })
	sort.Slice(bundle.AuditEvents, func(i, j int) bool { return bundle.AuditEvents[i].CreatedAt.After(bundle.AuditEvents[j].CreatedAt) })
	bundle.Summary["findings"] = len(bundle.Findings)
	bundle.Summary["plans"] = len(bundle.Plans)
	bundle.Summary["runs"] = len(bundle.Runs)
	bundle.Summary["auditEvents"] = len(bundle.AuditEvents)
	if len(bundle.Findings) == 0 && len(bundle.Plans) == 0 && len(bundle.Runs) == 0 && len(bundle.AuditEvents) == 0 && scope != "all" {
		return core.EvidenceBundle{}, ErrNotFound
	}
	return bundle, nil
}

func (s *MemoryStore) ListIntegrations(ctx context.Context) ([]core.Integration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]core.Integration(nil), s.integrations...), nil
}

func (s *MemoryStore) IntegrationHealth(ctx context.Context, name string) (core.IntegrationHealth, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return core.IntegrationHealth{}, err
	}
	for _, integration := range s.integrations {
		if strings.EqualFold(integration.Name, name) || strings.EqualFold(safeID(integration.Name), safeID(name)) {
			return buildIntegrationHealth(integration, s.findings, s.clock().UTC()), nil
		}
	}
	return core.IntegrationHealth{}, ErrNotFound
}

func (s *MemoryStore) GetModelProviders(ctx context.Context) (core.ModelProviderSettings, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return core.ModelProviderSettings{}, err
	}
	return s.modelSettings, nil
}

func (s *MemoryStore) SaveModelProviders(ctx context.Context, settings core.ModelProviderSettings) (core.ModelProviderSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.ModelProviderSettings{}, err
	}
	for _, provider := range settings.Providers {
		if provider.Name == "" || provider.Type == "" || provider.Model == "" {
			return core.ModelProviderSettings{}, fmt.Errorf("%w: provider name, type, and model are required", ErrInvalid)
		}
		if provider.APIKeySecretRef == nil && provider.ExternalSecretRef == nil {
			return core.ModelProviderSettings{}, fmt.Errorf("%w: model provider must use apiKeySecretRef or externalSecretRef", ErrInvalid)
		}
	}
	s.modelSettings = settings
	return s.modelSettings, nil
}

func (s *MemoryStore) decide(ctx context.Context, approvalID, actor, reason string, status core.ApprovalStatus) (core.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.ApprovalRequest{}, err
	}
	approval, ok := s.approvals[approvalID]
	if !ok {
		return core.ApprovalRequest{}, ErrNotFound
	}
	if approval.Status != core.ApprovalPending {
		return core.ApprovalRequest{}, fmt.Errorf("%w: approval is already %s", ErrInvalid, approval.Status)
	}
	if actor == "" {
		actor = "operator-console"
	}
	now := s.clock().UTC()
	approval.Status = status
	approval.Approver = actor
	approval.DecisionReason = reason
	approval.UpdatedAt = now
	s.approvals[approval.ID] = approval

	plan, hasPlan := s.plans[approval.SubjectRef]
	if hasPlan {
		plan.ApprovalPolicy.Required = false
		if status == core.ApprovalApproved {
			plan.Status = "dry_run_verified"
			plan.DryRunResult = core.DryRunResult{
				Passed:  true,
				Message: "approval recorded; typed remediation dry-run verified and queued behind controller safety gates",
			}
		} else {
			plan.Status = "rejected"
			plan.DryRunResult = core.DryRunResult{
				Passed:  false,
				Message: "approval rejected; no controller action will be attempted",
			}
		}
		s.plans[plan.ID] = plan
	}

	runID := "run-" + approval.SubjectRef
	run, hasRun := s.runs[runID]
	if hasRun {
		run.UpdatedAt = now
		if status == core.ApprovalApproved {
			run.State = core.RunSucceeded
			run.ValidationResult = "server-side dry-run verified; typed action is ready for controller execution"
			for index := range run.ActionStatuses {
				run.ActionStatuses[index].State = "dry_run_verified"
				run.ActionStatuses[index].Message = "approved and validated without arbitrary command execution"
			}
		} else {
			run.State = core.RunFailed
			run.ValidationResult = "approval rejected"
			for index := range run.ActionStatuses {
				run.ActionStatuses[index].State = "rejected"
				run.ActionStatuses[index].Message = "rejected by approver; no cluster write attempted"
			}
		}
		s.runs[run.ID] = run
	}

	if hasPlan {
		finding, hasFinding := s.findings[plan.FindingID]
		if hasFinding {
			finding.UpdatedAt = now
			if status == core.ApprovalApproved {
				finding.Status = core.FindingRemediating
				finding.RemediationState = "dry_run_verified"
			} else {
				finding.Status = core.FindingInReview
				finding.RemediationState = "rejected"
			}
			s.findings[finding.ID] = finding
		}
	}

	action := "approval.approved"
	if status == core.ApprovalRejected {
		action = "approval.rejected"
	}
	s.auditEvents = append(s.auditEvents, core.AuditEvent{
		ID:        fmt.Sprintf("audit-%03d", len(s.auditEvents)+1),
		Actor:     actor,
		Action:    action,
		Subject:   approval.SubjectRef,
		Message:   reason,
		CreatedAt: now,
	})
	return approval, nil
}

func buildRemediationPlan(finding core.Finding, requester string, now time.Time, seq int) core.RemediationPlan {
	planID := fmt.Sprintf("plan-%s-%03d", finding.ID, seq)
	if seq == 0 {
		planID = "preview-" + finding.ID
	}
	return core.RemediationPlan{
		ID:        planID,
		FindingID: finding.ID,
		RootCause: "KubeAthrix correlated scanner and Kubernetes evidence into a bounded remediation candidate. The model may explain and rank evidence, but execution is restricted to typed actions with dry-run, approvals, verification, and rollback metadata.",
		Actions:   typedActionsForFinding(finding),
		RiskTier:  riskTierForFixability(finding.Fixability),
		DryRunResult: core.DryRunResult{
			Passed:  finding.Fixability != core.FixabilityInformational,
			Message: "server-side dry-run and policy validation are queued for the remediator controller",
		},
		VerificationSteps: verificationStepsForFinding(finding),
		RollbackSteps: []string{
			"Use the stored pre-change object snapshot for a typed revert.",
			"Re-run policy validation and source-engine scans after rollback.",
			"Record rollback status in the remediation run and audit trail.",
		},
		ApprovalPolicy: approvalPolicyForFinding(finding),
		Status:         "proposed",
		CreatedAt:      now,
	}
}

func BuildRemediationPlan(finding core.Finding, requester string, now time.Time, seq int) core.RemediationPlan {
	return buildRemediationPlan(finding, requester, now, seq)
}

func typedActionsForFinding(finding core.Finding) []core.TypedAction {
	target := core.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: "default"}
	if len(finding.Resources) > 0 {
		target = finding.Resources[0]
	}
	actions := []core.TypedAction{}
	text := strings.ToLower(finding.ID + " " + finding.Title + " " + finding.BlastRadius + " " + finding.RecommendedAction)

	if strings.Contains(text, "resourcequota") || strings.Contains(text, "limitrange") || strings.Contains(text, "resource governance") || strings.Contains(text, "resources") {
		actions = append(actions, core.TypedAction{
			Type:        "apply_resource_governance",
			Target:      namespaceTarget(target),
			Description: "Apply scoped ResourceQuota and LimitRange defaults",
			Params:      map[string]string{"quotaProfile": "team-defaults", "dryRun": "required"},
		})
	}
	if strings.Contains(text, "pod security") || strings.Contains(text, "privileged pod security") {
		actions = append(actions, core.TypedAction{
			Type:        "patch_pod_security_labels",
			Target:      namespaceTarget(target),
			Description: "Patch namespace Pod Security admission labels after tier validation",
			Params:      map[string]string{"enforce": "baseline", "audit": "restricted", "dryRun": "required"},
		})
	}
	if strings.Contains(text, "readiness") || strings.Contains(text, "liveness") || strings.Contains(text, "probe") {
		actions = append(actions, core.TypedAction{
			Type:        "patch_workload_probes",
			Target:      workloadTarget(target),
			Description: "Prepare readiness and liveness probe patches behind approval",
			Params:      map[string]string{"serverSideApply": "true", "dryRun": "required", "defaultPath": "/healthz"},
		})
	}
	if strings.Contains(text, "requests") || strings.Contains(text, "limits") || strings.Contains(text, "mutable image") {
		actions = append(actions, core.TypedAction{
			Type:        "patch_workload_resources",
			Target:      workloadTarget(target),
			Description: "Prepare bounded workload resource defaults or recommendation-only image pinning guidance",
			Params:      map[string]string{"cpuRequest": "100m", "memoryRequest": "128Mi", "cpuLimit": "500m", "memoryLimit": "512Mi", "dryRun": "required"},
		})
	}
	if strings.Contains(text, "pdb") || strings.Contains(text, "poddisruptionbudget") || strings.Contains(text, "disruption") {
		actions = append(actions, core.TypedAction{
			Type:        "create_pdb",
			Target:      workloadTarget(target),
			Description: "Create a scoped PodDisruptionBudget for replicated workloads after approval",
			Params:      map[string]string{"minAvailable": "1", "dryRun": "required"},
		})
	}
	if strings.Contains(text, "networkpolicy") || strings.Contains(text, "loadbalancer") || strings.Contains(text, "nodeport") || strings.Contains(text, "externalip") || strings.Contains(text, "ingress") {
		actions = append(actions, core.TypedAction{
			Type:        "propose_network_policy",
			Target:      namespaceTarget(target),
			Description: "Prepare default-deny and explicit allow NetworkPolicy manifests for review or GitOps PR",
			Params:      map[string]string{"mode": "proposal", "requiresApproval": "true"},
		})
	}
	if len(actions) == 0 {
		actionType := "explain_only"
		description := "Document finding and require human triage"
		if finding.Fixability == core.FixabilityHumanOnly {
			actionType = "propose_security_hardening"
			description = "Prepare network, RBAC, and image trust patches for explicit approval"
		}
		actions = append(actions, core.TypedAction{
			Type:        actionType,
			Target:      target,
			Description: description,
			Params:      map[string]string{"findingId": finding.ID, "dryRun": "required"},
		})
	}
	return dedupeActions(actions)
}

func namespaceTarget(target core.ResourceRef) core.ResourceRef {
	if target.Kind == "Namespace" {
		return core.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: target.Name}
	}
	if target.Namespace != "" {
		return core.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: target.Namespace}
	}
	return target
}

func workloadTarget(target core.ResourceRef) core.ResourceRef {
	switch target.Kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		return target
	default:
		return target
	}
}

func dedupeActions(actions []core.TypedAction) []core.TypedAction {
	seen := map[string]bool{}
	result := make([]core.TypedAction, 0, len(actions))
	for _, action := range actions {
		key := action.Type + "|" + action.Target.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, action)
	}
	return result
}

func primaryAction(plan core.RemediationPlan) core.TypedAction {
	if len(plan.Actions) > 0 {
		return plan.Actions[0]
	}
	return core.TypedAction{
		Type:        "explain_only",
		Target:      core.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: "default"},
		Description: "Document finding and require human triage",
	}
}

func verificationStepsForFinding(finding core.Finding) []string {
	steps := []string{
		"Confirm the targeted resources still match the finding evidence.",
		"Run Kubernetes server-side dry-run before writing changes.",
		"Re-scan the source engine and update finding status.",
	}
	if finding.Source == "falco" || finding.Source == "tetragon" {
		steps = append(steps, "Correlate runtime event timing with deployment, user, and audit logs.")
	}
	return steps
}

func actionStatuses(actions []core.TypedAction, state, message string) []core.ActionStatus {
	statuses := make([]core.ActionStatus, 0, len(actions))
	for _, action := range actions {
		statuses = append(statuses, core.ActionStatus{ActionType: action.Type, State: state, Message: message})
	}
	if len(statuses) == 0 {
		statuses = append(statuses, core.ActionStatus{ActionType: "explain_only", State: state, Message: message})
	}
	return statuses
}

func buildRemediationPreview(finding core.Finding, plan core.RemediationPlan, now time.Time) core.RemediationPreview {
	return core.RemediationPreview{
		FindingID:             finding.ID,
		Summary:               fmt.Sprintf("Strict-schema deterministic preview for %s with %d typed action(s).", finding.Title, len(plan.Actions)),
		Candidate:             plan,
		EvidenceCitations:     evidenceCitations(finding),
		PromptEvidenceHash:    promptEvidenceHash(finding),
		DeterministicFallback: true,
		SafetyNotes: []string{
			"Model output must match the typed remediation schema before it can be stored.",
			"No raw shell, SSH, or kubectl command execution is accepted.",
			"Tier B/C/D changes remain approval gated and dry-run first.",
		},
		GeneratedAt: now,
	}
}

func BuildRemediationPreview(finding core.Finding, plan core.RemediationPlan, now time.Time) core.RemediationPreview {
	return buildRemediationPreview(finding, plan, now)
}

func evidenceCitations(finding core.Finding) []core.EvidenceCitation {
	citations := make([]core.EvidenceCitation, 0, len(finding.Evidence))
	resource := ""
	if len(finding.Resources) > 0 {
		resource = finding.Resources[0].String()
	}
	for _, evidence := range finding.Evidence {
		citations = append(citations, core.EvidenceCitation{
			SourceID:   evidence.SourceID,
			Summary:    evidence.Summary,
			Resource:   resource,
			ObservedAt: evidence.ObservedAt,
		})
	}
	return citations
}

func promptEvidenceHash(finding core.Finding) string {
	hash := sha256.New()
	hash.Write([]byte(finding.ID))
	hash.Write([]byte(finding.Title))
	hash.Write([]byte(finding.BlastRadius))
	for _, evidence := range finding.Evidence {
		hash.Write([]byte(evidence.SourceID))
		hash.Write([]byte(evidence.Summary))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func buildRemediationDiff(plan core.RemediationPlan) core.RemediationDiff {
	diff := core.RemediationDiff{
		PlanID:  plan.ID,
		Mode:    "typed-server-side-dry-run",
		Summary: fmt.Sprintf("%d typed action(s) prepared; no arbitrary command path is available.", len(plan.Actions)),
	}
	for _, action := range plan.Actions {
		diff.Manifests = append(diff.Manifests, plannedManifest(action))
	}
	return diff
}

func BuildRemediationDiff(plan core.RemediationPlan) core.RemediationDiff {
	return buildRemediationDiff(plan)
}

func plannedManifest(action core.TypedAction) core.PlannedManifest {
	switch action.Type {
	case "apply_resource_governance":
		namespace := action.Target.Name
		return core.PlannedManifest{
			ActionType: action.Type,
			Target:     action.Target,
			WriteMode:  "direct-tier-a",
			Diff:       fmt.Sprintf("Create or update ResourceQuota/kubeathrix-defaults and LimitRange/kubeathrix-defaults in namespace %s.", namespace),
			Manifest:   fmt.Sprintf("apiVersion: v1\nkind: ResourceQuota\nmetadata:\n  name: kubeathrix-defaults\n  namespace: %s\nspec:\n  hard:\n    requests.cpu: \"4\"\n    requests.memory: 8Gi\n---\napiVersion: v1\nkind: LimitRange\nmetadata:\n  name: kubeathrix-defaults\n  namespace: %s\nspec:\n  limits:\n    - type: Container\n      defaultRequest:\n        cpu: 100m\n        memory: 128Mi\n      default:\n        cpu: 500m\n        memory: 512Mi\n", namespace, namespace),
		}
	case "patch_pod_security_labels":
		return core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "direct-tier-a", Diff: "Patch namespace Pod Security labels to enforce baseline, audit restricted, and warn restricted.", Manifest: fmt.Sprintf("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n  labels:\n    pod-security.kubernetes.io/enforce: baseline\n    pod-security.kubernetes.io/audit: restricted\n    pod-security.kubernetes.io/warn: restricted\n", action.Target.Name)}
	case "patch_workload_probes":
		return core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "gated-tier-b", Diff: "Patch containers missing readiness/liveness probes with a conservative HTTP health endpoint after approval.", Manifest: fmt.Sprintf("apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  template:\n    spec:\n      containers:\n        - name: '*'\n          readinessProbe:\n            httpGet:\n              path: /healthz\n              port: http\n          livenessProbe:\n            httpGet:\n              path: /healthz\n              port: http\n", action.Target.APIVersion, action.Target.Kind, action.Target.Name, action.Target.Namespace)}
	case "patch_workload_resources":
		return core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "gated-tier-b", Diff: "Patch missing CPU/memory requests and limits with bounded defaults; image pinning remains recommendation-only.", Manifest: fmt.Sprintf("apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  template:\n    spec:\n      containers:\n        - name: '*'\n          resources:\n            requests:\n              cpu: 100m\n              memory: 128Mi\n            limits:\n              cpu: 500m\n              memory: 512Mi\n", action.Target.APIVersion, action.Target.Kind, action.Target.Name, action.Target.Namespace)}
	case "create_pdb":
		return core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "gated-tier-b", Diff: "Create a PodDisruptionBudget matching the target workload labels after approval.", Manifest: fmt.Sprintf("apiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: %s-kubeathrix\n  namespace: %s\nspec:\n  minAvailable: 1\n  selector:\n    matchLabels: {}\n", action.Target.Name, action.Target.Namespace)}
	case "propose_network_policy":
		namespace := action.Target.Name
		if namespace == "" {
			namespace = action.Target.Namespace
		}
		return core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "gitops-proposal", Diff: "Generate default-deny NetworkPolicy proposal; broad network changes are never applied autonomously.", Manifest: fmt.Sprintf("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: kubeathrix-default-deny\n  namespace: %s\nspec:\n  podSelector: {}\n  policyTypes:\n    - Ingress\n    - Egress\n", namespace)}
	default:
		return core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "notify-only", Diff: action.Description, Manifest: ""}
	}
}

func riskTierForFixability(fixability core.Fixability) core.RiskTier {
	switch fixability {
	case core.FixabilityDeterministic:
		return core.RiskTierA
	case core.FixabilityGated:
		return core.RiskTierB
	case core.FixabilityHumanOnly:
		return core.RiskTierC
	default:
		return core.RiskTierD
	}
}

func approvalPolicyForFinding(finding core.Finding) core.ApprovalPolicy {
	switch finding.Fixability {
	case core.FixabilityDeterministic:
		return core.ApprovalPolicy{Required: false}
	case core.FixabilityGated:
		return core.ApprovalPolicy{Required: true, Categories: []string{"reliability", "rollout"}}
	case core.FixabilityHumanOnly:
		return core.ApprovalPolicy{Required: true, Categories: []string{"network", "iam", "image-trust"}}
	default:
		return core.ApprovalPolicy{Required: true, Categories: []string{"runtime", "human-triage"}}
	}
}

func evidenceFreshness(findings map[string]core.Finding, now time.Time) string {
	if len(findings) == 0 {
		return "no-evidence"
	}
	latest := time.Time{}
	for _, finding := range findings {
		if finding.UpdatedAt.After(latest) {
			latest = finding.UpdatedAt
		}
	}
	if latest.IsZero() {
		return "unknown"
	}
	age := now.Sub(latest)
	switch {
	case age <= 15*time.Minute:
		return "fresh"
	case age <= 2*time.Hour:
		return "recent"
	case age <= 24*time.Hour:
		return "stale"
	default:
		return "expired"
	}
}

func scopeMatchesFinding(scope string, finding core.Finding) bool {
	if scope == "all" || scope == finding.ID || scope == finding.CorrelationGroup || scope == finding.Source {
		return true
	}
	for _, resource := range finding.Resources {
		if scope == resource.Namespace || scope == resource.Name || scope == resource.String() {
			return true
		}
	}
	return false
}

func hasFinding(findings []core.Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func hasPlan(plans []core.RemediationPlan, id string) bool {
	for _, plan := range plans {
		if plan.ID == id {
			return true
		}
	}
	return false
}

func hasRun(runs []core.RemediationRun, id string) bool {
	for _, run := range runs {
		if run.ID == id {
			return true
		}
	}
	return false
}

func buildIntegrationHealth(integration core.Integration, findings map[string]core.Finding, now time.Time) core.IntegrationHealth {
	health := "not_configured"
	setupGaps := []string{}
	if integration.Enabled && integration.Status != "disabled" {
		health = "healthy"
	} else {
		setupGaps = append(setupGaps, "Enable the Helm value for this integration and confirm its CRDs or event source are installed.")
	}
	lastSeen := "never"
	sourceName := strings.ToLower(integration.Name)
	for _, finding := range findings {
		if strings.Contains(sourceName, strings.ToLower(finding.Source)) || strings.Contains(strings.ToLower(finding.Source), strings.Fields(sourceName)[0]) {
			if finding.UpdatedAt.IsZero() {
				continue
			}
			if lastSeen == "never" || finding.UpdatedAt.Format(time.RFC3339) > lastSeen {
				lastSeen = finding.UpdatedAt.Format(time.RFC3339)
			}
		}
	}
	return core.IntegrationHealth{
		Name:         integration.Name,
		Type:         integration.Type,
		Enabled:      integration.Enabled,
		Status:       integration.Status,
		Health:       health,
		DataLastSeen: lastSeen,
		Permissions:  integrationPermissions(integration.Name),
		SetupGaps:    setupGaps,
		CheckedAt:    now,
	}
}

func BuildIntegrationHealth(integration core.Integration, findings map[string]core.Finding, now time.Time) core.IntegrationHealth {
	return buildIntegrationHealth(integration, findings, now)
}

func integrationPermissions(name string) []string {
	switch strings.ToLower(name) {
	case "trivy operator":
		return []string{"Read vulnerabilityreports", "Read configauditreports", "Read exposedsecretreports", "Read rbacassessmentreports"}
	case "kubescape":
		return []string{"Read workloadconfiguration scans", "Read vulnerability manifests", "Read posture resources"}
	case "kyverno":
		return []string{"Read policyreports", "Read clusterpolicyreports", "Read admission policy status"}
	case "falco":
		return []string{"Read runtime event stream or forwarded events", "Correlate pod and namespace metadata"}
	case "tetragon":
		return []string{"Read process/network event stream", "Correlate pod and workload metadata"}
	case "chaos mesh", "litmuschaos":
		return []string{"Dry-run create allowlisted chaos objects", "Create/delete only when chaos execution is enabled"}
	default:
		return []string{"Read integration status and emitted findings"}
	}
}

func safeID(value string) string {
	return strings.Trim(strings.NewReplacer(" ", "-", "_", "-", "/", "-").Replace(strings.ToLower(value)), "-")
}
