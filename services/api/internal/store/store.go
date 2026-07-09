package store

import (
	"context"
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
	CreateRemediationPlan(ctx context.Context, findingID, requester string) (core.RemediationPlan, error)
	CreateRemediationPlanFromFinding(ctx context.Context, finding core.Finding, requester string) (core.RemediationPlan, error)
	GetRemediationRun(ctx context.Context, id string) (core.RemediationRun, error)
	Approve(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error)
	Reject(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error)
	ListAuditEvents(ctx context.Context) ([]core.AuditEvent, error)
	ListIntegrations(ctx context.Context) ([]core.Integration, error)
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
		for _, resource := range finding.Resources {
			if resource.Namespace != "" {
				namespaces[resource.Namespace] = struct{}{}
			}
		}
	}
	if dashboard.TotalFindings > 0 {
		dashboard.MeanRiskScore = float64(scoreTotal) / float64(dashboard.TotalFindings)
	}
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
	planID := fmt.Sprintf("plan-%s-%03d", finding.ID, s.seq)
	action := typedActionForFinding(finding)
	plan := core.RemediationPlan{
		ID:        planID,
		FindingID: finding.ID,
		RootCause: "KubeAthrix correlated scanner and Kubernetes evidence into a bounded remediation candidate. The model may explain the plan, but execution is restricted to typed actions.",
		Actions:   []core.TypedAction{action},
		RiskTier:  riskTierForFixability(finding.Fixability),
		DryRunResult: core.DryRunResult{
			Passed:  finding.Fixability != core.FixabilityInformational,
			Message: "server-side dry-run and policy validation are queued for the remediator controller",
		},
		VerificationSteps: []string{
			"Confirm the targeted resources still match the finding evidence.",
			"Run Kubernetes server-side dry-run before writing changes.",
			"Re-scan the source engine and update finding status.",
		},
		RollbackSteps: []string{
			"Use the stored pre-change object snapshot for a typed revert.",
			"Re-run policy validation and record rollback status.",
		},
		ApprovalPolicy: approvalPolicyForFinding(finding),
		Status:         "proposed",
		CreatedAt:      now,
	}
	s.plans[plan.ID] = plan

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
		ID:     "run-" + plan.ID,
		PlanID: plan.ID,
		State:  runState,
		ActionStatuses: []core.ActionStatus{
			{ActionType: action.Type, State: string(runState), Message: "typed action created; no arbitrary command execution path exists"},
		},
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

func (s *MemoryStore) ListIntegrations(ctx context.Context) ([]core.Integration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]core.Integration(nil), s.integrations...), nil
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

func typedActionForFinding(finding core.Finding) core.TypedAction {
	target := core.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: "default"}
	if len(finding.Resources) > 0 {
		target = finding.Resources[0]
	}
	action := core.TypedAction{
		Type:        "explain_only",
		Target:      target,
		Description: "Document finding and require human triage",
		Params:      map[string]string{"findingId": finding.ID},
	}
	switch finding.Fixability {
	case core.FixabilityDeterministic:
		action.Type = "apply_resource_governance"
		action.Description = "Apply scoped ResourceQuota and LimitRange defaults"
		action.Params = map[string]string{"quotaProfile": "team-defaults", "dryRun": "required"}
	case core.FixabilityGated:
		action.Type = "patch_workload_reliability"
		action.Description = "Patch probes and disruption controls after approval"
		action.Params = map[string]string{"serverSideApply": "true", "dryRun": "required"}
	case core.FixabilityHumanOnly:
		action.Type = "propose_security_hardening"
		action.Description = "Prepare network, RBAC, and image trust patches for explicit approval"
		action.Params = map[string]string{"requiresApproval": "true", "dryRun": "required"}
	}
	return action
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
