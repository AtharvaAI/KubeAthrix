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
			{Name: "Trivy Operator", Type: "scanner", Enabled: true, Status: "online"},
			{Name: "Kyverno", Type: "policy", Enabled: true, Status: "online"},
			{Name: "Kubescape", Type: "scanner", Enabled: true, Status: "online"},
			{Name: "Falco", Type: "runtime", Enabled: false, Status: "stubbed"},
			{Name: "Tetragon", Type: "runtime", Enabled: false, Status: "stubbed"},
			{Name: "Chaos Mesh", Type: "verification", Enabled: false, Status: "stubbed"},
			{Name: "LitmusChaos", Type: "verification", Enabled: false, Status: "stubbed"},
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

func WithDemoData() Option {
	return func(s *MemoryStore) {
		now := s.clock().UTC()
		demoFindings := []core.Finding{
			{
				ID:       "finding-public-rbac-image",
				Source:   "correlator",
				Title:    "Public workload combines broad RBAC, stale image, and missing network policy",
				Severity: core.SeverityCritical,
				Evidence: []core.Evidence{
					{Summary: "Service is exposed through a public LoadBalancer.", Details: "Service checkout-api accepts traffic from 0.0.0.0/0.", SourceID: "kubescape/network", ObservedAt: now.Add(-27 * time.Minute)},
					{Summary: "ServiceAccount can list secrets.", Details: "RoleBinding grants get/list/watch on secrets in payments.", SourceID: "kyverno/rbac", ObservedAt: now.Add(-25 * time.Minute)},
					{Summary: "Image contains critical CVEs.", Details: "Trivy reported 3 critical and 9 high vulnerabilities.", SourceID: "trivy/vuln", ObservedAt: now.Add(-23 * time.Minute)},
				},
				Resources: []core.ResourceRef{
					{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "payments", Name: "checkout-api"},
					{APIVersion: "v1", Kind: "Service", Namespace: "payments", Name: "checkout-api"},
					{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "payments", Name: "checkout-secret-reader"},
				},
				BlastRadius:       "Internet-facing payment API, namespace-scoped secret read access, and vulnerable runtime image.",
				Fixability:        core.FixabilityHumanOnly,
				Status:            core.FindingOpen,
				CorrelationGroup:  "payments-checkout-exposure",
				RiskScore:         97,
				RemediationState:  "approval_required",
				RecommendedAction: "Review proposed network, RBAC, and image trust changes before rollout.",
				CreatedAt:         now.Add(-45 * time.Minute),
				UpdatedAt:         now.Add(-23 * time.Minute),
			},
			{
				ID:       "finding-missing-probes-pdb",
				Source:   "kubeathrix",
				Title:    "Critical API lacks readiness probes and disruption protection",
				Severity: core.SeverityHigh,
				Evidence: []core.Evidence{
					{Summary: "Deployment has no readiness probe.", Details: "rollout-controller cannot confirm request-serving health.", SourceID: "kubeathrix/reliability", ObservedAt: now.Add(-18 * time.Minute)},
					{Summary: "No PodDisruptionBudget protects replicas.", Details: "Voluntary disruptions can evict all replicas.", SourceID: "kubeathrix/reliability", ObservedAt: now.Add(-18 * time.Minute)},
				},
				Resources: []core.ResourceRef{
					{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "platform", Name: "tenant-router"},
				},
				BlastRadius:       "Tenant routing can flap during node maintenance or noisy rollouts.",
				Fixability:        core.FixabilityGated,
				Status:            core.FindingInReview,
				CorrelationGroup:  "platform-tenant-router-resilience",
				RiskScore:         82,
				RemediationState:  "dry_run_ready",
				RecommendedAction: "Create a readiness probe and PDB after dry-run validation.",
				CreatedAt:         now.Add(-2 * time.Hour),
				UpdatedAt:         now.Add(-18 * time.Minute),
			},
			{
				ID:       "finding-namespace-quota",
				Source:   "kyverno",
				Title:    "Developer namespace has no ResourceQuota or LimitRange",
				Severity: core.SeverityMedium,
				Evidence: []core.Evidence{
					{Summary: "Namespace allows unbounded workload requests.", Details: "No ResourceQuota or LimitRange exists in team-labs.", SourceID: "kyverno/policyreport", ObservedAt: now.Add(-12 * time.Minute)},
				},
				Resources: []core.ResourceRef{
					{APIVersion: "v1", Kind: "Namespace", Name: "team-labs"},
				},
				BlastRadius:       "A single runaway workload can starve shared nodes.",
				Fixability:        core.FixabilityDeterministic,
				Status:            core.FindingOpen,
				CorrelationGroup:  "team-labs-resource-hygiene",
				RiskScore:         61,
				RemediationState:  "autofix_available",
				RecommendedAction: "Apply namespace-scoped quota and default request limits.",
				CreatedAt:         now.Add(-6 * time.Hour),
				UpdatedAt:         now.Add(-12 * time.Minute),
			},
			{
				ID:       "finding-runtime-shell",
				Source:   "falco",
				Title:    "Interactive shell opened in production workload",
				Severity: core.SeverityHigh,
				Evidence: []core.Evidence{
					{Summary: "Unexpected shell spawned.", Details: "bash was executed inside prod/catalog-api by kubectl exec.", SourceID: "falco/runtime", ObservedAt: now.Add(-4 * time.Minute)},
				},
				Resources: []core.ResourceRef{
					{APIVersion: "v1", Kind: "Pod", Namespace: "prod", Name: "catalog-api-657ccd4f9d-q2k84"},
				},
				BlastRadius:       "Runtime activity may indicate manual debugging or compromise.",
				Fixability:        core.FixabilityInformational,
				Status:            core.FindingOpen,
				CorrelationGroup:  "prod-catalog-runtime",
				RiskScore:         76,
				RemediationState:  "triage_required",
				RecommendedAction: "Verify actor, correlate with deployment window, and consider runtime containment policy.",
				CreatedAt:         now.Add(-8 * time.Minute),
				UpdatedAt:         now.Add(-4 * time.Minute),
			},
		}
		for _, finding := range demoFindings {
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
		if integration.Enabled && integration.Status == "online" {
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
	if requester == "" {
		requester = "dev-mode"
	}

	now := s.clock().UTC()
	s.seq++
	planID := fmt.Sprintf("plan-%s-%03d", findingID, s.seq)
	action := typedActionForFinding(finding)
	plan := core.RemediationPlan{
		ID:        planID,
		FindingID: findingID,
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
		actor = "dev-mode"
	}
	now := s.clock().UTC()
	approval.Status = status
	approval.Approver = actor
	approval.DecisionReason = reason
	approval.UpdatedAt = now
	s.approvals[approval.ID] = approval

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
