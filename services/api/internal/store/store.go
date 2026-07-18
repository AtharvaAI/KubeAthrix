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

	"github.com/atharvaai/kubeathrix/pkg/actioncatalog"
	"github.com/atharvaai/kubeathrix/services/api/internal/core"
)

var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid request")
	ErrConflict = errors.New("conflict")
)

type FindingFilter struct {
	Severity   string
	Status     string
	Source     string
	Query      string
	Namespace  string
	Kind       string
	Fixability string
	MinRisk    int
}

type Repository interface {
	Health(ctx context.Context) error
	Dashboard(ctx context.Context) (core.Dashboard, error)
	ListFindings(ctx context.Context, filter FindingFilter) ([]core.Finding, error)
	GetFinding(ctx context.Context, id string) (core.Finding, error)
	PreviewRemediationPlan(ctx context.Context, findingID, requester string) (core.RemediationPreview, error)
	CreateRemediationPlan(ctx context.Context, findingID, requester string, idempotencyKey ...string) (core.RemediationPlan, error)
	CreateRemediationPlanFromFinding(ctx context.Context, finding core.Finding, requester string, idempotencyKey ...string) (core.RemediationPlan, error)
	GetRemediationPlan(ctx context.Context, id string) (core.RemediationPlan, error)
	SyncRemediationPlan(ctx context.Context, plan core.RemediationPlan) error
	GetRemediationPlanDiff(ctx context.Context, id string) (core.RemediationDiff, error)
	ExecuteRemediationPlan(ctx context.Context, id, actor string) (core.RemediationRun, error)
	RequestRollback(ctx context.Context, runID, actor string) (core.RemediationRun, error)
	GetRemediationRun(ctx context.Context, id string) (core.RemediationRun, error)
	SyncFinding(ctx context.Context, finding core.Finding) error
	ExpireFindings(ctx context.Context, observedBefore time.Time) error
	SyncRemediationRun(ctx context.Context, run core.RemediationRun) error
	UpdateFindingStatus(ctx context.Context, id string, status core.FindingStatus, actor, reason string) (core.Finding, error)
	ListExceptions(ctx context.Context) ([]core.Exception, error)
	CreateException(ctx context.Context, exception core.Exception, actor string) (core.Exception, error)
	DeleteException(ctx context.Context, id, actor string) error
	Approve(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error)
	Reject(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error)
	ListAuditEvents(ctx context.Context) ([]core.AuditEvent, error)
	CreateChaosRun(ctx context.Context, run core.ChaosExperimentRun, actor, auditAction string) (core.ChaosExperimentRun, error)
	GetChaosRun(ctx context.Context, id string) (core.ChaosExperimentRun, error)
	ListChaosRuns(ctx context.Context) ([]core.ChaosExperimentRun, error)
	UpdateChaosRun(ctx context.Context, run core.ChaosExperimentRun, expectedVersion int64, actor, auditAction string) (core.ChaosExperimentRun, error)
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
	chaosRuns     map[string]core.ChaosExperimentRun
	auditEvents   []core.AuditEvent
	integrations  []core.Integration
	modelSettings core.ModelProviderSettings
	idempotency   map[string]string
	exceptions    map[string]core.Exception
	clock         func() time.Time
	seq           int
}

func NewMemoryStore(options ...Option) *MemoryStore {
	s := &MemoryStore{
		findings:    map[string]core.Finding{},
		plans:       map[string]core.RemediationPlan{},
		approvals:   map[string]core.ApprovalRequest{},
		runs:        map[string]core.RemediationRun{},
		chaosRuns:   map[string]core.ChaosExperimentRun{},
		idempotency: map[string]string{},
		exceptions:  map[string]core.Exception{},
		clock:       time.Now,
		integrations: []core.Integration{
			{Name: "Trivy Operator", Type: "scanner", Enabled: false, Status: "disabled"},
			{Name: "Kyverno", Type: "policy", Enabled: false, Status: "disabled"},
			{Name: "Kubescape", Type: "scanner", Enabled: false, Status: "disabled"},
			{Name: "Falco", Type: "runtime", Enabled: false, Status: "disabled"},
			{Name: "Tetragon", Type: "runtime", Enabled: false, Status: "disabled"},
			{Name: "Chaos Mesh", Type: "verification", Enabled: false, Status: "disabled"},
			{Name: "LitmusChaos", Type: "verification", Enabled: false, Status: "disabled"},
		},
		modelSettings: core.ModelProviderSettings{Providers: []core.ModelProvider{}},
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.Dashboard{}, err
	}
	s.expireExceptionsLocked()

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
	for _, approval := range s.approvals {
		if approval.Status == core.ApprovalPending && approval.ExpiresAt.After(s.clock().UTC()) {
			dashboard.PendingApprovals++
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.expireExceptionsLocked()

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
		if filter.Fixability != "" && string(finding.Fixability) != filter.Fixability {
			continue
		}
		if filter.MinRisk > 0 && finding.RiskScore < filter.MinRisk {
			continue
		}
		if !matchesResourceFilter(finding, filter.Namespace, filter.Kind) {
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

func matchesResourceFilter(finding core.Finding, namespace, kind string) bool {
	if namespace == "" && kind == "" {
		return true
	}
	for _, resource := range finding.Resources {
		resourceNamespace := resource.Namespace
		if resource.Kind == "Namespace" {
			resourceNamespace = resource.Name
		}
		if (namespace == "" || resourceNamespace == namespace) && (kind == "" || resource.Kind == kind) {
			return true
		}
	}
	return false
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

func (s *MemoryStore) CreateRemediationPlan(ctx context.Context, findingID, requester string, idempotencyKey ...string) (core.RemediationPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.RemediationPlan{}, err
	}
	finding, ok := s.findings[findingID]
	if !ok {
		return core.RemediationPlan{}, ErrNotFound
	}
	return s.createRemediationPlanLocked(finding, requester, first(idempotencyKey))
}

func (s *MemoryStore) CreateRemediationPlanFromFinding(ctx context.Context, finding core.Finding, requester string, idempotencyKey ...string) (core.RemediationPlan, error) {
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
	return s.createRemediationPlanLocked(finding, requester, first(idempotencyKey))
}

func (s *MemoryStore) createRemediationPlanLocked(finding core.Finding, requester, idempotencyKey string) (core.RemediationPlan, error) {
	if requester == "" {
		return core.RemediationPlan{}, fmt.Errorf("%w: authenticated requester is required", ErrInvalid)
	}
	if idempotencyKey != "" {
		scope := requester + "|" + idempotencyKey
		if planID, ok := s.idempotency[scope]; ok {
			plan, exists := s.plans[planID]
			if !exists || plan.FindingID != finding.ID {
				return core.RemediationPlan{}, fmt.Errorf("%w: idempotency key was used for a different request", ErrConflict)
			}
			return plan, nil
		}
	}

	now := s.clock().UTC()
	s.seq++
	plan := buildRemediationPlan(finding, requester, now, s.seq)
	if idempotencyKey != "" {
		plan.ID = IdempotentPlanID(finding.ID, requester, idempotencyKey)
		s.idempotency[requester+"|"+idempotencyKey] = plan.ID
	}
	s.plans[plan.ID] = plan
	action := primaryAction(plan)

	runState := core.RunPrepared
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
		ValidationResult: "server-side dry-run has not been performed",
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

func (s *MemoryStore) SyncRemediationPlan(ctx context.Context, plan core.RemediationPlan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if plan.ID == "" || plan.FindingID == "" {
		return fmt.Errorf("%w: plan id and finding id are required", ErrInvalid)
	}
	if _, ok := s.plans[plan.ID]; !ok {
		return ErrNotFound
	}
	s.plans[plan.ID] = plan
	return nil
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
		return core.RemediationRun{}, fmt.Errorf("%w: authenticated actor is required", ErrInvalid)
	}
	plan, ok := s.plans[id]
	if !ok {
		return core.RemediationRun{}, ErrNotFound
	}
	if plan.ApprovalPolicy.Required && plan.ApprovalPolicy.Decision != core.ApprovalApproved {
		return core.RemediationRun{}, fmt.Errorf("%w: approval is still required", ErrInvalid)
	}
	if plan.Status == "rejected" {
		return core.RemediationRun{}, fmt.Errorf("%w: rejected plan cannot be executed", ErrInvalid)
	}
	now := s.clock().UTC()
	plan.Status = "execution_requested"
	plan.DryRunResult = core.DryRunResult{Passed: false, Message: "execution requested; waiting for controller server-side dry-run"}
	s.plans[plan.ID] = plan

	runID := "run-" + plan.ID
	run, ok := s.runs[runID]
	if !ok {
		run = core.RemediationRun{ID: runID, PlanID: plan.ID, CreatedAt: now}
	}
	run.State = core.RunExecutionRequested
	run.UpdatedAt = now
	run.ValidationResult = "execution requested; controller validation has not completed"
	run.RollbackMetadata = "pre-change snapshots are required before mutating actions"
	run.ActionStatuses = actionStatuses(plan.Actions, "execution_requested", "waiting for typed operator reconciliation")
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

func (s *MemoryStore) SyncFinding(ctx context.Context, finding core.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if existing, ok := s.findings[finding.ID]; ok {
		if finding.Status == core.FindingOpen && (existing.Status == core.FindingInReview || existing.Status == core.FindingSuppressed || existing.Status == core.FindingRemediating || existing.Status == core.FindingResolved) {
			finding.Status = existing.Status
			finding.RemediationState = existing.RemediationState
		}
		if !existing.CreatedAt.IsZero() && (finding.CreatedAt.IsZero() || existing.CreatedAt.Before(finding.CreatedAt)) {
			finding.CreatedAt = existing.CreatedAt
		}
	}
	for _, exception := range s.exceptions {
		if exception.Status == "active" && exception.ExpiresAt.After(s.clock().UTC()) && exceptionMatches(exception, finding) {
			finding.Status = core.FindingSuppressed
		}
	}
	s.findings[finding.ID] = finding
	return nil
}

func (s *MemoryStore) ExpireFindings(ctx context.Context, observedBefore time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.clock().UTC()
	for id, finding := range s.findings {
		if finding.Status != core.FindingOpen && finding.Status != core.FindingInReview {
			continue
		}
		observedAt := LastObservedAt(finding)
		if observedAt.IsZero() || !observedAt.Before(observedBefore) {
			continue
		}
		finding.Status = core.FindingExpired
		finding.RemediationState = "evidence_expired"
		finding.UpdatedAt = now
		s.findings[id] = finding
		s.auditEvents = append(s.auditEvents, core.AuditEvent{ID: fmt.Sprintf("audit-%03d", len(s.auditEvents)+1), Actor: "system", Action: "finding.expired", Subject: id, Message: "Finding evidence exceeded the configured freshness window", CreatedAt: now})
	}
	return nil
}

func LastObservedAt(finding core.Finding) time.Time {
	latest := time.Time{}
	for _, evidence := range finding.Evidence {
		if evidence.ObservedAt.After(latest) {
			latest = evidence.ObservedAt
		}
	}
	if latest.IsZero() {
		latest = finding.CreatedAt
	}
	return latest
}

func (s *MemoryStore) UpdateFindingStatus(ctx context.Context, id string, status core.FindingStatus, actor, reason string) (core.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.Finding{}, err
	}
	if actor == "" || strings.TrimSpace(reason) == "" {
		return core.Finding{}, fmt.Errorf("%w: actor and reason are required", ErrInvalid)
	}
	if status != core.FindingOpen && status != core.FindingInReview {
		return core.Finding{}, fmt.Errorf("%w: only open and in_review are manual lifecycle transitions", ErrInvalid)
	}
	finding, ok := s.findings[id]
	if !ok {
		return core.Finding{}, ErrNotFound
	}
	if finding.Status == core.FindingResolved || finding.Status == core.FindingRemediating {
		return core.Finding{}, fmt.Errorf("%w: cluster-backed lifecycle state cannot be changed manually", ErrConflict)
	}
	finding.Status = status
	finding.UpdatedAt = s.clock().UTC()
	s.findings[id] = finding
	s.auditEvents = append(s.auditEvents, core.AuditEvent{ID: fmt.Sprintf("audit-%03d", len(s.auditEvents)+1), Actor: actor, Action: "finding.status.changed", Subject: id, Message: reason, CreatedAt: finding.UpdatedAt})
	return finding, nil
}

func (s *MemoryStore) ListExceptions(ctx context.Context) ([]core.Exception, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.expireExceptionsLocked()
	items := make([]core.Exception, 0, len(s.exceptions))
	for _, exception := range s.exceptions {
		items = append(items, exception)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items, nil
}

func (s *MemoryStore) CreateException(ctx context.Context, exception core.Exception, actor string) (core.Exception, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.Exception{}, err
	}
	now := s.clock().UTC()
	if actor == "" || strings.TrimSpace(exception.Scope) == "" || strings.TrimSpace(exception.Reason) == "" {
		return core.Exception{}, fmt.Errorf("%w: scope, reason, and authenticated actor are required", ErrInvalid)
	}
	if !exception.ExpiresAt.After(now) || exception.ExpiresAt.After(now.Add(365*24*time.Hour)) {
		return core.Exception{}, fmt.Errorf("%w: expiration must be in the future and no more than 365 days", ErrInvalid)
	}
	s.seq++
	exception.ID = fmt.Sprintf("exception-%d-%03d", now.Unix(), s.seq)
	exception.Owner, exception.Status = actor, "active"
	exception.AuditMetadata = "created by authenticated API request"
	exception.CreatedAt, exception.UpdatedAt = now, now
	s.exceptions[exception.ID] = exception
	for id, finding := range s.findings {
		if exceptionMatches(exception, finding) {
			finding.Status = core.FindingSuppressed
			finding.UpdatedAt = now
			s.findings[id] = finding
		}
	}
	s.auditEvents = append(s.auditEvents, core.AuditEvent{ID: fmt.Sprintf("audit-%03d", len(s.auditEvents)+1), Actor: actor, Action: "exception.created", Subject: exception.ID, Message: exception.Reason, CreatedAt: now})
	return exception, nil
}

func (s *MemoryStore) DeleteException(ctx context.Context, id, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	exception, ok := s.exceptions[id]
	if !ok {
		return ErrNotFound
	}
	now := s.clock().UTC()
	delete(s.exceptions, id)
	for findingID, finding := range s.findings {
		if finding.Status == core.FindingSuppressed && exceptionMatches(exception, finding) && !s.hasActiveExceptionLocked(finding, now) {
			finding.Status = core.FindingOpen
			finding.UpdatedAt = now
			s.findings[findingID] = finding
		}
	}
	s.auditEvents = append(s.auditEvents, core.AuditEvent{ID: fmt.Sprintf("audit-%03d", len(s.auditEvents)+1), Actor: actor, Action: "exception.deleted", Subject: id, Message: "Exception removed", CreatedAt: now})
	return nil
}

func exceptionMatches(exception core.Exception, finding core.Finding) bool {
	return exception.Scope == finding.ID || exception.Scope == finding.CorrelationGroup || exception.Scope == "source:"+finding.Source
}

func (s *MemoryStore) hasActiveExceptionLocked(finding core.Finding, now time.Time) bool {
	for _, exception := range s.exceptions {
		if exception.Status == "active" && exception.ExpiresAt.After(now) && exceptionMatches(exception, finding) {
			return true
		}
	}
	return false
}

func (s *MemoryStore) expireExceptionsLocked() {
	now := s.clock().UTC()
	for id, exception := range s.exceptions {
		if exception.Status == "active" && !exception.ExpiresAt.After(now) {
			exception.Status = "expired"
			exception.UpdatedAt = now
			s.exceptions[id] = exception
			s.auditEvents = append(s.auditEvents, core.AuditEvent{ID: fmt.Sprintf("audit-%03d", len(s.auditEvents)+1), Actor: "system", Action: "exception.expired", Subject: id, Message: "Exception expiration elapsed", CreatedAt: now})
		}
	}
	for id, finding := range s.findings {
		if finding.Status == core.FindingSuppressed && !s.hasActiveExceptionLocked(finding, now) {
			finding.Status = core.FindingOpen
			finding.UpdatedAt = now
			s.findings[id] = finding
		}
	}
}

func (s *MemoryStore) SyncRemediationRun(ctx context.Context, run core.RemediationRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.runs[run.ID] = run
	if plan, ok := s.plans[run.PlanID]; ok {
		plan.Status = string(run.State)
		if run.State == core.RunDryRunPassed || run.State == core.RunVerifying || run.State == core.RunSucceeded {
			plan.DryRunResult = core.DryRunResult{Passed: true, Message: run.ValidationResult}
		}
		s.plans[plan.ID] = plan
	}
	return nil
}

func (s *MemoryStore) RequestRollback(ctx context.Context, runID, actor string) (core.RemediationRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.RemediationRun{}, err
	}
	if actor == "" {
		return core.RemediationRun{}, fmt.Errorf("%w: authenticated actor is required", ErrInvalid)
	}
	run, ok := s.runs[runID]
	if !ok {
		return core.RemediationRun{}, ErrNotFound
	}
	now := s.clock().UTC()
	run.State = core.RunRollbackRequested
	run.ValidationResult = "rollback requested; waiting for Kubernetes controller status"
	run.UpdatedAt = now
	s.runs[run.ID] = run
	if plan, ok := s.plans[run.PlanID]; ok {
		plan.Status = "rollback_requested"
		s.plans[plan.ID] = plan
	}
	s.auditEvents = append(s.auditEvents, core.AuditEvent{
		ID: fmt.Sprintf("audit-%03d", len(s.auditEvents)+1), Actor: actor,
		Action: "remediation.rollback.requested", Subject: run.ID,
		Message: "Rollback requested for remediation run", CreatedAt: now,
	})
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

func (s *MemoryStore) CreateChaosRun(ctx context.Context, run core.ChaosExperimentRun, actor, auditAction string) (core.ChaosExperimentRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.ChaosExperimentRun{}, err
	}
	if run.ID == "" || run.Version != 0 {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: new chaos run must have an id and version zero", ErrInvalid)
	}
	if _, exists := s.chaosRuns[run.ID]; exists {
		return core.ChaosExperimentRun{}, ErrConflict
	}
	run.Version = 1
	s.chaosRuns[run.ID] = run
	s.appendChaosAuditLocked(run, actor, auditAction)
	return run, nil
}

func (s *MemoryStore) GetChaosRun(ctx context.Context, id string) (core.ChaosExperimentRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return core.ChaosExperimentRun{}, err
	}
	run, ok := s.chaosRuns[id]
	if !ok {
		return core.ChaosExperimentRun{}, ErrNotFound
	}
	return run, nil
}

func (s *MemoryStore) ListChaosRuns(ctx context.Context) ([]core.ChaosExperimentRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runs := make([]core.ChaosExperimentRun, 0, len(s.chaosRuns))
	for _, run := range s.chaosRuns {
		runs = append(runs, run)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].CreatedAt.After(runs[j].CreatedAt) })
	return runs, nil
}

func (s *MemoryStore) UpdateChaosRun(ctx context.Context, run core.ChaosExperimentRun, expectedVersion int64, actor, auditAction string) (core.ChaosExperimentRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return core.ChaosExperimentRun{}, err
	}
	current, ok := s.chaosRuns[run.ID]
	if !ok {
		return core.ChaosExperimentRun{}, ErrNotFound
	}
	if current.Version != expectedVersion || run.Version != expectedVersion {
		return core.ChaosExperimentRun{}, ErrConflict
	}
	run.Version++
	s.chaosRuns[run.ID] = run
	s.appendChaosAuditLocked(run, actor, auditAction)
	return run, nil
}

func (s *MemoryStore) appendChaosAuditLocked(run core.ChaosExperimentRun, actor, action string) {
	if action == "" {
		return
	}
	s.seq++
	s.auditEvents = append(s.auditEvents, core.AuditEvent{
		ID: fmt.Sprintf("audit-chaos-%06d", s.seq), Actor: actor, Action: action,
		Subject: run.ID, Message: run.Message, CreatedAt: run.UpdatedAt,
	})
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
	for _, run := range s.chaosRuns {
		if scope == "all" || scope == run.ID || scope == run.ExperimentID {
			bundle.ChaosRuns = append(bundle.ChaosRuns, run)
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
	sort.Slice(bundle.ChaosRuns, func(i, j int) bool { return bundle.ChaosRuns[i].UpdatedAt.After(bundle.ChaosRuns[j].UpdatedAt) })
	sort.Slice(bundle.AuditEvents, func(i, j int) bool { return bundle.AuditEvents[i].CreatedAt.After(bundle.AuditEvents[j].CreatedAt) })
	bundle.Summary["findings"] = len(bundle.Findings)
	bundle.Summary["plans"] = len(bundle.Plans)
	bundle.Summary["runs"] = len(bundle.Runs)
	bundle.Summary["chaosRuns"] = len(bundle.ChaosRuns)
	bundle.Summary["auditEvents"] = len(bundle.AuditEvents)
	if len(bundle.Findings) == 0 && len(bundle.Plans) == 0 && len(bundle.Runs) == 0 && len(bundle.ChaosRuns) == 0 && len(bundle.AuditEvents) == 0 && scope != "all" {
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
		return core.ApprovalRequest{}, fmt.Errorf("%w: authenticated actor is required", ErrInvalid)
	}
	now := s.clock().UTC()
	approval.Status = status
	approval.Approver = actor
	approval.DecisionReason = reason
	approval.UpdatedAt = now
	s.approvals[approval.ID] = approval

	plan, hasPlan := s.plans[approval.SubjectRef]
	if hasPlan {
		if status == core.ApprovalApproved {
			plan.Status = "approved"
			plan.ApprovalPolicy.Decision = core.ApprovalApproved
			plan.DryRunResult = core.DryRunResult{
				Passed:  false,
				Message: "approval recorded; server-side dry-run has not yet been performed",
			}
		} else {
			plan.Status = "rejected"
			plan.ApprovalPolicy.Decision = core.ApprovalRejected
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
			run.State = core.RunApproved
			run.ValidationResult = "approved; execution and server-side dry-run have not been requested"
			for index := range run.ActionStatuses {
				run.ActionStatuses[index].State = "approved"
				run.ActionStatuses[index].Message = "approved; no cluster write or dry-run has occurred"
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
				finding.Status = core.FindingInReview
				finding.RemediationState = "approval_granted"
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
	actions := typedActionsForFinding(finding)
	return core.RemediationPlan{
		ID:             planID,
		CatalogVersion: actioncatalog.Version,
		FindingID:      finding.ID,
		RootCause:      "KubeAthrix correlated scanner and Kubernetes evidence into a bounded deterministic remediation candidate. Execution is restricted to typed actions with dry-run, approvals, verification, and rollback metadata.",
		Actions:        actions,
		RiskTier:       riskTierForActions(actions),
		DryRunResult: core.DryRunResult{
			Passed:  false,
			Message: "server-side dry-run has not been performed; this is a proposal",
		},
		VerificationSteps: verificationStepsForActions(actions, finding),
		RollbackSteps:     rollbackStepsForActions(actions),
		ApprovalPolicy:    approvalPolicyForActions(actions),
		Status:            "proposed",
		CreatedAt:         now,
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
	if strings.HasPrefix(strings.ToLower(finding.Source), "managed-resource") || strings.Contains(text, "kubernetes-managed external resource") {
		managementSystem := strings.TrimPrefix(finding.CorrelationKeys.Identity, "managed-resource:")
		if managementSystem == "" {
			managementSystem = "unknown"
		}
		return []core.TypedAction{{
			Type:        actioncatalog.ManagedResourceReviewAction,
			Target:      target,
			Description: "Review the managed-resource flaw and its authoritative source; an exact change requires a separate trusted proposal",
			Params: map[string]string{
				"findingId":        finding.ID,
				"managementSystem": managementSystem,
				"sourceOfTruth":    "owning Kubernetes controller resource or upstream GitOps repository",
			},
		}}
	}

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
	if isWorkloadTarget(target) && (strings.Contains(text, "readiness") || strings.Contains(text, "liveness") || strings.Contains(text, "probe")) {
		actions = append(actions, core.TypedAction{
			Type:        "patch_workload_probes",
			Target:      workloadTarget(target),
			Description: "Prepare readiness and liveness probe patches behind approval",
			Params:      map[string]string{"configured": "false", "dryRun": "required"},
		})
	}
	if isWorkloadTarget(target) && (strings.Contains(text, "requests") || strings.Contains(text, "limits") || strings.Contains(text, "mutable image")) {
		actions = append(actions, core.TypedAction{
			Type:        "patch_workload_resources",
			Target:      workloadTarget(target),
			Description: "Prepare bounded workload resource defaults or recommendation-only image pinning guidance",
			Params:      map[string]string{"cpuRequest": "100m", "memoryRequest": "128Mi", "cpuLimit": "500m", "memoryLimit": "512Mi", "dryRun": "required"},
		})
	}
	if isWorkloadTarget(target) && (strings.Contains(text, "pdb") || strings.Contains(text, "poddisruptionbudget") || strings.Contains(text, "disruption")) {
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

func isWorkloadTarget(target core.ResourceRef) bool {
	return target.APIVersion == "apps/v1" && (target.Kind == "Deployment" || target.Kind == "StatefulSet" || target.Kind == "DaemonSet")
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

func verificationStepsForActions(actions []core.TypedAction, finding core.Finding) []string {
	steps := []string{}
	seen := map[string]bool{}
	for _, action := range actions {
		definition, err := actioncatalog.ValidateProposal(catalogAction(action))
		if err != nil {
			continue
		}
		for _, step := range definition.VerificationChecks {
			if !seen[step] {
				seen[step] = true
				steps = append(steps, step)
			}
		}
	}
	if len(steps) == 0 {
		return verificationStepsForFinding(finding)
	}
	return steps
}

func rollbackStepsForActions(actions []core.TypedAction) []string {
	steps := []string{}
	seen := map[string]bool{}
	for _, action := range actions {
		definition, err := actioncatalog.ValidateProposal(catalogAction(action))
		if err != nil {
			continue
		}
		for _, step := range definition.RollbackProcedure {
			if !seen[step] {
				seen[step] = true
				steps = append(steps, step)
			}
		}
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
	definition, err := actioncatalog.ValidateProposal(catalogAction(action))
	if err != nil {
		return core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "invalid", Diff: err.Error()}
	}
	decorate := func(manifest core.PlannedManifest) core.PlannedManifest {
		manifest.RiskTier = string(definition.RiskTier)
		manifest.ApprovalRequired = definition.ApprovalRequired
		manifest.RequiredPermissions = append([]string(nil), definition.RequiredPermissions...)
		manifest.VerificationChecks = append([]string(nil), definition.VerificationChecks...)
		manifest.RollbackProcedure = append([]string(nil), definition.RollbackProcedure...)
		manifest.IdempotencyBehavior = definition.IdempotencyBehavior
		manifest.FailureHandling = definition.FailureHandling
		return manifest
	}
	mode := actioncatalog.ExecutionModeFor(catalogAction(action))
	if mode == actioncatalog.ModeProposal || mode == actioncatalog.ModeInformation || (mode == actioncatalog.ModeGitOps && action.Type != "propose_network_policy") {
		return decorate(core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: string(mode), Diff: definition.DiffStrategy})
	}
	switch action.Type {
	case "apply_resource_governance":
		namespace := action.Target.Name
		return decorate(core.PlannedManifest{
			ActionType: action.Type,
			Target:     action.Target,
			WriteMode:  "direct-tier-a",
			Diff:       fmt.Sprintf("Create or update ResourceQuota/kubeathrix-defaults and LimitRange/kubeathrix-defaults in namespace %s.", namespace),
			Manifest:   fmt.Sprintf("apiVersion: v1\nkind: ResourceQuota\nmetadata:\n  name: kubeathrix-defaults\n  namespace: %s\nspec:\n  hard:\n    requests.cpu: \"4\"\n    requests.memory: 8Gi\n---\napiVersion: v1\nkind: LimitRange\nmetadata:\n  name: kubeathrix-defaults\n  namespace: %s\nspec:\n  limits:\n    - type: Container\n      defaultRequest:\n        cpu: 100m\n        memory: 128Mi\n      default:\n        cpu: 500m\n        memory: 512Mi\n", namespace, namespace),
		})
	case "patch_pod_security_labels":
		return decorate(core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "direct-tier-b", Diff: "Patch namespace Pod Security labels to enforce baseline, audit restricted, and warn restricted.", Manifest: fmt.Sprintf("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n  labels:\n    pod-security.kubernetes.io/enforce: baseline\n    pod-security.kubernetes.io/audit: restricted\n    pod-security.kubernetes.io/warn: restricted\n", action.Target.Name)})
	case "patch_workload_probes":
		return decorate(core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "proposal_only", Diff: definition.DiffStrategy})
	case "patch_workload_resources":
		return decorate(core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "direct-tier-b", Diff: "Fill only missing CPU/memory requests and limits on the exact containers resolved by the controller; existing values are preserved.", Manifest: ""})
	case "create_pdb":
		return decorate(core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "direct-tier-b", Diff: "Resolve the exact non-empty workload selector, then create or reconcile the managed PodDisruptionBudget after approval.", Manifest: ""})
	case "propose_network_policy":
		namespace := action.Target.Name
		if namespace == "" {
			namespace = action.Target.Namespace
		}
		return decorate(core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "gitops-proposal", Diff: "Generate default-deny NetworkPolicy proposal; broad network changes are never applied autonomously.", Manifest: fmt.Sprintf("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: kubeathrix-default-deny\n  namespace: %s\nspec:\n  podSelector: {}\n  policyTypes:\n    - Ingress\n    - Egress\n", namespace)})
	default:
		return decorate(core.PlannedManifest{ActionType: action.Type, Target: action.Target, WriteMode: "notify-only", Diff: action.Description, Manifest: ""})
	}
}

func riskTierForActions(actions []core.TypedAction) core.RiskTier {
	highest := core.RiskTierA
	rank := map[core.RiskTier]int{core.RiskTierA: 1, core.RiskTierB: 2, core.RiskTierC: 3, core.RiskTierD: 4}
	for _, action := range actions {
		definition, err := actioncatalog.ValidateProposal(catalogAction(action))
		if err != nil {
			return core.RiskTierD
		}
		tier := core.RiskTier(definition.RiskTier)
		if rank[tier] > rank[highest] {
			highest = tier
		}
	}
	return highest
}

func approvalPolicyForActions(actions []core.TypedAction) core.ApprovalPolicy {
	policy := core.ApprovalPolicy{Decision: core.ApprovalApproved}
	for _, action := range actions {
		definition, err := actioncatalog.ValidateProposal(catalogAction(action))
		if err != nil || definition.ApprovalRequired {
			policy.Required = true
			policy.Decision = core.ApprovalPending
		}
		policy.Categories = append(policy.Categories, action.Type)
	}
	return policy
}

func catalogAction(action core.TypedAction) actioncatalog.Action {
	return actioncatalog.Action{Type: action.Type, APIVersion: action.Target.APIVersion, Kind: action.Target.Kind, Params: action.Params}
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

func IdempotentPlanID(findingID, requester, key string) string {
	hash := sha256.Sum256([]byte(requester + "\x00" + key + "\x00" + findingID))
	prefix := safeID(findingID)
	if len(prefix) > 36 {
		prefix = strings.Trim(prefix[:36], "-")
	}
	return "plan-" + prefix + "-" + hex.EncodeToString(hash[:])[:12]
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
