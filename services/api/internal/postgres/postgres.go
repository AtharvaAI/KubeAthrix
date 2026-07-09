package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	db       *sql.DB
	delegate store.Repository
	clock    func() time.Time
}

func New(ctx context.Context, databaseURL string, delegate store.Repository) (*Store, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &Store{db: db, delegate: delegate, clock: time.Now}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.seedDefaults(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS kubeathrix_findings (
	id TEXT PRIMARY KEY,
	payload JSONB NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS kubeathrix_remediation_plans (
	id TEXT PRIMARY KEY,
	finding_id TEXT NOT NULL,
	payload JSONB NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS kubeathrix_approval_requests (
	id TEXT PRIMARY KEY,
	subject_ref TEXT NOT NULL,
	payload JSONB NOT NULL,
	expires_at TIMESTAMPTZ,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS kubeathrix_remediation_runs (
	id TEXT PRIMARY KEY,
	plan_id TEXT NOT NULL,
	payload JSONB NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS kubeathrix_audit_events (
	id TEXT PRIMARY KEY,
	payload JSONB NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS kubeathrix_integrations (
	name TEXT PRIMARY KEY,
	payload JSONB NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS kubeathrix_settings (
	key TEXT PRIMARY KEY,
	payload JSONB NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kubeathrix_findings_payload_severity_idx ON kubeathrix_findings ((payload->>'severity'));
CREATE INDEX IF NOT EXISTS kubeathrix_findings_payload_source_idx ON kubeathrix_findings ((payload->>'source'));
CREATE INDEX IF NOT EXISTS kubeathrix_remediation_plans_finding_idx ON kubeathrix_remediation_plans (finding_id);
CREATE INDEX IF NOT EXISTS kubeathrix_remediation_runs_plan_idx ON kubeathrix_remediation_runs (plan_id);
`)
	return err
}

func (s *Store) seedDefaults(ctx context.Context) error {
	integrations, err := s.delegate.ListIntegrations(ctx)
	if err == nil {
		for _, integration := range integrations {
			if err := s.saveIntegration(ctx, integration); err != nil {
				return err
			}
		}
	}
	settings, err := s.delegate.GetModelProviders(ctx)
	if err == nil {
		return s.saveSetting(ctx, "modelProviders", settings)
	}
	return nil
}

func (s *Store) Health(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) Dashboard(ctx context.Context) (core.Dashboard, error) {
	findings, err := s.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		return core.Dashboard{}, err
	}
	integrations, err := s.ListIntegrations(ctx)
	if err != nil {
		return core.Dashboard{}, err
	}
	runs, err := s.listRuns(ctx)
	if err != nil {
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
	latest := time.Time{}
	for _, integration := range integrations {
		if integration.Enabled && integration.Status != "disabled" {
			dashboard.BundledEnginesOnline++
		}
	}
	for _, finding := range findings {
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
		if finding.UpdatedAt.After(latest) {
			latest = finding.UpdatedAt
		}
		for _, resource := range finding.Resources {
			if resource.Namespace != "" {
				namespaces[resource.Namespace] = struct{}{}
			}
		}
	}
	for _, run := range runs {
		if run.State == core.RunSucceeded {
			dashboard.VerifiedRemediations++
		}
	}
	if dashboard.TotalFindings > 0 {
		dashboard.MeanRiskScore = float64(scoreTotal) / float64(dashboard.TotalFindings)
	}
	dashboard.EvidenceFreshness = freshness(latest, s.clock().UTC())
	if len(namespaces) > dashboard.ProtectedNamespaces {
		dashboard.ProtectedNamespaces = len(namespaces)
	}
	return dashboard, nil
}

func (s *Store) ListFindings(ctx context.Context, filter store.FindingFilter) ([]core.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM kubeathrix_findings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	findings := []core.Finding{}
	for rows.Next() {
		var finding core.Finding
		if err := scanJSON(rows, &finding); err != nil {
			return nil, err
		}
		if matchesFilter(finding, filter) {
			findings = append(findings, finding)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(findings) == 0 {
		delegateFindings, err := s.delegate.ListFindings(ctx, filter)
		if err == nil {
			findings = append(findings, delegateFindings...)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RiskScore == findings[j].RiskScore {
			return findings[i].UpdatedAt.After(findings[j].UpdatedAt)
		}
		return findings[i].RiskScore > findings[j].RiskScore
	})
	return findings, nil
}

func (s *Store) GetFinding(ctx context.Context, id string) (core.Finding, error) {
	var finding core.Finding
	err := s.queryJSON(ctx, `SELECT payload FROM kubeathrix_findings WHERE id = $1`, []any{id}, &finding)
	if err == nil {
		return finding, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return core.Finding{}, err
	}
	return s.delegate.GetFinding(ctx, id)
}

func (s *Store) PreviewRemediationPlan(ctx context.Context, findingID, requester string) (core.RemediationPreview, error) {
	finding, err := s.GetFinding(ctx, findingID)
	if err != nil {
		return core.RemediationPreview{}, err
	}
	now := s.clock().UTC()
	plan := store.BuildRemediationPlan(finding, requester, now, 0)
	plan.ID = "preview-" + finding.ID
	return store.BuildRemediationPreview(finding, plan, now), nil
}

func (s *Store) CreateRemediationPlan(ctx context.Context, findingID, requester string) (core.RemediationPlan, error) {
	finding, err := s.GetFinding(ctx, findingID)
	if err != nil {
		return core.RemediationPlan{}, err
	}
	return s.CreateRemediationPlanFromFinding(ctx, finding, requester)
}

func (s *Store) CreateRemediationPlanFromFinding(ctx context.Context, finding core.Finding, requester string) (core.RemediationPlan, error) {
	if finding.ID == "" {
		return core.RemediationPlan{}, fmt.Errorf("%w: finding id is required", store.ErrInvalid)
	}
	if requester == "" {
		requester = "operator-console"
	}
	if err := s.saveFinding(ctx, finding); err != nil {
		return core.RemediationPlan{}, err
	}
	seq, err := s.nextPlanSequence(ctx)
	if err != nil {
		return core.RemediationPlan{}, err
	}
	now := s.clock().UTC()
	plan := store.BuildRemediationPlan(finding, requester, now, seq)
	if err := s.savePlan(ctx, plan); err != nil {
		return core.RemediationPlan{}, err
	}
	action := plan.Actions[0]
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
		if err := s.saveApproval(ctx, approval); err != nil {
			return core.RemediationPlan{}, err
		}
	}
	run := core.RemediationRun{
		ID:               "run-" + plan.ID,
		PlanID:           plan.ID,
		State:            runState,
		ValidationResult: "pending controller validation",
		RollbackMetadata: "pre-change snapshot will be captured by remediator before write",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	for _, action := range plan.Actions {
		run.ActionStatuses = append(run.ActionStatuses, core.ActionStatus{ActionType: action.Type, State: string(runState), Message: "typed action created; no arbitrary command execution path exists"})
	}
	if err := s.saveRun(ctx, run); err != nil {
		return core.RemediationPlan{}, err
	}
	if err := s.saveAuditEvent(ctx, core.AuditEvent{
		ID:        fmt.Sprintf("audit-%d", now.UnixNano()),
		Actor:     requester,
		Action:    "remediation.plan.created",
		Subject:   plan.ID,
		Message:   "Created typed remediation plan for " + finding.ID,
		CreatedAt: now,
	}); err != nil {
		return core.RemediationPlan{}, err
	}
	return plan, nil
}

func (s *Store) GetRemediationPlan(ctx context.Context, id string) (core.RemediationPlan, error) {
	var plan core.RemediationPlan
	err := s.queryJSON(ctx, `SELECT payload FROM kubeathrix_remediation_plans WHERE id = $1`, []any{id}, &plan)
	if err == nil {
		return plan, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return core.RemediationPlan{}, err
	}
	return s.delegate.GetRemediationPlan(ctx, id)
}

func (s *Store) GetRemediationPlanDiff(ctx context.Context, id string) (core.RemediationDiff, error) {
	plan, err := s.GetRemediationPlan(ctx, id)
	if err != nil {
		return core.RemediationDiff{}, err
	}
	return store.BuildRemediationDiff(plan), nil
}

func (s *Store) ExecuteRemediationPlan(ctx context.Context, id, actor string) (core.RemediationRun, error) {
	if actor == "" {
		actor = "operator-console"
	}
	plan, err := s.GetRemediationPlan(ctx, id)
	if err != nil {
		return core.RemediationRun{}, err
	}
	if plan.ApprovalPolicy.Required {
		return core.RemediationRun{}, fmt.Errorf("%w: approval is still required", store.ErrInvalid)
	}
	if plan.Status == "rejected" {
		return core.RemediationRun{}, fmt.Errorf("%w: rejected plan cannot be executed", store.ErrInvalid)
	}
	now := s.clock().UTC()
	plan.Status = "execution_requested"
	plan.DryRunResult = core.DryRunResult{Passed: true, Message: "server-side dry-run passed; operator reconciliation has been requested"}
	if err := s.savePlan(ctx, plan); err != nil {
		return core.RemediationRun{}, err
	}
	run, err := s.GetRemediationRun(ctx, "run-"+plan.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return core.RemediationRun{}, err
	}
	if errors.Is(err, store.ErrNotFound) {
		run = core.RemediationRun{ID: "run-" + plan.ID, PlanID: plan.ID, CreatedAt: now}
	}
	run.State = core.RunRunning
	run.ActionStatuses = make([]core.ActionStatus, 0, len(plan.Actions))
	for _, action := range plan.Actions {
		run.ActionStatuses = append(run.ActionStatuses, core.ActionStatus{ActionType: action.Type, State: "running", Message: "execution requested for typed operator reconciliation"})
	}
	run.ValidationResult = "operator reconciliation requested; typed actions only"
	run.RollbackMetadata = "pre-change snapshots are required before mutating actions"
	run.UpdatedAt = now
	if err := s.saveRun(ctx, run); err != nil {
		return core.RemediationRun{}, err
	}
	finding, err := s.GetFinding(ctx, plan.FindingID)
	if err == nil {
		finding.Status = core.FindingRemediating
		finding.RemediationState = "execution_requested"
		finding.UpdatedAt = now
		_ = s.saveFinding(ctx, finding)
	}
	_ = s.saveAuditEvent(ctx, core.AuditEvent{
		ID:        fmt.Sprintf("audit-%d", now.UnixNano()),
		Actor:     actor,
		Action:    "remediation.execution.requested",
		Subject:   plan.ID,
		Message:   "Execution requested for typed remediation plan",
		CreatedAt: now,
	})
	return run, nil
}

func (s *Store) GetRemediationRun(ctx context.Context, id string) (core.RemediationRun, error) {
	var run core.RemediationRun
	err := s.queryJSON(ctx, `SELECT payload FROM kubeathrix_remediation_runs WHERE id = $1`, []any{id}, &run)
	if err == nil {
		return run, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return core.RemediationRun{}, err
	}
	return s.delegate.GetRemediationRun(ctx, id)
}

func (s *Store) Approve(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error) {
	return s.decide(ctx, approvalID, actor, reason, core.ApprovalApproved)
}

func (s *Store) Reject(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error) {
	return s.decide(ctx, approvalID, actor, reason, core.ApprovalRejected)
}

func (s *Store) decide(ctx context.Context, approvalID, actor, reason string, status core.ApprovalStatus) (core.ApprovalRequest, error) {
	if actor == "" {
		actor = "operator-console"
	}
	var approval core.ApprovalRequest
	if err := s.queryJSON(ctx, `SELECT payload FROM kubeathrix_approval_requests WHERE id = $1`, []any{approvalID}, &approval); err != nil {
		return core.ApprovalRequest{}, err
	}
	if approval.Status != core.ApprovalPending {
		return core.ApprovalRequest{}, fmt.Errorf("%w: approval is already %s", store.ErrInvalid, approval.Status)
	}
	now := s.clock().UTC()
	approval.Status = status
	approval.Approver = actor
	approval.DecisionReason = reason
	approval.UpdatedAt = now
	if err := s.saveApproval(ctx, approval); err != nil {
		return core.ApprovalRequest{}, err
	}

	plan, err := s.GetRemediationPlan(ctx, approval.SubjectRef)
	if err == nil {
		plan.ApprovalPolicy.Required = false
		if status == core.ApprovalApproved {
			plan.Status = "dry_run_verified"
			plan.DryRunResult = core.DryRunResult{Passed: true, Message: "approval recorded; typed remediation dry-run verified and queued behind controller safety gates"}
		} else {
			plan.Status = "rejected"
			plan.DryRunResult = core.DryRunResult{Passed: false, Message: "approval rejected; no controller action will be attempted"}
		}
		_ = s.savePlan(ctx, plan)
	}
	run, err := s.GetRemediationRun(ctx, "run-"+approval.SubjectRef)
	if err == nil {
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
		_ = s.saveRun(ctx, run)
	}
	if plan.FindingID != "" {
		finding, findingErr := s.GetFinding(ctx, plan.FindingID)
		if findingErr == nil {
			finding.UpdatedAt = now
			if status == core.ApprovalApproved {
				finding.Status = core.FindingRemediating
				finding.RemediationState = "dry_run_verified"
			} else {
				finding.Status = core.FindingInReview
				finding.RemediationState = "rejected"
			}
			_ = s.saveFinding(ctx, finding)
		}
	}
	action := "approval.approved"
	if status == core.ApprovalRejected {
		action = "approval.rejected"
	}
	_ = s.saveAuditEvent(ctx, core.AuditEvent{
		ID:        fmt.Sprintf("audit-%d", now.UnixNano()),
		Actor:     actor,
		Action:    action,
		Subject:   approval.SubjectRef,
		Message:   reason,
		CreatedAt: now,
	})
	return approval, nil
}

func (s *Store) ListAuditEvents(ctx context.Context) ([]core.AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM kubeathrix_audit_events ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []core.AuditEvent{}
	for rows.Next() {
		var event core.AuditEvent
		if err := scanJSON(rows, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (s *Store) EvidenceBundle(ctx context.Context, scope string) (core.EvidenceBundle, error) {
	if scope == "" {
		scope = "all"
	}
	findings, err := s.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		return core.EvidenceBundle{}, err
	}
	plans, err := s.listPlans(ctx)
	if err != nil {
		return core.EvidenceBundle{}, err
	}
	runs, err := s.listRuns(ctx)
	if err != nil {
		return core.EvidenceBundle{}, err
	}
	events, err := s.ListAuditEvents(ctx)
	if err != nil {
		return core.EvidenceBundle{}, err
	}
	bundle := core.EvidenceBundle{Scope: scope, GeneratedAt: s.clock().UTC(), Summary: map[string]int{}}
	for _, finding := range findings {
		if scope == "all" || scope == finding.ID || scope == finding.Source || scope == finding.CorrelationGroup {
			bundle.Findings = append(bundle.Findings, finding)
		}
	}
	for _, plan := range plans {
		if scope == "all" || scope == plan.ID || scope == plan.FindingID || containsFinding(bundle.Findings, plan.FindingID) {
			bundle.Plans = append(bundle.Plans, plan)
		}
	}
	for _, run := range runs {
		if scope == "all" || scope == run.ID || scope == run.PlanID || containsPlan(bundle.Plans, run.PlanID) {
			bundle.Runs = append(bundle.Runs, run)
		}
	}
	for _, event := range events {
		if scope == "all" || event.Subject == scope || containsPlan(bundle.Plans, event.Subject) {
			bundle.AuditEvents = append(bundle.AuditEvents, event)
		}
	}
	bundle.Summary["findings"] = len(bundle.Findings)
	bundle.Summary["plans"] = len(bundle.Plans)
	bundle.Summary["runs"] = len(bundle.Runs)
	bundle.Summary["auditEvents"] = len(bundle.AuditEvents)
	if len(bundle.Findings) == 0 && len(bundle.Plans) == 0 && len(bundle.Runs) == 0 && len(bundle.AuditEvents) == 0 && scope != "all" {
		return core.EvidenceBundle{}, store.ErrNotFound
	}
	return bundle, nil
}

func (s *Store) ListIntegrations(ctx context.Context) ([]core.Integration, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM kubeathrix_integrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	integrations := []core.Integration{}
	for rows.Next() {
		var integration core.Integration
		if err := scanJSON(rows, &integration); err != nil {
			return nil, err
		}
		integrations = append(integrations, integration)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(integrations, func(i, j int) bool { return integrations[i].Name < integrations[j].Name })
	return integrations, nil
}

func (s *Store) IntegrationHealth(ctx context.Context, name string) (core.IntegrationHealth, error) {
	integrations, err := s.ListIntegrations(ctx)
	if err != nil {
		return core.IntegrationHealth{}, err
	}
	findings, err := s.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		return core.IntegrationHealth{}, err
	}
	findingMap := map[string]core.Finding{}
	for _, finding := range findings {
		findingMap[finding.ID] = finding
	}
	normalized := normalize(name)
	for _, integration := range integrations {
		if strings.EqualFold(integration.Name, name) || normalize(integration.Name) == normalized {
			return store.BuildIntegrationHealth(integration, findingMap, s.clock().UTC()), nil
		}
	}
	return core.IntegrationHealth{}, store.ErrNotFound
}

func (s *Store) GetModelProviders(ctx context.Context) (core.ModelProviderSettings, error) {
	var settings core.ModelProviderSettings
	err := s.queryJSON(ctx, `SELECT payload FROM kubeathrix_settings WHERE key = $1`, []any{"modelProviders"}, &settings)
	if err == nil {
		return settings, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return core.ModelProviderSettings{}, err
	}
	return s.delegate.GetModelProviders(ctx)
}

func (s *Store) SaveModelProviders(ctx context.Context, settings core.ModelProviderSettings) (core.ModelProviderSettings, error) {
	for _, provider := range settings.Providers {
		if provider.Name == "" || provider.Type == "" || provider.Model == "" {
			return core.ModelProviderSettings{}, fmt.Errorf("%w: provider name, type, and model are required", store.ErrInvalid)
		}
		if provider.APIKeySecretRef == nil && provider.ExternalSecretRef == nil {
			return core.ModelProviderSettings{}, fmt.Errorf("%w: model provider must use apiKeySecretRef or externalSecretRef", store.ErrInvalid)
		}
	}
	if err := s.saveSetting(ctx, "modelProviders", settings); err != nil {
		return core.ModelProviderSettings{}, err
	}
	return settings, nil
}

func (s *Store) nextPlanSequence(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM kubeathrix_remediation_plans`).Scan(&count); err != nil {
		return 0, err
	}
	return count + 1, nil
}

func (s *Store) saveFinding(ctx context.Context, finding core.Finding) error {
	payload, err := json.Marshal(finding)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kubeathrix_findings (id, payload, updated_at) VALUES ($1, $2, $3)
ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at`, finding.ID, payload, finding.UpdatedAt)
	return err
}

func (s *Store) savePlan(ctx context.Context, plan core.RemediationPlan) error {
	payload, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kubeathrix_remediation_plans (id, finding_id, payload, created_at, updated_at) VALUES ($1, $2, $3, $4, now())
ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, finding_id = EXCLUDED.finding_id, updated_at = now()`, plan.ID, plan.FindingID, payload, plan.CreatedAt)
	return err
}

func (s *Store) saveApproval(ctx context.Context, approval core.ApprovalRequest) error {
	payload, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kubeathrix_approval_requests (id, subject_ref, payload, expires_at, updated_at) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, subject_ref = EXCLUDED.subject_ref, expires_at = EXCLUDED.expires_at, updated_at = EXCLUDED.updated_at`, approval.ID, approval.SubjectRef, payload, approval.ExpiresAt, approval.UpdatedAt)
	return err
}

func (s *Store) saveRun(ctx context.Context, run core.RemediationRun) error {
	payload, err := json.Marshal(run)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kubeathrix_remediation_runs (id, plan_id, payload, updated_at) VALUES ($1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, plan_id = EXCLUDED.plan_id, updated_at = EXCLUDED.updated_at`, run.ID, run.PlanID, payload, run.UpdatedAt)
	return err
}

func (s *Store) saveAuditEvent(ctx context.Context, event core.AuditEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kubeathrix_audit_events (id, payload, created_at) VALUES ($1, $2, $3)
ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, created_at = EXCLUDED.created_at`, event.ID, payload, event.CreatedAt)
	return err
}

func (s *Store) saveIntegration(ctx context.Context, integration core.Integration) error {
	payload, err := json.Marshal(integration)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kubeathrix_integrations (name, payload, updated_at) VALUES ($1, $2, now())
ON CONFLICT (name) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`, integration.Name, payload)
	return err
}

func (s *Store) saveSetting(ctx context.Context, key string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kubeathrix_settings (key, payload, updated_at) VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`, key, payload)
	return err
}

func (s *Store) listPlans(ctx context.Context) ([]core.RemediationPlan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM kubeathrix_remediation_plans`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plans := []core.RemediationPlan{}
	for rows.Next() {
		var plan core.RemediationPlan
		if err := scanJSON(rows, &plan); err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	return plans, rows.Err()
}

func (s *Store) listRuns(ctx context.Context) ([]core.RemediationRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM kubeathrix_remediation_runs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := []core.RemediationRun{}
	for rows.Next() {
		var run core.RemediationRun
		if err := scanJSON(rows, &run); err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (s *Store) queryJSON(ctx context.Context, query string, args []any, target any) error {
	var payload []byte
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		return err
	}
	return json.Unmarshal(payload, target)
}

type jsonScanner interface {
	Scan(dest ...any) error
}

func scanJSON(row jsonScanner, target any) error {
	var payload []byte
	if err := row.Scan(&payload); err != nil {
		return err
	}
	return json.Unmarshal(payload, target)
}

func matchesFilter(finding core.Finding, filter store.FindingFilter) bool {
	if filter.Severity != "" && string(finding.Severity) != filter.Severity {
		return false
	}
	if filter.Status != "" && string(finding.Status) != filter.Status {
		return false
	}
	if filter.Source != "" && finding.Source != filter.Source {
		return false
	}
	if filter.Query != "" {
		haystack := strings.ToLower(finding.Title + " " + finding.BlastRadius + " " + finding.CorrelationGroup)
		if !strings.Contains(haystack, strings.ToLower(filter.Query)) {
			return false
		}
	}
	return true
}

func freshness(latest, now time.Time) string {
	if latest.IsZero() {
		return "no-evidence"
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

func normalize(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(value), " ", "-"), "_", "-")
}

func containsFinding(findings []core.Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func containsPlan(plans []core.RemediationPlan, id string) bool {
	for _, plan := range plans {
		if plan.ID == id {
			return true
		}
	}
	return false
}
