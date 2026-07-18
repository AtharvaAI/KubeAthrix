package postgres

import (
	"context"
	"crypto/sha256"
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
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS kubeathrix_schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`); err != nil {
		return err
	}
	migrations := []struct {
		version int
		name    string
		sql     string
	}{
		{version: 1, name: "initial_workflow_tables", sql: `
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
`},
		{version: 2, name: "idempotency_keys", sql: `CREATE TABLE IF NOT EXISTS kubeathrix_idempotency (
	scope TEXT NOT NULL,
	idempotency_key TEXT NOT NULL,
	subject_id TEXT NOT NULL,
	request_fingerprint TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (scope, idempotency_key)
);`},
		{version: 3, name: "finding_exceptions", sql: `CREATE TABLE IF NOT EXISTS kubeathrix_exceptions (
	id TEXT PRIMARY KEY,
	scope TEXT NOT NULL,
	payload JSONB NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS kubeathrix_exceptions_scope_idx ON kubeathrix_exceptions (scope);
CREATE INDEX IF NOT EXISTS kubeathrix_exceptions_expires_idx ON kubeathrix_exceptions (expires_at);`},
		{version: 4, name: "persistent_chaos_runs", sql: `CREATE TABLE IF NOT EXISTS kubeathrix_chaos_runs (
	id TEXT PRIMARY KEY,
	status TEXT NOT NULL,
	version BIGINT NOT NULL,
	payload JSONB NOT NULL,
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS kubeathrix_chaos_runs_status_idx ON kubeathrix_chaos_runs (status);
CREATE INDEX IF NOT EXISTS kubeathrix_chaos_runs_updated_idx ON kubeathrix_chaos_runs (updated_at);`},
	}
	for _, migration := range migrations {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1229801285)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		var applied bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM kubeathrix_schema_migrations WHERE version = $1)`, migration.version).Scan(&applied); err != nil {
			_ = tx.Rollback()
			return err
		}
		if !applied {
			if _, err := tx.ExecContext(ctx, migration.sql); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("apply database migration %d (%s): %w", migration.version, migration.name, err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO kubeathrix_schema_migrations (version, name) VALUES ($1, $2)`, migration.version, migration.name); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
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
	pendingApprovals, err := s.countPendingApprovals(ctx)
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
	dashboard.PendingApprovals = pendingApprovals
	if dashboard.TotalFindings > 0 {
		dashboard.MeanRiskScore = float64(scoreTotal) / float64(dashboard.TotalFindings)
	}
	dashboard.EvidenceFreshness = freshness(latest, s.clock().UTC())
	if len(namespaces) > dashboard.ProtectedNamespaces {
		dashboard.ProtectedNamespaces = len(namespaces)
	}
	return dashboard, nil
}

func (s *Store) countPendingApprovals(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM kubeathrix_approval_requests WHERE payload->>'status' = 'pending' AND (expires_at IS NULL OR expires_at > now())`).Scan(&count)
	return count, err
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

func (s *Store) CreateRemediationPlan(ctx context.Context, findingID, requester string, idempotencyKey ...string) (core.RemediationPlan, error) {
	finding, err := s.GetFinding(ctx, findingID)
	if err != nil {
		return core.RemediationPlan{}, err
	}
	return s.CreateRemediationPlanFromFinding(ctx, finding, requester, idempotencyKey...)
}

func (s *Store) CreateRemediationPlanFromFinding(ctx context.Context, finding core.Finding, requester string, idempotencyKey ...string) (core.RemediationPlan, error) {
	if finding.ID == "" {
		return core.RemediationPlan{}, fmt.Errorf("%w: finding id is required", store.ErrInvalid)
	}
	if requester == "" {
		return core.RemediationPlan{}, fmt.Errorf("%w: authenticated requester is required", store.ErrInvalid)
	}
	key := ""
	if len(idempotencyKey) > 0 {
		key = idempotencyKey[0]
	}
	if key != "" {
		return s.createRemediationPlanIdempotent(ctx, finding, requester, key)
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
		if err := s.saveApproval(ctx, approval); err != nil {
			return core.RemediationPlan{}, err
		}
	}
	run := core.RemediationRun{
		ID:               "run-" + plan.ID,
		PlanID:           plan.ID,
		State:            runState,
		ValidationResult: "server-side dry-run has not been performed",
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

func (s *Store) createRemediationPlanIdempotent(ctx context.Context, finding core.Finding, requester, key string) (core.RemediationPlan, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return core.RemediationPlan{}, err
	}
	defer tx.Rollback()
	lockKey := idempotencyAdvisoryLockKey(requester, key)
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return core.RemediationPlan{}, err
	}
	expectedPlanID := store.IdempotentPlanID(finding.ID, requester, key)
	var subjectID, fingerprint string
	err = tx.QueryRowContext(ctx, `SELECT subject_id, request_fingerprint FROM kubeathrix_idempotency WHERE scope = $1 AND idempotency_key = $2`, requester, key).Scan(&subjectID, &fingerprint)
	if err == nil {
		if subjectID != expectedPlanID || fingerprint != finding.ID {
			return core.RemediationPlan{}, fmt.Errorf("%w: idempotency key was used for a different request", store.ErrConflict)
		}
		var plan core.RemediationPlan
		if err := queryJSONTx(ctx, tx, `SELECT payload FROM kubeathrix_remediation_plans WHERE id = $1`, []any{subjectID}, &plan); err != nil {
			return core.RemediationPlan{}, err
		}
		if err := tx.Commit(); err != nil {
			return core.RemediationPlan{}, err
		}
		return plan, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return core.RemediationPlan{}, err
	}
	now := s.clock().UTC()
	plan := store.BuildRemediationPlan(finding, requester, now, 1)
	plan.ID = expectedPlanID
	actionDescription := "Review remediation plan"
	if len(plan.Actions) > 0 {
		actionDescription = plan.Actions[0].Description
	}
	runState := core.RunPrepared
	var approval *core.ApprovalRequest
	if plan.ApprovalPolicy.Required {
		runState = core.RunPendingApproval
		approval = &core.ApprovalRequest{
			ID: "approval-" + plan.ID, SubjectRef: plan.ID, RequestedAction: actionDescription,
			Requester: requester, Status: core.ApprovalPending, ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now, UpdatedAt: now,
		}
	}
	run := core.RemediationRun{
		ID: "run-" + plan.ID, PlanID: plan.ID, State: runState,
		ValidationResult: "server-side dry-run has not been performed",
		RollbackMetadata: "pre-change snapshot will be captured by remediator before write",
		CreatedAt:        now, UpdatedAt: now,
	}
	for _, action := range plan.Actions {
		run.ActionStatuses = append(run.ActionStatuses, core.ActionStatus{ActionType: action.Type, State: string(runState), Message: "typed action created; no arbitrary command execution path exists"})
	}
	audit := core.AuditEvent{
		ID: "audit-" + plan.ID, Actor: requester, Action: "remediation.plan.created", Subject: plan.ID,
		Message: "Created typed remediation plan for " + finding.ID, CreatedAt: now,
	}
	if err := insertFindingTx(ctx, tx, finding); err != nil {
		return core.RemediationPlan{}, err
	}
	if err := insertPlanTx(ctx, tx, plan); err != nil {
		return core.RemediationPlan{}, err
	}
	if approval != nil {
		if err := insertApprovalTx(ctx, tx, *approval); err != nil {
			return core.RemediationPlan{}, err
		}
	}
	if err := insertRunTx(ctx, tx, run); err != nil {
		return core.RemediationPlan{}, err
	}
	if err := insertAuditTx(ctx, tx, audit); err != nil {
		return core.RemediationPlan{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO kubeathrix_idempotency (scope, idempotency_key, subject_id, request_fingerprint) VALUES ($1, $2, $3, $4)`, requester, key, plan.ID, finding.ID); err != nil {
		return core.RemediationPlan{}, err
	}
	if err := tx.Commit(); err != nil {
		return core.RemediationPlan{}, err
	}
	return plan, nil
}

func idempotencyAdvisoryLockKey(requester, key string) string {
	digest := sha256.Sum256([]byte(requester + "\x00" + key))
	return fmt.Sprintf("remediation-plan:%x", digest)
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

func (s *Store) SyncRemediationPlan(ctx context.Context, plan core.RemediationPlan) error {
	if plan.ID == "" || plan.FindingID == "" {
		return fmt.Errorf("%w: plan id and finding id are required", store.ErrInvalid)
	}
	if _, err := s.GetRemediationPlan(ctx, plan.ID); err != nil {
		return err
	}
	return s.savePlan(ctx, plan)
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
		return core.RemediationRun{}, fmt.Errorf("%w: authenticated actor is required", store.ErrInvalid)
	}
	plan, err := s.GetRemediationPlan(ctx, id)
	if err != nil {
		return core.RemediationRun{}, err
	}
	if plan.ApprovalPolicy.Required && plan.ApprovalPolicy.Decision != core.ApprovalApproved {
		return core.RemediationRun{}, fmt.Errorf("%w: approval is still required", store.ErrInvalid)
	}
	if plan.Status == "rejected" {
		return core.RemediationRun{}, fmt.Errorf("%w: rejected plan cannot be executed", store.ErrInvalid)
	}
	now := s.clock().UTC()
	plan.Status = "execution_requested"
	plan.DryRunResult = core.DryRunResult{Passed: false, Message: "execution requested; waiting for controller server-side dry-run"}
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
	run.State = core.RunExecutionRequested
	run.ActionStatuses = make([]core.ActionStatus, 0, len(plan.Actions))
	for _, action := range plan.Actions {
		run.ActionStatuses = append(run.ActionStatuses, core.ActionStatus{ActionType: action.Type, State: "execution_requested", Message: "waiting for typed operator reconciliation"})
	}
	run.ValidationResult = "execution requested; controller validation has not completed"
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

func (s *Store) SyncFinding(ctx context.Context, finding core.Finding) error {
	var existing core.Finding
	if err := s.queryJSON(ctx, `SELECT payload FROM kubeathrix_findings WHERE id = $1`, []any{finding.ID}, &existing); err == nil {
		if finding.Status == core.FindingOpen && (existing.Status == core.FindingInReview || existing.Status == core.FindingSuppressed || existing.Status == core.FindingRemediating || existing.Status == core.FindingResolved) {
			finding.Status, finding.RemediationState = existing.Status, existing.RemediationState
		}
		if !existing.CreatedAt.IsZero() && (finding.CreatedAt.IsZero() || existing.CreatedAt.Before(finding.CreatedAt)) {
			finding.CreatedAt = existing.CreatedAt
		}
	}
	exceptions, _ := s.ListExceptions(ctx)
	for _, exception := range exceptions {
		if exception.Status == "active" && exceptionMatches(exception, finding) {
			finding.Status = core.FindingSuppressed
			break
		}
	}
	return s.saveFinding(ctx, finding)
}

func (s *Store) ExpireFindings(ctx context.Context, observedBefore time.Time) error {
	findings, err := s.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		return err
	}
	now := s.clock().UTC()
	for _, finding := range findings {
		if finding.Status != core.FindingOpen && finding.Status != core.FindingInReview {
			continue
		}
		observedAt := store.LastObservedAt(finding)
		if observedAt.IsZero() || !observedAt.Before(observedBefore) {
			continue
		}
		tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return err
		}
		finding.Status = core.FindingExpired
		finding.RemediationState = "evidence_expired"
		finding.UpdatedAt = now
		if err := insertFindingTx(ctx, tx, finding); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := insertAuditTx(ctx, tx, core.AuditEvent{ID: fmt.Sprintf("audit-%d-%s", now.UnixNano(), finding.ID), Actor: "system", Action: "finding.expired", Subject: finding.ID, Message: "Finding evidence exceeded the configured freshness window", CreatedAt: now}); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UpdateFindingStatus(ctx context.Context, id string, status core.FindingStatus, actor, reason string) (core.Finding, error) {
	if actor == "" || strings.TrimSpace(reason) == "" {
		return core.Finding{}, fmt.Errorf("%w: actor and reason are required", store.ErrInvalid)
	}
	if status != core.FindingOpen && status != core.FindingInReview {
		return core.Finding{}, fmt.Errorf("%w: only open and in_review are manual lifecycle transitions", store.ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return core.Finding{}, err
	}
	defer tx.Rollback()
	var finding core.Finding
	if err := queryJSONTx(ctx, tx, `SELECT payload FROM kubeathrix_findings WHERE id = $1 FOR UPDATE`, []any{id}, &finding); err != nil {
		return core.Finding{}, err
	}
	if finding.Status == core.FindingResolved || finding.Status == core.FindingRemediating {
		return core.Finding{}, fmt.Errorf("%w: cluster-backed lifecycle state cannot be changed manually", store.ErrConflict)
	}
	now := s.clock().UTC()
	finding.Status, finding.UpdatedAt = status, now
	if err := insertFindingTx(ctx, tx, finding); err != nil {
		return core.Finding{}, err
	}
	if err := insertAuditTx(ctx, tx, core.AuditEvent{ID: fmt.Sprintf("audit-%d", now.UnixNano()), Actor: actor, Action: "finding.status.changed", Subject: id, Message: reason, CreatedAt: now}); err != nil {
		return core.Finding{}, err
	}
	return finding, tx.Commit()
}

func (s *Store) ListExceptions(ctx context.Context) ([]core.Exception, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM kubeathrix_exceptions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := s.clock().UTC()
	items := []core.Exception{}
	expiredChanged := false
	for rows.Next() {
		var exception core.Exception
		if err := scanJSON(rows, &exception); err != nil {
			return nil, err
		}
		if exception.Status == "active" && !exception.ExpiresAt.After(now) {
			exception.Status, exception.UpdatedAt = "expired", now
			_ = s.saveException(ctx, exception)
			_ = s.saveAuditEvent(ctx, core.AuditEvent{ID: fmt.Sprintf("audit-%d-%s", now.UnixNano(), exception.ID), Actor: "system", Action: "exception.expired", Subject: exception.ID, Message: "Exception expiration elapsed", CreatedAt: now})
			expiredChanged = true
		}
		items = append(items, exception)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if expiredChanged {
		_ = rows.Close()
		findings, err := s.ListFindings(ctx, store.FindingFilter{})
		if err != nil {
			return nil, err
		}
		for _, finding := range findings {
			if finding.Status != core.FindingSuppressed {
				continue
			}
			active := false
			for _, exception := range items {
				if exception.Status == "active" && exceptionMatches(exception, finding) {
					active = true
					break
				}
			}
			if !active {
				finding.Status, finding.UpdatedAt = core.FindingOpen, now
				if err := s.saveFinding(ctx, finding); err != nil {
					return nil, err
				}
			}
		}
	}
	return items, nil
}

func (s *Store) CreateException(ctx context.Context, exception core.Exception, actor string) (core.Exception, error) {
	now := s.clock().UTC()
	if actor == "" || strings.TrimSpace(exception.Scope) == "" || strings.TrimSpace(exception.Reason) == "" {
		return core.Exception{}, fmt.Errorf("%w: scope, reason, and authenticated actor are required", store.ErrInvalid)
	}
	if !exception.ExpiresAt.After(now) || exception.ExpiresAt.After(now.Add(365*24*time.Hour)) {
		return core.Exception{}, fmt.Errorf("%w: expiration must be in the future and no more than 365 days", store.ErrInvalid)
	}
	exception.ID = fmt.Sprintf("exception-%d", now.UnixNano())
	exception.Owner, exception.Status = actor, "active"
	exception.AuditMetadata = "created by authenticated API request"
	exception.CreatedAt, exception.UpdatedAt = now, now
	findings, err := s.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		return core.Exception{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return core.Exception{}, err
	}
	defer tx.Rollback()
	payload, err := json.Marshal(exception)
	if err != nil {
		return core.Exception{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO kubeathrix_exceptions (id, scope, payload, expires_at, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6)`, exception.ID, exception.Scope, payload, exception.ExpiresAt, now, now); err != nil {
		return core.Exception{}, err
	}
	for _, finding := range findings {
		if exceptionMatches(exception, finding) {
			finding.Status, finding.UpdatedAt = core.FindingSuppressed, now
			if err := insertFindingTx(ctx, tx, finding); err != nil {
				return core.Exception{}, err
			}
		}
	}
	if err := insertAuditTx(ctx, tx, core.AuditEvent{ID: fmt.Sprintf("audit-%d", now.UnixNano()), Actor: actor, Action: "exception.created", Subject: exception.ID, Message: exception.Reason, CreatedAt: now}); err != nil {
		return core.Exception{}, err
	}
	return exception, tx.Commit()
}

func (s *Store) DeleteException(ctx context.Context, id, actor string) error {
	var removed core.Exception
	if err := s.queryJSON(ctx, `SELECT payload FROM kubeathrix_exceptions WHERE id = $1`, []any{id}, &removed); err != nil {
		return err
	}
	findings, err := s.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		return err
	}
	exceptions, err := s.ListExceptions(ctx)
	if err != nil {
		return err
	}
	now := s.clock().UTC()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM kubeathrix_exceptions WHERE id = $1`, id); err != nil {
		return err
	}
	for _, finding := range findings {
		if finding.Status != core.FindingSuppressed || !exceptionMatches(removed, finding) {
			continue
		}
		stillSuppressed := false
		for _, exception := range exceptions {
			if exception.ID != id && exception.Status == "active" && exceptionMatches(exception, finding) {
				stillSuppressed = true
				break
			}
		}
		if !stillSuppressed {
			finding.Status, finding.UpdatedAt = core.FindingOpen, now
			if err := insertFindingTx(ctx, tx, finding); err != nil {
				return err
			}
		}
	}
	if err := insertAuditTx(ctx, tx, core.AuditEvent{ID: fmt.Sprintf("audit-%d", now.UnixNano()), Actor: actor, Action: "exception.deleted", Subject: id, Message: "Exception removed", CreatedAt: now}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) saveException(ctx context.Context, exception core.Exception) error {
	payload, err := json.Marshal(exception)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE kubeathrix_exceptions SET payload=$2, expires_at=$3, updated_at=$4 WHERE id=$1`, exception.ID, payload, exception.ExpiresAt, exception.UpdatedAt)
	return err
}

func exceptionMatches(exception core.Exception, finding core.Finding) bool {
	return exception.Scope == finding.ID || exception.Scope == finding.CorrelationGroup || exception.Scope == "source:"+finding.Source
}

func (s *Store) SyncRemediationRun(ctx context.Context, run core.RemediationRun) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := upsertRunTx(ctx, tx, run); err != nil {
		return err
	}
	var plan core.RemediationPlan
	err = queryJSONTx(ctx, tx, `SELECT payload FROM kubeathrix_remediation_plans WHERE id = $1 FOR UPDATE`, []any{run.PlanID}, &plan)
	if errors.Is(err, store.ErrNotFound) {
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	plan.Status = string(run.State)
	if run.State == core.RunDryRunPassed || run.State == core.RunVerifying || run.State == core.RunSucceeded {
		plan.DryRunResult = core.DryRunResult{Passed: true, Message: run.ValidationResult}
	}
	if err := upsertPlanTx(ctx, tx, plan); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RequestRollback(ctx context.Context, runID, actor string) (core.RemediationRun, error) {
	if actor == "" {
		return core.RemediationRun{}, fmt.Errorf("%w: authenticated actor is required", store.ErrInvalid)
	}
	run, err := s.GetRemediationRun(ctx, runID)
	if err != nil {
		return core.RemediationRun{}, err
	}
	now := s.clock().UTC()
	run.State = core.RunRollbackRequested
	run.ValidationResult = "rollback requested; waiting for Kubernetes controller status"
	run.UpdatedAt = now
	if err := s.saveRun(ctx, run); err != nil {
		return core.RemediationRun{}, err
	}
	if plan, planErr := s.GetRemediationPlan(ctx, run.PlanID); planErr == nil {
		plan.Status = "rollback_requested"
		_ = s.savePlan(ctx, plan)
	}
	_ = s.saveAuditEvent(ctx, core.AuditEvent{
		ID: fmt.Sprintf("audit-%d", now.UnixNano()), Actor: actor,
		Action: "remediation.rollback.requested", Subject: run.ID,
		Message: "Rollback requested for remediation run", CreatedAt: now,
	})
	return run, nil
}

func (s *Store) Approve(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error) {
	return s.decide(ctx, approvalID, actor, reason, core.ApprovalApproved)
}

func (s *Store) Reject(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error) {
	return s.decide(ctx, approvalID, actor, reason, core.ApprovalRejected)
}

func (s *Store) decide(ctx context.Context, approvalID, actor, reason string, status core.ApprovalStatus) (core.ApprovalRequest, error) {
	if actor == "" {
		return core.ApprovalRequest{}, fmt.Errorf("%w: authenticated actor is required", store.ErrInvalid)
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
		if status == core.ApprovalApproved {
			plan.Status = "approved"
			plan.ApprovalPolicy.Decision = core.ApprovalApproved
			plan.DryRunResult = core.DryRunResult{Passed: false, Message: "approval recorded; server-side dry-run has not yet been performed"}
		} else {
			plan.Status = "rejected"
			plan.ApprovalPolicy.Decision = core.ApprovalRejected
			plan.DryRunResult = core.DryRunResult{Passed: false, Message: "approval rejected; no controller action will be attempted"}
		}
		_ = s.savePlan(ctx, plan)
	}
	run, err := s.GetRemediationRun(ctx, "run-"+approval.SubjectRef)
	if err == nil {
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
		_ = s.saveRun(ctx, run)
	}
	if plan.FindingID != "" {
		finding, findingErr := s.GetFinding(ctx, plan.FindingID)
		if findingErr == nil {
			finding.UpdatedAt = now
			if status == core.ApprovalApproved {
				finding.Status = core.FindingInReview
				finding.RemediationState = "approval_granted"
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

func (s *Store) CreateChaosRun(ctx context.Context, run core.ChaosExperimentRun, actor, auditAction string) (core.ChaosExperimentRun, error) {
	if run.ID == "" || run.Version != 0 {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: new chaos run must have an id and version zero", store.ErrInvalid)
	}
	run.Version = 1
	payload, err := json.Marshal(run)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO kubeathrix_chaos_runs (id, status, version, payload, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)`, run.ID, run.Status, run.Version, payload, run.CreatedAt, run.UpdatedAt); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
			return core.ChaosExperimentRun{}, store.ErrConflict
		}
		return core.ChaosExperimentRun{}, err
	}
	if auditAction != "" {
		if err := insertAuditTx(ctx, tx, chaosAudit(run, actor, auditAction)); err != nil {
			return core.ChaosExperimentRun{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return core.ChaosExperimentRun{}, err
	}
	return run, nil
}

func (s *Store) GetChaosRun(ctx context.Context, id string) (core.ChaosExperimentRun, error) {
	var run core.ChaosExperimentRun
	if err := s.queryJSON(ctx, `SELECT payload FROM kubeathrix_chaos_runs WHERE id = $1`, []any{id}, &run); err != nil {
		return core.ChaosExperimentRun{}, err
	}
	return run, nil
}

func (s *Store) ListChaosRuns(ctx context.Context) ([]core.ChaosExperimentRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM kubeathrix_chaos_runs ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := []core.ChaosExperimentRun{}
	for rows.Next() {
		var run core.ChaosExperimentRun
		if err := scanJSON(rows, &run); err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (s *Store) UpdateChaosRun(ctx context.Context, run core.ChaosExperimentRun, expectedVersion int64, actor, auditAction string) (core.ChaosExperimentRun, error) {
	if run.ID == "" || run.Version != expectedVersion {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: chaos run version does not match expected version", store.ErrInvalid)
	}
	run.Version++
	payload, err := json.Marshal(run)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE kubeathrix_chaos_runs
SET status = $2, version = $3, payload = $4, updated_at = $5 WHERE id = $1 AND version = $6`,
		run.ID, run.Status, run.Version, payload, run.UpdatedAt, expectedVersion)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	if changed != 1 {
		return core.ChaosExperimentRun{}, store.ErrConflict
	}
	if auditAction != "" {
		if err := insertAuditTx(ctx, tx, chaosAudit(run, actor, auditAction)); err != nil {
			return core.ChaosExperimentRun{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return core.ChaosExperimentRun{}, err
	}
	return run, nil
}

func chaosAudit(run core.ChaosExperimentRun, actor, action string) core.AuditEvent {
	return core.AuditEvent{
		ID: fmt.Sprintf("audit-chaos-%s-%d", run.ID, run.Version), Actor: actor, Action: action,
		Subject: run.ID, Message: run.Message, CreatedAt: run.UpdatedAt,
	}
}

func (s *Store) EvidenceBundle(ctx context.Context, scope string) (core.EvidenceBundle, error) {
	if scope == "" {
		scope = "all"
	}
	findings, err := s.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		return core.EvidenceBundle{}, err
	}
	chaosRuns, err := s.ListChaosRuns(ctx)
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
	for _, run := range chaosRuns {
		if scope == "all" || scope == run.ID || scope == run.ExperimentID {
			bundle.ChaosRuns = append(bundle.ChaosRuns, run)
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
	bundle.Summary["chaosRuns"] = len(bundle.ChaosRuns)
	bundle.Summary["auditEvents"] = len(bundle.AuditEvents)
	if len(bundle.Findings) == 0 && len(bundle.Plans) == 0 && len(bundle.Runs) == 0 && len(bundle.ChaosRuns) == 0 && len(bundle.AuditEvents) == 0 && scope != "all" {
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

func insertFindingTx(ctx context.Context, tx *sql.Tx, finding core.Finding) error {
	payload, err := json.Marshal(finding)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO kubeathrix_findings (id, payload, updated_at) VALUES ($1, $2, $3)
ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at`, finding.ID, payload, finding.UpdatedAt)
	return err
}

func insertPlanTx(ctx context.Context, tx *sql.Tx, plan core.RemediationPlan) error {
	payload, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO kubeathrix_remediation_plans (id, finding_id, payload, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)`, plan.ID, plan.FindingID, payload, plan.CreatedAt)
	return err
}

func insertApprovalTx(ctx context.Context, tx *sql.Tx, approval core.ApprovalRequest) error {
	payload, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO kubeathrix_approval_requests (id, subject_ref, payload, expires_at, updated_at) VALUES ($1, $2, $3, $4, $5)`, approval.ID, approval.SubjectRef, payload, approval.ExpiresAt, approval.UpdatedAt)
	return err
}

func insertRunTx(ctx context.Context, tx *sql.Tx, run core.RemediationRun) error {
	payload, err := json.Marshal(run)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO kubeathrix_remediation_runs (id, plan_id, payload, updated_at) VALUES ($1, $2, $3, $4)`, run.ID, run.PlanID, payload, run.UpdatedAt)
	return err
}

func upsertRunTx(ctx context.Context, tx *sql.Tx, run core.RemediationRun) error {
	payload, err := json.Marshal(run)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO kubeathrix_remediation_runs (id, plan_id, payload, updated_at) VALUES ($1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, plan_id = EXCLUDED.plan_id, updated_at = EXCLUDED.updated_at`, run.ID, run.PlanID, payload, run.UpdatedAt)
	return err
}

func upsertPlanTx(ctx context.Context, tx *sql.Tx, plan core.RemediationPlan) error {
	payload, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO kubeathrix_remediation_plans (id, finding_id, payload, created_at, updated_at) VALUES ($1, $2, $3, $4, now())
ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, finding_id = EXCLUDED.finding_id, updated_at = now()`, plan.ID, plan.FindingID, payload, plan.CreatedAt)
	return err
}

func insertAuditTx(ctx context.Context, tx *sql.Tx, event core.AuditEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO kubeathrix_audit_events (id, payload, created_at) VALUES ($1, $2, $3)`, event.ID, payload, event.CreatedAt)
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

func queryJSONTx(ctx context.Context, tx *sql.Tx, query string, args []any, target any) error {
	var payload []byte
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&payload); err != nil {
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
	if filter.Fixability != "" && string(finding.Fixability) != filter.Fixability {
		return false
	}
	if filter.MinRisk > 0 && finding.RiskScore < filter.MinRisk {
		return false
	}
	if filter.Namespace != "" || filter.Kind != "" {
		matched := false
		for _, resource := range finding.Resources {
			namespace := resource.Namespace
			if resource.Kind == "Namespace" {
				namespace = resource.Name
			}
			if (filter.Namespace == "" || namespace == filter.Namespace) && (filter.Kind == "" || resource.Kind == filter.Kind) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
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
