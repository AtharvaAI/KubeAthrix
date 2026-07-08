package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	db       *sql.DB
	delegate store.Repository
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
	s := &Store{db: db, delegate: delegate}
	if err := s.migrate(ctx); err != nil {
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
CREATE TABLE IF NOT EXISTS kubeathrix_audit_events (
	id TEXT PRIMARY KEY,
	payload JSONB NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kubeathrix_findings_payload_severity_idx ON kubeathrix_findings ((payload->>'severity'));
CREATE INDEX IF NOT EXISTS kubeathrix_findings_payload_source_idx ON kubeathrix_findings ((payload->>'source'));
`)
	return err
}

func (s *Store) Health(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return err
	}
	return s.delegate.Health(ctx)
}

func (s *Store) Dashboard(ctx context.Context) (core.Dashboard, error) {
	return s.delegate.Dashboard(ctx)
}

func (s *Store) ListFindings(ctx context.Context, filter store.FindingFilter) ([]core.Finding, error) {
	return s.delegate.ListFindings(ctx, filter)
}

func (s *Store) GetFinding(ctx context.Context, id string) (core.Finding, error) {
	return s.delegate.GetFinding(ctx, id)
}

func (s *Store) CreateRemediationPlan(ctx context.Context, findingID, requester string) (core.RemediationPlan, error) {
	return s.delegate.CreateRemediationPlan(ctx, findingID, requester)
}

func (s *Store) GetRemediationRun(ctx context.Context, id string) (core.RemediationRun, error) {
	return s.delegate.GetRemediationRun(ctx, id)
}

func (s *Store) Approve(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error) {
	return s.delegate.Approve(ctx, approvalID, actor, reason)
}

func (s *Store) Reject(ctx context.Context, approvalID, actor, reason string) (core.ApprovalRequest, error) {
	return s.delegate.Reject(ctx, approvalID, actor, reason)
}

func (s *Store) ListAuditEvents(ctx context.Context) ([]core.AuditEvent, error) {
	return s.delegate.ListAuditEvents(ctx)
}

func (s *Store) ListIntegrations(ctx context.Context) ([]core.Integration, error) {
	return s.delegate.ListIntegrations(ctx)
}

func (s *Store) GetModelProviders(ctx context.Context) (core.ModelProviderSettings, error) {
	return s.delegate.GetModelProviders(ctx)
}

func (s *Store) SaveModelProviders(ctx context.Context, settings core.ModelProviderSettings) (core.ModelProviderSettings, error) {
	return s.delegate.SaveModelProviders(ctx, settings)
}
