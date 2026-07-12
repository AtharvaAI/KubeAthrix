//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/postgres"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresMigrationsPersistenceAndExceptions(t *testing.T) {
	url := os.Getenv("KUBEATHRIX_POSTGRES_TEST_URL")
	if url == "" {
		t.Skip("KUBEATHRIX_POSTGRES_TEST_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, table := range []string{"kubeathrix_chaos_runs", "kubeathrix_idempotency", "kubeathrix_exceptions", "kubeathrix_remediation_runs", "kubeathrix_approval_requests", "kubeathrix_remediation_plans", "kubeathrix_audit_events", "kubeathrix_findings", "kubeathrix_integrations", "kubeathrix_settings", "kubeathrix_schema_migrations"} {
		_, _ = db.ExecContext(ctx, "DROP TABLE IF EXISTS "+table+" CASCADE")
	}
	delegate := store.NewMemoryStore()
	persisted, err := postgres.New(ctx, url, delegate)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	finding := core.Finding{ID: "finding-persistence", Source: "test", Title: "persistent finding", Severity: core.SeverityMedium, Status: core.FindingOpen, Resources: []core.ResourceRef{{APIVersion: "v1", Kind: "Namespace", Name: "sandbox"}}, UpdatedAt: now, CreatedAt: now}
	if err := persisted.SyncFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	exception, err := persisted.CreateException(ctx, core.Exception{Scope: finding.ID, Reason: "integration test", ExpiresAt: now.Add(time.Hour)}, "test-user")
	if err != nil {
		t.Fatal(err)
	}
	if exception.Owner != "test-user" {
		t.Fatalf("owner was not derived: %#v", exception)
	}
	approvalExpiry := now.Add(15 * time.Minute)
	chaosRun, err := persisted.CreateChaosRun(ctx, core.ChaosExperimentRun{
		ID: "chaos-run-persistence", ExperimentID: "network-latency-service", Status: core.ChaosPendingApproval,
		Message: "approval required", RequestedBy: "test-user", Resource: core.ResourceRef{APIVersion: "chaos-mesh.org/v1alpha1", Kind: "NetworkChaos", Namespace: "sandbox", Name: "latency"},
		CreatedAt: now, UpdatedAt: now, ApprovalExpiresAt: &approvalExpiry,
	}, "test-user", "chaos.approval.requested")
	if err != nil {
		t.Fatal(err)
	}
	chaosRun.Status, chaosRun.Message, chaosRun.ApprovedBy, chaosRun.UpdatedAt = core.ChaosApproved, "approved", "approver", now.Add(time.Second)
	chaosRun, err = persisted.UpdateChaosRun(ctx, chaosRun, chaosRun.Version, "approver", "chaos.approved")
	if err != nil {
		t.Fatal(err)
	}
	stale := chaosRun
	stale.Version--
	if _, err := persisted.UpdateChaosRun(ctx, stale, stale.Version, "stale-writer", "chaos.invalid"); err == nil {
		t.Fatal("stale chaos transition was not rejected")
	}
	if err := persisted.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := postgres.New(ctx, url, delegate)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	findings, err := restarted.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Status != core.FindingSuppressed {
		t.Fatalf("finding did not survive restart with suppression: %#v", findings)
	}
	exceptions, err := restarted.ListExceptions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(exceptions) != 1 || exceptions[0].ID != exception.ID {
		t.Fatalf("exception did not survive restart: %#v", exceptions)
	}
	restartedChaos, err := restarted.GetChaosRun(ctx, chaosRun.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restartedChaos.Status != core.ChaosApproved || restartedChaos.Version != chaosRun.Version || restartedChaos.ApprovedBy != "approver" {
		t.Fatalf("chaos run did not survive restart: %#v", restartedChaos)
	}
	var migrations int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM kubeathrix_schema_migrations`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations < 4 {
		t.Fatalf("expected at least four migrations, got %d", migrations)
	}
}
