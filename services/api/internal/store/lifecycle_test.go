package store

import (
	"context"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
)

func TestFindingEvidenceExpirationAndReopen(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	finding := core.Finding{
		ID: "finding-stale", Source: "scanner", Status: core.FindingOpen, RemediationState: "not_started",
		Evidence:  []core.Evidence{{SourceID: "scanner/report", ObservedAt: now.Add(-25 * time.Hour)}},
		CreatedAt: now.Add(-25 * time.Hour), UpdatedAt: now.Add(-25 * time.Hour),
	}
	repository := NewMemoryStore(WithClock(func() time.Time { return now }), WithFindings([]core.Finding{finding}))
	if err := repository.ExpireFindings(context.Background(), now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	expired, err := repository.GetFinding(context.Background(), finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if expired.Status != core.FindingExpired || expired.RemediationState != "evidence_expired" {
		t.Fatalf("stale finding did not expire: %#v", expired)
	}
	audit, err := repository.ListAuditEvents(context.Background())
	if err != nil || len(audit) != 1 || audit[0].Action != "finding.expired" || audit[0].Actor != "system" {
		t.Fatalf("expiration was not audited: %#v, %v", audit, err)
	}

	finding.Evidence[0].ObservedAt = now.Add(time.Minute)
	finding.UpdatedAt = now.Add(time.Minute)
	if err := repository.SyncFinding(context.Background(), finding); err != nil {
		t.Fatal(err)
	}
	reopened, err := repository.GetFinding(context.Background(), finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status != core.FindingOpen {
		t.Fatalf("fresh evidence did not reopen expired finding: %#v", reopened)
	}
}
