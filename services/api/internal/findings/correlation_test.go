package findings

import (
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
)

func TestCorrelationUsesExplicitKeysAndTimeWindows(t *testing.T) {
	now := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	base := core.Finding{Severity: core.SeverityHigh, UpdatedAt: now, Resources: []core.ResourceRef{{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "payments", Name: "checkout"}}}
	first := base
	first.ID, first.Source = "finding-a", "trivy"
	first.CorrelationKeys.Image = "sha256:abc"
	second := base
	second.ID, second.Source = "finding-b", "kyverno"
	second.UpdatedAt = now.Add(time.Hour)
	second.CorrelationKeys.Image = "sha256:abc"
	third := base
	third.ID, third.Source = "finding-c", "kubescape"
	third.UpdatedAt = now.Add(25 * time.Hour)
	third.CorrelationKeys.Image = "sha256:abc"
	correlated := Correlate([]core.Finding{first, second, third})
	if correlated[0].CorrelationGroup != correlated[1].CorrelationGroup {
		t.Fatal("same image within the time window did not correlate")
	}
	if correlated[2].CorrelationGroup == correlated[0].CorrelationGroup {
		t.Fatal("finding outside the image time window was incorrectly correlated")
	}
	if correlated[0].RiskExplanation.Version != RiskModelVersion || correlated[0].RiskExplanation.FinalScore <= correlated[0].RiskExplanation.BaseScore {
		t.Fatalf("risk score is not explainable: %#v", correlated[0].RiskExplanation)
	}
}

func TestCorrelationDoesNotUseTitlesOrFreeFormStrings(t *testing.T) {
	now := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	left := core.Finding{ID: "left", Source: "a", Title: "identical title", BlastRadius: "identical words", Severity: core.SeverityMedium, UpdatedAt: now}
	right := core.Finding{ID: "right", Source: "b", Title: "identical title", BlastRadius: "identical words", Severity: core.SeverityMedium, UpdatedAt: now}
	correlated := Correlate([]core.Finding{left, right})
	if correlated[0].CorrelationGroup == correlated[1].CorrelationGroup {
		t.Fatal("free-form title or blast-radius text must not correlate findings")
	}
}

func TestRiskConfigIsValidatedAndChangesExplainableScore(t *testing.T) {
	config, err := ParseConfig(`{"highBase":60,"multiSourcePoints":10}`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	left := core.Finding{ID: "a", Source: "one", Severity: core.SeverityHigh, UpdatedAt: now, CorrelationKeys: core.CorrelationKeys{Identity: "rbac/role"}}
	right := core.Finding{ID: "b", Source: "two", Severity: core.SeverityHigh, UpdatedAt: now, CorrelationKeys: core.CorrelationKeys{Identity: "rbac/role"}}
	correlated := CorrelateWithConfig([]core.Finding{left, right}, config)
	if correlated[0].RiskExplanation.BaseScore != 60 {
		t.Fatalf("configured base score was ignored: %#v", correlated[0].RiskExplanation)
	}
	if _, err := ParseConfig(`{"criticalBase":20,"highBase":80}`); err == nil {
		t.Fatal("invalid descending severity configuration was accepted")
	}
}
