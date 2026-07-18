package store

import (
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/pkg/actioncatalog"
	"github.com/atharvaai/kubeathrix/services/api/internal/core"
)

func TestManagedResourceFindingNeverSelectsDirectResourceGovernance(t *testing.T) {
	finding := core.Finding{
		ID:                "managed-resource-role-team-reader-not-ready",
		Source:            "managed-resource",
		Title:             "Kubernetes-managed external resource is not ready",
		Fixability:        core.FixabilityHumanOnly,
		RecommendedAction: "Review the owning resource and controller status",
		Resources: []core.ResourceRef{{
			APIVersion: "iam.services.k8s.aws/v1alpha1",
			Kind:       "Role",
			Namespace:  "payments",
			Name:       "team-reader",
		}},
	}

	plan := BuildRemediationPlan(finding, "operator@example.com", time.Unix(1, 0).UTC(), 1)
	if len(plan.Actions) != 1 {
		t.Fatalf("expected one bounded proposal, got %#v", plan.Actions)
	}
	action := plan.Actions[0]
	if action.Type != actioncatalog.ManagedResourceReviewAction {
		t.Fatalf("managed resource finding must remain proposal-only, got %q", action.Type)
	}
	if plan.RiskTier != core.RiskTierC || !plan.ApprovalPolicy.Required {
		t.Fatalf("managed resource proposal must be Tier C with approval, got tier=%s approval=%v", plan.RiskTier, plan.ApprovalPolicy.Required)
	}
	if action.Type == "apply_resource_governance" {
		t.Fatal("generic resource text must not select a direct namespace mutation")
	}
}
