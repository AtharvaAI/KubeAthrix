package actioncatalog

import "testing"

func TestEveryDefinitionDeclaresSafetyContract(t *testing.T) {
	for _, definition := range All() {
		if definition.Type == "" || len(definition.SupportedResources) == 0 || definition.RiskTier == "" || definition.DryRunBehavior == "" || definition.DiffStrategy == "" || len(definition.VerificationChecks) == 0 || len(definition.RollbackProcedure) == 0 || definition.IdempotencyBehavior == "" || definition.FailureHandling == "" || definition.DefaultExecutionMode == "" {
			t.Fatalf("incomplete catalog definition: %#v", definition)
		}
	}
}

func TestProbeExecutionRequiresExplicitConfiguration(t *testing.T) {
	action := Action{Type: "patch_workload_probes", APIVersion: "apps/v1", Kind: "Deployment", Params: map[string]string{"configured": "false"}}
	if ExecutionModeFor(action) != ModeProposal {
		t.Fatal("unconfigured probe action must remain proposal-only")
	}
	if _, err := Validate(action); err == nil {
		t.Fatal("unconfigured probe action must fail executable action validation")
	}
}
