package actioncatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

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

func TestManagedResourceChangeIsStrictHITLProposal(t *testing.T) {
	action := validManagedResourceChangeAction(t)
	definition, err := ValidateProposal(action)
	if err != nil {
		t.Fatalf("valid managed resource proposal was rejected: %v", err)
	}
	if _, err := Validate(action); err != nil {
		t.Fatalf("valid managed resource action was rejected: %v", err)
	}
	if definition.RiskTier != RiskC || !definition.ApprovalRequired {
		t.Fatalf("managed resource changes must be approval-gated Tier C: %#v", definition)
	}
	if ExecutionModeFor(action) != ModeProposal {
		t.Fatalf("managed resource changes must remain proposal-only, got %s", ExecutionModeFor(action))
	}
	if !supports(definition, "iam.services.k8s.aws/v1alpha1", "Role") {
		t.Fatal("managed resource proposal must support allowlisted resources through its wildcard catalog entry")
	}
	checks := strings.Join(definition.VerificationChecks, " ")
	if !strings.Contains(checks, "observedGeneration") || !strings.Contains(checks, "Ready=True") || !strings.Contains(checks, "Synced=True") {
		t.Fatalf("managed resource verification contract is incomplete: %v", definition.VerificationChecks)
	}
	rollback := strings.Join(definition.RollbackProcedure, " ")
	if !strings.Contains(rollback, "rollbackSourceSpec") || !strings.Contains(rollback, "owning Kubernetes source") {
		t.Fatalf("managed resource rollback must restore the source spec: %v", definition.RollbackProcedure)
	}
}

func TestManagedResourceReviewIsReachableHITLWithoutFabricatingPatch(t *testing.T) {
	action := Action{
		Type: ManagedResourceReviewAction, APIVersion: "iam.services.k8s.aws/v1alpha1", Kind: "Role",
		Params: map[string]string{
			"findingId":        "managed-resource-iam-wildcard-action-1234",
			"managementSystem": "crossplane",
			"sourceOfTruth":    "owning Kubernetes controller resource or upstream GitOps repository",
		},
	}
	definition, err := ValidateProposal(action)
	if err != nil {
		t.Fatalf("valid managed-resource review was rejected: %v", err)
	}
	if definition.RiskTier != RiskC || !definition.ApprovalRequired || ExecutionModeFor(action) != ModeProposal {
		t.Fatalf("managed-resource review escaped HITL proposal policy: %#v", definition)
	}
	action.Params["patch"] = `[{"op":"remove","path":"/spec/policy"}]`
	if _, err := ValidateProposal(action); err == nil {
		t.Fatal("review action accepted a mutation parameter")
	}
}

func TestManagedResourceChangeRequiresEveryParameterAtProposalTime(t *testing.T) {
	valid := validManagedResourceChangeAction(t)
	definition, ok := Lookup(ManagedResourceChangeAction)
	if !ok {
		t.Fatal("managed resource action missing from catalog")
	}
	for _, parameter := range definition.RequiredParameters {
		t.Run(parameter, func(t *testing.T) {
			action := valid
			action.Params = cloneParams(valid.Params)
			delete(action.Params, parameter)
			if _, err := ValidateProposal(action); err == nil || !strings.Contains(err.Error(), parameter) {
				t.Fatalf("missing %s should fail strict proposal validation, got %v", parameter, err)
			}
		})
	}
}

func TestManagedResourceChangeRejectsUnknownOrUnsafePatchParameters(t *testing.T) {
	tests := map[string]func(map[string]string){
		"unknown parameter": func(params map[string]string) { params["cloudCredential"] = "forbidden" },
		"wrong patch type":  func(params map[string]string) { params["patchType"] = "application/merge-patch+json" },
		"metadata patch": func(params map[string]string) {
			params["patch"] = `[{"op":"replace","path":"/metadata/name","value":"other"}]`
		},
		"unsupported op": func(params map[string]string) {
			params["patch"] = `[{"op":"move","path":"/spec/policy","from":"/spec/old"}]`
		},
		"empty mutation":   func(params map[string]string) { params["patch"] = `[{"op":"test","path":"/spec/policy","value":{}}]` },
		"invalid rollback": func(params map[string]string) { params["rollbackSourceSpec"] = `[]` },
		"null rollback":    func(params map[string]string) { params["rollbackSourceSpec"] = `null` },
		"stale diff hash":  func(params map[string]string) { params["rollbackSourceSpec"] = `{"policy":"different"}` },
		"invalid generation": func(params map[string]string) {
			params["sourceGeneration"] = "0"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			action := validManagedResourceChangeAction(t)
			mutate(action.Params)
			if _, err := ValidateProposal(action); err == nil {
				t.Fatal("unsafe managed resource proposal was accepted")
			}
		})
	}
}

func validManagedResourceChangeAction(t *testing.T) Action {
	t.Helper()
	rollbackSpec := map[string]any{"policy": map[string]any{"statements": []any{"read"}}}
	canonical, err := json.Marshal(rollbackSpec)
	if err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256(canonical)
	diff, err := json.Marshal(managedResourceDiff{
		Format:         "unified",
		BeforeSpecHash: hex.EncodeToString(before[:]),
		AfterSpecHash:  strings.Repeat("a", 64),
		Content:        "--- before/spec.json\n+++ after/spec.json\n@@ -1 +1 @@\n-read\n+read-limited\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	return Action{
		Type:       ManagedResourceChangeAction,
		APIVersion: "iam.services.k8s.aws/v1alpha1",
		Kind:       "Role",
		Params: map[string]string{
			"managementController":  "ack.services.k8s.aws",
			"sourceName":            "application-reader",
			"sourceNamespace":       "payments",
			"sourceUID":             "ef12d3c4-5678-49ab-8cde-f0123456789a",
			"sourceResourceVersion": "19342",
			"sourceGeneration":      "7",
			"externalResourceID":    "arn:aws:iam::123456789012:role/application-reader",
			"patchType":             ManagedResourceJSONPatch,
			"patch":                 `[{"op":"test","path":"/spec/policy","value":{"statements":["read"]}},{"op":"replace","path":"/spec/policy","value":{"statements":["read-limited"]}}]`,
			"diff":                  string(diff),
			"rollbackSourceSpec":    string(canonical),
		},
	}
}

func cloneParams(params map[string]string) map[string]string {
	clone := make(map[string]string, len(params))
	for key, value := range params {
		clone[key] = value
	}
	return clone
}
