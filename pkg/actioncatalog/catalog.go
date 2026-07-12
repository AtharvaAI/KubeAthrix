package actioncatalog

import (
	"fmt"
	"sort"
	"strings"
)

const Version = "v1"

type RiskTier string
type ExecutionMode string

const (
	RiskA RiskTier = "A"
	RiskB RiskTier = "B"
	RiskC RiskTier = "C"
	RiskD RiskTier = "D"

	ModeDirect      ExecutionMode = "direct"
	ModeGitOps      ExecutionMode = "gitops_proposal"
	ModeProposal    ExecutionMode = "proposal_only"
	ModeInformation ExecutionMode = "informational"
)

type ResourceKind struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

type Action struct {
	Type       string
	APIVersion string
	Kind       string
	Params     map[string]string
}

type Definition struct {
	Type                 string         `json:"type"`
	SupportedResources   []ResourceKind `json:"supportedResources"`
	RiskTier             RiskTier       `json:"riskTier"`
	RequiredPermissions  []string       `json:"requiredPermissions"`
	ApprovalRequired     bool           `json:"approvalRequired"`
	DryRunBehavior       string         `json:"dryRunBehavior"`
	DiffStrategy         string         `json:"diffStrategy"`
	VerificationChecks   []string       `json:"verificationChecks"`
	RollbackProcedure    []string       `json:"rollbackProcedure"`
	IdempotencyBehavior  string         `json:"idempotencyBehavior"`
	FailureHandling      string         `json:"failureHandling"`
	DefaultExecutionMode ExecutionMode  `json:"defaultExecutionMode"`
	RequiredParameters   []string       `json:"requiredParameters,omitempty"`
}

var definitions = map[string]Definition{
	"apply_resource_governance": {
		Type: "apply_resource_governance", SupportedResources: []ResourceKind{{APIVersion: "v1", Kind: "Namespace"}},
		RiskTier: RiskA, RequiredPermissions: []string{"get/list/create/update ResourceQuota", "get/list/create/update LimitRange"},
		DryRunBehavior:       "Server-side dry-run every create or update before mutation.",
		DiffStrategy:         "Render exact ResourceQuota and LimitRange objects from the selected governance profile.",
		VerificationChecks:   []string{"Read both objects back", "Compare hard limits and container defaults", "Re-run namespace governance scan"},
		RollbackProcedure:    []string{"Restore pre-change objects", "Delete only objects created by the run", "Re-run namespace governance scan"},
		IdempotencyBehavior:  "Use fixed managed object names and converge specs with optimistic concurrency.",
		FailureHandling:      "Stop before the second write if dry-run fails; on partial application, restore the captured snapshot.",
		DefaultExecutionMode: ModeDirect,
	},
	"patch_pod_security_labels": {
		Type: "patch_pod_security_labels", SupportedResources: []ResourceKind{{APIVersion: "v1", Kind: "Namespace"}},
		RiskTier: RiskB, ApprovalRequired: true, RequiredPermissions: []string{"get/patch Namespace metadata"},
		DryRunBehavior:      "Server-side dry-run an optimistic metadata patch and reject system namespaces.",
		DiffStrategy:        "Show the exact previous and proposed Pod Security label maps.",
		VerificationChecks:  []string{"Read namespace labels back", "Re-scan namespace Pod Security posture"},
		RollbackProcedure:   []string{"Restore the exact prior values or absence of each managed label"},
		IdempotencyBehavior: "Patch only the three managed label keys using the observed resourceVersion.",
		FailureHandling:     "Do not retry conflicts blindly; re-read and regenerate the diff.", DefaultExecutionMode: ModeDirect,
	},
	"patch_workload_resources": {
		Type: "patch_workload_resources", SupportedResources: workloadKinds(), RiskTier: RiskB, ApprovalRequired: true,
		RequiredPermissions: []string{"get/patch target workload"},
		DryRunBehavior:      "Server-side dry-run an exact strategic merge patch for named containers.",
		DiffStrategy:        "Show each named container's previous and proposed CPU/memory requests and limits.",
		VerificationChecks:  []string{"Read workload template back", "Wait for rollout availability", "Re-run resource posture scan"},
		RollbackProcedure:   []string{"Restore the exact workload template resource fields from the pre-change snapshot"},
		IdempotencyBehavior: "Do not overwrite existing resources unless the plan explicitly includes their observed values.",
		FailureHandling:     "Stop on rollout regression and make the snapshot eligible for rollback.", DefaultExecutionMode: ModeDirect,
		RequiredParameters: []string{"cpuRequest", "memoryRequest", "cpuLimit", "memoryLimit"},
	},
	"create_pdb": {
		Type: "create_pdb", SupportedResources: []ResourceKind{{APIVersion: "apps/v1", Kind: "Deployment"}, {APIVersion: "apps/v1", Kind: "StatefulSet"}},
		RiskTier: RiskB, ApprovalRequired: true, RequiredPermissions: []string{"get target workload", "get/list/create/update PodDisruptionBudget"},
		DryRunBehavior:      "Resolve the workload selector, reject empty selectors, then server-side dry-run the exact PDB.",
		DiffStrategy:        "Show the resolved non-empty matchLabels selector and availability threshold.",
		VerificationChecks:  []string{"Read PDB back", "Confirm expectedPods and disruptionAllowed conditions become observable"},
		RollbackProcedure:   []string{"Restore a prior same-name PDB or delete only the PDB created by the run"},
		IdempotencyBehavior: "Use a deterministic managed name and refuse ownership collisions.",
		FailureHandling:     "Never create a PDB with an empty selector; leave the action failed with no mutation.", DefaultExecutionMode: ModeDirect,
		RequiredParameters: []string{"minAvailable"},
	},
	"patch_workload_probes": {
		Type: "patch_workload_probes", SupportedResources: workloadKinds(), RiskTier: RiskB, ApprovalRequired: true,
		RequiredPermissions:  []string{"get/patch target workload"},
		DryRunBehavior:       "Only dry-run when named containers, ports, paths, timings, and failure thresholds are explicitly configured.",
		DiffStrategy:         "Show complete prior and proposed probe objects for every named container.",
		VerificationChecks:   []string{"Read workload template back", "Wait for rollout availability", "Observe readiness without restart regression"},
		RollbackProcedure:    []string{"Restore exact prior readiness, liveness, and startup probe objects"},
		IdempotencyBehavior:  "Patch only explicitly named containers and compare the observed template before writing.",
		FailureHandling:      "Missing configuration is proposal-only; rollout or health regression makes the snapshot eligible for rollback.",
		DefaultExecutionMode: ModeDirect,
		RequiredParameters:   []string{"configured", "container", "port", "readinessPath", "livenessPath"},
	},
	"propose_network_policy":     proposal("propose_network_policy", RiskC, "Generate reviewable NetworkPolicy manifests; no executor is registered."),
	"propose_security_hardening": proposal("propose_security_hardening", RiskC, "Generate RBAC, image, admission, or network review artifacts; no executor is registered."),
	"explain_only": {
		Type: "explain_only", SupportedResources: []ResourceKind{{APIVersion: "*", Kind: "*"}}, RiskTier: RiskD,
		ApprovalRequired: true, DryRunBehavior: "No write is possible.", DiffStrategy: "Evidence and recommendation only.",
		VerificationChecks: []string{"Human triage records a disposition"}, RollbackProcedure: []string{"Not applicable"},
		IdempotencyBehavior: "Repeated proposals reuse the request idempotency key.", FailureHandling: "Remain informational.",
		DefaultExecutionMode: ModeInformation,
	},
}

func Lookup(actionType string) (Definition, bool) {
	definition, ok := definitions[actionType]
	return definition, ok
}

func All() []Definition {
	result := make([]Definition, 0, len(definitions))
	for _, definition := range definitions {
		result = append(result, definition)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Type < result[j].Type })
	return result
}

func Validate(action Action) (Definition, error) {
	definition, err := ValidateProposal(action)
	if err != nil {
		return Definition{}, err
	}
	for _, parameter := range definition.RequiredParameters {
		if strings.TrimSpace(action.Params[parameter]) == "" {
			return Definition{}, fmt.Errorf("action %s requires parameter %s", action.Type, parameter)
		}
	}
	return definition, nil
}

func ValidateProposal(action Action) (Definition, error) {
	definition, ok := Lookup(action.Type)
	if !ok {
		return Definition{}, fmt.Errorf("unknown action type %q in catalog %s", action.Type, Version)
	}
	if !supports(definition, action.APIVersion, action.Kind) {
		return Definition{}, fmt.Errorf("action %s does not support %s %s", action.Type, action.APIVersion, action.Kind)
	}
	return definition, nil
}

func ExecutionModeFor(action Action) ExecutionMode {
	definition, ok := Lookup(action.Type)
	if !ok {
		return ModeProposal
	}
	if action.Type == "patch_workload_probes" && action.Params["configured"] != "true" {
		return ModeProposal
	}
	return definition.DefaultExecutionMode
}

func supports(definition Definition, apiVersion, kind string) bool {
	for _, resource := range definition.SupportedResources {
		if (resource.APIVersion == "*" || resource.APIVersion == apiVersion) && (resource.Kind == "*" || resource.Kind == kind) {
			return true
		}
	}
	return false
}

func workloadKinds() []ResourceKind {
	return []ResourceKind{{APIVersion: "apps/v1", Kind: "Deployment"}, {APIVersion: "apps/v1", Kind: "StatefulSet"}, {APIVersion: "apps/v1", Kind: "DaemonSet"}}
}

func proposal(actionType string, risk RiskTier, detail string) Definition {
	return Definition{
		Type: actionType, SupportedResources: []ResourceKind{{APIVersion: "*", Kind: "*"}}, RiskTier: risk,
		ApprovalRequired: true, DryRunBehavior: "No cluster write is attempted.", DiffStrategy: detail,
		VerificationChecks:  []string{"Review generated artifacts against current cluster state"},
		RollbackProcedure:   []string{"Not applicable until a separately reviewed system applies the proposal"},
		IdempotencyBehavior: "Repeated proposals reuse the request idempotency key.",
		FailureHandling:     "Keep the action proposal-only and report the generation error.", DefaultExecutionMode: ModeGitOps,
	}
}
