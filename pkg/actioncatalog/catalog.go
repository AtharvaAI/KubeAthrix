package actioncatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
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

const (
	ManagedResourceChangeAction = "propose_managed_resource_change"
	ManagedResourceReviewAction = "review_managed_resource_finding"
	ManagedResourceJSONPatch    = "application/json-patch+json"
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
	AllowedParameters    []string       `json:"allowedParameters,omitempty"`
	StrictParameters     bool           `json:"strictParameters,omitempty"`
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
	ManagedResourceReviewAction: {
		Type: ManagedResourceReviewAction, SupportedResources: []ResourceKind{{APIVersion: "*", Kind: "*"}}, RiskTier: RiskC,
		ApprovalRequired: true,
		RequiredPermissions: []string{
			"list the allowlisted Kubernetes-managed resource API group",
			"no Kubernetes or external-provider mutation permission",
		},
		DryRunBehavior:       "Validate the finding, target, management system, and declared source of truth without producing or applying a patch.",
		DiffStrategy:         "Show the cited flaw and source-of-truth review instruction; an exact change requires a separate trusted proposal artifact.",
		VerificationChecks:   []string{"A reviewer confirms the controller or GitOps source of truth", "The source owner records a disposition or supplies a separately validated exact proposal"},
		RollbackProcedure:    []string{"Not applicable because this review action cannot mutate Kubernetes or an external provider"},
		IdempotencyBehavior:  "Reuse the finding identity and evidence fingerprint; a recreated Kubernetes object receives a new UID-derived finding identity.",
		FailureHandling:      "Remain proposal-only and notify the source owner; never infer an IAM or provider change from incomplete evidence.",
		DefaultExecutionMode: ModeProposal,
		RequiredParameters:   []string{"findingId", "managementSystem", "sourceOfTruth"},
		AllowedParameters:    []string{"findingId", "managementSystem", "sourceOfTruth"},
		StrictParameters:     true,
	},
	ManagedResourceChangeAction: {
		Type: ManagedResourceChangeAction, SupportedResources: []ResourceKind{{APIVersion: "*", Kind: "*"}}, RiskTier: RiskC,
		ApprovalRequired: true,
		RequiredPermissions: []string{
			"list the allowlisted Kubernetes-managed resource API group",
			"no mutation permission; applying the proposal requires a separately approved source-owner workflow",
		},
		DryRunBehavior: "Validate the source identity, resourceVersion, generation, RFC 6902 spec patch, exact before/after diff metadata, and rollback spec without writing to Kubernetes or the external provider.",
		DiffStrategy:   "Show the exact RFC 6902 patch against the owning Kubernetes resource spec and a unified before/after diff bound to SHA-256 spec hashes.",
		VerificationChecks: []string{
			"Confirm status.observedGeneration equals metadata.generation on the owning Kubernetes source",
			"Confirm Ready=True and Synced=True conditions for the current generation",
			"Re-run the originating policy and relationship checks against the reconciled external resource",
		},
		RollbackProcedure: []string{
			"Restore rollbackSourceSpec through the owning Kubernetes source after a separate approval",
			"Wait for status.observedGeneration to match metadata.generation and for Ready=True and Synced=True",
			"Re-run the originating policy and relationship checks after reconciliation",
		},
		IdempotencyBehavior:  "Bind the proposal to sourceUID, sourceResourceVersion, sourceGeneration, and spec hashes; regenerate instead of applying when any value is stale.",
		FailureHandling:      "Remain proposal-only; never report success or mutate either Kubernetes or the external provider unless the source-owner workflow applies the reviewed patch and every verification check passes.",
		DefaultExecutionMode: ModeProposal,
		RequiredParameters: []string{
			"managementController", "sourceName", "sourceUID", "sourceResourceVersion", "sourceGeneration",
			"externalResourceID", "patchType", "patch", "diff", "rollbackSourceSpec",
		},
		AllowedParameters: []string{
			"managementController", "sourceName", "sourceNamespace", "sourceUID", "sourceResourceVersion", "sourceGeneration",
			"externalResourceID", "patchType", "patch", "diff", "rollbackSourceSpec",
		},
		StrictParameters: true,
	},
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
	if err := validateParameters(definition, action); err != nil {
		return Definition{}, err
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
	if definition.StrictParameters {
		if err := validateParameters(definition, action); err != nil {
			return Definition{}, err
		}
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

func validateParameters(definition Definition, action Action) error {
	for _, parameter := range definition.RequiredParameters {
		if strings.TrimSpace(action.Params[parameter]) == "" {
			return fmt.Errorf("action %s requires parameter %s", action.Type, parameter)
		}
	}
	if len(definition.AllowedParameters) > 0 {
		allowed := make(map[string]struct{}, len(definition.AllowedParameters))
		for _, parameter := range definition.AllowedParameters {
			allowed[parameter] = struct{}{}
		}
		for parameter := range action.Params {
			if _, ok := allowed[parameter]; !ok {
				return fmt.Errorf("action %s does not allow parameter %s", action.Type, parameter)
			}
		}
	}
	if action.Type == ManagedResourceChangeAction {
		return validateManagedResourceChange(action)
	}
	return nil
}

type managedResourcePatchOperation struct {
	Operation string          `json:"op"`
	Path      string          `json:"path"`
	Value     json.RawMessage `json:"value,omitempty"`
}

type managedResourceDiff struct {
	Format         string `json:"format"`
	BeforeSpecHash string `json:"beforeSpecHash"`
	AfterSpecHash  string `json:"afterSpecHash"`
	Content        string `json:"content"`
}

func validateManagedResourceChange(action Action) error {
	if strings.TrimSpace(action.APIVersion) == "" || strings.TrimSpace(action.Kind) == "" || action.APIVersion == "*" || action.Kind == "*" {
		return fmt.Errorf("action %s requires a concrete apiVersion and kind", action.Type)
	}
	if !validDNSName(action.Params["managementController"]) {
		return fmt.Errorf("action %s parameter managementController must be a lowercase DNS name", action.Type)
	}
	generation, err := strconv.ParseInt(action.Params["sourceGeneration"], 10, 64)
	if err != nil || generation < 1 {
		return fmt.Errorf("action %s parameter sourceGeneration must be a positive integer", action.Type)
	}
	if action.Params["patchType"] != ManagedResourceJSONPatch {
		return fmt.Errorf("action %s parameter patchType must be %s", action.Type, ManagedResourceJSONPatch)
	}

	var operations []managedResourcePatchOperation
	if err := decodeStrictJSON(action.Params["patch"], &operations); err != nil {
		return fmt.Errorf("action %s parameter patch must be a strict RFC 6902 array: %w", action.Type, err)
	}
	mutating := false
	for index, operation := range operations {
		if operation.Path != "/spec" && !strings.HasPrefix(operation.Path, "/spec/") {
			return fmt.Errorf("action %s patch operation %d must target /spec", action.Type, index)
		}
		switch operation.Operation {
		case "add", "replace":
			if len(operation.Value) == 0 {
				return fmt.Errorf("action %s patch operation %d requires value", action.Type, index)
			}
			mutating = true
		case "remove":
			if len(operation.Value) != 0 {
				return fmt.Errorf("action %s remove operation %d must not include value", action.Type, index)
			}
			mutating = true
		case "test":
			if len(operation.Value) == 0 {
				return fmt.Errorf("action %s test operation %d requires value", action.Type, index)
			}
		default:
			return fmt.Errorf("action %s patch operation %d uses unsupported op %q", action.Type, index, operation.Operation)
		}
	}
	if !mutating {
		return fmt.Errorf("action %s parameter patch requires at least one add, remove, or replace operation", action.Type)
	}

	var rollbackSpec map[string]any
	if err := decodeStrictJSON(action.Params["rollbackSourceSpec"], &rollbackSpec); err != nil {
		return fmt.Errorf("action %s parameter rollbackSourceSpec must be a JSON object: %w", action.Type, err)
	}
	if rollbackSpec == nil {
		return fmt.Errorf("action %s parameter rollbackSourceSpec must be a JSON object", action.Type)
	}
	canonicalRollbackSpec, err := json.Marshal(rollbackSpec)
	if err != nil {
		return fmt.Errorf("action %s parameter rollbackSourceSpec cannot be canonicalized: %w", action.Type, err)
	}

	var diff managedResourceDiff
	if err := decodeStrictJSON(action.Params["diff"], &diff); err != nil {
		return fmt.Errorf("action %s parameter diff must contain exact diff metadata: %w", action.Type, err)
	}
	if diff.Format != "unified" {
		return fmt.Errorf("action %s diff format must be unified", action.Type)
	}
	if !validSHA256(diff.BeforeSpecHash) || !validSHA256(diff.AfterSpecHash) {
		return fmt.Errorf("action %s diff requires valid beforeSpecHash and afterSpecHash SHA-256 values", action.Type)
	}
	rollbackHash := sha256.Sum256(canonicalRollbackSpec)
	if !strings.EqualFold(diff.BeforeSpecHash, hex.EncodeToString(rollbackHash[:])) {
		return fmt.Errorf("action %s diff beforeSpecHash does not match rollbackSourceSpec", action.Type)
	}
	if strings.EqualFold(diff.BeforeSpecHash, diff.AfterSpecHash) {
		return fmt.Errorf("action %s diff beforeSpecHash and afterSpecHash must differ", action.Type)
	}
	if !strings.Contains(diff.Content, "--- ") || !strings.Contains(diff.Content, "+++ ") || !strings.Contains(diff.Content, "@@") {
		return fmt.Errorf("action %s diff content must be a unified diff", action.Type)
	}
	return nil
}

func decodeStrictJSON(value string, target any) error {
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || !asciiAlphaNumeric(label[0]) || !asciiAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !asciiAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
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
