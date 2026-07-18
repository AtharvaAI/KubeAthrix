package managedresources

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
)

var jwtPattern = regexp.MustCompile(`(?i)\beyJ[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\b`)
var awsAccessKeyPattern = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)
var bearerPattern = regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}`)
var assignedSecretPattern = regexp.MustCompile(`(?i)\b(?:password|passwd|token|api[_-]?key|client[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*[^\s,;]+`)
var credentialURLPattern = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@`)

func sanitizeValue(value any, path string) (any, []string) {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		paths := []string{}
		for key, child := range typed {
			childPath := path + "." + key
			if isSensitiveKey(key) {
				result[key] = RedactedValue
				paths = append(paths, childPath)
				continue
			}
			sanitized, childPaths := sanitizeValue(child, childPath)
			result[key] = sanitized
			paths = append(paths, childPaths...)
		}
		return result, paths
	case []any:
		result := make([]any, len(typed))
		paths := []string{}
		for index, child := range typed {
			sanitized, childPaths := sanitizeValue(child, fmt.Sprintf("%s[%d]", path, index))
			result[index] = sanitized
			paths = append(paths, childPaths...)
		}
		return result, paths
	case string:
		sanitized, redacted := sanitizeString(typed)
		if redacted {
			return RedactedValue, []string{path}
		}
		return sanitized, nil
	default:
		return typed, nil
	}
}

func sanitizeStringMap(values map[string]string, path string) (map[string]string, []string) {
	if len(values) == 0 {
		return nil, nil
	}
	result := make(map[string]string, len(values))
	paths := []string{}
	for key, value := range values {
		itemPath := path + "." + key
		if isSensitiveKey(key) || key == "kubectl.kubernetes.io/last-applied-configuration" {
			result[key] = RedactedValue
			paths = append(paths, itemPath)
			continue
		}
		sanitized, redacted := sanitizeString(value)
		if redacted {
			result[key] = RedactedValue
			paths = append(paths, itemPath)
		} else {
			result[key] = sanitized
		}
	}
	return result, paths
}

func isSensitiveKey(key string) bool {
	normalized := normalizeKey(key)
	if strings.HasSuffix(normalized, "ref") || strings.HasSuffix(normalized, "refs") || strings.HasSuffix(normalized, "selector") {
		return false
	}
	switch normalized {
	case "password", "passwd", "credential", "credentials", "token", "accesstoken", "refreshtoken",
		"bearertoken", "apikey", "privatekey", "secretkey", "secretaccesskey", "clientsecret",
		"connectionstring", "stringdata", "binarydata", "data":
		return true
	}
	return strings.Contains(normalized, "password") || strings.Contains(normalized, "privatekey") ||
		strings.Contains(normalized, "clientsecret") || strings.Contains(normalized, "secretaccesskey") ||
		strings.Contains(normalized, "connectionstring")
}

func normalizeKey(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func sanitizeString(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "-----begin") && strings.Contains(lower, "private key-----") {
		return RedactedValue, true
	}
	if strings.HasPrefix(lower, "bearer ") || jwtPattern.MatchString(trimmed) || awsAccessKeyPattern.MatchString(trimmed) {
		return RedactedValue, true
	}
	if parsed, err := url.Parse(trimmed); err == nil && parsed.User != nil {
		if _, hasPassword := parsed.User.Password(); hasPassword {
			return RedactedValue, true
		}
	}
	return sanitizeText(value, 4096), false
}

func sanitizeText(value string, limit int) string {
	if value == "" {
		return ""
	}
	if sanitized, redacted := sanitizeTextPatterns(value); redacted {
		return sanitized
	}
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit]) + "..."
	}
	return value
}

func sanitizedScalar(value string, limit int) string {
	sanitized, redacted := sanitizeString(value)
	if redacted {
		return RedactedValue
	}
	return sanitizeText(sanitized, limit)
}

func sanitizeTextPatterns(value string) (string, bool) {
	if jwtPattern.MatchString(value) || awsAccessKeyPattern.MatchString(value) || bearerPattern.MatchString(value) ||
		assignedSecretPattern.MatchString(value) || credentialURLPattern.MatchString(value) ||
		(strings.Contains(strings.ToLower(value), "-----begin") && strings.Contains(strings.ToLower(value), "private key-----")) {
		return RedactedValue, true
	}
	return value, false
}

func findingsForResource(resource Resource, sensitivePaths []string, now time.Time) []core.Finding {
	findings := []core.Finding{}
	if len(sensitivePaths) > 0 {
		paths := uniqueStrings(sensitivePaths)
		findings = append(findings, newManagedFinding(resource, now,
			"inline-sensitive-value", "Managed external resource contains inline sensitive data", core.SeverityHigh, 88,
			"Sensitive values were redacted at: "+strings.Join(paths, ", ")+".",
			"Move credential material to an approved secret reference and rotate the exposed value before updating the owning source.", core.FixabilityHumanOnly))
	}
	if resource.Provenance.System == ManagementUnknown {
		findings = append(findings, newManagedFinding(resource, now,
			"unknown-provenance", "Managed external resource has unknown ownership", core.SeverityMedium, 55,
			"No Argo CD, Flux, Helm, Crossplane, or operator ownership signal was found.",
			"Establish the owning controller or source repository before proposing a change.", core.FixabilityInformational))
	}
	if resource.Status.Ready != nil && !*resource.Status.Ready {
		findings = append(findings, newManagedFinding(resource, now,
			"not-ready", "Managed external resource is not ready", core.SeverityHigh, 78,
			conditionEvidence(resource.Status.Conditions, "ready"),
			"Review the owning controller, provider events, and current source specification before preparing a human-approved correction.", core.FixabilityHumanOnly))
	}
	if resource.Status.Synced != nil && !*resource.Status.Synced {
		findings = append(findings, newManagedFinding(resource, now,
			"reconcile-failed", "Managed external resource is not synchronized", core.SeverityHigh, 82,
			conditionEvidence(resource.Status.Conditions, "synced"),
			"Resolve the reported reconciliation failure at the owning source and verify controller convergence.", core.FixabilityHumanOnly))
	}
	if resource.Status.Stalled != nil && *resource.Status.Stalled {
		findings = append(findings, newManagedFinding(resource, now,
			"stalled", "Managed external resource reconciliation is stalled", core.SeverityHigh, 84,
			conditionEvidence(resource.Status.Conditions, "stalled"),
			"Inspect controller events and dependencies, then prepare a reviewed change at the owning source.", core.FixabilityHumanOnly))
	}
	if resource.Generation > 0 && resource.Status.ObservedGeneration > 0 && resource.Status.ObservedGeneration < resource.Generation {
		findings = append(findings, newManagedFinding(resource, now,
			"stale-generation", "Managed external resource status is stale", core.SeverityMedium, 62,
			fmt.Sprintf("Controller observed generation %d while the resource is at generation %d.", resource.Status.ObservedGeneration, resource.Generation),
			"Wait for or troubleshoot controller reconciliation before using this resource as remediation evidence.", core.FixabilityInformational))
	}
	if resource.DeletionTimestamp != nil && len(resource.Finalizers) > 0 && now.Sub(*resource.DeletionTimestamp) >= 15*time.Minute {
		findings = append(findings, newManagedFinding(resource, now,
			"deletion-stuck", "Managed external resource deletion may be stuck", core.SeverityMedium, 65,
			fmt.Sprintf("Deletion has remained pending with %d finalizer(s) for at least 15 minutes.", len(resource.Finalizers)),
			"Inspect controller and provider state; do not remove finalizers without confirming external cleanup.", core.FixabilityHumanOnly))
	}
	findings = append(findings, iamFindings(resource, now)...)
	return findings
}

func iamFindings(resource Resource, now time.Time) []core.Finding {
	var wildcardPaths []string
	var publicPaths []string
	walkPolicyMaps(resource.Spec, "spec", &wildcardPaths, &publicPaths)
	findings := []core.Finding{}
	if len(wildcardPaths) > 0 {
		findings = append(findings, newManagedFinding(resource, now,
			"iam-wildcard-action", "Managed IAM policy allows wildcard actions", core.SeverityCritical, 94,
			"Allow statements contain wildcard actions at: "+strings.Join(uniqueStrings(wildcardPaths), ", ")+".",
			"Replace wildcard actions with the least-privilege action set through the owning Kubernetes or GitOps source, with approval.", core.FixabilityHumanOnly))
	}
	if len(publicPaths) > 0 {
		findings = append(findings, newManagedFinding(resource, now,
			"iam-public-principal", "Managed IAM policy grants access to a public principal", core.SeverityCritical, 97,
			"Public principals appear in non-deny statements at: "+strings.Join(uniqueStrings(publicPaths), ", ")+".",
			"Remove the public principal or add an explicitly reviewed restriction through the owning source.", core.FixabilityHumanOnly))
	}
	return findings
}

func walkPolicyMaps(value any, path string, wildcardPaths, publicPaths *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		effect := strings.ToLower(stringAtKey(typed, "effect"))
		if effect == "allow" {
			for key, child := range typed {
				normalized := normalizeKey(key)
				if (normalized == "action" || normalized == "actions") && containsWildcardPermission(child) {
					*wildcardPaths = append(*wildcardPaths, path+"."+key)
				}
			}
		}
		if effect != "deny" {
			for key, child := range typed {
				normalized := normalizeKey(key)
				if normalized == "principal" || normalized == "principals" || normalized == "member" || normalized == "members" {
					if containsPublicPrincipal(child) {
						*publicPaths = append(*publicPaths, path+"."+key)
					}
				}
			}
		}
		for key, child := range typed {
			walkPolicyMaps(child, path+"."+key, wildcardPaths, publicPaths)
		}
	case []any:
		for index, child := range typed {
			walkPolicyMaps(child, fmt.Sprintf("%s[%d]", path, index), wildcardPaths, publicPaths)
		}
	}
}

func stringAtKey(values map[string]any, wanted string) string {
	for key, value := range values {
		if strings.EqualFold(key, wanted) {
			return stringValue(value)
		}
	}
	return ""
}

func containsWildcardPermission(value any) bool {
	for _, item := range scalarStrings(value) {
		item = strings.TrimSpace(item)
		if item == "*" || strings.HasSuffix(item, ":*") {
			return true
		}
	}
	return false
}

func containsPublicPrincipal(value any) bool {
	for _, item := range scalarStrings(value) {
		switch strings.ToLower(strings.TrimSpace(item)) {
		case "*", "allusers", "allauthenticatedusers", "anonymous", "system:anonymous":
			return true
		}
	}
	return false
}

func scalarStrings(value any) []string {
	result := []string{}
	switch typed := value.(type) {
	case string:
		result = append(result, typed)
	case []any:
		for _, child := range typed {
			result = append(result, scalarStrings(child)...)
		}
	case []string:
		result = append(result, typed...)
	case map[string]any:
		for _, child := range typed {
			result = append(result, scalarStrings(child)...)
		}
	}
	return result
}

func conditionEvidence(conditions []Condition, wanted string) string {
	for _, condition := range conditions {
		if strings.EqualFold(condition.Type, wanted) {
			details := "Condition " + condition.Type + " is " + condition.Status
			if condition.Reason != "" {
				details += " with reason " + condition.Reason
			}
			return details + "."
		}
	}
	return "The controller-reported condition is not healthy."
}

func newManagedFinding(resource Resource, now time.Time, rule, title string, severity core.Severity, risk int, details, recommendation string, fixability core.Fixability) core.Finding {
	identity := resource.ID
	if resource.UID != "" {
		identity += "|" + resource.UID
	}
	hash := sha256.Sum256([]byte(rule + "|" + identity))
	id := "managed-resource-" + rule + "-" + hex.EncodeToString(hash[:6])
	target := core.ResourceRef{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
	state := "approval_required"
	if fixability == core.FixabilityInformational {
		state = "triage_required"
	}
	return core.Finding{
		ID:       id,
		Source:   "managed-resource",
		Title:    title,
		Severity: severity,
		Evidence: []core.Evidence{{
			Summary:    title,
			Details:    strings.TrimSpace(details + " " + sourceOfTruthEvidence(resource.Provenance)),
			SourceID:   "kubeathrix/managed-resource",
			ObservedAt: now,
		}},
		Resources:        []core.ResourceRef{target},
		BlastRadius:      "The Kubernetes-managed external resource may affect provider-side access, availability, or reconciliation.",
		Fixability:       fixability,
		Status:           core.FindingOpen,
		CorrelationGroup: "managed-resource:" + resource.ID,
		CorrelationKeys: core.CorrelationKeys{
			Namespace: resource.Namespace,
			Identity:  "managed-resource:" + string(resource.Provenance.System),
		},
		RiskScore:         risk,
		RiskExplanation:   core.RiskExplanation{Version: "managed-resource/v1", BaseScore: risk, FinalScore: risk},
		RemediationState:  state,
		RecommendedAction: recommendation,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func sourceOfTruthEvidence(provenance Provenance) string {
	switch provenance.System {
	case ManagementArgoCD, ManagementFlux:
		return "Source of truth is an upstream GitOps repository; do not patch the live object."
	case ManagementHelm:
		return "Source of truth is the Helm release values or chart; do not patch generated live state."
	case ManagementCrossplane:
		return "Source of truth is the owning Crossplane claim or composite resource; do not patch a generated child."
	case ManagementOperator:
		return "Source of truth is the owning Kubernetes custom resource managed by its controller."
	default:
		return "Source of truth is unknown and must be established before any change is proposed."
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
