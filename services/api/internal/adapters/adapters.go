package adapters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type NativeSource interface {
	Snapshot(ctx context.Context) (core.ClusterSnapshot, error)
}

type Collection struct {
	Integrations []core.Integration
	Health       []core.IntegrationHealth
	Findings     []core.Finding
}

type result struct {
	integration core.Integration
	health      core.IntegrationHealth
	findings    []core.Finding
}

type adapter interface {
	collect(ctx context.Context) result
}

type Manager struct {
	adapters []adapter
	now      func() time.Time
	ttl      time.Duration

	mu       sync.Mutex
	cached   Collection
	cachedAt time.Time
}

func NewManager(native NativeSource) (*Manager, error) {
	config, err := kubernetesConfig()
	if err != nil {
		return nil, err
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return NewManagerFromClient(client, native, nil), nil
}

func NewManagerFromClient(client dynamic.Interface, native NativeSource, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	adapters := []adapter{
		&trivyAdapter{client: client, now: now},
		&kyvernoAdapter{client: client, now: now},
		&kubescapeAdapter{client: client, now: now},
	}
	if native != nil {
		adapters = append(adapters, &nativeAdapter{source: native, now: now})
	}
	return &Manager{adapters: adapters, now: now, ttl: 30 * time.Second}
}

func (m *Manager) Collect(ctx context.Context) Collection {
	m.mu.Lock()
	if !m.cachedAt.IsZero() && m.now().Sub(m.cachedAt) < m.ttl {
		cached := cloneCollection(m.cached)
		m.mu.Unlock()
		return cached
	}
	m.mu.Unlock()

	results := make([]result, len(m.adapters))
	var wait sync.WaitGroup
	for index, source := range m.adapters {
		wait.Add(1)
		go func(index int, source adapter) {
			defer wait.Done()
			results[index] = source.collect(ctx)
		}(index, source)
	}
	wait.Wait()
	collection := Collection{}
	seen := map[string]struct{}{}
	for _, item := range results {
		collection.Integrations = append(collection.Integrations, item.integration)
		collection.Health = append(collection.Health, item.health)
		for _, finding := range item.findings {
			if _, ok := seen[finding.ID]; ok {
				continue
			}
			seen[finding.ID] = struct{}{}
			collection.Findings = append(collection.Findings, finding)
		}
	}
	sort.Slice(collection.Integrations, func(i, j int) bool { return collection.Integrations[i].Name < collection.Integrations[j].Name })
	sort.Slice(collection.Health, func(i, j int) bool { return collection.Health[i].Name < collection.Health[j].Name })
	sort.Slice(collection.Findings, func(i, j int) bool {
		if collection.Findings[i].RiskScore == collection.Findings[j].RiskScore {
			return collection.Findings[i].ID < collection.Findings[j].ID
		}
		return collection.Findings[i].RiskScore > collection.Findings[j].RiskScore
	})
	m.mu.Lock()
	m.cached = cloneCollection(collection)
	m.cachedAt = m.now()
	m.mu.Unlock()
	return collection
}

type reportResource struct {
	gvr        schema.GroupVersionResource
	namespaced bool
	kind       string
}

func collectResources(ctx context.Context, client dynamic.Interface, resources []reportResource) ([]unstructured.Unstructured, []string, error) {
	items := []unstructured.Unstructured{}
	available := []string{}
	var firstPermissionError error
	for _, source := range resources {
		var list *unstructured.UnstructuredList
		var err error
		if source.namespaced {
			list, err = client.Resource(source.gvr).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		} else {
			list, err = client.Resource(source.gvr).List(ctx, metav1.ListOptions{})
		}
		if apierrors.IsNotFound(err) || apierrors.IsMethodNotSupported(err) {
			continue
		}
		if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
			if firstPermissionError == nil {
				firstPermissionError = err
			}
			continue
		}
		if err != nil {
			return items, available, err
		}
		available = append(available, source.gvr.Group+"/"+source.gvr.Version+" "+source.gvr.Resource)
		items = append(items, list.Items...)
	}
	return items, available, firstPermissionError
}

type trivyAdapter struct {
	client dynamic.Interface
	now    func() time.Time
}

func (a *trivyAdapter) collect(ctx context.Context) result {
	resources := []reportResource{
		{gvr: schema.GroupVersionResource{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "vulnerabilityreports"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "configauditreports"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "exposedsecretreports"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "rbacassessmentreports"}, namespaced: true},
	}
	items, available, err := collectResources(ctx, a.client, resources)
	findings := []core.Finding{}
	lastSeen := time.Time{}
	for index := range items {
		object := &items[index]
		if object.GetCreationTimestamp().Time.After(lastSeen) {
			lastSeen = object.GetCreationTimestamp().Time
		}
		switch object.GetKind() {
		case "VulnerabilityReport":
			findings = append(findings, normalizeTrivyVulnerabilities(object)...)
		case "ConfigAuditReport", "RbacAssessmentReport":
			findings = append(findings, normalizeTrivyChecks(object)...)
		case "ExposedSecretReport":
			findings = append(findings, normalizeTrivySecrets(object)...)
		}
	}
	return adapterResult("Trivy Operator", "scanner", []string{"aquasecurity.github.io/v1alpha1"},
		[]string{"list/watch VulnerabilityReport", "list/watch ConfigAuditReport", "list/watch ExposedSecretReport", "list/watch RbacAssessmentReport"},
		available, lastSeen, findings, err, a.now())
}

type kyvernoAdapter struct {
	client dynamic.Interface
	now    func() time.Time
}

func (a *kyvernoAdapter) collect(ctx context.Context) result {
	resources := []reportResource{
		{gvr: schema.GroupVersionResource{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "policyreports"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "clusterpolicyreports"}},
		{gvr: schema.GroupVersionResource{Group: "openreports.io", Version: "v1alpha1", Resource: "reports"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "openreports.io", Version: "v1alpha1", Resource: "clusterreports"}},
	}
	items, available, err := collectResources(ctx, a.client, resources)
	findings := []core.Finding{}
	lastSeen := time.Time{}
	for index := range items {
		object := &items[index]
		if object.GetCreationTimestamp().Time.After(lastSeen) {
			lastSeen = object.GetCreationTimestamp().Time
		}
		findings = append(findings, normalizePolicyReport(object)...)
	}
	return adapterResult("Kyverno", "policy", []string{"wgpolicyk8s.io/v1alpha2", "openreports.io/v1alpha1"},
		[]string{"list/watch namespaced policy reports", "list/watch cluster policy reports"}, available, lastSeen, findings, err, a.now())
}

type kubescapeAdapter struct {
	client dynamic.Interface
	now    func() time.Time
}

func (a *kubescapeAdapter) collect(ctx context.Context) result {
	resources := []reportResource{
		{gvr: schema.GroupVersionResource{Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "workloadconfigurationscansummaries"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "vulnerabilitymanifestsummaries"}, namespaced: true},
	}
	items, available, err := collectResources(ctx, a.client, resources)
	findings := []core.Finding{}
	lastSeen := time.Time{}
	for index := range items {
		object := &items[index]
		if object.GetCreationTimestamp().Time.After(lastSeen) {
			lastSeen = object.GetCreationTimestamp().Time
		}
		findings = append(findings, normalizeKubescapeSummary(object)...)
	}
	return adapterResult("Kubescape", "scanner", []string{"spdx.softwarecomposition.kubescape.io/v1beta1"},
		[]string{"list/watch WorkloadConfigurationScanSummary", "list/watch VulnerabilityManifestSummary"}, available, lastSeen, findings, err, a.now())
}

type nativeAdapter struct {
	source NativeSource
	now    func() time.Time
}

func (a *nativeAdapter) collect(ctx context.Context) result {
	snapshot, err := a.source.Snapshot(ctx)
	lastSeen := snapshot.Scan.LastRunAt
	available := []string{}
	if err == nil {
		available = []string{"kubernetes/v1 native posture"}
	}
	return adapterResult("Kubernetes native posture", "native", []string{"kubernetes/v1"},
		[]string{"read workload and namespace specs/status", "read RBAC rules", "no Secret object access"},
		available, lastSeen, snapshot.Findings, err, a.now())
}

func adapterResult(name, integrationType string, supported, permissions, available []string, lastSeen time.Time, findings []core.Finding, collectErr error, checkedAt time.Time) result {
	enabled := len(available) > 0
	status := "not_configured"
	health := "not_configured"
	setupGaps := []string{}
	errorState := ""
	if enabled {
		status, health = "online", "healthy"
	}
	if collectErr != nil {
		errorState = collectErr.Error()
		if apierrors.IsForbidden(collectErr) || apierrors.IsUnauthorized(collectErr) {
			status, health = "permission_denied", "degraded"
			setupGaps = append(setupGaps, "Grant the documented read-only report permissions to the API service account.")
		} else {
			status, health = "error", "unhealthy"
			setupGaps = append(setupGaps, "Inspect the adapter error and Kubernetes API availability.")
		}
	} else if !enabled {
		setupGaps = append(setupGaps, "Install or enable a supported report API; an environment flag alone is not considered healthy.")
	}
	lastSeenText := "never"
	if !lastSeen.IsZero() {
		lastSeenText = lastSeen.UTC().Format(time.RFC3339)
	}
	return result{
		integration: core.Integration{Name: name, Type: integrationType, Enabled: enabled, Status: status},
		health: core.IntegrationHealth{
			Name: name, Type: integrationType, Enabled: enabled, Status: status, Health: health,
			DataLastSeen: lastSeenText, Permissions: permissions, SetupGaps: setupGaps,
			SupportedVersions: supported, ErrorState: errorState, FindingsCount: len(findings), CheckedAt: checkedAt.UTC(),
		},
		findings: findings,
	}
}

func normalizeTrivyVulnerabilities(object *unstructured.Unstructured) []core.Finding {
	vulnerabilities, _, _ := unstructured.NestedSlice(object.Object, "report", "vulnerabilities")
	artifactRepository, _, _ := unstructured.NestedString(object.Object, "report", "artifact", "repository")
	artifactTag, _, _ := unstructured.NestedString(object.Object, "report", "artifact", "tag")
	artifactDigest, _, _ := unstructured.NestedString(object.Object, "report", "artifact", "digest")
	resource := trivyResource(object)
	findings := []core.Finding{}
	for _, raw := range vulnerabilities {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		vulnerabilityID, _, _ := unstructured.NestedString(item, "vulnerabilityID")
		severityText, _, _ := unstructured.NestedString(item, "severity")
		title, _, _ := unstructured.NestedString(item, "title")
		fixedVersion, _, _ := unstructured.NestedString(item, "fixedVersion")
		primaryLink, _, _ := unstructured.NestedString(item, "primaryLink")
		severity := severityFromText(severityText)
		image := strings.Trim(artifactRepository+":"+artifactTag, ":")
		correlation := "image:" + valueOr(artifactDigest, image)
		details := strings.TrimSpace(fmt.Sprintf("image=%s digest=%s fixedVersion=%s advisory=%s", image, artifactDigest, fixedVersion, primaryLink))
		finding := newFinding("trivy", object, vulnerabilityID, valueOr(title, vulnerabilityID), severity, resource, details, correlation)
		finding.CorrelationKeys.Image = valueOr(artifactDigest, image)
		findings = append(findings, finding)
	}
	return findings
}

func normalizeTrivyChecks(object *unstructured.Unstructured) []core.Finding {
	checks, _, _ := unstructured.NestedSlice(object.Object, "report", "checks")
	resource := trivyResource(object)
	findings := []core.Finding{}
	for _, raw := range checks {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		success, found, _ := unstructured.NestedBool(item, "success")
		if found && success {
			continue
		}
		checkID, _, _ := unstructured.NestedString(item, "checkID")
		severityText, _, _ := unstructured.NestedString(item, "severity")
		messages, _, _ := unstructured.NestedStringSlice(item, "messages")
		findings = append(findings, newFinding("trivy", object, checkID, "Trivy configuration check failed: "+checkID, severityFromText(severityText), resource, strings.Join(messages, "; "), resource.String()))
	}
	return findings
}

func normalizeTrivySecrets(object *unstructured.Unstructured) []core.Finding {
	secrets, _, _ := unstructured.NestedSlice(object.Object, "report", "secrets")
	resource := trivyResource(object)
	findings := []core.Finding{}
	for index, raw := range secrets {
		item, _ := raw.(map[string]any)
		ruleID, _, _ := unstructured.NestedString(item, "ruleID")
		title, _, _ := unstructured.NestedString(item, "title")
		findings = append(findings, newFinding("trivy", object, fmt.Sprintf("%s-%d", ruleID, index), "Potential exposed secret: "+valueOr(title, ruleID), core.SeverityCritical, resource, "Trivy reported secret material; KubeAthrix intentionally does not copy the matched value.", resource.String()))
	}
	return findings
}

func normalizePolicyReport(object *unstructured.Unstructured) []core.Finding {
	results, _, _ := unstructured.NestedSlice(object.Object, "results")
	scope, _, _ := unstructured.NestedMap(object.Object, "scope")
	resource := core.ResourceRef{}
	resource.APIVersion, _, _ = unstructured.NestedString(scope, "apiVersion")
	resource.Kind, _, _ = unstructured.NestedString(scope, "kind")
	resource.Namespace, _, _ = unstructured.NestedString(scope, "namespace")
	resource.Name, _, _ = unstructured.NestedString(scope, "name")
	if resource.Name == "" {
		resource = ownerResource(object)
	}
	findings := []core.Finding{}
	for index, raw := range results {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		outcome, _, _ := unstructured.NestedString(item, "result")
		if outcome == "pass" || outcome == "skip" {
			continue
		}
		policy, _, _ := unstructured.NestedString(item, "policy")
		rule, _, _ := unstructured.NestedString(item, "rule")
		message, _, _ := unstructured.NestedString(item, "message")
		severityText, _, _ := unstructured.NestedString(item, "severity")
		severity := severityFromText(severityText)
		if severityText == "" {
			if outcome == "error" {
				severity = core.SeverityHigh
			} else {
				severity = core.SeverityMedium
			}
		}
		key := fmt.Sprintf("%s/%s/%s/%d", policy, rule, outcome, index)
		findings = append(findings, newFinding("kyverno", object, key, fmt.Sprintf("Policy %s/%s reported %s", policy, rule, outcome), severity, resource, message, resource.String()+"|policy:"+policy))
	}
	return findings
}

func normalizeKubescapeSummary(object *unstructured.Unstructured) []core.Finding {
	resource := kubescapeResource(object)
	controls := nestedSliceAny(object.Object, []string{"spec", "controls"}, []string{"status", "controls"})
	findings := []core.Finding{}
	for index, raw := range controls {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		status, _, _ := unstructured.NestedString(item, "status")
		if status == "passed" || status == "pass" || status == "skipped" {
			continue
		}
		controlID := firstNestedString(item, "controlID", "controlId", "id")
		name := firstNestedString(item, "name", "controlName")
		severity := severityFromText(firstNestedString(item, "severity"))
		if severity == core.SeverityInfo {
			severity = core.SeverityMedium
		}
		findings = append(findings, newFinding("kubescape", object, fmt.Sprintf("%s-%d", controlID, index), "Kubescape control failed: "+valueOr(name, controlID), severity, resource, "Kubescape workload configuration summary reports status "+status, resource.String()+"|control:"+controlID))
	}
	if len(findings) > 0 {
		return findings
	}
	severities := nestedMapAny(object.Object, []string{"spec", "severities"}, []string{"status", "severities"}, []string{"spec", "summary"})
	severity, count := highestCountSeverity(severities)
	if count > 0 {
		findings = append(findings, newFinding("kubescape", object, "summary", fmt.Sprintf("Kubescape reports %d %s workload findings", count, severity), severity, resource, "Kubescape summary contains failed controls or vulnerabilities; inspect the cited CRD for individual entries.", resource.String()))
	}
	return findings
}

func newFinding(source string, object *unstructured.Unstructured, sourceKey, title string, severity core.Severity, resource core.ResourceRef, details, correlation string) core.Finding {
	observedAt := object.GetCreationTimestamp().Time
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	reference := fmt.Sprintf("k8s://%s/%s/%s/%s", object.GetAPIVersion(), object.GetKind(), object.GetNamespace(), object.GetName())
	fingerprint := stableID(source, string(object.GetUID())+"|"+sourceKey+"|"+resource.String())
	finding := core.Finding{
		ID: "finding-" + source + "-" + fingerprint, Source: source, Title: title, Severity: severity,
		Evidence:  []core.Evidence{{Summary: title, Details: details, SourceID: reference, ObservedAt: observedAt}},
		Resources: []core.ResourceRef{resource}, BlastRadius: "Affected Kubernetes resource: " + resource.String(),
		Fixability: core.FixabilityHumanOnly, Status: core.FindingOpen, CorrelationGroup: correlation,
		RiskScore: riskForSeverity(severity), RemediationState: "proposal_only",
		RecommendedAction: "Review source evidence and generate only a typed catalog action supported for this resource.",
		CreatedAt:         observedAt, UpdatedAt: observedAt,
	}
	finding.CorrelationKeys.Namespace = resource.Namespace
	if resource.Kind == "Namespace" {
		finding.CorrelationKeys.Namespace = resource.Name
	}
	switch resource.Kind {
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod", "Workload":
		finding.CorrelationKeys.Workload = resource.Namespace + "/" + resource.Kind + "/" + resource.Name
	case "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "ServiceAccount", "RbacAssessmentReport":
		finding.CorrelationKeys.Identity = resource.String()
	case "Service", "Ingress", "NetworkPolicy":
		finding.CorrelationKeys.NetworkExposure = resource.String()
	}
	return finding
}

func trivyResource(object *unstructured.Unstructured) core.ResourceRef {
	labels := object.GetLabels()
	resource := core.ResourceRef{
		Kind: labels["trivy-operator.resource.kind"], Namespace: object.GetNamespace(), Name: labels["trivy-operator.resource.name"],
	}
	if resource.Name == "" {
		resource = ownerResource(object)
	}
	if resource.APIVersion == "" {
		resource.APIVersion = apiVersionForKind(resource.Kind)
	}
	return resource
}

func kubescapeResource(object *unstructured.Unstructured) core.ResourceRef {
	labels := object.GetLabels()
	resource := core.ResourceRef{
		APIVersion: labels["kubescape.io/workload-api-version"], Kind: labels["kubescape.io/workload-kind"],
		Namespace: object.GetNamespace(), Name: labels["kubescape.io/workload-name"],
	}
	if resource.Name == "" {
		resource = ownerResource(object)
	}
	if resource.Name == "" {
		resource = core.ResourceRef{APIVersion: "apps/v1", Kind: "Workload", Namespace: object.GetNamespace(), Name: object.GetName()}
	}
	return resource
}

func ownerResource(object *unstructured.Unstructured) core.ResourceRef {
	owners := object.GetOwnerReferences()
	if len(owners) == 0 {
		return core.ResourceRef{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
	}
	owner := owners[0]
	return core.ResourceRef{APIVersion: owner.APIVersion, Kind: owner.Kind, Namespace: object.GetNamespace(), Name: owner.Name}
}

func apiVersionForKind(kind string) string {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
		return "apps/v1"
	case "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding":
		return "rbac.authorization.k8s.io/v1"
	default:
		return "v1"
	}
}

func severityFromText(value string) core.Severity {
	switch strings.ToLower(value) {
	case "critical":
		return core.SeverityCritical
	case "high", "error":
		return core.SeverityHigh
	case "medium", "moderate", "warn", "warning":
		return core.SeverityMedium
	case "low":
		return core.SeverityLow
	default:
		return core.SeverityInfo
	}
}

func riskForSeverity(severity core.Severity) int {
	switch severity {
	case core.SeverityCritical:
		return 95
	case core.SeverityHigh:
		return 80
	case core.SeverityMedium:
		return 60
	case core.SeverityLow:
		return 35
	default:
		return 10
	}
}

func stableID(parts ...string) string {
	hash := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(hash[:])[:20]
}

func cloneCollection(source Collection) Collection {
	return Collection{
		Integrations: append([]core.Integration(nil), source.Integrations...),
		Health:       append([]core.IntegrationHealth(nil), source.Health...),
		Findings:     append([]core.Finding(nil), source.Findings...),
	}
}

func kubernetesConfig() (*rest.Config, error) {
	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes configuration: %w", err)
	}
	return config, nil
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func firstNestedString(item map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, _, _ := unstructured.NestedString(item, key); value != "" {
			return value
		}
	}
	return ""
}

func nestedSliceAny(object map[string]any, paths ...[]string) []any {
	for _, path := range paths {
		if value, ok, _ := unstructured.NestedSlice(object, path...); ok {
			return value
		}
	}
	return nil
}

func nestedMapAny(object map[string]any, paths ...[]string) map[string]any {
	for _, path := range paths {
		if value, ok, _ := unstructured.NestedMap(object, path...); ok {
			return value
		}
	}
	return nil
}

func highestCountSeverity(values map[string]any) (core.Severity, int) {
	for _, entry := range []struct {
		keys     []string
		severity core.Severity
	}{{[]string{"critical", "Critical"}, core.SeverityCritical}, {[]string{"high", "High"}, core.SeverityHigh}, {[]string{"medium", "Medium"}, core.SeverityMedium}, {[]string{"low", "Low"}, core.SeverityLow}} {
		for _, key := range entry.keys {
			if value, ok := values[key]; ok {
				switch typed := value.(type) {
				case int64:
					if typed > 0 {
						return entry.severity, int(typed)
					}
				case float64:
					if typed > 0 {
						return entry.severity, int(typed)
					}
				}
			}
		}
	}
	return core.SeverityInfo, 0
}
