package managedresources

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestDiscoveryRedactsBuildsRelationshipsAndFindings(t *testing.T) {
	now := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	gvr := schema.GroupVersionResource{Group: "iam.aws.upbound.io", Version: "v1beta1", Resource: "roles"}
	controller := true
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "iam.aws.upbound.io/v1beta1",
		"kind":       "Role",
		"metadata": map[string]any{
			"name":       "workload-admin",
			"namespace":  "payments",
			"generation": int64(2),
			"annotations": map[string]any{
				"crossplane.io/external-name":                      "arn:aws:iam::123456789012:role/workload-admin",
				"kubectl.kubernetes.io/last-applied-configuration": `{"password":"do-not-leak"}`,
			},
			"ownerReferences": []any{map[string]any{
				"apiVersion": "apiextensions.crossplane.io/v1",
				"kind":       "CompositeResourceDefinition",
				"name":       "iam-role",
				"uid":        "owner-1",
				"controller": controller,
			}},
		},
		"spec": map[string]any{
			"forProvider": map[string]any{
				"password": "do-not-leak",
				"policyDocument": map[string]any{
					"statements": []any{map[string]any{
						"effect":     "Allow",
						"actions":    []any{"iam:*"},
						"principals": map[string]any{"aws": "*"},
					}},
				},
			},
			"providerConfigRef":          map[string]any{"name": "default"},
			"writeConnectionSecretToRef": map[string]any{"name": "role-connection", "namespace": "secrets"},
		},
		"status": map[string]any{
			"observedGeneration": int64(1),
			"conditions": []any{
				map[string]any{"type": "Ready", "status": "False", "reason": "Unavailable", "message": "eyJabcdefghijk.abcdefghijk.abcdefghijk"},
				map[string]any{"type": "Synced", "status": "False", "reason": "ReconcileError"},
			},
		},
	}}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gvr: "RoleList"}, object)
	discovery, err := NewDiscovery(client, Config{Enabled: true, Allowlist: []AllowlistEntry{{APIGroup: gvr.Group, Version: gvr.Version, Resources: []string{gvr.Resource}, Namespaced: true}}}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewDiscovery: %v", err)
	}

	snapshot, err := discovery.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(snapshot.Resources) != 1 {
		t.Fatalf("resources = %d, want 1", len(snapshot.Resources))
	}
	resource := snapshot.Resources[0]
	if resource.Provenance.System != ManagementCrossplane {
		t.Fatalf("provenance = %q, want crossplane", resource.Provenance.System)
	}
	if resource.Spec != nil || resource.Labels != nil || resource.Annotations != nil {
		t.Fatalf("internal analysis inputs must be discarded after findings are built: %#v", resource)
	}
	if len(snapshot.Relationships) != 3 {
		t.Fatalf("relationships = %#v, want owner and two references", snapshot.Relationships)
	}
	for _, rule := range []string{"inline-sensitive-value", "iam-wildcard-action", "iam-public-principal", "not-ready", "reconcile-failed", "stale-generation"} {
		if !hasFindingRule(snapshot, rule) {
			t.Fatalf("missing finding rule %q in %#v", rule, snapshot.Findings)
		}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, secret := range []string{"do-not-leak", "eyJabcdefghijk.abcdefghijk.abcdefghijk"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("snapshot leaked sensitive value %q: %s", secret, encoded)
		}
	}
	for _, internalField := range []string{`"spec"`, `"labels"`, `"annotations"`, `"message"`} {
		if strings.Contains(string(encoded), internalField) {
			t.Fatalf("snapshot exposed internal analysis field %s: %s", internalField, encoded)
		}
	}
	for _, finding := range snapshot.Findings {
		if finding.Source != "managed-resource" {
			t.Fatalf("finding source = %q", finding.Source)
		}
		if len(finding.Evidence) == 0 || !strings.Contains(finding.Evidence[0].Details, "Crossplane") {
			t.Fatalf("finding omitted deterministic source-of-truth context: %#v", finding.Evidence)
		}
	}
}

func TestSanitizeValueRedactsSensitiveFieldsBeforeAnalysis(t *testing.T) {
	value, paths := sanitizeValue(map[string]any{
		"password": "do-not-leak",
		"policy":   map[string]any{"effect": "Allow", "actions": []any{"iam:GetRole"}},
	}, "spec")
	sanitized, ok := value.(map[string]any)
	if !ok || sanitized["password"] != RedactedValue {
		t.Fatalf("sensitive field was not redacted: %#v", value)
	}
	if len(paths) != 1 || paths[0] != "spec.password" {
		t.Fatalf("unexpected sensitive paths: %#v", paths)
	}
}

func TestManagedFindingIdentityIncludesKubernetesUID(t *testing.T) {
	now := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	first := Resource{ID: "example.io/v1/roles/payments/reader", UID: "uid-one", APIVersion: "example.io/v1", Kind: "Role", Namespace: "payments", Name: "reader"}
	second := first
	second.UID = "uid-two"
	firstFinding := newManagedFinding(first, now, "not-ready", "Not ready", core.SeverityHigh, 80, "Ready=False", "Review", core.FixabilityHumanOnly)
	secondFinding := newManagedFinding(second, now, "not-ready", "Not ready", core.SeverityHigh, 80, "Ready=False", "Review", core.FixabilityHumanOnly)
	if firstFinding.ID == secondFinding.ID {
		t.Fatalf("delete/recreate inherited the same finding identity: %q", firstFinding.ID)
	}
}

func TestDiscoveryStopsAtConfiguredSnapshotLimit(t *testing.T) {
	now := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	gvr := schema.GroupVersionResource{Group: "example.io", Version: "v1", Resource: "resources"}
	first := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "example.io/v1", "kind": "Resource", "metadata": map[string]any{"name": "first", "namespace": "payments"}}}
	second := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "example.io/v1", "kind": "Resource", "metadata": map[string]any{"name": "second", "namespace": "payments"}}}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gvr: "ResourceList"}, first, second)
	discovery, err := NewDiscovery(client, Config{Enabled: true, Allowlist: []AllowlistEntry{{APIGroup: gvr.Group, Version: gvr.Version, Resources: []string{gvr.Resource}, Namespaced: true}}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	discovery.maxObjects = 1
	snapshot, err := discovery.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Resources) != 1 {
		t.Fatalf("expected one bounded resource, got %d", len(snapshot.Resources))
	}
	if len(snapshot.Warnings) != 1 || snapshot.Warnings[0].Code != "snapshot_limit_reached" {
		t.Fatalf("expected an explicit safety-limit warning, got %#v", snapshot.Warnings)
	}
}

func TestExtractProvenanceSignals(t *testing.T) {
	tests := []struct {
		name        string
		labels      map[string]string
		annotations map[string]string
		want        ManagementSystem
		wantSource  string
	}{
		{name: "argocd", annotations: map[string]string{"argocd.argoproj.io/tracking-id": "payments"}, want: ManagementArgoCD},
		{name: "flux", labels: map[string]string{"kustomize.toolkit.fluxcd.io/name": "platform"}, want: ManagementFlux},
		{name: "helm", annotations: map[string]string{"meta.helm.sh/release-name": "infra"}, want: ManagementHelm},
		{name: "credential-like provenance", annotations: map[string]string{"argocd.argoproj.io/tracking-id": "https://user:password@example.invalid/repo"}, want: ManagementArgoCD, wantSource: RedactedValue},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object := &unstructured.Unstructured{}
			object.SetLabels(test.labels)
			object.SetAnnotations(test.annotations)
			got := extractProvenance(object, "example.io")
			if got.System != test.want {
				t.Fatalf("system = %q, want %q", got.System, test.want)
			}
			if test.wantSource != "" && got.SourceRef != test.wantSource {
				t.Fatalf("sourceRef = %q, want %q", got.SourceRef, test.wantSource)
			}
		})
	}
}

func hasFindingRule(snapshot Snapshot, rule string) bool {
	for _, finding := range snapshot.Findings {
		if strings.HasPrefix(finding.ID, "managed-resource-"+rule+"-") {
			return true
		}
	}
	return false
}

var _ = metav1.NamespaceAll
