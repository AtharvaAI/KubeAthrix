package adapters

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

type fixtureNativeSource struct {
	snapshot core.ClusterSnapshot
}

func (s fixtureNativeSource) Snapshot(context.Context) (core.ClusterSnapshot, error) {
	return s.snapshot, nil
}

func TestSupportedAdaptersNormalizeFixturesWithEvidenceAndStableIDs(t *testing.T) {
	fixed := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	objects := []runtime.Object{
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "aquasecurity.github.io/v1alpha1", "kind": "VulnerabilityReport",
			"metadata": metadata("replicaset-router-router", "platform", "trivy-vuln", fixed, map[string]any{
				"trivy-operator.resource.kind": "Deployment", "trivy-operator.resource.name": "router",
			}),
			"report": map[string]any{
				"artifact":        map[string]any{"repository": "example/router", "tag": "1.2.3", "digest": "sha256:abc"},
				"vulnerabilities": []any{map[string]any{"vulnerabilityID": "CVE-2026-0001", "severity": "CRITICAL", "title": "Example vulnerability", "fixedVersion": "1.2.4", "primaryLink": "https://example.invalid/CVE-2026-0001"}},
			},
		}},
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "aquasecurity.github.io/v1alpha1", "kind": "ConfigAuditReport",
			"metadata": metadata("deployment-router", "platform", "trivy-config", fixed.Add(time.Minute), map[string]any{
				"trivy-operator.resource.kind": "Deployment", "trivy-operator.resource.name": "router",
			}),
			"report": map[string]any{"checks": []any{map[string]any{"checkID": "KSV001", "severity": "HIGH", "success": false, "messages": []any{"Privileged container is not allowed"}}}},
		}},
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
			"metadata": metadata("router-policy", "platform", "kyverno-report", fixed.Add(2*time.Minute), map[string]any{"app.kubernetes.io/managed-by": "kyverno"}),
			"scope":    map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "namespace": "platform", "name": "router"},
			"results":  []any{map[string]any{"policy": "require-resources", "rule": "check-limits", "result": "fail", "severity": "medium", "message": "CPU limit is required"}},
		}},
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "openreports.io/v1alpha1", "kind": "Report",
			"metadata": metadata("router-openreport", "platform", "kyverno-openreport", fixed.Add(3*time.Minute), map[string]any{"app.kubernetes.io/managed-by": "kyverno"}),
			"scope":    map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "namespace": "platform", "name": "router"},
			"results":  []any{map[string]any{"policy": "require-team", "rule": "team-label", "result": "warn", "message": "team label is missing"}},
		}},
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1", "kind": "WorkloadConfigurationScanSummary",
			"metadata": metadata("router", "platform", "kubescape-summary", fixed.Add(4*time.Minute), map[string]any{
				"kubescape.io/workload-api-version": "apps/v1", "kubescape.io/workload-kind": "Deployment", "kubescape.io/workload-name": "router",
			}),
			"spec": map[string]any{"controls": []any{map[string]any{"controlID": "C-0012", "name": "Applications credentials in configuration files", "status": "failed", "severity": "high"}}},
		}},
	}
	listKinds := map[schema.GroupVersionResource]string{
		{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "vulnerabilityreports"}:                             "VulnerabilityReportList",
		{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "configauditreports"}:                               "ConfigAuditReportList",
		{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "exposedsecretreports"}:                             "ExposedSecretReportList",
		{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "rbacassessmentreports"}:                            "RbacAssessmentReportList",
		{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "policyreports"}:                                            "PolicyReportList",
		{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "clusterpolicyreports"}:                                     "ClusterPolicyReportList",
		{Group: "openreports.io", Version: "v1alpha1", Resource: "reports"}:                                                  "ReportList",
		{Group: "openreports.io", Version: "v1alpha1", Resource: "clusterreports"}:                                           "ClusterReportList",
		{Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "workloadconfigurationscansummaries"}: "WorkloadConfigurationScanSummaryList",
		{Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "vulnerabilitymanifestsummaries"}:     "VulnerabilityManifestSummaryList",
	}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)
	nativeFinding := core.Finding{ID: "finding-native", Source: "kubeathrix-native", Title: "Native posture", Severity: core.SeverityLow, RiskScore: 30}
	manager := NewManagerFromClient(client, fixtureNativeSource{snapshot: core.ClusterSnapshot{Findings: []core.Finding{nativeFinding}, Scan: core.ScanSummary{LastRunAt: fixed}}}, func() time.Time { return fixed.Add(5 * time.Minute) })
	collection := manager.Collect(context.Background())
	if len(collection.Integrations) != 4 || len(collection.Health) != 4 {
		t.Fatalf("expected four real adapter health records, got %#v", collection.Health)
	}
	counts := map[string]int{}
	ids := map[string]bool{}
	for _, finding := range collection.Findings {
		counts[finding.Source]++
		if finding.ID == "" || ids[finding.ID] {
			t.Fatalf("finding IDs must be non-empty and stable: %#v", finding)
		}
		ids[finding.ID] = true
		if finding.Source != "kubeathrix-native" {
			if len(finding.Evidence) == 0 || finding.Evidence[0].SourceID == "" || len(finding.Resources) == 0 {
				t.Fatalf("adapter finding lost evidence provenance: %#v", finding)
			}
		}
	}
	if counts["trivy"] != 2 || counts["kyverno"] != 2 || counts["kubescape"] != 1 || counts["kubeathrix-native"] != 1 {
		t.Fatalf("unexpected normalized finding counts: %#v", counts)
	}
	second := manager.Collect(context.Background())
	if len(second.Findings) != len(collection.Findings) {
		t.Fatal("cached adapter collection changed finding count")
	}
	for index := range collection.Findings {
		if collection.Findings[index].ID != second.Findings[index].ID {
			t.Fatal("adapter finding ID changed across repeated scans")
		}
	}
	for _, health := range collection.Health {
		if len(health.SupportedVersions) == 0 || len(health.Permissions) == 0 || health.CheckedAt.IsZero() {
			t.Fatalf("adapter health is incomplete: %#v", health)
		}
	}
}

func metadata(name, namespace, uid string, created time.Time, labels map[string]any) map[string]any {
	return map[string]any{
		"name": name, "namespace": namespace, "uid": string(types.UID(uid)),
		"creationTimestamp": created.Format(time.RFC3339), "labels": labels,
	}
}

func TestSeverityAndEvidenceNeverCopySecretValues(t *testing.T) {
	object := &unstructured.Unstructured{}
	object.SetAPIVersion("aquasecurity.github.io/v1alpha1")
	object.SetKind("ExposedSecretReport")
	object.SetName("secret-report")
	object.SetNamespace("platform")
	object.SetUID(types.UID("secret-report-uid"))
	object.SetCreationTimestamp(metav1.NewTime(time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)))
	object.Object["report"] = map[string]any{"secrets": []any{map[string]any{"ruleID": "aws-key", "title": "AWS access key", "match": "SHOULD-NOT-LEAK"}}}
	findings := normalizeTrivySecrets(object)
	if len(findings) != 1 || findings[0].Severity != core.SeverityCritical {
		t.Fatalf("unexpected secret finding: %#v", findings)
	}
	if strings.Contains(findings[0].Evidence[0].Details, "SHOULD-NOT-LEAK") {
		t.Fatal("adapter copied matched secret material into evidence")
	}
}
