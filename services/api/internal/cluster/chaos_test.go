package cluster

import (
	"context"
	"strings"
	"testing"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
)

const validChaosManifest = `apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: latency
  namespace: sandbox
spec:
  action: delay
  direction: to
  mode: one
  selector:
    namespaces: [sandbox]
    labelSelectors:
      app: checkout
  delay:
    latency: 100ms
  duration: 60s`

func TestChaosPreflightIsBoundedAndDoesNotExecute(t *testing.T) {
	runner := NewChaosPreflightRunner("sandbox")
	run, err := runner.Run(context.Background(), "latency", validChaosManifest)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "preflight_validated" || !strings.Contains(run.Message, "no chaos resource was created") {
		t.Fatalf("unexpected preflight result: %#v", run)
	}
}

func TestChaosPreflightRejectsUnsafeTargets(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
	}{
		{"protected namespace", strings.ReplaceAll(validChaosManifest, "sandbox", "kube-system")},
		{"not allowlisted", strings.ReplaceAll(validChaosManifest, "sandbox", "production")},
		{"missing labels", strings.Replace(validChaosManifest, "    labelSelectors:\n      app: checkout\n", "", 1)},
		{"unbounded mode", strings.Replace(validChaosManifest, "mode: one", "mode: all", 1)},
		{"long duration", strings.Replace(validChaosManifest, "duration: 60s", "duration: 10m", 1)},
		{"unbounded network action", strings.Replace(validChaosManifest, "action: delay", "action: partition", 1)},
		{"excessive latency", strings.Replace(validChaosManifest, "latency: 100ms", "latency: 2s", 1)},
		{"secondary target", strings.Replace(validChaosManifest, "  delay:\n", "  target:\n    mode: all\n  delay:\n", 1)},
		{"direction requiring secondary target", strings.Replace(validChaosManifest, "direction: to", "direction: both", 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewChaosPreflightRunner("sandbox").Run(context.Background(), "unsafe", test.manifest); err == nil {
				t.Fatal("unsafe chaos manifest was accepted")
			}
		})
	}
}

func TestDefaultChaosTemplatesStayWithinKindSpecificBounds(t *testing.T) {
	for _, experiment := range core.DefaultChaosExperiments() {
		t.Run(experiment.ID, func(t *testing.T) {
			manifest := strings.NewReplacer(
				"{{TARGET_NAMESPACE}}", "sandbox",
				"{{TARGET_LABEL_KEY}}", "app",
				"{{TARGET_LABEL_VALUE}}", "checkout",
			).Replace(experiment.Manifest)
			if _, err := NewChaosPreflightRunner("sandbox").Run(context.Background(), experiment.ID, manifest); err != nil {
				t.Fatalf("default template violates chaos bounds: %v", err)
			}
		})
	}
}

func TestChaosKindSpecificBoundsRejectDangerousParameters(t *testing.T) {
	stress := strings.NewReplacer("{{TARGET_NAMESPACE}}", "sandbox", "{{TARGET_LABEL_KEY}}", "app", "{{TARGET_LABEL_VALUE}}", "checkout").Replace(core.DefaultChaosExperiments()[1].Manifest)
	dns := strings.NewReplacer("{{TARGET_NAMESPACE}}", "sandbox", "{{TARGET_LABEL_KEY}}", "app", "{{TARGET_LABEL_VALUE}}", "checkout").Replace(core.DefaultChaosExperiments()[2].Manifest)
	tests := []struct{ name, manifest string }{
		{"memory stress", strings.Replace(stress, "  stressors:\n", "  stressors:\n    memory:\n      workers: 1\n      size: 1GB\n", 1)},
		{"excessive cpu", strings.Replace(stress, "load: 70", "load: 100", 1)},
		{"wildcard dns", strings.Replace(dns, "dependency.internal", "*.internal", 1)},
		{"dns random action", strings.Replace(dns, "action: error", "action: random", 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewChaosPreflightRunner("sandbox").Run(context.Background(), "unsafe", test.manifest); err == nil {
				t.Fatal("dangerous kind-specific parameters were accepted")
			}
		})
	}
}
