package cluster

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
)

type ChaosRunner struct {
	client dynamic.Interface
	now    func() time.Time
}

var allowedChaosResources = map[schema.GroupVersionKind]schema.GroupVersionResource{
	{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "NetworkChaos"}: {
		Group: "chaos-mesh.org", Version: "v1alpha1", Resource: "networkchaos",
	},
	{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "StressChaos"}: {
		Group: "chaos-mesh.org", Version: "v1alpha1", Resource: "stresschaos",
	},
	{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "DNSChaos"}: {
		Group: "chaos-mesh.org", Version: "v1alpha1", Resource: "dnschaos",
	},
	{Group: "litmuschaos.io", Version: "v1alpha1", Kind: "ChaosEngine"}: {
		Group: "litmuschaos.io", Version: "v1alpha1", Resource: "chaosengines",
	},
}

func NewChaosRunner() (*ChaosRunner, error) {
	config, err := kubeConfig()
	if err != nil {
		return nil, err
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &ChaosRunner{client: client, now: time.Now}, nil
}

func NewChaosRunnerFromClient(client dynamic.Interface, now func() time.Time) *ChaosRunner {
	if now == nil {
		now = time.Now
	}
	return &ChaosRunner{client: client, now: now}
}

func (r *ChaosRunner) Run(ctx context.Context, experimentID, manifest string) (core.ChaosExperimentRun, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	object, err := decodeChaosObject(manifest)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	gvk := object.GroupVersionKind()
	gvr, ok := allowedChaosResources[gvk]
	if !ok {
		return core.ChaosExperimentRun{}, fmt.Errorf("chaos kind %s is not allowlisted", gvk.String())
	}
	if object.GetNamespace() == "" {
		object.SetNamespace("default")
	}

	resource := r.client.Resource(gvr).Namespace(object.GetNamespace())
	if _, err := resource.Create(ctx, object.DeepCopy(), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
		return core.ChaosExperimentRun{}, fmt.Errorf("chaos dry-run failed: %w", err)
	}
	if _, err := resource.Create(ctx, object, metav1.CreateOptions{}); err != nil {
		if errors.IsAlreadyExists(err) {
			return core.ChaosExperimentRun{}, fmt.Errorf("chaos object already exists: %w", err)
		}
		return core.ChaosExperimentRun{}, fmt.Errorf("create chaos object: %w", err)
	}

	now := r.now().UTC()
	return core.ChaosExperimentRun{
		ID:           fmt.Sprintf("chaos-run-%d", now.UnixNano()),
		ExperimentID: experimentID,
		Status:       "running",
		Message:      fmt.Sprintf("created %s/%s in namespace %s after server-side dry-run", gvk.Kind, object.GetName(), object.GetNamespace()),
		Manifest:     manifest,
		CreatedAt:    now,
	}, nil
}

func decodeChaosObject(manifest string) (*unstructured.Unstructured, error) {
	decoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(manifest), 4096)
	object := &unstructured.Unstructured{}
	if err := decoder.Decode(object); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if object.GetAPIVersion() == "" || object.GetKind() == "" || object.GetName() == "" {
		return nil, fmt.Errorf("manifest must include apiVersion, kind, metadata.name")
	}
	return object, nil
}
