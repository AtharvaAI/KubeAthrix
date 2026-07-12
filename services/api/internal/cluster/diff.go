package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (c *WorkflowClient) RenderDiff(ctx context.Context, plan core.RemediationPlan) (core.RemediationDiff, error) {
	diff := store.BuildRemediationDiff(plan)
	for index := range diff.Manifests {
		manifest := &diff.Manifests[index]
		action := plan.Actions[index]
		var err error
		switch action.Type {
		case "patch_pod_security_labels":
			err = c.renderPodSecurityDiff(ctx, action, manifest)
		case "patch_workload_resources":
			err = c.renderWorkloadResourcesDiff(ctx, action, manifest)
		case "create_pdb":
			err = c.renderPDBDiff(ctx, action, manifest)
		case "patch_workload_probes":
			if action.Params["configured"] == "true" {
				err = c.renderWorkloadProbesDiff(ctx, action, manifest)
			}
		}
		if err != nil {
			return core.RemediationDiff{}, fmt.Errorf("render exact diff for %s: %w", action.Type, err)
		}
	}
	return diff, nil
}

func (c *WorkflowClient) renderPodSecurityDiff(ctx context.Context, action core.TypedAction, manifest *core.PlannedManifest) error {
	object, err := c.client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}).Get(ctx, action.Target.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	desired := map[string]string{
		"pod-security.kubernetes.io/enforce": valueOrDefault(action.Params["enforce"], "baseline"),
		"pod-security.kubernetes.io/audit":   valueOrDefault(action.Params["audit"], "restricted"),
		"pod-security.kubernetes.io/warn":    valueOrDefault(action.Params["warn"], "restricted"),
	}
	lines := []string{}
	labels := object.GetLabels()
	for _, key := range sortedKeys(desired) {
		lines = append(lines, fmt.Sprintf("metadata.labels[%q]: %q -> %q", key, labels[key], desired[key]))
	}
	manifest.Diff = strings.Join(lines, "\n")
	manifest.Manifest = prettyJSON(map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": action.Target.Name, "labels": desired},
	})
	return nil
}

func (c *WorkflowClient) renderWorkloadResourcesDiff(ctx context.Context, action core.TypedAction, manifest *core.PlannedManifest) error {
	object, err := c.getWorkload(ctx, action.Target)
	if err != nil {
		return err
	}
	podSpec, ok, _ := unstructured.NestedMap(object.Object, "spec", "template", "spec")
	if !ok {
		return fmt.Errorf("workload has no pod template spec")
	}
	changes := []string{}
	for _, field := range []string{"initContainers", "containers"} {
		items, _, _ := unstructured.NestedSlice(podSpec, field)
		for index, raw := range items {
			container, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name, _, _ := unstructured.NestedString(container, "name")
			resources, _, _ := unstructured.NestedMap(container, "resources")
			if resources == nil {
				resources = map[string]any{}
			}
			requests, _, _ := unstructured.NestedStringMap(resources, "requests")
			limits, _, _ := unstructured.NestedStringMap(resources, "limits")
			if requests == nil {
				requests = map[string]string{}
			}
			if limits == nil {
				limits = map[string]string{}
			}
			addMissing(&changes, requests, "cpu", action.Params["cpuRequest"], field, name, "requests")
			addMissing(&changes, requests, "memory", action.Params["memoryRequest"], field, name, "requests")
			addMissing(&changes, limits, "cpu", action.Params["cpuLimit"], field, name, "limits")
			addMissing(&changes, limits, "memory", action.Params["memoryLimit"], field, name, "limits")
			resources["requests"] = stringMapAny(requests)
			resources["limits"] = stringMapAny(limits)
			container["resources"] = resources
			items[index] = container
		}
		podSpec[field] = items
	}
	manifest.Diff = valueOrDefault(strings.Join(changes, "\n"), "No resource fields would change; the action is already idempotent.")
	manifest.Manifest = prettyJSON(map[string]any{
		"apiVersion": action.Target.APIVersion, "kind": action.Target.Kind,
		"metadata": map[string]any{"name": action.Target.Name, "namespace": action.Target.Namespace},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"initContainers": podSpec["initContainers"], "containers": podSpec["containers"],
		}}},
	})
	return nil
}

func (c *WorkflowClient) renderPDBDiff(ctx context.Context, action core.TypedAction, manifest *core.PlannedManifest) error {
	workload, err := c.getWorkload(ctx, action.Target)
	if err != nil {
		return err
	}
	selector, ok, _ := unstructured.NestedStringMap(workload.Object, "spec", "selector", "matchLabels")
	if !ok || len(selector) == 0 {
		return fmt.Errorf("workload selector is empty")
	}
	minimum := action.Params["minAvailable"]
	object := map[string]any{
		"apiVersion": "policy/v1", "kind": "PodDisruptionBudget",
		"metadata": map[string]any{"name": action.Target.Name + "-kubeathrix", "namespace": action.Target.Namespace},
		"spec":     map[string]any{"minAvailable": minimum, "selector": map[string]any{"matchLabels": stringMapAny(selector)}},
	}
	manifest.Diff = fmt.Sprintf("create/reconcile policy/v1 PodDisruptionBudget %s/%s-kubeathrix with minAvailable=%s and matchLabels=%s", action.Target.Namespace, action.Target.Name, minimum, prettyJSON(selector))
	manifest.Manifest = prettyJSON(object)
	return nil
}

func (c *WorkflowClient) renderWorkloadProbesDiff(ctx context.Context, action core.TypedAction, manifest *core.PlannedManifest) error {
	object, err := c.getWorkload(ctx, action.Target)
	if err != nil {
		return err
	}
	containers, ok, _ := unstructured.NestedSlice(object.Object, "spec", "template", "spec", "containers")
	if !ok {
		return fmt.Errorf("workload has no containers")
	}
	containerName := action.Params["container"]
	found := false
	for _, raw := range containers {
		container, _ := raw.(map[string]any)
		name, _, _ := unstructured.NestedString(container, "name")
		if name == containerName {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("configured container %s does not exist", containerName)
	}
	manifest.WriteMode = "direct-tier-b"
	manifest.Diff = fmt.Sprintf("container %s: add missing readiness HTTP GET %s:%s and liveness HTTP GET %s:%s; existing probes remain unchanged", containerName, action.Params["readinessPath"], action.Params["port"], action.Params["livenessPath"], action.Params["port"])
	manifest.Manifest = prettyJSON(map[string]any{
		"apiVersion": action.Target.APIVersion, "kind": action.Target.Kind,
		"metadata": map[string]any{"name": action.Target.Name, "namespace": action.Target.Namespace},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{
			"name":           containerName,
			"readinessProbe": map[string]any{"httpGet": map[string]any{"path": action.Params["readinessPath"], "port": action.Params["port"]}},
			"livenessProbe":  map[string]any{"httpGet": map[string]any{"path": action.Params["livenessPath"], "port": action.Params["port"]}},
		}}}}},
	})
	return nil
}

func (c *WorkflowClient) getWorkload(ctx context.Context, target core.ResourceRef) (*unstructured.Unstructured, error) {
	resources := map[string]schema.GroupVersionResource{
		"Deployment":  {Group: "apps", Version: "v1", Resource: "deployments"},
		"StatefulSet": {Group: "apps", Version: "v1", Resource: "statefulsets"},
		"DaemonSet":   {Group: "apps", Version: "v1", Resource: "daemonsets"},
	}
	resource, ok := resources[target.Kind]
	if !ok {
		return nil, fmt.Errorf("unsupported workload kind %s", target.Kind)
	}
	return c.client.Resource(resource).Namespace(target.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
}

func addMissing(changes *[]string, values map[string]string, key, desired, field, container, resourceField string) {
	if _, exists := values[key]; exists {
		return
	}
	values[key] = desired
	*changes = append(*changes, fmt.Sprintf("spec.template.spec.%s[%q].resources.%s.%s: <absent> -> %q", field, container, resourceField, key, desired))
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func stringMapAny(values map[string]string) map[string]any {
	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func prettyJSON(value any) string {
	payload, _ := json.MarshalIndent(value, "", "  ")
	return string(payload)
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
