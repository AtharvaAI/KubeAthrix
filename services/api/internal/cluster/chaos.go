package cluster

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
)

type ChaosRunner struct {
	client            dynamic.Interface
	now               func() time.Time
	allowedNamespaces map[string]struct{}
	serverSideDryRun  bool
}

type ChaosObservation struct {
	AllInjected bool
	Failed      bool
	Message     string
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
}

var protectedChaosNamespaces = map[string]struct{}{
	"kube-system": {}, "kube-public": {}, "kube-node-lease": {}, "kubeathrix-system": {},
}

const maxChaosDuration = 5 * time.Minute
const maxChaosTargetCandidates = 20

var podsResource = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

func NewChaosRunner() (*ChaosRunner, error) {
	config, err := kubeConfig()
	if err != nil {
		return nil, err
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &ChaosRunner{client: client, now: time.Now, allowedNamespaces: namespaceAllowlist(os.Getenv("KUBEATHRIX_CHAOS_NAMESPACE_ALLOWLIST")), serverSideDryRun: true}, nil
}

func NewChaosRunnerFromClient(client dynamic.Interface, now func() time.Time) *ChaosRunner {
	if now == nil {
		now = time.Now
	}
	return &ChaosRunner{client: client, now: now, allowedNamespaces: map[string]struct{}{"default": {}}, serverSideDryRun: true}
}

func NewChaosPreflightRunner(allowlist string) *ChaosRunner {
	return &ChaosRunner{now: time.Now, allowedNamespaces: namespaceAllowlist(allowlist)}
}

func (r *ChaosRunner) Run(ctx context.Context, experimentID, manifest string) (core.ChaosExperimentRun, error) {
	return r.Preflight(ctx, experimentID, manifest, false)
}

func (r *ChaosRunner) Health(ctx context.Context) error {
	if r.client == nil {
		return fmt.Errorf("Kubernetes chaos client is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, resource := range allowedChaosResources {
		if _, err := r.client.Resource(resource).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
			return fmt.Errorf("discover %s: %w", resource.Resource, err)
		}
	}
	return nil
}

func (r *ChaosRunner) Preflight(ctx context.Context, experimentID, manifest string, discoverTargets bool) (core.ChaosExperimentRun, error) {
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
		return core.ChaosExperimentRun{}, fmt.Errorf("chaos manifest must declare metadata.namespace")
	}
	if err := r.validateTarget(object); err != nil {
		return core.ChaosExperimentRun{}, err
	}
	targetLabels, _, _ := unstructured.NestedStringMap(object.Object, "spec", "selector", "labelSelectors")
	targetCount, err := plannedTargetCount(object)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	if discoverTargets {
		if r.client == nil {
			return core.ChaosExperimentRun{}, fmt.Errorf("live target discovery is unavailable")
		}
		if err := r.validateLiveTargets(ctx, object.GetNamespace(), targetLabels, targetCount); err != nil {
			return core.ChaosExperimentRun{}, err
		}
	}
	message := fmt.Sprintf("validated %s/%s in namespace %s; no chaos resource was created", gvk.Kind, object.GetName(), object.GetNamespace())
	if r.serverSideDryRun && r.client != nil {
		resource := r.client.Resource(gvr).Namespace(object.GetNamespace())
		if _, err := resource.Create(ctx, object.DeepCopy(), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
			return core.ChaosExperimentRun{}, fmt.Errorf("chaos server-side dry-run failed: %w", err)
		}
		message = fmt.Sprintf("server-side dry-run validated %s/%s in namespace %s; no chaos resource was created", gvk.Kind, object.GetName(), object.GetNamespace())
	}

	now := r.now().UTC()
	durationText, _, _ := unstructured.NestedString(object.Object, "spec", "duration")
	duration, _ := time.ParseDuration(durationText)
	return core.ChaosExperimentRun{
		ID:              fmt.Sprintf("chaos-run-%d", now.UnixNano()),
		ExperimentID:    experimentID,
		Status:          core.ChaosPreflightValidated,
		Message:         message,
		Manifest:        manifest,
		Resource:        core.ResourceRef{APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Namespace: object.GetNamespace(), Name: object.GetName()},
		TargetSelector:  targetLabels,
		TargetCount:     targetCount,
		DurationSeconds: int64(duration.Seconds()),
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

func (r *ChaosRunner) Start(ctx context.Context, run core.ChaosExperimentRun) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	object, err := decodeChaosObject(run.Manifest)
	if err != nil {
		return err
	}
	gvr, ok := allowedChaosResources[object.GroupVersionKind()]
	if !ok {
		return fmt.Errorf("chaos kind %s is not allowlisted", object.GroupVersionKind().String())
	}
	if err := r.validateTarget(object); err != nil {
		return err
	}
	if object.GetNamespace() != run.Resource.Namespace || object.GetName() != run.Resource.Name || object.GetKind() != run.Resource.Kind {
		return fmt.Errorf("persisted chaos resource identity does not match manifest")
	}
	if err := r.validateLiveTargets(ctx, run.Resource.Namespace, run.TargetSelector, run.TargetCount); err != nil {
		return err
	}
	resource := r.client.Resource(gvr).Namespace(object.GetNamespace())
	if r.serverSideDryRun {
		if _, err := resource.Create(ctx, object.DeepCopy(), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldManager: "kubeathrix-chaos"}); err != nil {
			return fmt.Errorf("chaos server-side dry-run failed: %w", err)
		}
	}
	object = object.DeepCopy()
	objectLabels := object.GetLabels()
	if objectLabels == nil {
		objectLabels = map[string]string{}
	}
	objectLabels["app.kubernetes.io/managed-by"] = "kubeathrix"
	objectLabels["security.kubeathrix.io/chaos-run"] = run.ID
	object.SetLabels(objectLabels)
	created, err := resource.Create(ctx, object, metav1.CreateOptions{FieldManager: "kubeathrix-chaos"})
	if apierrors.IsAlreadyExists(err) {
		created, err = resource.Get(ctx, object.GetName(), metav1.GetOptions{})
		if err == nil && created.GetLabels()["security.kubeathrix.io/chaos-run"] != run.ID {
			return fmt.Errorf("chaos resource %s/%s already exists and is not owned by run %s", object.GetNamespace(), object.GetName(), run.ID)
		}
	}
	if err != nil {
		return fmt.Errorf("create chaos resource: %w", err)
	}
	return nil
}

func (r *ChaosRunner) Exists(ctx context.Context, run core.ChaosExperimentRun) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resource, err := r.resourceForRun(run)
	if err != nil {
		return false, err
	}
	object, err := resource.Get(ctx, run.Resource.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if object.GetLabels()["security.kubeathrix.io/chaos-run"] != run.ID {
		return false, fmt.Errorf("chaos resource ownership label does not match run %s", run.ID)
	}
	return true, nil
}

// Observe reads the Chaos Mesh controller status. Object creation alone is not
// evidence that the requested fault was injected; AllInjected=True is.
func (r *ChaosRunner) Observe(ctx context.Context, run core.ChaosExperimentRun) (ChaosObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resource, err := r.resourceForRun(run)
	if err != nil {
		return ChaosObservation{}, err
	}
	object, err := resource.Get(ctx, run.Resource.Name, metav1.GetOptions{})
	if err != nil {
		return ChaosObservation{}, err
	}
	if object.GetLabels()["security.kubeathrix.io/chaos-run"] != run.ID {
		return ChaosObservation{}, fmt.Errorf("chaos resource ownership label does not match run %s", run.ID)
	}
	conditions, _, err := unstructured.NestedSlice(object.Object, "status", "conditions")
	if err != nil {
		return ChaosObservation{}, fmt.Errorf("read chaos status conditions: %w", err)
	}
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		conditionType, _ := condition["type"].(string)
		conditionStatus, _ := condition["status"].(string)
		if conditionType != "AllInjected" {
			continue
		}
		reason, _ := condition["reason"].(string)
		if conditionStatus == "True" {
			return ChaosObservation{AllInjected: true, Message: "Chaos Mesh reported AllInjected=True"}, nil
		}
		if strings.TrimSpace(reason) != "" {
			return ChaosObservation{Message: "Chaos Mesh has not completed injection: " + reason}, nil
		}
	}
	records, _, err := unstructured.NestedSlice(object.Object, "status", "experiment", "containerRecords")
	if err != nil {
		return ChaosObservation{}, fmt.Errorf("read chaos experiment records: %w", err)
	}
	for _, rawRecord := range records {
		record, ok := rawRecord.(map[string]any)
		if !ok {
			continue
		}
		events, _, _ := unstructured.NestedSlice(record, "events")
		for index := len(events) - 1; index >= 0; index-- {
			event, ok := events[index].(map[string]any)
			if !ok || event["type"] != "Failed" || event["operation"] != "Apply" {
				continue
			}
			message, _ := event["message"].(string)
			message = strings.TrimSpace(message)
			if len(message) > 512 {
				message = message[:512]
			}
			return ChaosObservation{Failed: true, Message: "Chaos Mesh reported an injection failure: " + message}, nil
		}
	}
	return ChaosObservation{Message: "awaiting Chaos Mesh AllInjected=True status"}, nil
}

func (r *ChaosRunner) Delete(ctx context.Context, run core.ChaosExperimentRun) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resource, err := r.resourceForRun(run)
	if err != nil {
		return err
	}
	propagation := metav1.DeletePropagationBackground
	err = resource.Delete(ctx, run.Resource.Name, metav1.DeleteOptions{PropagationPolicy: &propagation})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (r *ChaosRunner) VerifyRecovery(ctx context.Context, run core.ChaosExperimentRun) (bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pods, err := r.targetPods(ctx, run.Resource.Namespace, run.TargetSelector)
	if err != nil {
		return false, "", err
	}
	if len(pods.Items) < run.TargetCount {
		return false, fmt.Sprintf("only %d matching pods are present; expected at least %d", len(pods.Items), run.TargetCount), nil
	}
	for index := range pods.Items {
		if !chaosTargetPodReady(&pods.Items[index]) {
			return false, fmt.Sprintf("pod %s has not recovered to Running and Ready", pods.Items[index].GetName()), nil
		}
	}
	return true, fmt.Sprintf("%d matching pods are Running and Ready after cleanup", len(pods.Items)), nil
}

func (r *ChaosRunner) resourceForRun(run core.ChaosExperimentRun) (dynamic.ResourceInterface, error) {
	if r.client == nil {
		return nil, fmt.Errorf("Kubernetes chaos client is unavailable")
	}
	gv, err := schema.ParseGroupVersion(run.Resource.APIVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid chaos resource apiVersion: %w", err)
	}
	gvr, ok := allowedChaosResources[gv.WithKind(run.Resource.Kind)]
	if !ok {
		return nil, fmt.Errorf("chaos kind %s/%s is not allowlisted", run.Resource.APIVersion, run.Resource.Kind)
	}
	return r.client.Resource(gvr).Namespace(run.Resource.Namespace), nil
}

func (r *ChaosRunner) validateTarget(object *unstructured.Unstructured) error {
	namespace := object.GetNamespace()
	if _, protected := protectedChaosNamespaces[namespace]; protected || strings.HasPrefix(namespace, "kube-") {
		return fmt.Errorf("namespace %q is protected from chaos experiments", namespace)
	}
	if _, allowed := r.allowedNamespaces[namespace]; !allowed {
		return fmt.Errorf("namespace %q is not in KUBEATHRIX_CHAOS_NAMESPACE_ALLOWLIST", namespace)
	}
	selectorNamespaces, _, _ := unstructured.NestedStringSlice(object.Object, "spec", "selector", "namespaces")
	if len(selectorNamespaces) != 1 || selectorNamespaces[0] != namespace {
		return fmt.Errorf("spec.selector.namespaces must contain exactly metadata.namespace")
	}
	labels, _, _ := unstructured.NestedStringMap(object.Object, "spec", "selector", "labelSelectors")
	if len(labels) == 0 {
		return fmt.Errorf("spec.selector.labelSelectors must select an explicit workload")
	}
	mode, _, _ := unstructured.NestedString(object.Object, "spec", "mode")
	switch mode {
	case "one":
	case "fixed":
		value, _, _ := unstructured.NestedString(object.Object, "spec", "value")
		count, err := strconv.Atoi(value)
		if err != nil || count < 1 || count > 3 {
			return fmt.Errorf("fixed chaos mode requires spec.value between 1 and 3")
		}
	default:
		return fmt.Errorf("spec.mode must be one or fixed")
	}
	durationText, _, _ := unstructured.NestedString(object.Object, "spec", "duration")
	duration, err := time.ParseDuration(durationText)
	if err != nil || duration <= 0 || duration > maxChaosDuration {
		return fmt.Errorf("spec.duration must be greater than zero and at most %s", maxChaosDuration)
	}
	return validateChaosKindBounds(object)
}

func validateChaosKindBounds(object *unstructured.Unstructured) error {
	switch object.GetKind() {
	case "NetworkChaos":
		action, _, _ := unstructured.NestedString(object.Object, "spec", "action")
		if action != "delay" {
			return fmt.Errorf("NetworkChaos supports only the bounded delay action")
		}
		direction, _, _ := unstructured.NestedString(object.Object, "spec", "direction")
		if direction != "to" {
			return fmt.Errorf("NetworkChaos spec.direction must be to when secondary targets are disabled")
		}
		if _, found, _ := unstructured.NestedFieldNoCopy(object.Object, "spec", "target"); found {
			return fmt.Errorf("NetworkChaos spec.target is not supported")
		}
		if external, _, _ := unstructured.NestedStringSlice(object.Object, "spec", "externalTargets"); len(external) > 0 {
			return fmt.Errorf("NetworkChaos externalTargets are not supported")
		}
		latencyText, _, _ := unstructured.NestedString(object.Object, "spec", "delay", "latency")
		latency, err := time.ParseDuration(latencyText)
		if err != nil || latency <= 0 || latency > 500*time.Millisecond {
			return fmt.Errorf("NetworkChaos delay.latency must be greater than zero and at most 500ms")
		}
		jitterText, _, _ := unstructured.NestedString(object.Object, "spec", "delay", "jitter")
		if jitterText != "" {
			jitter, err := time.ParseDuration(jitterText)
			if err != nil || jitter < 0 || jitter > 100*time.Millisecond {
				return fmt.Errorf("NetworkChaos delay.jitter must be at most 100ms")
			}
		}
		correlationText, _, _ := unstructured.NestedString(object.Object, "spec", "delay", "correlation")
		if correlationText != "" {
			correlation, err := strconv.Atoi(correlationText)
			if err != nil || correlation < 0 || correlation > 100 {
				return fmt.Errorf("NetworkChaos delay.correlation must be between 0 and 100")
			}
		}
		if _, found, _ := unstructured.NestedFieldNoCopy(object.Object, "spec", "delay", "reorder"); found {
			return fmt.Errorf("NetworkChaos packet reordering is not supported")
		}
	case "StressChaos":
		if _, found, _ := unstructured.NestedFieldNoCopy(object.Object, "spec", "stressors", "memory"); found {
			return fmt.Errorf("StressChaos memory pressure is not supported")
		}
		workers, found, err := unstructured.NestedInt64(object.Object, "spec", "stressors", "cpu", "workers")
		if err != nil || !found || workers != 1 {
			return fmt.Errorf("StressChaos cpu.workers must equal 1")
		}
		load, found, err := unstructured.NestedInt64(object.Object, "spec", "stressors", "cpu", "load")
		if err != nil || !found || load < 1 || load > 80 {
			return fmt.Errorf("StressChaos cpu.load must be between 1 and 80")
		}
	case "DNSChaos":
		action, _, _ := unstructured.NestedString(object.Object, "spec", "action")
		if action != "error" {
			return fmt.Errorf("DNSChaos supports only the error action")
		}
		patterns, _, _ := unstructured.NestedStringSlice(object.Object, "spec", "patterns")
		if len(patterns) == 0 || len(patterns) > 5 {
			return fmt.Errorf("DNSChaos requires between one and five exact DNS patterns")
		}
		for _, pattern := range patterns {
			if !validExactDNSName(pattern) {
				return fmt.Errorf("DNSChaos pattern %q must be an exact DNS name without wildcards", pattern)
			}
		}
	default:
		return fmt.Errorf("chaos kind %s is not supported", object.GetKind())
	}
	return nil
}

func validExactDNSName(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "*?/") {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, character := range part {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func plannedTargetCount(object *unstructured.Unstructured) (int, error) {
	mode, _, _ := unstructured.NestedString(object.Object, "spec", "mode")
	if mode == "one" {
		return 1, nil
	}
	value, _, _ := unstructured.NestedString(object.Object, "spec", "value")
	count, err := strconv.Atoi(value)
	if mode != "fixed" || err != nil || count < 1 || count > 3 {
		return 0, fmt.Errorf("chaos target count is invalid")
	}
	return count, nil
}

func (r *ChaosRunner) validateLiveTargets(ctx context.Context, namespace string, targetLabels map[string]string, targetCount int) error {
	pods, err := r.targetPods(ctx, namespace, targetLabels)
	if err != nil {
		return fmt.Errorf("discover chaos targets: %w", err)
	}
	if len(pods.Items) < targetCount {
		return fmt.Errorf("target selector matched %d pods but the experiment requires %d", len(pods.Items), targetCount)
	}
	if len(pods.Items) > maxChaosTargetCandidates {
		return fmt.Errorf("target selector matched %d pods; maximum candidate set is %d", len(pods.Items), maxChaosTargetCandidates)
	}
	for index := range pods.Items {
		if !chaosTargetPodReady(&pods.Items[index]) {
			return fmt.Errorf("target pod %s must be Running and Ready before chaos execution", pods.Items[index].GetName())
		}
	}
	return nil
}

func (r *ChaosRunner) targetPods(ctx context.Context, namespace string, targetLabels map[string]string) (*unstructured.UnstructuredList, error) {
	if r.client == nil {
		return nil, fmt.Errorf("Kubernetes chaos client is unavailable")
	}
	selector := labels.SelectorFromSet(labels.Set(targetLabels)).String()
	return r.client.Resource(podsResource).Namespace(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: maxChaosTargetCandidates + 1})
}

func chaosTargetPodReady(pod *unstructured.Unstructured) bool {
	if pod.GetDeletionTimestamp() != nil {
		return false
	}
	phase, _, _ := unstructured.NestedString(pod.Object, "status", "phase")
	if phase != "Running" {
		return false
	}
	conditions, _, _ := unstructured.NestedSlice(pod.Object, "status", "conditions")
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if condition["type"] == "Ready" && condition["status"] == "True" {
			return true
		}
	}
	return false
}

func namespaceAllowlist(value string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, namespace := range strings.Split(value, ",") {
		namespace = strings.TrimSpace(namespace)
		if namespace != "" {
			result[namespace] = struct{}{}
		}
	}
	return result
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
