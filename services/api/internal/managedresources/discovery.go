package managedresources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Discovery struct {
	client         dynamic.Interface
	config         Config
	now            func() time.Time
	totalTimeout   time.Duration
	requestTimeout time.Duration
	pageSize       int64
	maxObjects     int
	maxBytes       int
}

const (
	defaultRequestTimeout = 10 * time.Second
	defaultTotalTimeout   = 30 * time.Second
	defaultPageSize       = int64(250)
	defaultMaxObjects     = 10_000
	defaultMaxBytes       = 32 << 20
)

func NewDiscovery(client dynamic.Interface, config Config, now func() time.Time) (*Discovery, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	if normalized.Enabled && client == nil {
		return nil, fmt.Errorf("dynamic Kubernetes client is required when managed resource discovery is enabled")
	}
	if now == nil {
		now = time.Now
	}
	return &Discovery{
		client: client, config: normalized, now: now,
		totalTimeout: defaultTotalTimeout, requestTimeout: defaultRequestTimeout, pageSize: defaultPageSize,
		maxObjects: defaultMaxObjects, maxBytes: defaultMaxBytes,
	}, nil
}

// NewDiscoveryFromKubeConfig creates a read-only dynamic client from in-cluster
// configuration, falling back to KUBECONFIG. No client is initialized when the
// feature is disabled.
func NewDiscoveryFromKubeConfig(config Config, now func() time.Time) (*Discovery, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	if !normalized.Enabled {
		return NewDiscovery(nil, normalized, now)
	}
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes configuration for managed resource discovery: %w", err)
	}
	restConfig.QPS = 20
	restConfig.Burst = 40
	client, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("create managed resource discovery client: %w", err)
	}
	return NewDiscovery(client, normalized, now)
}

func (d *Discovery) Discover(ctx context.Context) (Snapshot, error) {
	now := d.now().UTC()
	snapshot := Snapshot{
		ObservedAt:    now,
		Resources:     []Resource{},
		Relationships: []Relationship{},
		Findings:      []core.Finding{},
	}
	if !d.config.Enabled {
		return snapshot, nil
	}
	discoveryContext, stopDiscovery := context.WithTimeout(ctx, d.totalTimeout)
	defer stopDiscovery()

	totalObjects, totalBytes := 0, 0
rules:
	for _, rule := range configRules(d.config) {
		if err := discoveryContext.Err(); err != nil {
			if ctx.Err() != nil {
				return snapshot, ctx.Err()
			}
			snapshot.Warnings = append(snapshot.Warnings, Warning{APIGroup: "kubeathrix.io", Version: "v1", Resource: "managedresources", Code: "discovery_timeout", Message: "Discovery stopped at the total " + d.totalTimeout.String() + " safety deadline."})
			break
		}
		resourceClient := d.client.Resource(rule.gvr)
		ruleContext, cancel := context.WithTimeout(discoveryContext, d.requestTimeout)
		continueToken := ""
		for {
			options := metav1.ListOptions{Limit: d.pageSize, Continue: continueToken}
			var list *unstructured.UnstructuredList
			var err error
			if rule.namespaced {
				list, err = resourceClient.Namespace(metav1.NamespaceAll).List(ruleContext, options)
			} else {
				list, err = resourceClient.List(ruleContext, options)
			}
			if err != nil {
				cancel()
				if ctx.Err() != nil {
					return snapshot, ctx.Err()
				}
				snapshot.Warnings = append(snapshot.Warnings, warningFor(rule, err))
				if discoveryContext.Err() != nil {
					break rules
				}
				continue rules
			}
			for index := range list.Items {
				objectBytes, marshalErr := json.Marshal(list.Items[index].Object)
				if marshalErr != nil {
					snapshot.Warnings = append(snapshot.Warnings, Warning{APIGroup: rule.gvr.Group, Version: rule.gvr.Version, Resource: rule.gvr.Resource, Code: "object_invalid", Message: "A managed resource could not be bounded for analysis."})
					continue
				}
				if totalObjects >= d.maxObjects || totalBytes+len(objectBytes) > d.maxBytes {
					snapshot.Warnings = append(snapshot.Warnings, Warning{APIGroup: rule.gvr.Group, Version: rule.gvr.Version, Resource: rule.gvr.Resource, Code: "snapshot_limit_reached", Message: fmt.Sprintf("Discovery stopped at the safety limit of %d objects or %d bytes.", d.maxObjects, d.maxBytes)})
					cancel()
					break rules
				}
				totalObjects++
				totalBytes += len(objectBytes)
				resource, sensitivePaths := resourceFromObject(&list.Items[index], rule, now)
				snapshot.Relationships = append(snapshot.Relationships, relationshipsFromObject(resource, &list.Items[index])...)
				snapshot.Findings = append(snapshot.Findings, findingsForResource(resource, sensitivePaths, now)...)
				resource.Spec = nil
				resource.Labels = nil
				resource.Annotations = nil
				snapshot.Resources = append(snapshot.Resources, resource)
			}
			continueToken = list.GetContinue()
			if continueToken == "" {
				break
			}
		}
		cancel()
	}

	sort.Slice(snapshot.Resources, func(i, j int) bool { return snapshot.Resources[i].ID < snapshot.Resources[j].ID })
	sort.Slice(snapshot.Relationships, func(i, j int) bool {
		left := relationshipKey(snapshot.Relationships[i])
		right := relationshipKey(snapshot.Relationships[j])
		return left < right
	})
	sort.Slice(snapshot.Findings, func(i, j int) bool { return snapshot.Findings[i].ID < snapshot.Findings[j].ID })
	sort.Slice(snapshot.Warnings, func(i, j int) bool {
		left := snapshot.Warnings[i]
		right := snapshot.Warnings[j]
		return left.APIGroup+"/"+left.Version+"/"+left.Resource < right.APIGroup+"/"+right.Version+"/"+right.Resource
	})
	return snapshot, nil
}

func warningFor(rule resourceRule, err error) Warning {
	code := "list_failed"
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		code = "request_timeout"
	case apierrors.IsNotFound(err), apierrors.IsMethodNotSupported(err):
		code = "resource_unavailable"
	case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
		code = "access_denied"
	}
	return Warning{
		APIGroup: rule.gvr.Group,
		Version:  rule.gvr.Version,
		Resource: rule.gvr.Resource,
		Code:     code,
		Message:  sanitizedScalar(err.Error(), 512),
	}
}

func resourceFromObject(object *unstructured.Unstructured, rule resourceRule, now time.Time) (Resource, []string) {
	apiVersion := object.GetAPIVersion()
	if apiVersion == "" {
		apiVersion = rule.gvr.Group + "/" + rule.gvr.Version
	}
	kind := object.GetKind()
	if kind == "" {
		kind = inferredKind(rule.gvr.Resource)
	}
	spec, _, _ := unstructured.NestedMap(object.Object, "spec")
	sanitizedSpecValue, sensitivePaths := sanitizeValue(spec, "spec")
	sanitizedSpec, _ := sanitizedSpecValue.(map[string]any)
	labels, labelSensitive := sanitizeStringMap(object.GetLabels(), "metadata.labels")
	annotations, annotationSensitive := sanitizeStringMap(object.GetAnnotations(), "metadata.annotations")
	sensitivePaths = append(sensitivePaths, labelSensitive...)
	sensitivePaths = append(sensitivePaths, annotationSensitive...)
	sensitivePaths = uniqueStrings(sensitivePaths)

	resource := Resource{
		APIGroup:    rule.gvr.Group,
		Version:     rule.gvr.Version,
		Plural:      rule.gvr.Resource,
		APIVersion:  apiVersion,
		Kind:        kind,
		Namespace:   object.GetNamespace(),
		Name:        object.GetName(),
		UID:         string(object.GetUID()),
		Generation:  object.GetGeneration(),
		CreatedAt:   object.GetCreationTimestamp().Time.UTC(),
		Finalizers:  append([]string(nil), object.GetFinalizers()...),
		Labels:      labels,
		Annotations: annotations,
		Spec:        sanitizedSpec,
		Status:      extractStatus(object),
		Provenance:  extractProvenance(object, rule.gvr.Group),
	}
	resource.ID = resourceID(resource)
	if deletion := object.GetDeletionTimestamp(); deletion != nil {
		value := deletion.Time.UTC()
		resource.DeletionTimestamp = &value
	}
	resource.ExternalID = extractExternalID(object)
	if sanitized, redacted := sanitizeString(resource.ExternalID); redacted {
		resource.ExternalID = RedactedValue
	} else {
		resource.ExternalID = sanitized
	}
	_ = now
	return resource, sensitivePaths
}

func resourceID(resource Resource) string {
	parts := []string{resource.APIGroup, resource.Version, resource.Plural}
	if resource.Namespace != "" {
		parts = append(parts, resource.Namespace)
	}
	parts = append(parts, resource.Name)
	return strings.Join(parts, "/")
}

func inferredKind(resource string) string {
	value := resource
	if strings.HasSuffix(value, "ies") {
		value = strings.TrimSuffix(value, "ies") + "y"
	} else {
		value = strings.TrimSuffix(value, "s")
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	for index := range parts {
		if parts[index] != "" {
			parts[index] = strings.ToUpper(parts[index][:1]) + parts[index][1:]
		}
	}
	return strings.Join(parts, "")
}

func extractStatus(object *unstructured.Unstructured) ResourceStatus {
	status := ResourceStatus{}
	if observed, found, _ := unstructured.NestedInt64(object.Object, "status", "observedGeneration"); found {
		status.ObservedGeneration = observed
	}
	for _, path := range [][]string{{"status", "state"}, {"status", "phase"}, {"status", "provisioningState"}, {"status", "atProvider", "state"}, {"status", "atProvider", "status"}} {
		if value, found, _ := unstructured.NestedString(object.Object, path...); found && value != "" {
			status.State = sanitizedScalar(value, 256)
			break
		}
	}
	rawConditions, found, _ := unstructured.NestedSlice(object.Object, "status", "conditions")
	if !found {
		return status
	}
	for _, raw := range rawConditions {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		condition := Condition{
			Type:   sanitizedScalar(stringValue(item["type"]), 128),
			Status: sanitizedScalar(stringValue(item["status"]), 32),
			Reason: sanitizedScalar(stringValue(item["reason"]), 256),
		}
		condition.ObservedGeneration = int64Value(item["observedGeneration"])
		if condition.ObservedGeneration > status.ObservedGeneration {
			status.ObservedGeneration = condition.ObservedGeneration
		}
		if parsed, err := time.Parse(time.RFC3339, stringValue(item["lastTransitionTime"])); err == nil {
			parsed = parsed.UTC()
			condition.LastTransitionTime = &parsed
		}
		setConditionState(&status, condition)
		status.Conditions = append(status.Conditions, condition)
	}
	sort.Slice(status.Conditions, func(i, j int) bool { return status.Conditions[i].Type < status.Conditions[j].Type })
	return status
}

func setConditionState(status *ResourceStatus, condition Condition) {
	value, known := conditionBool(condition.Status)
	if !known {
		return
	}
	switch strings.ToLower(condition.Type) {
	case "ready", "healthy", "available":
		status.Ready = boolPointer(value)
	case "synced", "reconciled":
		status.Synced = boolPointer(value)
	case "stalled":
		status.Stalled = boolPointer(value)
	}
}

func conditionBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func boolPointer(value bool) *bool { return &value }

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return ""
	}
}

func int64Value(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	case jsonNumber:
		parsed, _ := strconv.ParseInt(string(typed), 10, 64)
		return parsed
	default:
		return 0
	}
}

type jsonNumber string

func extractExternalID(object *unstructured.Unstructured) string {
	if value := object.GetAnnotations()["crossplane.io/external-name"]; value != "" {
		return value
	}
	for _, path := range [][]string{
		{"status", "atProvider", "arn"}, {"status", "atProvider", "selfLink"},
		{"status", "atProvider", "id"}, {"status", "atProvider", "resourceId"},
		{"status", "resourceID"}, {"status", "resourceId"}, {"status", "id"},
	} {
		if value, found, _ := unstructured.NestedString(object.Object, path...); found && value != "" {
			return value
		}
	}
	return ""
}

func relationshipKey(value Relationship) string {
	return string(value.Type) + "|" + value.From.APIVersion + "|" + value.From.Namespace + "|" + value.From.Kind + "|" + value.From.Name + "|" + value.To.APIVersion + "|" + value.To.Namespace + "|" + value.To.Kind + "|" + value.To.Name + "|" + value.Path
}
