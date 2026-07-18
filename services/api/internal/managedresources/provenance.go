package managedresources

import (
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func extractProvenance(object *unstructured.Unstructured, apiGroup string) Provenance {
	labels := object.GetLabels()
	annotations := object.GetAnnotations()
	managedBy := strings.ToLower(labels["app.kubernetes.io/managed-by"])
	controllers := managedControllers(object.GetManagedFields())

	if source := firstNonEmpty(annotations["argocd.argoproj.io/tracking-id"], labels["argocd.argoproj.io/instance"]); source != "" || strings.Contains(managedBy, "argocd") || strings.Contains(managedBy, "argo cd") {
		source = sanitizedScalar(source, 512)
		return Provenance{System: ManagementArgoCD, SourceRef: safeProvenanceString(source), GitOps: true, Controller: safeProvenanceString(firstController(controllers)), Signals: presentSignals(
			"argocd tracking/instance metadata", source != "",
			"app.kubernetes.io/managed-by", strings.Contains(managedBy, "argo"),
		)}
	}
	if source := firstNonEmpty(
		labels["kustomize.toolkit.fluxcd.io/name"],
		labels["helm.toolkit.fluxcd.io/name"],
		annotations["kustomize.toolkit.fluxcd.io/name"],
	); source != "" || strings.Contains(managedBy, "flux") {
		source = sanitizedScalar(source, 512)
		return Provenance{System: ManagementFlux, SourceRef: safeProvenanceString(source), GitOps: true, Controller: safeProvenanceString(firstController(controllers)), Signals: presentSignals(
			"Flux toolkit metadata", source != "",
			"app.kubernetes.io/managed-by", strings.Contains(managedBy, "flux"),
		)}
	}
	if isCrossplaneResource(object, apiGroup, controllers) {
		source := sanitizedScalar(firstNonEmpty(labels["crossplane.io/claim-name"], annotations["crossplane.io/external-name"]), 512)
		return Provenance{System: ManagementCrossplane, SourceRef: safeProvenanceString(source), Controller: safeProvenanceString(firstController(controllers)), Signals: []string{"Crossplane API group or controller metadata"}}
	}
	if source := annotations["meta.helm.sh/release-name"]; source != "" || managedBy == "helm" {
		if namespace := annotations["meta.helm.sh/release-namespace"]; source != "" && namespace != "" {
			source = namespace + "/" + source
		}
		source = sanitizedScalar(source, 512)
		return Provenance{System: ManagementHelm, SourceRef: safeProvenanceString(source), Controller: safeProvenanceString(firstController(controllers)), Signals: []string{"Helm release metadata"}}
	}
	if source := labels["app.kubernetes.io/managed-by"]; source != "" || isKnownOperatorGroup(apiGroup) || len(controllers) > 0 || hasControllerOwner(object.GetOwnerReferences()) {
		source = sanitizedScalar(source, 512)
		return Provenance{System: ManagementOperator, SourceRef: safeProvenanceString(source), Controller: safeProvenanceString(firstController(controllers)), Signals: []string{"operator/controller ownership metadata"}}
	}
	return Provenance{System: ManagementUnknown}
}

func isCrossplaneResource(object *unstructured.Unstructured, apiGroup string, controllers []string) bool {
	if strings.Contains(apiGroup, "crossplane.io") || strings.HasSuffix(apiGroup, ".upbound.io") {
		return true
	}
	labels := object.GetLabels()
	annotations := object.GetAnnotations()
	if labels["crossplane.io/claim-name"] != "" || annotations["crossplane.io/external-name"] != "" {
		return true
	}
	for _, controller := range controllers {
		lower := strings.ToLower(controller)
		if strings.Contains(lower, "crossplane") || strings.HasPrefix(lower, "provider-") {
			return true
		}
	}
	return false
}

func isKnownOperatorGroup(apiGroup string) bool {
	return strings.HasSuffix(apiGroup, ".services.k8s.aws") ||
		strings.HasSuffix(apiGroup, ".cnrm.cloud.google.com") ||
		strings.Contains(apiGroup, "azure.com")
}

func managedControllers(fields []metav1.ManagedFieldsEntry) []string {
	ignored := map[string]bool{
		"kubectl": true, "kubectl-client-side-apply": true, "kubectl-edit": true,
		"helm": true, "kube-controller-manager": true,
	}
	controllers := []string{}
	for _, field := range fields {
		manager := strings.TrimSpace(field.Manager)
		if manager == "" || ignored[strings.ToLower(manager)] {
			continue
		}
		controllers = append(controllers, manager)
	}
	return uniqueStrings(controllers)
}

func firstController(controllers []string) string {
	if len(controllers) == 0 {
		return ""
	}
	return sanitizedScalar(controllers[0], 253)
}

func hasControllerOwner(owners []metav1.OwnerReference) bool {
	for _, owner := range owners {
		if owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func safeProvenanceString(value string) string {
	value, redacted := sanitizeString(value)
	if redacted {
		return RedactedValue
	}
	return value
}

func presentSignals(pairs ...any) []string {
	values := []string{}
	for index := 0; index+1 < len(pairs); index += 2 {
		label, _ := pairs[index].(string)
		present, _ := pairs[index+1].(bool)
		if present {
			values = append(values, label)
		}
	}
	sort.Strings(values)
	return values
}

func relationshipsFromObject(resource Resource, object *unstructured.Unstructured) []Relationship {
	relationships := []Relationship{}
	from := resource.Reference()
	for _, owner := range object.GetOwnerReferences() {
		namespace := resource.Namespace
		relationships = append(relationships, Relationship{
			From: from,
			To: ResourceReference{
				APIVersion: owner.APIVersion,
				Kind:       owner.Kind,
				Namespace:  namespace,
				Name:       owner.Name,
				UID:        string(owner.UID),
			},
			Type: RelationshipOwner,
			Path: "metadata.ownerReferences",
		})
	}

	labels := object.GetLabels()
	if claimName := labels["crossplane.io/claim-name"]; claimName != "" {
		claimNamespace := firstNonEmpty(labels["crossplane.io/claim-namespace"], resource.Namespace)
		relationships = append(relationships, Relationship{
			From: from,
			To: ResourceReference{
				APIVersion: labels["crossplane.io/claim-api-version"],
				Kind:       labels["crossplane.io/claim-kind"],
				Namespace:  claimNamespace,
				Name:       claimName,
			},
			Type: RelationshipClaim,
			Path: "metadata.labels.crossplane.io/claim-name",
		})
	}
	if spec, found, _ := unstructured.NestedMap(object.Object, "spec"); found {
		walkReferences(spec, "spec", from, resource.Namespace, &relationships)
	}

	seen := map[string]struct{}{}
	result := make([]Relationship, 0, len(relationships))
	for _, relationship := range relationships {
		key := relationshipKey(relationship)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, relationship)
	}
	return result
}

func walkReferences(value any, path string, from ResourceReference, defaultNamespace string, relationships *[]Relationship) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := path + "." + key
			normalized := normalizeKey(key)
			if strings.HasSuffix(normalized, "ref") {
				if reference, ok := referenceFromValue(child, key, defaultNamespace); ok {
					*relationships = append(*relationships, Relationship{From: from, To: reference, Type: RelationshipReference, Path: childPath})
				}
			} else if strings.HasSuffix(normalized, "refs") {
				if list, ok := child.([]any); ok {
					for index, item := range list {
						if reference, ok := referenceFromValue(item, strings.TrimSuffix(key, "s"), defaultNamespace); ok {
							*relationships = append(*relationships, Relationship{From: from, To: reference, Type: RelationshipReference, Path: fmt.Sprintf("%s[%d]", childPath, index)})
						}
					}
				}
			}
			walkReferences(child, childPath, from, defaultNamespace, relationships)
		}
	case []any:
		for index, child := range typed {
			walkReferences(child, fmt.Sprintf("%s[%d]", path, index), from, defaultNamespace, relationships)
		}
	}
}

func referenceFromValue(value any, key, defaultNamespace string) (ResourceReference, bool) {
	object, ok := value.(map[string]any)
	if !ok {
		return ResourceReference{}, false
	}
	name := stringValue(object["name"])
	if name == "" {
		return ResourceReference{}, false
	}
	kind := stringValue(object["kind"])
	if kind == "" {
		kind = inferredReferenceKind(key)
	}
	namespace := stringValue(object["namespace"])
	if namespace == "" {
		namespace = defaultNamespace
	}
	return ResourceReference{
		APIVersion: stringValue(object["apiVersion"]),
		Kind:       kind,
		Namespace:  namespace,
		Name:       name,
	}, true
}

func inferredReferenceKind(key string) string {
	base := key
	for _, suffix := range []string{"Reference", "Refs", "Ref"} {
		base = strings.TrimSuffix(base, suffix)
	}
	switch normalizeKey(base) {
	case "writeconnectionsecretto", "secret", "connectionsecret":
		return "Secret"
	case "configmap":
		return "ConfigMap"
	case "serviceaccount":
		return "ServiceAccount"
	case "providerconfig":
		return "ProviderConfig"
	}
	if base == "" {
		return ""
	}
	return strings.ToUpper(base[:1]) + base[1:]
}
