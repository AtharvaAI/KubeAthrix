package cluster

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Inspector struct {
	client kubernetes.Interface
	now    func() time.Time
}

func NewInspector() (*Inspector, error) {
	config, err := kubeConfig()
	if err != nil {
		return nil, err
	}
	config.QPS = 20
	config.Burst = 40

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &Inspector{client: client, now: time.Now}, nil
}

func kubeConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
	}
	if err != nil {
		return nil, err
	}
	config.QPS = 20
	config.Burst = 40
	return config, nil
}

func NewInspectorFromClient(client kubernetes.Interface, now func() time.Time) *Inspector {
	if now == nil {
		now = time.Now
	}
	return &Inspector{client: client, now: now}
}

func (i *Inspector) Snapshot(ctx context.Context) (core.ClusterSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	opts := metav1.ListOptions{}
	nodes, err := i.client.CoreV1().Nodes().List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list nodes: %w", err)
	}
	namespaces, err := i.client.CoreV1().Namespaces().List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list namespaces: %w", err)
	}
	pods, err := i.client.CoreV1().Pods("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list pods: %w", err)
	}
	services, err := i.client.CoreV1().Services("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list services: %w", err)
	}
	serviceAccounts, err := i.client.CoreV1().ServiceAccounts("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list serviceaccounts: %w", err)
	}
	configMaps, err := i.client.CoreV1().ConfigMaps("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list configmaps: %w", err)
	}
	resourceQuotas, err := i.client.CoreV1().ResourceQuotas("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list resourcequotas: %w", err)
	}
	limitRanges, err := i.client.CoreV1().LimitRanges("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list limitranges: %w", err)
	}
	pvcs, err := i.client.CoreV1().PersistentVolumeClaims("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list persistentvolumeclaims: %w", err)
	}
	events, err := i.client.CoreV1().Events("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list events: %w", err)
	}
	deployments, err := i.client.AppsV1().Deployments("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list deployments: %w", err)
	}
	statefulSets, err := i.client.AppsV1().StatefulSets("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list statefulsets: %w", err)
	}
	daemonSets, err := i.client.AppsV1().DaemonSets("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list daemonsets: %w", err)
	}
	jobs, err := i.client.BatchV1().Jobs("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list jobs: %w", err)
	}
	ingresses, err := i.client.NetworkingV1().Ingresses("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list ingresses: %w", err)
	}
	networkPolicies, err := i.client.NetworkingV1().NetworkPolicies("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list networkpolicies: %w", err)
	}
	pdbs, err := i.client.PolicyV1().PodDisruptionBudgets("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list poddisruptionbudgets: %w", err)
	}
	hpas, err := i.client.AutoscalingV2().HorizontalPodAutoscalers("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list horizontalpodautoscalers: %w", err)
	}
	roles, err := i.client.RbacV1().Roles("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list roles: %w", err)
	}
	roleBindings, err := i.client.RbacV1().RoleBindings("").List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list rolebindings: %w", err)
	}
	clusterRoles, err := i.client.RbacV1().ClusterRoles().List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list clusterroles: %w", err)
	}
	clusterRoleBindings, err := i.client.RbacV1().ClusterRoleBindings().List(ctx, opts)
	if err != nil {
		return core.ClusterSnapshot{}, fmt.Errorf("list clusterrolebindings: %w", err)
	}
	now := i.now().UTC()
	inventory := core.ClusterInventory{
		Nodes:                    len(nodes.Items),
		ReadyNodes:               readyNodeCount(nodes.Items),
		Namespaces:               len(namespaces.Items),
		Pods:                     len(pods.Items),
		RunningPods:              podPhaseCount(pods.Items, corev1.PodRunning),
		PendingPods:              podPhaseCount(pods.Items, corev1.PodPending),
		Deployments:              len(deployments.Items),
		StatefulSets:             len(statefulSets.Items),
		DaemonSets:               len(daemonSets.Items),
		Services:                 len(services.Items),
		Ingresses:                len(ingresses.Items),
		Jobs:                     len(jobs.Items),
		ConfigMaps:               len(configMaps.Items),
		ServiceAccounts:          len(serviceAccounts.Items),
		Roles:                    len(roles.Items),
		RoleBindings:             len(roleBindings.Items),
		ClusterRoles:             len(clusterRoles.Items),
		ClusterRoleBindings:      len(clusterRoleBindings.Items),
		NetworkPolicies:          len(networkPolicies.Items),
		ResourceQuotas:           len(resourceQuotas.Items),
		LimitRanges:              len(limitRanges.Items),
		PersistentVolumeClaims:   len(pvcs.Items),
		PodDisruptionBudgets:     len(pdbs.Items),
		HorizontalPodAutoscalers: len(hpas.Items),
		Events:                   len(events.Items),
	}

	findings := scanFindings(now, nodes.Items, namespaces.Items, pods.Items, services.Items, deployments.Items, statefulSets.Items, daemonSets.Items, ingresses.Items, pvcs.Items, pdbs.Items, networkPolicies.Items, resourceQuotas.Items, limitRanges.Items, roles.Items, roleBindings.Items, clusterRoles.Items, clusterRoleBindings.Items)
	compliance := complianceControls(inventory, findings)
	scan := core.ScanSummary{
		LastRunAt:           now,
		ResourcesScanned:    resourcesScanned(inventory),
		PolicyChecks:        inventory.Namespaces + inventory.NetworkPolicies + inventory.ResourceQuotas + inventory.LimitRanges + inventory.PodDisruptionBudgets + inventory.Ingresses,
		PermissionChecks:    inventory.Roles + inventory.RoleBindings + inventory.ClusterRoles + inventory.ClusterRoleBindings,
		ConfigurationChecks: inventory.Nodes + inventory.Pods + inventory.Deployments + inventory.StatefulSets + inventory.DaemonSets + inventory.Services + inventory.PersistentVolumeClaims,
		ComplianceControls:  len(compliance),
		PassedControls:      countControls(compliance, "pass"),
		FailedControls:      countControls(compliance, "fail"),
	}

	return core.ClusterSnapshot{
		Inventory:   inventory,
		Findings:    findings,
		Scan:        scan,
		Compliance:  compliance,
		Experiments: core.DefaultChaosExperiments(),
	}, nil
}

func scanFindings(now time.Time, nodes []corev1.Node, namespaces []corev1.Namespace, pods []corev1.Pod, services []corev1.Service, deployments []appsv1.Deployment, statefulSets []appsv1.StatefulSet, daemonSets []appsv1.DaemonSet, ingresses []networkingv1.Ingress, pvcs []corev1.PersistentVolumeClaim, pdbs []policyv1.PodDisruptionBudget, networkPolicies []networkingv1.NetworkPolicy, quotas []corev1.ResourceQuota, limitRanges []corev1.LimitRange, roles []rbacv1.Role, roleBindings []rbacv1.RoleBinding, clusterRoles []rbacv1.ClusterRole, clusterRoleBindings []rbacv1.ClusterRoleBinding) []core.Finding {
	var findings []core.Finding
	networkPolicyByNamespace := networkPolicyNamespaceSet(networkPolicies)
	quotaByNamespace := quotaNamespaceSet(quotas)
	limitRangeByNamespace := limitRangeNamespaceSet(limitRanges)

	for _, node := range nodes {
		if !nodeReady(node) {
			findings = append(findings, newClusterFinding(now, "scan-node-not-ready-"+safeID(node.Name), "kubeathrix-scan", "Node is not Ready", core.SeverityHigh, core.ResourceRef{APIVersion: "v1", Kind: "Node", Name: node.Name}, "The node is not reporting Ready and may reduce scheduling capacity or availability.", core.FixabilityInformational, "triage_required", 78, "Inspect node conditions, kubelet health, and cloud provider events."))
		}
		if nodeUnderPressure(node) {
			findings = append(findings, newClusterFinding(now, "scan-node-pressure-"+safeID(node.Name), "kubeathrix-scan", "Node reports resource pressure", core.SeverityMedium, core.ResourceRef{APIVersion: "v1", Kind: "Node", Name: node.Name}, "The node reports memory, disk, or PID pressure.", core.FixabilityInformational, "triage_required", 68, "Review noisy workloads, eviction events, and node capacity before scheduling more pods."))
		}
	}

	for _, namespace := range namespaces {
		if isSystemNamespace(namespace.Name) {
			continue
		}
		if !quotaByNamespace[namespace.Name] || !limitRangeByNamespace[namespace.Name] {
			findings = append(findings, newClusterFinding(now, "scan-namespace-governance-"+safeID(namespace.Name), "kubeathrix-scan", "Namespace lacks resource governance", core.SeverityMedium, core.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: namespace.Name}, "No ResourceQuota or LimitRange fully bounds workload requests in this namespace.", core.FixabilityDeterministic, "autofix_available", 58, "Apply a namespace-scoped ResourceQuota and default LimitRange."))
		}
		if !networkPolicyByNamespace[namespace.Name] {
			findings = append(findings, newClusterFinding(now, "scan-networkpolicy-"+safeID(namespace.Name), "kubeathrix-scan", "Namespace has no NetworkPolicy guardrail", core.SeverityMedium, core.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: namespace.Name}, "Pods in this namespace have no namespace-local NetworkPolicy object to constrain traffic.", core.FixabilityGated, "dry_run_ready", 64, "Create a default-deny baseline and explicit allow policies after review."))
		}
		if missingPodSecurityLabel(namespace) {
			findings = append(findings, newClusterFinding(now, "scan-namespace-pod-security-"+safeID(namespace.Name), "kubeathrix-scan", "Namespace lacks Pod Security enforcement label", core.SeverityMedium, core.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: namespace.Name}, "The namespace does not set pod-security.kubernetes.io/enforce to baseline or restricted.", core.FixabilityDeterministic, "autofix_available", 57, "Set Pod Security admission labels that match the namespace risk tier."))
		}
		if privilegedPodSecurityLabel(namespace) {
			findings = append(findings, newClusterFinding(now, "scan-namespace-pod-security-privileged-"+safeID(namespace.Name), "kubeathrix-scan", "Namespace allows privileged Pod Security level", core.SeverityHigh, core.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: namespace.Name}, "The namespace explicitly enforces the privileged Pod Security level.", core.FixabilityHumanOnly, "approval_required", 84, "Review workloads and move the namespace to baseline or restricted where possible."))
		}
	}

	for _, service := range services {
		if isSystemNamespace(service.Namespace) {
			continue
		}
		switch service.Spec.Type {
		case corev1.ServiceTypeLoadBalancer:
			findings = append(findings, newClusterFinding(now, "scan-public-service-"+safeID(service.Namespace, service.Name), "kubeathrix-scan", "Service is exposed through a LoadBalancer", core.SeverityHigh, core.ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: service.Namespace, Name: service.Name}, "The service creates a cloud-facing load balancer and should be reviewed against ingress policy.", core.FixabilityHumanOnly, "approval_required", 86, "Validate intended exposure, source restrictions, and ownership before changing service type or ingress policy."))
		case corev1.ServiceTypeNodePort:
			findings = append(findings, newClusterFinding(now, "scan-nodeport-service-"+safeID(service.Namespace, service.Name), "kubeathrix-scan", "Service exposes a NodePort", core.SeverityMedium, core.ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: service.Namespace, Name: service.Name}, "NodePort opens a port on every node and can broaden the reachable surface.", core.FixabilityGated, "dry_run_ready", 66, "Confirm the exposure is required or migrate behind controlled ingress."))
		}
		if len(service.Spec.ExternalIPs) > 0 {
			findings = append(findings, newClusterFinding(now, "scan-externalip-service-"+safeID(service.Namespace, service.Name), "kubeathrix-scan", "Service uses externalIPs", core.SeverityHigh, core.ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: service.Namespace, Name: service.Name}, "Service externalIPs can route traffic outside normal load balancer and ingress controls.", core.FixabilityHumanOnly, "approval_required", 81, "Validate ownership of external IPs and remove the field if not explicitly required."))
		}
	}

	for _, ingress := range ingresses {
		if isSystemNamespace(ingress.Namespace) {
			continue
		}
		target := core.ResourceRef{APIVersion: "networking.k8s.io/v1", Kind: "Ingress", Namespace: ingress.Namespace, Name: ingress.Name}
		if len(ingress.Spec.TLS) == 0 {
			findings = append(findings, newClusterFinding(now, "scan-ingress-tls-"+safeID(ingress.Namespace, ingress.Name), "kubeathrix-scan", "Ingress has no TLS configuration", core.SeverityMedium, target, "The Ingress does not declare TLS blocks for its hosts.", core.FixabilityGated, "dry_run_ready", 63, "Attach a TLS secret and verify certificate ownership before exposing traffic."))
		}
		if ingressHasWildcardHost(ingress) {
			findings = append(findings, newClusterFinding(now, "scan-ingress-wildcard-"+safeID(ingress.Namespace, ingress.Name), "kubeathrix-scan", "Ingress uses wildcard host routing", core.SeverityMedium, target, "Wildcard host rules can accidentally expose additional hostnames.", core.FixabilityHumanOnly, "approval_required", 69, "Replace wildcard hosts with explicit hostnames unless ownership is proven."))
		}
	}

	for _, pvc := range pvcs {
		if isSystemNamespace(pvc.Namespace) {
			continue
		}
		target := core.ResourceRef{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name}
		if pvc.Status.Phase != corev1.ClaimBound {
			findings = append(findings, newClusterFinding(now, "scan-pvc-not-bound-"+safeID(pvc.Namespace, pvc.Name), "kubeathrix-scan", "PersistentVolumeClaim is not bound", core.SeverityMedium, target, "A PVC is not Bound and can block workload scheduling or recovery.", core.FixabilityInformational, "triage_required", 60, "Inspect storage class, events, capacity, and access mode compatibility."))
		}
		if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName == "" {
			findings = append(findings, newClusterFinding(now, "scan-pvc-storageclass-"+safeID(pvc.Namespace, pvc.Name), "kubeathrix-scan", "PersistentVolumeClaim has no StorageClass", core.SeverityLow, target, "PVC provisioning is not explicitly tied to a StorageClass.", core.FixabilityGated, "dry_run_ready", 42, "Set an approved StorageClass or document the static provisioning path."))
		}
	}

	for _, workload := range workloadTargets(deployments, statefulSets, daemonSets) {
		if isSystemNamespace(workload.Namespace) {
			continue
		}
		target := workload.Ref()
		if podSpecMissingResources(workload.PodSpec) {
			findings = append(findings, newClusterFinding(now, "scan-workload-resources-"+safeID(workload.Namespace, workload.Name), "kubeathrix-scan", workload.Kind+" containers miss resource requests or limits", core.SeverityMedium, target, "One or more containers do not specify CPU and memory requests and limits.", core.FixabilityDeterministic, "autofix_available", 62, "Patch workload resources with bounded defaults after dry-run validation."))
		}
		if podSpecMissingReadiness(workload.PodSpec) {
			findings = append(findings, newClusterFinding(now, "scan-workload-readiness-"+safeID(workload.Namespace, workload.Name), "kubeathrix-scan", workload.Kind+" lacks readiness probes", core.SeverityMedium, target, "One or more containers cannot prove request-serving readiness during rollouts.", core.FixabilityGated, "dry_run_ready", 67, "Add readiness probes and verify rollout health."))
		}
		if podSpecMissingLiveness(workload.PodSpec) {
			findings = append(findings, newClusterFinding(now, "scan-workload-liveness-"+safeID(workload.Namespace, workload.Name), "kubeathrix-scan", workload.Kind+" lacks liveness probes", core.SeverityLow, target, "One or more containers do not declare a liveness probe.", core.FixabilityGated, "dry_run_ready", 48, "Add liveness probes only where restart behavior is well understood."))
		}
		if workload.Replicas > 1 && !workloadHasPDB(workload, pdbs) {
			findings = append(findings, newClusterFinding(now, "scan-workload-pdb-"+safeID(workload.Namespace, workload.Name), "kubeathrix-scan", "Replicated "+workload.Kind+" lacks disruption protection", core.SeverityLow, target, "Voluntary disruptions may evict too many replicas because no matching PodDisruptionBudget was found.", core.FixabilityGated, "dry_run_ready", 46, "Create a scoped PodDisruptionBudget and verify it matches the workload labels."))
		}
		if podSpecUsesMutableImages(workload.PodSpec) {
			findings = append(findings, newClusterFinding(now, "scan-workload-image-mutability-"+safeID(workload.Namespace, workload.Name), "kubeathrix-scan", workload.Kind+" uses mutable image tags", core.SeverityMedium, target, "One or more containers use the latest tag or omit an immutable digest.", core.FixabilityGated, "dry_run_ready", 65, "Pin workload images to reviewed version tags or immutable digests."))
		}
		if podSpecMissingRuntimeHardening(workload.PodSpec) {
			findings = append(findings, newClusterFinding(now, "scan-workload-runtime-hardening-"+safeID(workload.Namespace, workload.Name), "kubeathrix-scan", workload.Kind+" misses restricted runtime settings", core.SeverityMedium, target, "The pod template does not consistently set runAsNonRoot, seccomp, and dropped capabilities.", core.FixabilityGated, "dry_run_ready", 70, "Apply restricted securityContext settings after validating workload compatibility."))
		}
		if podSpecAllowsHostAccess(workload.PodSpec) {
			findings = append(findings, newClusterFinding(now, "scan-workload-host-access-"+safeID(workload.Namespace, workload.Name), "kubeathrix-scan", workload.Kind+" requests host-level access", core.SeverityHigh, target, "The pod template uses host namespaces, host networking, or hostPath volumes.", core.FixabilityHumanOnly, "approval_required", 87, "Validate host access requirements and replace with scoped Kubernetes APIs where possible."))
		}
		if podSpecHasElevatedCapabilities(workload.PodSpec) {
			findings = append(findings, newClusterFinding(now, "scan-workload-capabilities-"+safeID(workload.Namespace, workload.Name), "kubeathrix-scan", workload.Kind+" grants elevated Linux capabilities", core.SeverityHigh, target, "One or more containers add Linux capabilities or allow privilege escalation.", core.FixabilityHumanOnly, "approval_required", 82, "Remove added capabilities and privilege escalation unless explicitly approved."))
		}
		if podSpecUsesDefaultServiceAccount(workload.PodSpec) {
			findings = append(findings, newClusterFinding(now, "scan-workload-default-serviceaccount-"+safeID(workload.Namespace, workload.Name), "kubeathrix-scan", workload.Kind+" uses the default ServiceAccount", core.SeverityLow, target, "The pod template uses the namespace default ServiceAccount instead of a workload-scoped identity.", core.FixabilityDeterministic, "autofix_available", 44, "Create a workload-specific ServiceAccount with least-privilege RBAC."))
		}
		if podSpecAutomountsServiceAccountToken(workload.PodSpec) {
			findings = append(findings, newClusterFinding(now, "scan-workload-serviceaccount-token-"+safeID(workload.Namespace, workload.Name), "kubeathrix-scan", workload.Kind+" automounts a ServiceAccount token", core.SeverityLow, target, "The pod template does not disable ServiceAccount token automounting.", core.FixabilityGated, "dry_run_ready", 40, "Disable automountServiceAccountToken for workloads that do not call the Kubernetes API."))
		}
	}

	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		if pod.Status.Phase == corev1.PodFailed {
			findings = append(findings, newClusterFinding(now, "scan-pod-failed-"+safeID(pod.Namespace, pod.Name), "kubeathrix-scan", "Pod is Failed", core.SeverityMedium, core.ResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name}, "A pod is in Failed phase and may represent a failed workload or job.", core.FixabilityInformational, "triage_required", 58, "Inspect pod status, events, and owning controller."))
		}
		if pod.Status.Phase == corev1.PodPending {
			findings = append(findings, newClusterFinding(now, "scan-pod-pending-"+safeID(pod.Namespace, pod.Name), "kubeathrix-scan", "Pod is Pending", core.SeverityLow, core.ResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name}, "A pod is Pending and may be blocked by scheduling, image pull, or storage.", core.FixabilityInformational, "triage_required", 49, "Inspect scheduling events, image pull state, and PVC binding."))
		}
		if podRestarting(pod) {
			findings = append(findings, newClusterFinding(now, "scan-pod-restarts-"+safeID(pod.Namespace, pod.Name), "kubeathrix-scan", "Pod has repeated restarts", core.SeverityMedium, core.ResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name}, "One or more containers have restarted repeatedly.", core.FixabilityInformational, "triage_required", 61, "Review logs, probes, resource limits, and recent deployments."))
		}
		if podHasPrivilegedContainer(pod) {
			findings = append(findings, newClusterFinding(now, "scan-privileged-pod-"+safeID(pod.Namespace, pod.Name), "kubeathrix-scan", "Pod permits privileged container behavior", core.SeverityHigh, core.ResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name}, "A container is privileged or allows privilege escalation.", core.FixabilityHumanOnly, "approval_required", 88, "Review workload requirements and enforce restricted security context."))
		}
	}

	for _, policy := range networkPolicies {
		if isSystemNamespace(policy.Namespace) {
			continue
		}
		if networkPolicyHasBroadIngress(policy) {
			findings = append(findings, newClusterFinding(now, "scan-networkpolicy-broad-ingress-"+safeID(policy.Namespace, policy.Name), "kubeathrix-scan", "NetworkPolicy allows broad ingress", core.SeverityMedium, core.ResourceRef{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Namespace: policy.Namespace, Name: policy.Name}, "A NetworkPolicy ingress rule has no source restrictions.", core.FixabilityGated, "dry_run_ready", 59, "Constrain ingress peers and ports to the required callers."))
		}
		if networkPolicyHasBroadEgress(policy) {
			findings = append(findings, newClusterFinding(now, "scan-networkpolicy-broad-egress-"+safeID(policy.Namespace, policy.Name), "kubeathrix-scan", "NetworkPolicy allows broad egress", core.SeverityMedium, core.ResourceRef{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Namespace: policy.Namespace, Name: policy.Name}, "A NetworkPolicy egress rule has no destination restrictions.", core.FixabilityGated, "dry_run_ready", 58, "Constrain egress peers and ports to known dependencies."))
		}
	}

	for _, role := range roles {
		if isSystemNamespace(role.Namespace) {
			continue
		}
		target := core.ResourceRef{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: role.Namespace, Name: role.Name}
		if hasWildcardRule(role.Rules) {
			findings = append(findings, newClusterFinding(now, "scan-role-wildcard-"+safeID(role.Namespace, role.Name), "kubeathrix-scan", "Namespace Role grants wildcard permissions", core.SeverityHigh, target, "The role contains wildcard verbs, API groups, or resources.", core.FixabilityHumanOnly, "approval_required", 82, "Replace broad RBAC with explicit resources and verbs."))
		}
		if roleAllowsSecretRead(role.Rules) {
			findings = append(findings, newClusterFinding(now, "scan-role-secret-read-"+safeID(role.Namespace, role.Name), "kubeathrix-scan", "Namespace Role can read Secrets", core.SeverityHigh, target, "The role can get, list, or watch Secret resources.", core.FixabilityHumanOnly, "approval_required", 80, "Narrow Secret access to exact workloads and rotate credentials if access is unexpected."))
		}
		if roleAllowsPrivilegeEscalation(role.Rules) {
			findings = append(findings, newClusterFinding(now, "scan-role-rbac-escalation-"+safeID(role.Namespace, role.Name), "kubeathrix-scan", "Namespace Role can escalate RBAC privilege", core.SeverityHigh, target, "The role grants bind, escalate, impersonate, or pod exec privileges.", core.FixabilityHumanOnly, "approval_required", 83, "Remove escalation verbs and require explicit break-glass approval."))
		}
	}

	for _, binding := range roleBindings {
		if isSystemNamespace(binding.Namespace) {
			continue
		}
		if binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == "cluster-admin" {
			findings = append(findings, newClusterFinding(now, "scan-rolebinding-clusteradmin-"+safeID(binding.Namespace, binding.Name), "kubeathrix-scan", "RoleBinding grants cluster-admin in namespace", core.SeverityHigh, core.ResourceRef{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: binding.Namespace, Name: binding.Name}, "A namespace RoleBinding references the cluster-admin ClusterRole.", core.FixabilityHumanOnly, "approval_required", 85, "Replace cluster-admin with a namespace-scoped least-privilege role."))
		}
	}

	for _, clusterRole := range clusterRoles {
		if isBuiltinClusterRole(clusterRole.Name) {
			continue
		}
		target := core.ResourceRef{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: clusterRole.Name}
		if hasWildcardRule(clusterRole.Rules) {
			findings = append(findings, newClusterFinding(now, "scan-clusterrole-wildcard-"+safeID(clusterRole.Name), "kubeathrix-scan", "ClusterRole grants wildcard permissions", core.SeverityHigh, target, "The cluster role contains wildcard verbs, API groups, or resources.", core.FixabilityHumanOnly, "approval_required", 84, "Constrain the role to explicit least-privilege rules."))
		}
		if roleAllowsSecretRead(clusterRole.Rules) {
			findings = append(findings, newClusterFinding(now, "scan-clusterrole-secret-read-"+safeID(clusterRole.Name), "kubeathrix-scan", "ClusterRole can read Secrets", core.SeverityHigh, target, "The cluster role can get, list, or watch Secret resources across namespaces.", core.FixabilityHumanOnly, "approval_required", 86, "Narrow Secret access or bind it only to explicitly approved controllers."))
		}
		if roleAllowsPrivilegeEscalation(clusterRole.Rules) {
			findings = append(findings, newClusterFinding(now, "scan-clusterrole-rbac-escalation-"+safeID(clusterRole.Name), "kubeathrix-scan", "ClusterRole can escalate RBAC privilege", core.SeverityHigh, target, "The cluster role grants bind, escalate, impersonate, or pod exec privileges.", core.FixabilityHumanOnly, "approval_required", 88, "Remove escalation paths or move them behind break-glass controls."))
		}
	}

	for _, binding := range clusterRoleBindings {
		if binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == "cluster-admin" && !isBuiltinClusterRoleBinding(binding.Name) {
			findings = append(findings, newClusterFinding(now, "scan-clusteradmin-binding-"+safeID(binding.Name), "kubeathrix-scan", "ClusterRoleBinding grants cluster-admin", core.SeverityCritical, core.ResourceRef{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Name: binding.Name}, "A subject is bound to cluster-admin outside the expected Kubernetes system bindings.", core.FixabilityHumanOnly, "approval_required", 95, "Verify owner, expiry, and remove or narrow cluster-admin access."))
		}
		if bindingHasUnauthenticatedSubject(binding) {
			findings = append(findings, newClusterFinding(now, "scan-clusterrolebinding-public-subject-"+safeID(binding.Name), "kubeathrix-scan", "ClusterRoleBinding targets unauthenticated subjects", core.SeverityCritical, core.ResourceRef{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Name: binding.Name}, "The binding includes system:unauthenticated, system:anonymous, or system:authenticated as a subject.", core.FixabilityHumanOnly, "approval_required", 92, "Remove broad public subjects and bind explicit service accounts or groups only."))
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RiskScore == findings[j].RiskScore {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].RiskScore > findings[j].RiskScore
	})
	return findings
}

func networkPolicyNamespaceSet(items []networkingv1.NetworkPolicy) map[string]bool {
	result := map[string]bool{}
	for _, item := range items {
		result[item.Namespace] = true
	}
	return result
}

func quotaNamespaceSet(items []corev1.ResourceQuota) map[string]bool {
	result := map[string]bool{}
	for _, item := range items {
		result[item.Namespace] = true
	}
	return result
}

func limitRangeNamespaceSet(items []corev1.LimitRange) map[string]bool {
	result := map[string]bool{}
	for _, item := range items {
		result[item.Namespace] = true
	}
	return result
}

type workloadTarget struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	Labels     map[string]string
	Replicas   int32
	PodSpec    corev1.PodSpec
}

func (w workloadTarget) Ref() core.ResourceRef {
	return core.ResourceRef{APIVersion: w.APIVersion, Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
}

func workloadTargets(deployments []appsv1.Deployment, statefulSets []appsv1.StatefulSet, daemonSets []appsv1.DaemonSet) []workloadTarget {
	workloads := make([]workloadTarget, 0, len(deployments)+len(statefulSets)+len(daemonSets))
	for _, deployment := range deployments {
		workloads = append(workloads, workloadTarget{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Namespace:  deployment.Namespace,
			Name:       deployment.Name,
			Labels:     deployment.Spec.Template.Labels,
			Replicas:   deploymentReplicas(deployment),
			PodSpec:    deployment.Spec.Template.Spec,
		})
	}
	for _, statefulSet := range statefulSets {
		replicas := int32(1)
		if statefulSet.Spec.Replicas != nil {
			replicas = *statefulSet.Spec.Replicas
		}
		workloads = append(workloads, workloadTarget{
			APIVersion: "apps/v1",
			Kind:       "StatefulSet",
			Namespace:  statefulSet.Namespace,
			Name:       statefulSet.Name,
			Labels:     statefulSet.Spec.Template.Labels,
			Replicas:   replicas,
			PodSpec:    statefulSet.Spec.Template.Spec,
		})
	}
	for _, daemonSet := range daemonSets {
		workloads = append(workloads, workloadTarget{
			APIVersion: "apps/v1",
			Kind:       "DaemonSet",
			Namespace:  daemonSet.Namespace,
			Name:       daemonSet.Name,
			Labels:     daemonSet.Spec.Template.Labels,
			Replicas:   2,
			PodSpec:    daemonSet.Spec.Template.Spec,
		})
	}
	return workloads
}

func missingPodSecurityLabel(namespace corev1.Namespace) bool {
	enforce := namespace.Labels["pod-security.kubernetes.io/enforce"]
	return enforce != "baseline" && enforce != "restricted"
}

func privilegedPodSecurityLabel(namespace corev1.Namespace) bool {
	return namespace.Labels["pod-security.kubernetes.io/enforce"] == "privileged"
}

func ingressHasWildcardHost(ingress networkingv1.Ingress) bool {
	for _, rule := range ingress.Spec.Rules {
		if strings.Contains(rule.Host, "*") {
			return true
		}
	}
	return false
}

func workloadHasPDB(workload workloadTarget, pdbs []policyv1.PodDisruptionBudget) bool {
	workloadLabels := labels.Set(workload.Labels)
	for _, pdb := range pdbs {
		if pdb.Namespace != workload.Namespace || pdb.Spec.Selector == nil {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err == nil && selector.Matches(workloadLabels) {
			return true
		}
	}
	return false
}

func podSpecMissingResources(podSpec corev1.PodSpec) bool {
	for _, container := range allContainers(podSpec) {
		if !hasResource(container.Resources.Requests, corev1.ResourceCPU) || !hasResource(container.Resources.Requests, corev1.ResourceMemory) || !hasResource(container.Resources.Limits, corev1.ResourceCPU) || !hasResource(container.Resources.Limits, corev1.ResourceMemory) {
			return true
		}
	}
	return false
}

func podSpecMissingReadiness(podSpec corev1.PodSpec) bool {
	for _, container := range podSpec.Containers {
		if container.ReadinessProbe == nil {
			return true
		}
	}
	return false
}

func podSpecMissingLiveness(podSpec corev1.PodSpec) bool {
	for _, container := range podSpec.Containers {
		if container.LivenessProbe == nil {
			return true
		}
	}
	return false
}

func podSpecUsesMutableImages(podSpec corev1.PodSpec) bool {
	for _, container := range allContainers(podSpec) {
		if imageIsMutable(container.Image) {
			return true
		}
	}
	return false
}

func imageIsMutable(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	repositoryPart := image
	if slash := strings.LastIndex(repositoryPart, "/"); slash >= 0 {
		repositoryPart = repositoryPart[slash+1:]
	}
	if !strings.Contains(repositoryPart, ":") {
		return true
	}
	tag := repositoryPart[strings.LastIndex(repositoryPart, ":")+1:]
	return tag == "" || tag == "latest"
}

func podSpecMissingRuntimeHardening(podSpec corev1.PodSpec) bool {
	return !podSpecRunsAsNonRoot(podSpec) || !podSpecHasSeccomp(podSpec) || !podSpecDropsAllCapabilities(podSpec)
}

func podSpecRunsAsNonRoot(podSpec corev1.PodSpec) bool {
	if podSpec.SecurityContext != nil && podSpec.SecurityContext.RunAsNonRoot != nil && *podSpec.SecurityContext.RunAsNonRoot {
		return true
	}
	for _, container := range allContainers(podSpec) {
		if container.SecurityContext == nil || container.SecurityContext.RunAsNonRoot == nil || !*container.SecurityContext.RunAsNonRoot {
			return false
		}
	}
	return len(allContainers(podSpec)) > 0
}

func podSpecHasSeccomp(podSpec corev1.PodSpec) bool {
	if podSpec.SecurityContext != nil && seccompIsRestricted(podSpec.SecurityContext.SeccompProfile) {
		return true
	}
	for _, container := range allContainers(podSpec) {
		if container.SecurityContext == nil || !seccompIsRestricted(container.SecurityContext.SeccompProfile) {
			return false
		}
	}
	return len(allContainers(podSpec)) > 0
}

func seccompIsRestricted(profile *corev1.SeccompProfile) bool {
	return profile != nil && (profile.Type == corev1.SeccompProfileTypeRuntimeDefault || profile.Type == corev1.SeccompProfileTypeLocalhost)
}

func podSpecDropsAllCapabilities(podSpec corev1.PodSpec) bool {
	for _, container := range allContainers(podSpec) {
		if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil || !capabilityListContains(container.SecurityContext.Capabilities.Drop, "ALL") {
			return false
		}
	}
	return len(allContainers(podSpec)) > 0
}

func podSpecAllowsHostAccess(podSpec corev1.PodSpec) bool {
	if podSpec.HostNetwork || podSpec.HostPID || podSpec.HostIPC {
		return true
	}
	for _, volume := range podSpec.Volumes {
		if volume.HostPath != nil {
			return true
		}
	}
	return false
}

func podSpecHasElevatedCapabilities(podSpec corev1.PodSpec) bool {
	for _, container := range allContainers(podSpec) {
		if container.SecurityContext == nil {
			continue
		}
		if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			return true
		}
		if container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
			return true
		}
		if container.SecurityContext.Capabilities != nil && len(container.SecurityContext.Capabilities.Add) > 0 {
			return true
		}
	}
	return false
}

func podSpecUsesDefaultServiceAccount(podSpec corev1.PodSpec) bool {
	return podSpec.ServiceAccountName == "" || podSpec.ServiceAccountName == "default"
}

func podSpecAutomountsServiceAccountToken(podSpec corev1.PodSpec) bool {
	return podSpec.AutomountServiceAccountToken == nil || *podSpec.AutomountServiceAccountToken
}

func allContainers(podSpec corev1.PodSpec) []corev1.Container {
	containers := make([]corev1.Container, 0, len(podSpec.InitContainers)+len(podSpec.Containers))
	containers = append(containers, podSpec.InitContainers...)
	containers = append(containers, podSpec.Containers...)
	return containers
}

func capabilityListContains(capabilities []corev1.Capability, value string) bool {
	for _, capability := range capabilities {
		if strings.EqualFold(string(capability), value) {
			return true
		}
	}
	return false
}

func podRestarting(pod corev1.Pod) bool {
	for _, status := range append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...) {
		if status.RestartCount >= 3 {
			return true
		}
	}
	return false
}

func networkPolicyHasBroadIngress(policy networkingv1.NetworkPolicy) bool {
	for _, rule := range policy.Spec.Ingress {
		if len(rule.From) == 0 {
			return true
		}
	}
	return false
}

func networkPolicyHasBroadEgress(policy networkingv1.NetworkPolicy) bool {
	for _, rule := range policy.Spec.Egress {
		if len(rule.To) == 0 {
			return true
		}
	}
	return false
}

func roleAllowsSecretRead(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if ruleResourceMatches(rule.Resources, "secrets") && ruleVerbMatches(rule.Verbs, "get", "list", "watch") {
			return true
		}
	}
	return false
}

func roleAllowsPrivilegeEscalation(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if ruleVerbMatches(rule.Verbs, "bind", "escalate", "impersonate") {
			return true
		}
		if ruleResourceMatches(rule.Resources, "pods/exec") && ruleVerbMatches(rule.Verbs, "create") {
			return true
		}
	}
	return false
}

func ruleResourceMatches(resources []string, targets ...string) bool {
	for _, resource := range resources {
		if resource == "*" {
			return true
		}
		for _, target := range targets {
			if resource == target {
				return true
			}
		}
	}
	return false
}

func ruleVerbMatches(verbs []string, targets ...string) bool {
	for _, verb := range verbs {
		if verb == "*" {
			return true
		}
		for _, target := range targets {
			if verb == target {
				return true
			}
		}
	}
	return false
}

func bindingHasUnauthenticatedSubject(binding rbacv1.ClusterRoleBinding) bool {
	for _, subject := range binding.Subjects {
		if subject.Kind == rbacv1.GroupKind && (subject.Name == "system:unauthenticated" || subject.Name == "system:authenticated") {
			return true
		}
		if subject.Kind == rbacv1.UserKind && subject.Name == "system:anonymous" {
			return true
		}
	}
	return false
}

func nodeReady(node corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func nodeUnderPressure(node corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		switch condition.Type {
		case corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure:
			if condition.Status == corev1.ConditionTrue {
				return true
			}
		}
	}
	return false
}

func newClusterFinding(now time.Time, id, source, title string, severity core.Severity, resource core.ResourceRef, evidence string, fixability core.Fixability, remediationState string, riskScore int, recommendation string) core.Finding {
	finding := core.Finding{
		ID:       id,
		Source:   source,
		Title:    title,
		Severity: severity,
		Evidence: []core.Evidence{
			{
				Summary:    title,
				Details:    evidence,
				SourceID:   "kubeathrix/live-scan",
				ObservedAt: now,
			},
		},
		Resources:         []core.ResourceRef{resource},
		BlastRadius:       evidence,
		Fixability:        fixability,
		Status:            core.FindingOpen,
		CorrelationGroup:  strings.Trim(safeID(resource.Namespace, resource.Kind, resource.Name), "-"),
		RiskScore:         riskScore,
		RemediationState:  remediationState,
		RecommendedAction: recommendation,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	finding.CorrelationKeys.Namespace = resource.Namespace
	if resource.Kind == "Namespace" {
		finding.CorrelationKeys.Namespace = resource.Name
	}
	switch resource.Kind {
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod":
		finding.CorrelationKeys.Workload = resource.Namespace + "/" + resource.Kind + "/" + resource.Name
	case "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "ServiceAccount":
		finding.CorrelationKeys.Identity = resource.String()
	case "Service", "Ingress", "NetworkPolicy":
		finding.CorrelationKeys.NetworkExposure = resource.String()
	}
	return finding
}

func complianceControls(inventory core.ClusterInventory, findings []core.Finding) []core.ComplianceControl {
	hasFinding := func(prefix string) bool {
		for _, finding := range findings {
			if strings.HasPrefix(finding.ID, prefix) {
				return true
			}
		}
		return false
	}
	return []core.ComplianceControl{
		control("KA-K8S-001", "Kubernetes baseline", "Workloads define CPU and memory requests and limits", core.SeverityMedium, hasFinding("scan-workload-resources-"), "Resource requirements bound scheduler and noisy-neighbor risk."),
		control("KA-K8S-002", "Kubernetes baseline", "Namespaces use ResourceQuota and LimitRange guardrails", core.SeverityMedium, hasFinding("scan-namespace-governance-"), fmt.Sprintf("%d quotas and %d limit ranges observed.", inventory.ResourceQuotas, inventory.LimitRanges)),
		control("KA-K8S-003", "NSA/CISA Kubernetes", "Namespaces use NetworkPolicy isolation", core.SeverityMedium, hasFinding("scan-networkpolicy-"), fmt.Sprintf("%d network policies observed.", inventory.NetworkPolicies)),
		control("KA-K8S-004", "Pod Security Standards", "Privileged container behavior is absent", core.SeverityHigh, hasFinding("scan-privileged-pod-"), "Privileged and privilege-escalating containers should be removed or explicitly approved."),
		control("KA-K8S-005", "RBAC least privilege", "RBAC avoids wildcard, secret-read, escalation, and cluster-admin grants", core.SeverityHigh, hasFinding("scan-role-wildcard-") || hasFinding("scan-clusterrole-wildcard-") || hasFinding("scan-role-secret-read-") || hasFinding("scan-clusterrole-secret-read-") || hasFinding("scan-role-rbac-escalation-") || hasFinding("scan-clusterrole-rbac-escalation-") || hasFinding("scan-clusteradmin-binding-") || hasFinding("scan-rolebinding-clusteradmin-"), "Broad permissions increase blast radius after compromise."),
		control("KA-K8S-006", "Reliability baseline", "Replicated workloads have disruption protection", core.SeverityLow, hasFinding("scan-workload-pdb-"), fmt.Sprintf("%d PodDisruptionBudgets observed.", inventory.PodDisruptionBudgets)),
		control("KA-K8S-007", "Pod Security Standards", "Namespaces enforce baseline or restricted Pod Security", core.SeverityMedium, hasFinding("scan-namespace-pod-security-"), "Pod Security labels define namespace-level admission posture."),
		control("KA-K8S-008", "Workload hardening", "Workloads avoid host access and elevated capabilities", core.SeverityHigh, hasFinding("scan-workload-host-access-") || hasFinding("scan-workload-capabilities-") || hasFinding("scan-workload-runtime-hardening-"), "Restricted runtime settings reduce container breakout blast radius."),
		control("KA-K8S-009", "Supply chain baseline", "Workloads avoid mutable image tags", core.SeverityMedium, hasFinding("scan-workload-image-mutability-"), "Mutable image references make deployed code harder to prove and reproduce."),
		control("KA-K8S-010", "Traffic exposure", "Ingress and Service exposure are explicitly controlled", core.SeverityHigh, hasFinding("scan-public-service-") || hasFinding("scan-nodeport-service-") || hasFinding("scan-externalip-service-") || hasFinding("scan-ingress-tls-") || hasFinding("scan-ingress-wildcard-"), "External traffic paths should be reviewed and encrypted."),
		control("KA-K8S-011", "Cluster health", "Nodes, pods, and PVCs are ready", core.SeverityMedium, hasFinding("scan-node-not-ready-") || hasFinding("scan-node-pressure-") || hasFinding("scan-pod-failed-") || hasFinding("scan-pod-pending-") || hasFinding("scan-pvc-not-bound-"), "Readiness and binding failures reduce resilience."),
	}
}

func control(id, framework, title string, severity core.Severity, failed bool, evidence string) core.ComplianceControl {
	status := "pass"
	if failed {
		status = "fail"
	}
	return core.ComplianceControl{
		ID:        id,
		Framework: framework,
		Title:     title,
		Status:    status,
		Severity:  severity,
		Evidence:  evidence,
	}
}

func countControls(controls []core.ComplianceControl, status string) int {
	count := 0
	for _, control := range controls {
		if control.Status == status {
			count++
		}
	}
	return count
}

func resourcesScanned(inventory core.ClusterInventory) int {
	return inventory.Nodes + inventory.Namespaces + inventory.Pods + inventory.Deployments + inventory.StatefulSets + inventory.DaemonSets + inventory.Services + inventory.Ingresses + inventory.Jobs + inventory.ConfigMaps + inventory.ServiceAccounts + inventory.Roles + inventory.RoleBindings + inventory.ClusterRoles + inventory.ClusterRoleBindings + inventory.NetworkPolicies + inventory.ResourceQuotas + inventory.LimitRanges + inventory.PersistentVolumeClaims + inventory.PodDisruptionBudgets + inventory.HorizontalPodAutoscalers
}

func readyNodeCount(nodes []corev1.Node) int {
	count := 0
	for _, node := range nodes {
		for _, condition := range node.Status.Conditions {
			if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
				count++
				break
			}
		}
	}
	return count
}

func podPhaseCount(pods []corev1.Pod, phase corev1.PodPhase) int {
	count := 0
	for _, pod := range pods {
		if pod.Status.Phase == phase {
			count++
		}
	}
	return count
}

func deploymentReplicas(deployment appsv1.Deployment) int32 {
	if deployment.Spec.Replicas == nil {
		return 1
	}
	return *deployment.Spec.Replicas
}

func deploymentMissingResources(deployment appsv1.Deployment) bool {
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if !hasResource(container.Resources.Requests, corev1.ResourceCPU) || !hasResource(container.Resources.Requests, corev1.ResourceMemory) || !hasResource(container.Resources.Limits, corev1.ResourceCPU) || !hasResource(container.Resources.Limits, corev1.ResourceMemory) {
			return true
		}
	}
	return false
}

func deploymentMissingReadiness(deployment appsv1.Deployment) bool {
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.ReadinessProbe == nil {
			return true
		}
	}
	return false
}

func deploymentHasPDB(deployment appsv1.Deployment, pdbs []policyv1.PodDisruptionBudget) bool {
	deploymentLabels := labels.Set(deployment.Spec.Template.Labels)
	for _, pdb := range pdbs {
		if pdb.Namespace != deployment.Namespace || pdb.Spec.Selector == nil {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err == nil && selector.Matches(deploymentLabels) {
			return true
		}
	}
	return false
}

func podHasPrivilegedContainer(pod corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext == nil {
			continue
		}
		if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			return true
		}
		if container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
			return true
		}
	}
	return false
}

func hasResource(resources corev1.ResourceList, name corev1.ResourceName) bool {
	quantity, ok := resources[name]
	return ok && !quantity.IsZero()
}

func hasWildcardRule(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if containsWildcard(rule.Verbs) || containsWildcard(rule.APIGroups) || containsWildcard(rule.Resources) {
			return true
		}
	}
	return false
}

func containsWildcard(values []string) bool {
	for _, value := range values {
		if value == "*" {
			return true
		}
	}
	return false
}

func isSystemNamespace(namespace string) bool {
	return namespace == "" ||
		namespace == "kube-system" ||
		namespace == "kube-public" ||
		namespace == "kube-node-lease" ||
		namespace == "local-path-storage"
}

func isBuiltinClusterRole(name string) bool {
	if strings.HasPrefix(name, "system:") || strings.HasPrefix(name, "eks:") || strings.HasPrefix(name, "kubeadm:") {
		return true
	}
	switch name {
	case "admin", "cluster-admin", "edit", "view":
		return true
	default:
		return false
	}
}

func isBuiltinClusterRoleBinding(name string) bool {
	return strings.HasPrefix(name, "system:") || strings.HasPrefix(name, "eks:") || strings.HasPrefix(name, "kubeadm:")
}

func safeID(parts ...string) string {
	joined := strings.ToLower(strings.Join(parts, "-"))
	var builder strings.Builder
	lastDash := false
	for _, r := range joined {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			builder.WriteRune('-')
			lastDash = true
		}
	}
	return strings.Trim(builder.String(), "-")
}
