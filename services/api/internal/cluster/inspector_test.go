package cluster

import (
	"strings"
	"testing"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestScanFindingsIncludesDetailedPostureChecks(t *testing.T) {
	now := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)
	privileged := true
	allowEscalation := true

	findings := scanFindings(
		now,
		[]corev1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
				Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
					{Type: corev1.NodeDiskPressure, Status: corev1.ConditionTrue},
				}},
			},
		},
		[]corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "payments"}}},
		[]corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "checkout-abc", Namespace: "payments"},
				Status: corev1.PodStatus{
					Phase: corev1.PodPending,
					ContainerStatuses: []corev1.ContainerStatus{
						{Name: "app", RestartCount: 4},
					},
				},
			},
		},
		[]corev1.Service{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "payments"},
				Spec: corev1.ServiceSpec{
					Type:        corev1.ServiceTypeLoadBalancer,
					ExternalIPs: []string{"203.0.113.10"},
				},
			},
		},
		[]appsv1.Deployment{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "payments"},
				Spec: appsv1.DeploymentSpec{
					Replicas: int32Ptr(2),
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app.kubernetes.io/name": "checkout"}},
						Spec: corev1.PodSpec{
							ServiceAccountName: "default",
							HostNetwork:        true,
							Volumes: []corev1.Volume{
								{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run"}}},
							},
							Containers: []corev1.Container{
								{
									Name:  "app",
									Image: "nginx:latest",
									SecurityContext: &corev1.SecurityContext{
										Privileged:               &privileged,
										AllowPrivilegeEscalation: &allowEscalation,
									},
								},
							},
						},
					},
				},
			},
		},
		nil,
		nil,
		[]networkingv1.Ingress{{ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "payments"}, Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{Host: "*.example.com"}}}}},
		[]corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "payments"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}},
		nil,
		[]networkingv1.NetworkPolicy{{ObjectMeta: metav1.ObjectMeta{Name: "open", Namespace: "payments"}, Spec: networkingv1.NetworkPolicySpec{Ingress: []networkingv1.NetworkPolicyIngressRule{{}}, Egress: []networkingv1.NetworkPolicyEgressRule{{}}}}},
		nil,
		nil,
		[]rbacv1.Role{{ObjectMeta: metav1.ObjectMeta{Name: "secret-reader", Namespace: "payments"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}}}},
		[]rbacv1.RoleBinding{{ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: "payments"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"}}},
		[]rbacv1.ClusterRole{{ObjectMeta: metav1.ObjectMeta{Name: "exec-all"}, Rules: []rbacv1.PolicyRule{{Resources: []string{"pods/exec"}, Verbs: []string{"create"}}}}},
		[]rbacv1.ClusterRoleBinding{{ObjectMeta: metav1.ObjectMeta{Name: "public-admin"}, Subjects: []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "system:unauthenticated"}}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"}}},
	)

	for _, prefix := range []string{
		"scan-node-not-ready-",
		"scan-node-pressure-",
		"scan-namespace-pod-security-",
		"scan-public-service-",
		"scan-externalip-service-",
		"scan-ingress-tls-",
		"scan-ingress-wildcard-",
		"scan-pvc-not-bound-",
		"scan-workload-image-mutability-",
		"scan-workload-host-access-",
		"scan-workload-capabilities-",
		"scan-networkpolicy-broad-ingress-",
		"scan-role-secret-read-",
		"scan-rolebinding-clusteradmin-",
		"scan-clusterrole-rbac-escalation-",
		"scan-clusterrolebinding-public-subject-",
	} {
		if !hasFindingPrefix(findings, prefix) {
			t.Fatalf("expected finding prefix %q in %#v", prefix, findings)
		}
	}
}

func hasFindingPrefix(findings []core.Finding, prefix string) bool {
	for _, finding := range findings {
		if strings.HasPrefix(finding.ID, prefix) {
			return true
		}
	}
	return false
}

func int32Ptr(value int32) *int32 {
	return &value
}
