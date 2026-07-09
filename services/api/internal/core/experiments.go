package core

func DefaultChaosExperiments() []ChaosExperiment {
	return []ChaosExperiment{
		{
			ID:          "pod-delete-resilience",
			Name:        "Pod delete resilience",
			Category:    "availability",
			Target:      "Deployment pods",
			Status:      "ready",
			Engine:      "litmus",
			Description: "Deletes one matching pod and verifies the workload recovers through its controller, probes, and disruption budget.",
			Preflight: []string{
				"Target deployment has at least two replicas.",
				"Readiness probes and a PodDisruptionBudget exist.",
				"Recent rollout is healthy before the experiment starts.",
			},
			Manifest: `apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: kubeathrix-pod-delete
  namespace: "{{TARGET_NAMESPACE}}"
spec:
  appinfo:
    appns: "{{TARGET_NAMESPACE}}"
    applabel: "{{TARGET_LABEL_KEY}}={{TARGET_LABEL_VALUE}}"
    appkind: deployment
  chaosServiceAccount: litmus-admin
  experiments:
    - name: pod-delete`,
		},
		{
			ID:          "network-latency-service",
			Name:        "Service network latency",
			Category:    "network",
			Target:      "Service-backed pods",
			Status:      "ready",
			Engine:      "chaos-mesh",
			Description: "Injects bounded latency into selected service pods to verify timeout, retry, and SLO behavior.",
			Preflight: []string{
				"Target selector resolves to non-system pods.",
				"Experiment duration and latency are bounded.",
				"Abort and rollback hooks are available.",
			},
			Manifest: `apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: kubeathrix-service-latency
  namespace: "{{TARGET_NAMESPACE}}"
spec:
  action: delay
  mode: one
  selector:
    namespaces:
      - "{{TARGET_NAMESPACE}}"
    labelSelectors:
      "{{TARGET_LABEL_KEY}}": "{{TARGET_LABEL_VALUE}}"
  delay:
    latency: "150ms"
    correlation: "25"
    jitter: "20ms"
  duration: "2m"`,
		},
		{
			ID:          "cpu-stress-workload",
			Name:        "Workload CPU stress",
			Category:    "capacity",
			Target:      "Deployment pods",
			Status:      "ready",
			Engine:      "chaos-mesh",
			Description: "Applies temporary CPU pressure to verify autoscaling, limits, and alerting behavior.",
			Preflight: []string{
				"Target pods have CPU requests and limits.",
				"HorizontalPodAutoscaler or runbook owner is defined.",
				"Duration is short enough for a safe maintenance window.",
			},
			Manifest: `apiVersion: chaos-mesh.org/v1alpha1
kind: StressChaos
metadata:
  name: kubeathrix-cpu-stress
  namespace: "{{TARGET_NAMESPACE}}"
spec:
  mode: one
  selector:
    namespaces:
      - "{{TARGET_NAMESPACE}}"
    labelSelectors:
      "{{TARGET_LABEL_KEY}}": "{{TARGET_LABEL_VALUE}}"
  stressors:
    cpu:
      workers: 1
      load: 70
  duration: "2m"`,
		},
		{
			ID:          "dns-failure-readiness",
			Name:        "DNS failure readiness",
			Category:    "dependency",
			Target:      "Application namespace",
			Status:      "ready",
			Engine:      "chaos-mesh",
			Description: "Blocks a controlled DNS query pattern to prove dependency handling and fallback behavior.",
			Preflight: []string{
				"Experiment is scoped to one namespace.",
				"Target application has health signals visible to KubeAthrix.",
				"Rollback simply deletes the generated chaos object.",
			},
			Manifest: `apiVersion: chaos-mesh.org/v1alpha1
kind: DNSChaos
metadata:
  name: kubeathrix-dns-failure
  namespace: "{{TARGET_NAMESPACE}}"
spec:
  action: error
  mode: one
  patterns:
    - "dependency.internal"
  selector:
    namespaces:
      - "{{TARGET_NAMESPACE}}"
    labelSelectors:
      "{{TARGET_LABEL_KEY}}": "{{TARGET_LABEL_VALUE}}"
  duration: "90s"`,
		},
	}
}
