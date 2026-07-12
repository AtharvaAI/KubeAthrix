package core

func DefaultChaosExperiments() []ChaosExperiment {
	return []ChaosExperiment{
		{
			ID:          "network-latency-service",
			Name:        "Service network latency",
			Category:    "network",
			Target:      "Service-backed pods",
			Status:      "preflight_default_execution_opt_in",
			Engine:      "chaos-mesh",
			Description: "Validates a bounded latency run for selected service pods. Explicitly configured installations persist approval, execution, cleanup, and recovery state.",
			Preflight: []string{
				"Target selector resolves to non-system pods.",
				"Experiment duration and latency are bounded.",
				"Execution requires durable persistence, a separate approver, and an explicit operator request.",
			},
			Manifest: `apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: kubeathrix-service-latency
  namespace: "{{TARGET_NAMESPACE}}"
spec:
  action: delay
  direction: to
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
			Status:      "preflight_default_execution_opt_in",
			Engine:      "chaos-mesh",
			Description: "Validates bounded CPU pressure. Execution-enabled installations clean up the resource and verify target pod recovery.",
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
			Status:      "preflight_default_execution_opt_in",
			Engine:      "chaos-mesh",
			Description: "Validates a scoped DNS-failure run with an opt-in persistent execution and recovery lifecycle.",
			Preflight: []string{
				"Experiment is scoped to one namespace.",
				"Target application has health signals visible to KubeAthrix.",
				"Execution requires durable persistence, a separate approver, and an explicit operator request.",
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
