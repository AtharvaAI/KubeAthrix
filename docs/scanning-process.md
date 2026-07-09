# Cluster Scanning Process

KubeAthrix now runs a production-oriented read-only posture scan from the API service account. The scanner does not read Secret payloads and does not execute shell or `kubectl`; it compares Kubernetes object specs, status, labels, and RBAC rules against built-in controls.

## Phase Comparison

| Area | Initial scanner | Current scanner |
| --- | --- | --- |
| Inventory | Counted core resources for the dashboard | Counts nodes, pods, namespaces, workloads, services, ingresses, jobs, config maps, Secret metadata, RBAC, NetworkPolicies, quotas, limits, PVCs, PDBs, HPAs, and events |
| Namespace policy | Missing quotas, limits, NetworkPolicies | Adds Pod Security admission labels and privileged namespace detection |
| Workloads | Missing resources, readiness, PDBs, privileged pods | Adds liveness, mutable images, host access, default ServiceAccounts, token automount, seccomp, runAsNonRoot, dropped capabilities, elevated capabilities |
| Network | LoadBalancer and NodePort services | Adds externalIPs, Ingress TLS gaps, wildcard hosts, broad NetworkPolicy ingress/egress |
| RBAC | Wildcard roles and cluster-admin bindings | Adds Secret read access, bind/escalate/impersonate/pods/exec paths, namespace cluster-admin bindings, public subjects |
| Health | Basic pod and node counts | Adds not-ready nodes, resource pressure, failed/pending pods, restart loops, unbound PVCs |

## Scan Groups

1. Cluster health
   - Node Ready condition and memory/disk/PID pressure.
   - Pod Failed/Pending phases and repeated restarts.
   - PVC binding status and StorageClass presence.

2. Network exposure
   - Service `LoadBalancer`, `NodePort`, and `externalIPs`.
   - Ingress without TLS and wildcard host routing.
   - NetworkPolicy rules with unrestricted ingress or egress peers.

3. Namespace guardrails
   - Missing `ResourceQuota`.
   - Missing `LimitRange`.
   - Missing `pod-security.kubernetes.io/enforce`.
   - Privileged Pod Security enforcement.

4. Workload hardening
   - Missing CPU/memory requests and limits.
   - Missing readiness and liveness probes.
   - Missing matching PodDisruptionBudget for replicated workloads.
   - Mutable image references such as `latest` or no tag.
   - Default ServiceAccount usage and ServiceAccount token automount.
   - Host network/PID/IPC or `hostPath` volumes.
   - Privilege escalation, privileged containers, added Linux capabilities.
   - Missing runAsNonRoot, seccomp, or drop-all capabilities.

5. RBAC posture
   - Wildcard verbs, resources, or API groups.
   - Secret read access.
   - `bind`, `escalate`, `impersonate`, and `pods/exec` paths.
   - RoleBinding or ClusterRoleBinding to `cluster-admin`.
   - Bindings to broad public subjects.

## Safety Boundary

The scanner emits normalized `Finding` objects and dashboard controls only. Remediation still goes through typed plans, server-side dry-run, approvals, and controller gates.
