# Installation Guide

## Prerequisites

- Kubernetes 1.28 or newer.
- Helm 3.
- A namespace for KubeAthrix.
- Optional external Postgres for production.
- Optional OIDC provider for production login.

## Development Install

The chart creates the `kubeathrix` release namespace and, when the bundled Kubescape engine is enabled, also creates the `kubescape` namespace required by the Kubescape subchart.

For fresh KubeAthrix installs, the Kyverno CRD migration hook is disabled by default through `kyverno.crds.migration.enabled=false`. Enable it only when intentionally upgrading an existing Kyverno install that needs CRD migration.

<!-- x-release-please-start-version -->
```powershell
helm dependency update charts/kubeathrix
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix --create-namespace
kubectl -n kubeathrix port-forward svc/kubeathrix-console 8080:80
```
<!-- x-release-please-end -->

The default install uses `ClusterIP` services and dev-mode auth. The API starts with empty workflow state, then populates dashboard and finding data from the live cluster scanner.

On EKS, the bundled Postgres StatefulSet uses the `gp2` storage class by default. Override it when your cluster uses a different storage class:

```powershell
--set postgres.storageClassName=<storage-class-name>
```

The chart sets `PGDATA=/var/lib/postgresql/data/pgdata` so Postgres initializes in a subdirectory of the mounted EBS volume rather than the mount root.

## Live Cluster Scanner

The API enables the read-only cluster inspector by default. It uses the API service account in-cluster, or your local kubeconfig when you run the API outside Kubernetes.

The scanner populates the console dashboard with nodes, pods, namespaces, workloads, services, ingresses, jobs, config maps, secret metadata counts, RBAC objects, NetworkPolicies, ResourceQuotas, LimitRanges, PVCs, PDBs, HPAs, and recent events.

It synthesizes findings across these scan groups:

- Cluster health: not-ready nodes, resource pressure, failed/pending pods, restart loops, unbound PVCs.
- Network exposure: LoadBalancer, NodePort, externalIPs, wildcard Ingress hosts, Ingress without TLS, broad NetworkPolicy ingress/egress.
- Namespace guardrails: missing ResourceQuota, missing LimitRange, missing or privileged Pod Security admission labels.
- Workload hardening: missing requests/limits, readiness/liveness probes, missing PDBs, mutable images, default ServiceAccounts, service account token automount, host access, elevated capabilities, missing seccomp/runAsNonRoot/drop-all capabilities.
- RBAC posture: wildcard roles, Secret read access, bind/escalate/impersonate/pods/exec paths, namespace and cluster-level cluster-admin bindings, public subjects.

Disable the inspector only for local no-cluster development:

```powershell
$env:KUBEATHRIX_CLUSTER_INSPECTOR="false"
```

Or through Helm:

```powershell
--set api.clusterInspector.enabled=false
```

After upgrading from an older chart, apply the new RBAC by running `helm upgrade` again before expecting live inventory counts in the console.

## Production-Oriented Values

```yaml
postgres:
  external: true
  host: postgres.example.internal
  port: 5432
  database: kubeathrix
  username: kubeathrix
  existingSecret: kubeathrix-postgres
  passwordKey: password

auth:
  devAuthEnabled: false
  oidc:
    enabled: true
    issuerURL: https://issuer.example.com
    clientID: kubeathrix
    existingSecret: kubeathrix-oidc

modelProviders:
  - name: primary
    type: openai-compatible
    model: gpt-5
    apiKeySecretRef:
      name: kubeathrix-llm
      key: api-key

service:
  type: ClusterIP
```

The default chart images come from the Docker Hub repository `docker.io/prashantdey/kubeathrix`.

<!-- x-release-please-start-version -->
```yaml
image:
  api:
    repository: docker.io/prashantdey/kubeathrix
    tag: api-0.1.0
  console:
    repository: docker.io/prashantdey/kubeathrix
    tag: console-0.1.0
  operator:
    repository: docker.io/prashantdey/kubeathrix
    tag: operator-0.1.0
```
<!-- x-release-please-end -->

## Access

KubeAthrix is internal by default:

```powershell
kubectl -n kubeathrix port-forward svc/kubeathrix-console 8080:80
kubectl -n kubeathrix port-forward svc/kubeathrix-api 8081:8080
```

Enable `ingress.enabled` only after OIDC and network policy are configured.

## Engine Toggles

```yaml
engines:
  trivyOperator:
    enabled: true
  kyverno:
    enabled: true
  kubescape:
    enabled: true
  falco:
    enabled: false
  tetragon:
    enabled: false
  chaosMesh:
    enabled: false
  litmus:
    enabled: false
```

## Chaos Experiments

The console includes predefined Litmus and Chaos Mesh experiment templates plus a custom YAML preflight path. By default, experiment run creation accepts a manifest and records a preflight-ready run without creating chaos resources.

After installing the matching chaos engine, enable the execution gate to let the API create only allowlisted chaos custom resources (`NetworkChaos`, `StressChaos`, `DNSChaos`, and `ChaosEngine`) after a Kubernetes server-side dry-run:

```powershell
--set chaos.execution.enabled=true
```

For small EKS clusters, keep heavyweight bundled engines disabled until the node group has enough pod capacity:

```powershell
helm upgrade --install kubeathrix ./charts/kubeathrix `
  -n kubeathrix --create-namespace `
  --set engines.trivyOperator.enabled=false `
  --set engines.kyverno.enabled=false `
  --set engines.kubescape.enabled=false
```
