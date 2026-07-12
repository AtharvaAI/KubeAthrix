# Installation Guide

## Prerequisites

- Kubernetes 1.28 or newer.
- Helm 3.
- A namespace for KubeAthrix.
- Optional external Postgres for production.
- Optional OIDC provider for production login.

## Secure install

The chart requires OIDC settings unless the explicitly insecure development
bypass is enabled. Create any confidential-client secret before installing:

```powershell
kubectl create namespace kubeathrix
kubectl -n kubeathrix create secret generic kubeathrix-oidc `
  --from-literal=client-secret='<OIDC client secret>'
helm dependency build charts/kubeathrix
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix `
  --set auth.oidc.issuerURL=https://identity.example.com/realms/platform `
  --set auth.oidc.clientID=kubeathrix `
  --set auth.oidc.existingSecret=kubeathrix-oidc `
  --set api.clusterID=production-us-east-1
```

JWT validation itself does not require the client secret; omit
`auth.oidc.existingSecret` for a public OIDC client. Configure the role and scope
claims described in [authentication.md](authentication.md) before giving users
access.

## Isolated demo install

The chart creates the `kubeathrix` release namespace and, when the bundled Kubescape engine is enabled, also creates the `kubescape` namespace required by the Kubescape subchart.

For fresh KubeAthrix installs, the Kyverno CRD migration hook is disabled by default through `kyverno.crds.migration.enabled=false`. Enable it only when intentionally upgrading an existing Kyverno install that needs CRD migration.

<!-- x-release-please-start-version -->
```powershell
helm dependency update charts/kubeathrix
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix --create-namespace `
  --set auth.insecureDevelopmentMode=true
kubectl -n kubeathrix port-forward svc/kubeathrix-console 8080:80
```
<!-- x-release-please-end -->

The demo bypass grants administrator access to every request and must not be
exposed outside an isolated local environment. Services remain `ClusterIP`.

On EKS, the bundled Postgres StatefulSet uses the `gp2` storage class by default. Override it when your cluster uses a different storage class:

```powershell
--set postgres.storageClassName=<storage-class-name>
```

The chart sets `PGDATA=/var/lib/postgresql/data/pgdata` so Postgres initializes in a subdirectory of the mounted EBS volume rather than the mount root.

## Live Cluster Scanner

The API enables the read-only cluster inspector by default. It uses the API service account in-cluster, or your local kubeconfig when you run the API outside Kubernetes.

The scanner populates the console dashboard with nodes, pods, namespaces, workloads, services, ingresses, jobs, config maps, RBAC objects, NetworkPolicies, ResourceQuotas, LimitRanges, PVCs, PDBs, HPAs, and recent events. It does not request Secret objects.

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
  insecureDevelopmentMode: false
  oidc:
    enabled: true
    issuerURL: https://issuer.example.com
    clientID: kubeathrix
    existingSecret: kubeathrix-oidc

service:
  type: ClusterIP
```

The current preview chart references versioned Docker Hub tags. A production
release is not declared until the release pipeline also publishes and verifies
image digests, signatures, SBOMs, and provenance.

<!-- x-release-please-start-version -->
```yaml
image:
  api:
    repository: docker.io/prashantdey/kubeathrix
    tag: api-0.2.0
  console:
    repository: docker.io/prashantdey/kubeathrix
    tag: console-0.2.0
  operator:
    repository: docker.io/prashantdey/kubeathrix
    tag: operator-0.2.0
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

The console includes bounded Chaos Mesh templates plus a custom YAML path. The default mode performs validation only and never creates a resource. Validation requires an explicit namespace allowlist, an exact namespace selector, a non-empty label selector, `one` or `fixed` mode (maximum three affected targets), no more than 20 candidate pods, healthy targets, and a duration of at most five minutes.

To enable persistent execution, first install a compatible Chaos Mesh control plane and use durable Postgres. Then enable the engine, execution gate, and exact non-system namespaces:

```powershell
--set chaos.execution.enabled=true \
--set engines.chaosMesh.enabled=true \
--set 'chaos.namespaceAllowlist={sandbox}'
```

An operator request performs live target discovery and Kubernetes server-side dry-run, then persists `pending_approval`. A different approver must approve with a reason, and execution remains a separate operator action. KubeAthrix labels the created resource with its run ID and keeps the state at `execution_requested` until Chaos Mesh reports `AllInjected=True`; object creation alone is not reported as `running`. Injection must be proven within 30 seconds. KubeAthrix then deletes the object after the bounded duration or on abort and reports `succeeded` only after the resource is gone and all matching pods are Running and Ready. Approvals expire after 15 minutes; creation retries are capped at three; cleanup has a deadline; recovery is retried for two minutes. Every transition is audited and survives API restart through Postgres.

For small EKS clusters, keep heavyweight bundled engines disabled until the node group has enough pod capacity:

```powershell
helm upgrade --install kubeathrix ./charts/kubeathrix `
  -n kubeathrix --create-namespace `
  --set engines.trivyOperator.enabled=false `
  --set engines.kyverno.enabled=false `
  --set engines.kubescape.enabled=false
```
