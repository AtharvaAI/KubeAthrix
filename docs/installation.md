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
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix `
  --dependency-update `
  --reset-values `
  --atomic --cleanup-on-fail --timeout 10m `
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
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix --create-namespace `
  --dependency-update `
  --reset-values `
  --atomic --cleanup-on-fail --timeout 10m `
  --set auth.insecureDevelopmentMode=true
kubectl -n kubeathrix port-forward svc/kubeathrix-console 8080:80
```
<!-- x-release-please-end -->

Use the same `helm upgrade --install` command for first install and upgrades.
`--dependency-update` removes the separate dependency step, `--reset-values`
lets new chart defaults such as image tags advance, and `--atomic` rolls back
the release if readiness does not complete before the timeout. Keep production
customizations in a values file and pass it with `-f` on the same command.

If you intentionally reuse mutable image tags, set `rollout.restartToken` to a
new value in the same command so Kubernetes creates a fresh ReplicaSet.

The demo bypass grants administrator access to every request and must not be
exposed outside an isolated local environment. Services remain `ClusterIP`.

On first install, an empty `postgres.storageClassName` uses the cluster's default StorageClass. Set it only when you need a specific class:

```powershell
--set postgres.storageClassName=<storage-class-name>
```

The bundled Postgres StatefulSet preserves its existing `volumeClaimTemplates`
during upgrades because Kubernetes does not allow those fields to be patched.
Changing storage class, access mode, or the claim template size after install is
a storage migration; use external managed Postgres for production.

The pinned Alpine Postgres image runs as UID/GID `70`. The chart repairs mounted
volume ownership during startup and then runs Postgres as that non-root user. If
you override `postgres.image`, set `postgres.uid` and `postgres.gid` to match the
image's `postgres` user.

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

### Opt-in Kubernetes-managed external resources

The API can inspect administrator-approved external-resource CRDs in its one
connected cluster. This feature is disabled by default and requires exact API
groups, versions, resource plurals, and scopes in a values file:

```yaml
api:
  managedExternalResources:
    enabled: true
    allowlist:
      - apiGroup: example.platform.io
        version: v1alpha1
        resources:
          - managedresources
        namespaced: true
      - apiGroup: iam.example.platform.io
        version: v1beta1
        resources:
          - roles
          - policies
        namespaced: false
```

Helm rejects an enabled empty allowlist, the core API group, and wildcard API
groups, versions, or resources. Each entry grants the API service account only
cluster-wide `list` on those API-group/resource plurals. Kubernetes RBAC cannot
restrict the grant to one served version, and `namespaced: true` still covers
all namespaces; the collector calls only the configured version and the API
filters responses by the authenticated namespace scope. Verify the CRD's actual
plural, served version, and scope before installing. Use separately maintained
namespace Roles/RoleBindings if the service account itself must not list every
namespace.

This setting does not enable direct AWS, Azure, GCP, or other provider API
access and does not discover resources that are absent from Kubernetes. It does
not grant access to core `Secret` objects or Secret payloads. The model receives
only redacted context selected by KubeAthrix, never Kubernetes or cloud
credentials.

The initial external-resource path is read-only and proposal-only. IAM changes
always require human review and explicit action at the source of truth. For a
controller-managed object, update the owning claim/custom resource rather than
its generated child. For Argo CD or Flux ownership, update the upstream Git
repository rather than patching live state; without a configured upstream
change path, stop at a reviewable proposal.

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

The chart defaults to image tags that match the chart release. Release Please
updates these defaults with the chart, so installing chart `<version>` runs the
same-version API, console, and operator images. Pin signed digests for
production deployments when you need immutable runtime inputs.

<!-- x-release-please-start-version -->
```yaml
image:
  api:
    repository: docker.io/prashantdey/kubeathrix
    tag: api-0.3.0
    pullPolicy: IfNotPresent
  console:
    repository: docker.io/prashantdey/kubeathrix
    tag: console-0.3.0
    pullPolicy: IfNotPresent
  operator:
    repository: docker.io/prashantdey/kubeathrix
    tag: operator-0.3.0
    pullPolicy: IfNotPresent
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

## Optional AI Assist and Agent

AI decision support is disabled by default. When enabled, it adds structured
explanations to remediation previews and plans; execution still uses only
catalog-validated typed actions with dry-run, approval, verification, rollback,
and audit controls.

```powershell
kubectl -n kubeathrix create secret generic kubeathrix-ai `
  --from-literal=api-key="<provider-api-key>"

helm upgrade --install kubeathrix ./charts/kubeathrix `
  -n kubeathrix --create-namespace `
  --reuse-values `
  --set ai.enabled=true `
  --set ai.provider=openai-compatible `
  --set ai.endpoint=https://api.openai.com/v1/chat/completions `
  --set ai.model=gpt-5 `
  --set ai.existingSecret=kubeathrix-ai `
  --set ai.apiKeyKey=api-key
```

To run the always-on AI agent, enable the agent gate as well:

```powershell
helm upgrade --install kubeathrix ./charts/kubeathrix `
  -n kubeathrix --create-namespace `
  --reuse-values `
  --set ai.enabled=true `
  --set ai.existingSecret=kubeathrix-ai `
  --set ai.model=gpt-5 `
  --set ai.agent.enabled=true `
  --set ai.agent.autoPlan=true `
  --set ai.agent.autoExecuteTierA=false
```

`autoExecuteTierA=true` only requests execution for non-approval Tier A typed
actions. Riskier plans remain approval-gated or proposal-only.

Production AI configuration should require HTTPS and normally set
`ai.endpointHostAllowlist`, plus `ai.excludedSources` and
`ai.excludedNamespaces` for evidence that must not leave the cluster. The
request is centrally redacted and bounded by `ai.maxInputBytes`; responses are
bounded by `ai.maxOutputTokens`, strictly validated, and protected by a
consecutive-failure circuit breaker. With empty exclusion lists, eligible
findings from every configured source and namespace may be sent to the approved
provider. The hostname check is application-level, so use an egress gateway or
site-specific NetworkPolicy when the network must enforce the destination too.

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
