# KubeAthrix

KubeAthrix is a production-shaped Kubernetes AI defender and reliability control plane. It normalizes signals from security engines, correlates them into operator-friendly findings, gates typed remediations through approvals, and keeps every action auditable.

The MVP is intentionally controller-driven: AI can explain, rank, and propose plans, but cluster writes flow through typed API and operator paths. There is no raw shell or arbitrary `kubectl` execution path.

## Repository Layout

- `apps/console` - React and TypeScript operator console.
- `services/api` - Go REST API, live cluster scanner, Postgres adapter seam, OpenAPI contract.
- `operator` - Go controller-runtime manager for KubeAthrix workflow CRDs.
- `charts/kubeathrix` - Helm chart, CRDs, RBAC, service exposure, engine dependencies.
- `docs` - Architecture, install, threat model, remediation catalog, model provider, and runbook docs.

## Local Development

```powershell
pnpm install
pnpm --filter @kubeathrix/console dev
go test ./services/api/... ./operator/...
```

Run the API locally:

```powershell
cd services/api
go run ./cmd/kubeathrix-api
```

The API starts with empty workflow state and enriches responses from the live cluster scanner when kubeconfig or in-cluster credentials are available. Set `DATABASE_URL` to activate the Postgres adapter path.

## Helm Install Shape

<!-- x-release-please-start-version -->
```powershell
helm dependency update charts/kubeathrix
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix --create-namespace
kubectl -n kubeathrix port-forward svc/kubeathrix-console 8080:80
```
<!-- x-release-please-end -->

The chart keeps UI/API access internal by default and bundles Trivy Operator, Kyverno, and Kubescape through Helm dependencies controlled by values.

## Docker Images

Release images are published to one Docker Hub repository with component-prefixed tags:

<!-- x-release-please-start-version -->
```powershell
docker pull docker.io/prashantdey/kubeathrix:api-0.1.0
docker pull docker.io/prashantdey/kubeathrix:console-0.1.0
docker pull docker.io/prashantdey/kubeathrix:operator-0.1.0
```
<!-- x-release-please-end -->

See [docs/product-strategy.md](docs/product-strategy.md), [docs/scanning-process.md](docs/scanning-process.md), [docs/remediation-catalog.md](docs/remediation-catalog.md), [docs/docker-from-source.md](docs/docker-from-source.md), [docs/docker-images.md](docs/docker-images.md), and [docs/release-process.md](docs/release-process.md).
