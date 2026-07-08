# KubeAthrix

KubeAthrix is a production-shaped Kubernetes AI defender and reliability control plane. It normalizes signals from security engines, correlates them into operator-friendly findings, gates typed remediations through approvals, and keeps every action auditable.

The MVP is intentionally controller-driven: AI can explain, rank, and propose plans, but cluster writes flow through typed API and operator paths. There is no raw shell or arbitrary `kubectl` execution path.

## Repository Layout

- `apps/console` - React and TypeScript operator console.
- `services/api` - Go REST API, demo seed data, Postgres adapter seam, OpenAPI contract.
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

The API defaults to seeded demo data. Set `DATABASE_URL` to activate the Postgres adapter path.

## Helm Install Shape

```powershell
helm dependency update charts/kubeathrix
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix --create-namespace
kubectl -n kubeathrix port-forward svc/kubeathrix-console 8080:80
```

The chart keeps UI/API access internal by default and bundles Trivy Operator, Kyverno, and Kubescape through Helm dependencies controlled by values.
