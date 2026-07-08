# Operations Runbook

## Health Checks

```powershell
kubectl -n kubeathrix get pods
kubectl -n kubeathrix get crds | Select-String kubeathrix
kubectl -n kubeathrix port-forward svc/kubeathrix-api 8081:8080
curl http://127.0.0.1:8081/api/health
```

## Common Tasks

List normalized findings:

```powershell
curl http://127.0.0.1:8081/api/findings
```

Create a remediation plan:

```powershell
curl -X POST http://127.0.0.1:8081/api/remediation-plans `
  -H 'Content-Type: application/json' `
  -d '{"findingId":"finding-missing-probes-pdb","requestedBy":"platform-sre"}'
```

Approve a gated action:

```powershell
curl -X POST http://127.0.0.1:8081/api/approvals/approval-plan-finding-missing-probes-pdb-001/approve `
  -H 'Content-Type: application/json' `
  -d '{"actor":"sre-lead","reason":"validated in staging"}'
```

## Backup And Restore

- Back up Postgres using the organization standard database backup process.
- Back up KubeAthrix CRDs with `kubectl get <resource> -A -o yaml`.
- Restore CRDs before restoring API history so workflow references remain resolvable.

## Upgrade And Rollback

- Run `helm template` and `helm lint` before upgrade.
- Confirm CRD schema changes are backward compatible.
- Upgrade core engines in a maintenance window if admission behavior changes.
- Roll back with `helm rollback` and restore database backups only if API migrations were applied.
