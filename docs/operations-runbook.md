# Operations Runbook

## Health Checks

```powershell
kubectl -n kubeathrix get pods
kubectl -n kubeathrix get crds | Select-String kubeathrix
kubectl -n kubeathrix port-forward svc/kubeathrix-api 8081:8080
curl http://127.0.0.1:8081/health/ready
```

## Common Tasks

List normalized findings:

```powershell
curl -H "Authorization: Bearer $env:KUBEATHRIX_TOKEN" http://127.0.0.1:8081/api/findings
```

Create a remediation plan:

```powershell
curl -X POST http://127.0.0.1:8081/api/remediation-plans `
  -H "Authorization: Bearer $env:KUBEATHRIX_TOKEN" `
  -H 'Content-Type: application/json' `
  -d '{"findingId":"finding-missing-probes-pdb"}'
```

Approve a gated action:

```powershell
curl -X POST http://127.0.0.1:8081/api/approvals/approval-plan-finding-missing-probes-pdb-001/approve `
  -H "Authorization: Bearer $env:KUBEATHRIX_TOKEN" `
  -H 'Content-Type: application/json' `
  -d '{"reason":"validated in staging"}'
```

## Backup And Restore

- Back up Postgres using the organization standard database backup process.
- Back up KubeAthrix CRDs with `kubectl get <resource> -A -o yaml`.
- Restore CRDs before restoring API history so workflow references remain resolvable.

## Incident runbooks

### Failed or stale scan

Read integration health, setup gaps, permissions, supported API versions, and
last-seen time. Confirm the source CRDs contain recent reports, then inspect API
adapter errors. Do not toggle an engine flag to force a healthy status.

### Failed remediation or verification

Inspect RemediationPlan/Run status, per-action messages, operator events and
logs, the server-side dry-run response, and target rollout/readback state. Fix
the underlying target or submit a new plan; never edit status to succeeded.

### Failed rollback

Stop further execution, retain the run and snapshot ConfigMap, inspect the
rollback action status, collision/ownership checks, and target events. Restore
from the recorded snapshot manually only under the incident change process,
then record evidence. Do not delete the snapshot until recovery is proven.

### Expired approval or exception

Create a new approval/exception with a fresh owner, reason, and expiration.
Never extend timestamps directly in Postgres or CRD status. Confirm previously
suppressed findings reopen when no other active exception covers them.

### Database failure

The readiness endpoint fails. Stop mutating workflows, fail over or restore
Postgres, verify `kubeathrix_schema_migrations`, compare workflow CRDs to API
responses, and only then resume traffic. See [operations.md](operations.md).

### Engine failure

Treat existing evidence as stale, restore CRD/report generation and API read
permission, and wait for actual last-seen data to advance. KubeAthrix does not
substitute environment flags for evidence.

### Failed or stuck chaos run

Read `/api/experiment-runs/{id}` and the matching `chaos.*` audit events before
touching the cluster. Confirm the object carries
`security.kubeathrix.io/chaos-run=<run-id>`; never delete a same-named object
without that ownership label. For `execution_requested`, fix API discovery or
admission errors before the third bounded retry. After creation, inspect Chaos
Mesh `status.conditions` and experiment events: KubeAthrix does not transition
to `running` without `AllInjected=True`, and requests cleanup if that proof is
absent after 30 seconds. For `running` past its cleanup
deadline, use the authenticated abort endpoint with a reason; it performs an
idempotent owned-resource delete. For `verifying_recovery`, inspect matching
pods and restore them to Running and Ready before the two-minute recovery
deadline. A missing resource before the requested duration is a failed run,
not a success. Abort is terminal only after object absence and Ready-pod
recovery are verified. If Postgres was restored, compare the persistent run state and
ownership label before restarting reconciliation.

## Upgrade And Rollback

- Run `helm template` and `helm lint` before upgrade.
- Confirm CRD schema changes are backward compatible.
- Upgrade core engines in a maintenance window if admission behavior changes.
- Roll back with `helm rollback` and restore database backups only if API migrations were applied.
