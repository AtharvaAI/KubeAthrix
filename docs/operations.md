# Operations, SLOs, backup, and capacity

## Signals

The API emits JSON logs with request IDs and exposes authenticated Prometheus
metrics at `/api/metrics`. The operator exposes controller-runtime metrics on
port 8080, health on 8081, and leader-election state through its lease and logs.
Liveness proves the process is alive; readiness checks repository and workflow
dependencies and, when execution is enabled, discovery of all three allowlisted
Chaos Mesh APIs.

Recommended initial SLOs are 99.9% API readiness, 99% finding ingestion within
five minutes of report creation, 99% operator reconciliation within two
minutes, and zero unverified success transitions. Alert on readiness failures,
5xx rate, reconciliation errors, stale integration data, expired approvals,
failed rollback, database saturation, leader-election churn, chaos creation
retries, cleanup past its deadline, and recovery-verification failures. The
`kubeathrix_chaos_runs{status=...}` gauge exposes persistent lifecycle counts.

## Capacity

Chart requests are evaluation starting points, not sizing guarantees. Measure
finding count, report size, API latency, controller queue depth, and database
growth. Raise API/operator memory before enabling several scanners on a large
cluster. The bundled single Postgres pod is not HA.

The chart defaults Deployment upgrades to `maxSurge=0` and `maxUnavailable=1`
so image updates can complete on small clusters without spare pod slots. This
keeps the one-command Helm upgrade path usable on constrained demos, but it can
briefly reduce component availability when a replica count is `1`. Increase
replicas and adjust `deploymentStrategy` for production availability targets.

## Postgres backup and restore

Use a managed external Postgres service in production. Test point-in-time
recovery and encrypt backups. For logical backup:

```powershell
pg_dump --format=custom --no-owner --dbname $env:DATABASE_URL --file kubeathrix.dump
pg_restore --clean --if-exists --no-owner --dbname $env:DATABASE_URL kubeathrix.dump
```

Stop API writers or use a transactionally consistent managed snapshot. Restore
into a new database, verify migration table and row counts, then switch the API
and observe readiness before retiring the old database.

## Optional OpenTelemetry tracing

Tracing is disabled by default. When enabled, the API accepts W3C `traceparent`
and baggage headers, creates HTTP server spans, returns `X-Trace-ID`, and sends
batched protobuf traces over OTLP/HTTP. Export initialization fails closed for
invalid endpoints, credentials embedded in URLs, invalid sampling, or insecure
transport that was not explicitly enabled.

```powershell
kubectl -n kubeathrix create secret generic kubeathrix-otel `
  --from-literal=headers='Authorization=Bearer REPLACE_ME'
helm upgrade kubeathrix ./charts/kubeathrix -n kubeathrix `
  --reuse-values `
  --set telemetry.tracing.enabled=true `
  --set telemetry.tracing.endpoint=https://otel.example.com:4318 `
  --set telemetry.tracing.existingSecret=kubeathrix-otel
```

For an in-cluster plaintext Collector, explicitly set
`telemetry.tracing.insecure=true` and ensure `telemetry.tracing.port` matches
the Collector service. Keep sampling low enough to respect backend capacity.
