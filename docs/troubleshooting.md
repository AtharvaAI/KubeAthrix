# Troubleshooting

## API will not start

Read the structured startup error. Secure mode requires a reachable HTTPS OIDC
issuer/client ID, Kubernetes workflow access, and a healthy database when
`DATABASE_URL` is set. The development bypass and in-memory workflow flags are
explicitly insecure and only for isolated demos.

## Console stays on authentication

Confirm `/auth/config`, the issuer discovery document, registered redirect URI,
PKCE support, browser CORS access to the token endpoint, token audience, roles,
and KubeAthrix scope claims. Tokens live only in browser session storage and are
cleared on expiry.

## Readiness fails

Check `/health/live`, then `/health/ready`, Postgres connectivity, OIDC discovery,
and API access to workflow CRDs. Inspect `kubectl -n kubeathrix logs` and events.

## Findings or integrations are empty

Read `/api/integrations` and each health endpoint. A Helm flag is not proof of
an integration; the API must discover a supported report resource and have
list/watch permission. Confirm report CRDs contain recent objects.

## Remediation does not advance

Inspect the RemediationPlan/Run/ApprovalRequest CRs, operator logs, action
catalog support, mutation gate, server-side dry-run error, snapshot ConfigMap,
and workload rollout status. Never manually mark a run succeeded.

See [operations-runbook.md](operations-runbook.md) for incident procedures.
