# Authentication and authorization

KubeAthrix fails closed by default. Every `/api/*` route requires an OIDC bearer
token; only `/health/live` and `/health/ready` are intentionally anonymous for
Kubernetes probes.

## OIDC token validation

The API loads the provider's OpenID discovery document and JWKS at startup. It
accepts only signed `RS256` or `ES256` JWTs and validates the signature, issuer,
audience, expiry, not-before time, issued-at time, and subject. Non-loopback
issuers and JWKS endpoints must use HTTPS. Signing keys are cached and refreshed
after their advertised cache lifetime or when an unknown key ID is received.

Configure the API with:

```text
OIDC_ISSUER_URL=https://identity.example.com/realms/platform
OIDC_CLIENT_ID=kubeathrix
KUBEATHRIX_CLUSTER_ID=production-us-east-1
```

The token may provide roles through `kubeathrix_roles`, `roles`, `groups`, or
`realm_access.roles`. Group values may be `viewer`, `kubeathrix-viewer`, or
`kubeathrix:viewer` (and the equivalent values for the other roles).

| Role | Access |
| --- | --- |
| `viewer` | Read findings in granted scopes. |
| `operator` | Viewer access plus plan preview/creation, approved remediation execution, and chaos request/execute/abort actions. |
| `approver` | Operator access plus approval decisions; a principal cannot approve or reject its own chaos request. |
| `administrator` | All scopes plus model-provider settings. |

The current hierarchy lets an approver perform operator actions. Administrator
always implies every role and scope.

## Cluster and namespace scopes

Use `kubeathrix_clusters` and `kubeathrix_namespaces` array claims:

```json
{
  "kubeathrix_roles": ["operator"],
  "kubeathrix_clusters": ["production-us-east-1"],
  "kubeathrix_namespaces": ["payments", "platform"]
}
```

Equivalent OAuth scope values are
`kubeathrix:cluster:production-us-east-1` and
`kubeathrix:namespace:payments`. `*` grants all values in that scope and should
be limited to administrators. Cluster dashboards, audit streams, integration
health, evidence bundles, and chaos templates require a cluster scope. A user
with namespace scopes only receives findings whose complete resource set is in
their allowed namespaces.

KubeAthrix derives requesters, approvers, executors, and audit actors from the
validated token subject. Client JSON fields named `actor` or `requestedBy` are
rejected.

## Development bypass

`KUBEATHRIX_INSECURE_DEV_AUTH=true` disables OIDC and treats every request as an
administrator with access to every cluster and namespace. The Helm equivalent
is `auth.insecureDevelopmentMode=true`. This bypass is for isolated local demos
only; never use it with an Ingress, LoadBalancer, shared cluster, or production
data.

## OIDC client secrets

JWT validation does not require a client secret. If a confidential OIDC client
is used by an authentication proxy or future server-side login flow, provide
the secret through a pre-existing Kubernetes Secret:

```yaml
auth:
  oidc:
    enabled: true
    issuerURL: https://identity.example.com/realms/platform
    clientID: kubeathrix
    existingSecret: kubeathrix-oidc
    clientSecretKey: client-secret
```

The chart sources `OIDC_CLIENT_SECRET` from that Secret; it is not stored in a
ConfigMap, API payload, database row, browser state, or log. The current API
does not use the value for JWT validation, so omit it for public clients.
