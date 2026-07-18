# AI assist and agent

KubeAthrix remains deterministic by default. The native scanner, risk scoring,
typed action selection, dry-run, approval gates, controller execution,
verification, rollback metadata, and audit trail do not require a model.

When `ai.enabled=true`, the API can call an OpenAI-compatible chat-completions
endpoint to attach structured decision support to remediation previews and
created plans. Model output is advisory only: it can explain evidence, impact,
confidence, and safety notes, but it cannot add executable actions, run
`kubectl`, bypass approvals, or change the versioned typed action catalog.

When `ai.agent.enabled=true`, the API also starts a background OpenAI-backed
agent. The agent continuously watches live Kubernetes evidence, adapter
findings, and persisted finding state. On each event cycle it can create an
AI-enriched typed plan, persist the plan to workflow CRDs, request safe Tier A
execution when explicitly enabled, and send webhook notifications.

## Enable AI Assist

Create a Kubernetes Secret that contains the provider API key:

```powershell
kubectl -n kubeathrix create secret generic kubeathrix-ai `
  --from-literal=api-key="<provider-api-key>"
```

Enable the advisor with Helm:

```powershell
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

Use the provider endpoint and model that your organization has approved. Keep
the API key in Kubernetes Secret material; do not put raw keys in the browser,
the provider-reference settings API, Git, values files, or logs.

For production, bind the advisor to approved data and network boundaries in a
values file:

```yaml
ai:
  endpoint: https://ai-gateway.example.com/v1/chat/completions
  endpointHostAllowlist:
    - ai-gateway.example.com
  excludedSources:
    - internal-sensitive-adapter
  excludedNamespaces:
    - regulated-workloads
  maxInputBytes: 65536
  maxOutputTokens: 700
  circuitBreakerThreshold: 3
  circuitBreakerCooldown: 30s
```

HTTPS is required by default, including after redirects, and hostname matches
are exact. `allowInsecureHTTP` exists only for isolated local testing. The
hostname allowlist is an application check; the chart NetworkPolicy still
permits TCP/443 for the Kubernetes API, OIDC, telemetry, and the provider. Use
an organization-controlled egress gateway or a stricter site NetworkPolicy
when destination enforcement must also happen at the network layer.

Unless excluded, eligible findings from every configured source and authorized
namespace can be sent to the provider. KubeAthrix sends a bounded projection of
finding identity, title, severity/risk, target references, redacted evidence,
and the already-selected typed plan. It does not send raw managed-resource
specs, labels, annotations, condition messages, credentials, or rollback
payloads. Consecutive provider failures open a bounded circuit breaker while
the deterministic plan remains available.

## Enable the Always-on Agent

The agent is opt-in and fail-closed. It requires `ai.enabled=true`, a non-empty
`ai.model`, and a Secret-backed API key. It starts inside the API deployment and
keeps running until the pod stops.

```powershell
helm upgrade --install kubeathrix ./charts/kubeathrix `
  -n kubeathrix --create-namespace `
  --reuse-values `
  --set ai.enabled=true `
  --set ai.existingSecret=kubeathrix-ai `
  --set ai.apiKeyKey=api-key `
  --set ai.model=gpt-5 `
  --set ai.agent.enabled=true `
  --set ai.agent.autoPlan=true `
  --set ai.agent.autoExecuteTierA=false
```

Set `ai.agent.autoExecuteTierA=true` only after reviewing the cluster policy.
That option requests execution only for non-approval Tier A typed actions. Tier
B/C/D plans, RBAC changes, NetworkPolicy proposals, admission changes,
destructive deletes, node configuration, and proposal-only actions remain
approval-gated or notify-only. The operator still performs Kubernetes
server-side dry-run and respects `remediation.mutationEnabled`.

Optional webhook notifications:

```powershell
kubectl -n kubeathrix create secret generic kubeathrix-notify `
  --from-literal=url="https://example.invalid/kubeathrix"

helm upgrade --install kubeathrix ./charts/kubeathrix `
  -n kubeathrix --reuse-values `
  --set notifications.webhooks.enabled=true `
  --set notifications.webhooks.existingSecret=kubeathrix-notify `
  --set notifications.webhooks.urlKey=url
```

## Safety Contract

- AI output is parsed as strict JSON with no unknown fields. Required text,
  confidence, a typed action identifier (or `human_review`), and evidence-source
  citations are validated against the projected input before it is returned.
- Validated evidence-source citations are surfaced in bounded safety notes.
- AI output is stored as `plan.ai` / `preview.ai` decision support metadata.
- The always-on agent uses OpenAI analysis to enrich and prioritize typed plans,
  not to invent write primitives.
- The executable plan remains the deterministic `actions[]` selected by
  KubeAthrix.
- Execution still requires catalog validation, server-side dry-run, approval
  where required, operator reconciliation, verification, rollback metadata, and
  audit events.
- The agent can request execution only for non-approval Tier A plans when
  `ai.agent.autoExecuteTierA=true`.
- Allowlisted Kubernetes-managed external-resource CRDs are read-only context.
  They never become model tools or executable action types.
- Managed IAM recommendations are always human-in-the-loop and proposal-only.
  Accepted changes must be made at the owning controller CR/claim or GitOps
  repository, never by patching generated live state.
- Managed-resource detectors create a review action, not an inferred patch. An
  exact managed-resource change is accepted only as a separately supplied,
  fully validated proposal artifact and still has no direct executor.
- KubeAthrix does not send Kubernetes or cloud credentials to the provider,
  read core `Secret` payloads, or use direct cloud APIs for this feature.
- If the provider is unavailable or returns invalid JSON, the API logs a warning
  and falls back to the deterministic plan.
