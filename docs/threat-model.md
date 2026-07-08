# Threat Model

KubeAthrix handles sensitive cluster evidence, remediation plans, and model-provider references. The MVP assumes a single cluster and a trusted platform team namespace.

## Primary Risks

- Prompt injection through manifests, logs, alerts, ticket text, or scanner output.
- Excessive agency if a model can trigger broad cluster writes.
- Secret exposure through Helm values, logs, browser payloads, or audit records.
- RBAC escalation through over-broad service accounts.
- Unsafe remediation that breaks availability or weakens policy.

## Controls

- The model produces structured explanations and plan proposals only.
- The API accepts typed remediation actions and rejects unknown JSON fields on sensitive settings.
- Raw model API keys are not part of the public settings schema.
- Helm creates separate service accounts for API, console, and operator.
- Mutating behavior is gated by risk tier and approval policy.
- Tier D actions are never autonomous.
- Audit events are produced for plan creation and approval decisions.

## Out Of Scope For v0.1

- Multi-cluster tenancy.
- Full runtime containment.
- Signed release provenance enforcement.
- Provider-specific IAM enforcement.

These are represented as extension points, not silent promises.
