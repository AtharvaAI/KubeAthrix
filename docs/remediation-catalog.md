# Remediation Catalog

KubeAthrix uses typed actions instead of arbitrary commands. Every action must declare a target resource, risk tier, dry-run requirement, verification steps, and rollback steps.

## v0.1 Action Families

| Family | Example action | Tier | Default approval |
| --- | --- | --- | --- |
| Resource governance | Apply ResourceQuota and LimitRange defaults | A | Not required |
| Workload reliability | Add probes, PDBs, topology spread hints | B | Required |
| Security hardening | Prepare RBAC, network, and image trust patches | C | Required |
| Runtime triage | Explain suspicious shell or binary activity | D | Required, notify-only |

## Non-Negotiable Guardrails

- No destructive deletes as autonomous actions.
- No broad admission policy rollout without human approval.
- No node or control-plane configuration mutation in v0.1.
- No shell, SSH, or generated `kubectl` execution path.
- Every write path must support server-side dry-run first.

## Acceptance Criteria

Every remediation plan must show:

- Source finding and affected resources.
- Root cause.
- Typed actions.
- Risk tier.
- Dry-run result.
- Verification and rollback steps.
- Approval requirement and categories.
