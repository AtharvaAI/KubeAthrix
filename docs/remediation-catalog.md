# Remediation Catalog

KubeAthrix uses typed actions instead of arbitrary commands. Every action must declare a target resource, risk tier, dry-run requirement, verification steps, and rollback steps.

## v0.2 Action Families

| Family | Example action | Tier | Default approval |
| --- | --- | --- | --- |
| Resource governance | `apply_resource_governance` creates ResourceQuota and LimitRange defaults | A | Not required |
| Namespace safety | `patch_pod_security_labels` prepares Pod Security admission labels | A | Not required unless namespace is privileged |
| Workload resources | `patch_workload_resources` prepares CPU/memory defaults and image-pin guidance | B | Required |
| Workload reliability | `patch_workload_probes` and `create_pdb` prepare probes and PDBs | B | Required |
| Network control | `propose_network_policy` generates default-deny or explicit allow proposals | C | Required |
| Security hardening | `propose_security_hardening` prepares RBAC, network, and image trust patches | C | Required |
| Runtime triage | `explain_only` documents suspicious runtime activity | D | Required, notify-only |

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
- Typed diff and write mode.
- Verification and rollback steps.
- Approval requirement and categories.
- Evidence bundle export path.
