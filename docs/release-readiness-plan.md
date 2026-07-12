# Release Readiness Plan

This document is the working implementation plan for moving KubeAthrix from the
0.2 architecture preview to a secure, community-ready release. A capability is
only marked complete when its behavior, tests, documentation, and release
claims agree.

## Baseline audit (2026-07-11)

The repository contains a React console, Go API, controller-runtime operator,
workflow CRDs, a Helm chart, and basic CI/release workflows. The pre-change unit
tests, console build, and Helm lint pass. Those checks do not establish release
readiness because the following blockers are present:

- API routes have no authentication or authorization middleware. OIDC settings
  are reported but not used, development authentication is enabled by default,
  and request bodies can choose audit actors.
- Remediation plans, approvals, and execution requests are stored in memory or
  JSONB but are not created as Kubernetes workflow objects by the API.
- Approval can mark an API run as succeeded before any cluster write or
  verification. The operator can apply a Tier A action merely because a plan's
  proposed dry-run flag is true; there is no separate execution request.
- Only ResourceQuota/LimitRange execution exists. Other catalog entries are
  rendered as proposals but their metadata is not a versioned validated action
  registry.
- Integration health is inferred from environment flags. There are no Trivy,
  Kyverno, or Kubescape report adapters.
- Findings are synthesized per check and grouped with string heuristics; there
  is no persisted ingestion/deduplication lifecycle or exception API.
- Model-provider settings are secret references only; there is no model
  gateway. Product behavior must remain deterministic and AI-optional.
- Chaos execution accepts allowlisted kinds but lacks target/namespace bounds,
  persistent approval, polling, abort, cleanup, and recovery verification.
- Helm defaults to development auth and bundled engines, has broad network
  rules, reads Secret objects through RBAC, has no pod security contexts or
  default resources, and uses an in-cluster database by default.
- Docker inputs and base images are not fully pinned, the console Dockerfile
  bypasses its lockfile, and releases have no SBOM, signing, chart OCI,
  checksums, or provenance gates.
- The project is missing the required license, community policies, templates,
  compatibility/deprecation documents, comprehensive runbooks, and an honest
  maturity-focused README.

## Phases

### 1. Security foundation — complete

- Fail closed unless OIDC JWT validation is configured or the explicit
  insecure development mode is enabled.
- Add viewer, operator, approver, and administrator roles; namespace and cluster
  scopes; and endpoint-level authorization.
- Derive all requester, approver, executor, and audit identities from the
  authenticated principal.
- Add request IDs, stable error envelopes, body limits, rate limits, security
  headers, HTTP timeouts, graceful shutdown, and separate liveness/readiness.
- Update Helm, console requests, OpenAPI, docs, and authentication tests.

### 2. Kubernetes workflow source of truth — complete

- Add an API Kubernetes workflow client for Finding, RemediationPlan,
  ApprovalRequest, and RemediationRun objects.
- Make plan creation idempotently create CRDs and treat their status as the
  authoritative runtime state; mirror it transactionally to Postgres.
- Separate proposal, approval, execution request, dry-run, application,
  verification, rollback, and terminal states.
- Add optimistic concurrency, recovery/reconciliation, restart, and failure
  tests.

### 3. Typed safe executors — complete

- Introduce a versioned action registry with resource support, risk,
  permissions, approval, dry-run, exact diff, verification, rollback,
  idempotency, and failure policy metadata.
- Implement and test ResourceQuota/LimitRange, Pod Security labels, workload
  resources, PDB creation, and explicitly configured probes.
- Keep network, RBAC, image, admission, node, Secret, and destructive actions
  proposal-only.

### 4. Evidence and integrations — complete

- Implement real Kubernetes adapters for Trivy Operator, Kyverno policy
  reports, Kubescape reports, and native posture data.
- Define non-claiming interfaces for future Falco and Tetragon sources.
- Persist normalized evidence with adapter health, permissions, supported
  versions, last-seen timestamps, correlation keys, and setup errors.
- Add explicit correlation rules, stable IDs, deduplication, lifecycle,
  exceptions, explainable scores, pagination, filters, sorting, and grouping.

### 5. Optional model gateway and bounded chaos — safely scoped

- Keep planning deterministic by default and label AI as optional until a
  provider passes structured-output, egress, injection, timeout, retry, cost,
  audit, and evaluation controls.
- Split chaos preflight from execution; add allowlists, system-namespace
  protection, selector/duration/blast-radius bounds, approvals, persistence,
  polling, abort, cleanup, TTL, recovery checks, and audit events.

The release deliberately implements no model invocation; model settings remain
reference inventory only. Chaos remains preflight-only by default. An explicit
execution profile now requires durable Postgres, a non-system namespace
allowlist, and a compatible Chaos Mesh API, then persists separate request,
approval, execution, polling, cleanup/abort, expiry, and recovery-verification
states with optimistic concurrency and audit events.

### 6. Platform and supply-chain hardening — complete pending hosted CI evidence

- Apply least privilege, pod security contexts, token automount rules, narrow
  NetworkPolicies, PDBs, resource defaults, portable storage, and an external
  Postgres production profile.
- Pin dependencies and release image digests, consume committed lockfiles, add
  OCI metadata, SBOMs, vulnerability/license/secret/SAST checks, signatures,
  checksums, attestations, chart OCI publishing, and version consistency gates.
- Add migration versioning, observability, backup/restore procedures, SLOs,
  alerts, and failure runbooks.

### 7. Community, UX, and release verification — local verification complete; hosted gates pending

- Add license, contribution/security/conduct/governance/support files, issue and
  PR templates, notices, roadmap, compatibility/deprecation/changelog policies,
  FAQ, troubleshooting, and uninstall/data-deletion guidance.
- Rewrite README and console copy around a guardrail and remediation control
  plane with an explicit maturity matrix and no simulated claims.
- Complete permission, stale/empty/failure, approval reason, live run,
  verification, rollback, exception, and evidence export UX.
- Run the full unit, race, integration, Postgres, envtest, Helm, kind/k3d,
  Playwright, security, packaging, upgrade, rollback, and release-gate suite.

## Release decision rule

The release remains **not ready** until every acceptance criterion in the
release brief has reproducible evidence. Features that cannot safely meet that
bar will be disabled or explicitly proposal-only and documented as limitations.

## Verification record (2026-07-12)

Local verification passed Go formatting, vet, tests, and the Linux race
detector; console typecheck, unit tests, and desktop/mobile Playwright tests,
including Authorization Code with PKCE against the real API; Postgres
migrations and restart persistence; real OTLP trace export; zero-warning
OpenAPI validation; CRD-inclusive Helm lint/render/package and schema checks;
Kubernetes 1.34 Kind install and chart tests; immutable Postgres filesystem
checks; Helm upgrade and exact-revision rollback with database credential
preservation; SAST, license and dependency checks; Go 1.25.12 vulnerability
analysis; secure-manifest scanning with zero high/critical misconfigurations;
and SPDX generation plus full-image scans with zero high or critical findings
for API, console, and operator.

The opt-in chaos execution path was also exercised against an isolated,
digest-pinned Kubernetes 1.33.4 Kind cluster with Chaos Mesh 2.8.3. A bounded
CPU stress run remained `execution_requested` until the controller reported
`AllInjected=True`, then completed owned-resource deletion and Ready-pod
recovery before `succeeded`. The same real lifecycle test is required by PR CI
and the pre-publish Kind gate.

The release is still **not published**. GitHub-hosted secret, manifest, image,
SBOM, signing, provenance, and publication jobs must pass and produce immutable
digests before the public-release decision changes to ready.
