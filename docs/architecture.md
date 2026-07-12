# KubeAthrix Architecture

KubeAthrix is a Kubernetes-native control plane for finding, explaining, fixing, verifying, and proving cluster security and reliability improvements.

## Planes

KubeAthrix is split into three planes:

- Evidence plane: collects findings from bundled engines, Kubernetes resources, policy reports, runtime adapters, and future cloud IAM adapters.
- Decision plane: correlates related signals into a single issue graph and creates bounded remediation plans.
- Execution plane: applies only typed controller actions after dry-run validation and, when required, approval.

Version 0.2.0 has no model invocation path. Planning, correlation, risk scoring, and typed action selection are deterministic. Provider-reference settings are inventory-only for a future gateway and are never resolved or called.

## Components

- Console: React UI for dashboard, findings, fix center, runtime view, policy view, experiments, audit, integrations, and settings.
- API: Go REST service for normalized findings, remediation plans, approvals, audit events, integrations, and model-provider configuration.
- Operator: controller-runtime manager that observes KubeAthrix CRDs and updates workflow status.
- Postgres: queryable history and dashboard storage path. The API can run with in-memory workflow state, but scanner and workflow responses still come from live API paths.
- Helm chart: internal-service install with CRDs, RBAC, services, deployments, Postgres, and bundled engine dependencies.

## Core Engines

External engines are disabled by default. Trivy Operator, Kyverno, and
Kubescape can be installed through pinned conditional Helm dependencies;
Falco, Tetragon, Chaos Mesh, and LitmusChaos require separately reviewed
installations and privileges before their integration values are enabled.

Opt-in Chaos Mesh execution uses Postgres as the durable run state and
Kubernetes as the execution observation source. The API persists preflight and
approval before creation, labels every resource with its run ID, and a
restart-safe reconciler owns polling, duration enforcement, deletion, abort,
approval expiry, and recovery verification. A request never becomes `running`
until Kubernetes acknowledges creation, and never becomes `succeeded` until
the object is absent and selected pods are Running and Ready.

## Safety Boundary

Remediations are classified into:

- Tier A: deterministic low-risk fixes.
- Tier B: dry-run then gated reliability and rollout fixes.
- Tier C: human-approved security-impacting changes.
- Tier D: never autonomous actions such as broad admission rollout, destructive delete, or node configuration mutation.

Controllers and API validation enforce this boundary by using typed action names and target references rather than command strings.
