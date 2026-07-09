# KubeAthrix Architecture

KubeAthrix is a Kubernetes-native control plane for finding, explaining, fixing, verifying, and proving cluster security and reliability improvements.

## Planes

KubeAthrix is split into three planes:

- Evidence plane: collects findings from bundled engines, Kubernetes resources, policy reports, runtime adapters, and future cloud IAM adapters.
- Decision plane: correlates related signals into a single issue graph and creates bounded remediation plans.
- Execution plane: applies only typed controller actions after dry-run validation and, when required, approval.

The AI model is part of the decision plane. It summarizes evidence and proposes structured plans, but it never receives raw cluster-admin credentials and never emits arbitrary shell commands for execution.

## Components

- Console: React UI for dashboard, findings, fix center, runtime view, policy view, experiments, audit, integrations, and settings.
- API: Go REST service for normalized findings, remediation plans, approvals, audit events, integrations, and model-provider configuration.
- Operator: controller-runtime manager that observes KubeAthrix CRDs and updates workflow status.
- Postgres: queryable history and dashboard storage path. The API can run with in-memory workflow state, but scanner and workflow responses still come from live API paths.
- Helm chart: internal-service install with CRDs, RBAC, services, deployments, Postgres, and bundled engine dependencies.

## Core Engines

The first install shape enables Trivy Operator, Kyverno, and Kubescape by default through Helm dependency conditions. Falco, Tetragon, Chaos Mesh, and LitmusChaos remain disabled until their Helm values and required privileges are enabled.

## Safety Boundary

Remediations are classified into:

- Tier A: deterministic low-risk fixes.
- Tier B: dry-run then gated reliability and rollout fixes.
- Tier C: human-approved security-impacting changes.
- Tier D: never autonomous actions such as broad admission rollout, destructive delete, or node configuration mutation.

Controllers and API validation enforce this boundary by using typed action names and target references rather than command strings.
