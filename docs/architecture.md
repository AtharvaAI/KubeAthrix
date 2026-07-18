# KubeAthrix Architecture

KubeAthrix is a Kubernetes-native control plane for finding, explaining, fixing, verifying, and proving cluster security and reliability improvements.

## Planes

KubeAthrix is split into three planes:

- Evidence plane: collects findings from bundled engines, Kubernetes resources, policy reports, runtime adapters, and explicitly allowlisted Kubernetes-managed external-resource CRDs.
- Decision plane: correlates related signals into a single issue graph and creates bounded remediation plans.
- Execution plane: applies only typed controller actions after dry-run validation and, when required, approval.

Planning, correlation, risk scoring, and typed action selection are deterministic by default. Optional AI decision support can annotate remediation previews and created plans with structured explanations, impact, confidence, and safety notes. The optional always-on AI agent watches live evidence and adapter findings, creates AI-enriched typed plans, sends notifications, and can request execution only for explicitly enabled non-approval Tier A actions. AI cannot add executable actions or bypass the typed action catalog, dry-run, approval, verification, rollback, and audit controls.

## Components

- Console: React UI for dashboard, findings, fix center, runtime view, policy view, experiments, audit, integrations, and settings.
- API: Go REST service for normalized findings, remediation plans, approvals, audit events, integrations, model-provider configuration, and the optional OpenAI-backed agent loop.
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

## Kubernetes-Managed External Resources

An administrator can opt one API instance into read-only discovery of exact
custom-resource plurals through `api.managedExternalResources`. The chart
rejects empty allowlists, the core API group, and wildcard groups, versions, or
resources. The generated ClusterRole adds only `list` for each named API
group/resource pair. Kubernetes RBAC cannot constrain this by served version,
and namespaced entries are listable across every namespace; the collector still
calls only the configured version, and API responses are filtered by the
authenticated KubeAthrix namespace scope. Cluster reads stay inside the API's
typed collector, and the model provider receives no Kubernetes credentials.

This boundary covers resources represented and reconciled through Kubernetes,
such as approved Crossplane or cloud-controller CRDs, in the single cluster
connected to that API instance. It does not inventory resources that exist only
in AWS, Azure, GCP, or another external system, and it never calls those
providers' APIs directly. Core `Secret` objects and Secret payloads remain
outside the discovery path.

Managed IAM is human-in-the-loop only. AI may correlate evidence and produce a
cited proposal, but it cannot patch an IAM CRD or request IAM execution. The
reviewer must apply an accepted change to the authoritative source: the owning
claim/custom resource for controller-managed resources, or the upstream
repository for GitOps-managed resources. Generated or observed child resources
must not be patched to bypass that source of truth.

Detectors create the domain-specific `review_managed_resource_finding` Tier C
action, which records internal approval and source ownership without inventing
a patch. The stricter `propose_managed_resource_change` catalog contract accepts
only a complete RFC 6902 `/spec` proposal with source UID, resourceVersion,
generation, before/after hashes, and rollback metadata. Discovery never
fabricates those values, and neither action has a direct executor or cloud API
path.

## Safety Boundary

Remediations are classified into:

- Tier A: deterministic low-risk fixes.
- Tier B: dry-run then gated reliability and rollout fixes.
- Tier C: human-approved security-impacting changes.
- Tier D: never autonomous actions such as broad admission rollout, destructive delete, or node configuration mutation.

Controllers and API validation enforce this boundary by using typed action names and target references rather than command strings.
