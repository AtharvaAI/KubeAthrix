# Product Strategy

KubeAthrix is positioned as a Kubernetes-native safety control plane for platform and SRE teams. It does not replace scanners, policy engines, runtime detectors, GitOps tools, or cost platforms. It sits above them as the trusted workflow layer that normalizes evidence, plans bounded remediation, gates execution, verifies outcomes, and preserves audit proof.

## Product Wedge

The first wedge is guarded remediation:

- Normalize findings from built-in scans and external engines into one operator queue.
- Generate strict typed remediation plans with evidence citations and prompt/evidence hashes.
- Expose exact typed diffs and proposed manifests before execution.
- Require approvals for Tier B/C/D actions.
- Allow only narrow low-risk Tier A controller writes in the first executor.
- Export evidence bundles for findings, plans, runs, and audit events.

## Competitive Shape

| Area | Common tools | KubeAthrix role |
| --- | --- | --- |
| AI diagnosis | K8sGPT, Komodor | Explain and rank evidence, but keep execution typed and gated. |
| Posture scanning | Trivy, Kubescape, Wiz, Snyk | Normalize scanner output into correlated findings and proof workflows. |
| Policy | Kyverno, Gatekeeper | Generate policy proposals and track policy evidence instead of replacing admission engines. |
| Runtime | Falco, Tetragon, Datadog | Correlate runtime alerts with workload, RBAC, image, and network posture. |
| Remediation | Robusta, Komodor, Datadog Bits | Provide auditable, approval-aware typed remediation with rollback metadata. |
| Cost/reliability | CAST AI, Fairwinds | Start with resource/probe/PDB guardrails; add Prometheus rightsizing later. |
| GitOps/platform | Argo CD, Crossplane | Prepare PR-ready manifests for higher-risk changes and add cloud/IAM context later. |

## Implemented MVP+ Capabilities

- Durable Postgres workflow tables for findings, plans, approvals, runs, audit events, integrations, and settings.
- Plan preview, typed diff, execution request, evidence bundle, finding grouping, and integration health API endpoints.
- Typed action catalog v1 covering resource governance, Pod Security labels, workload resources, probes, PDBs, network policy proposals, and explain-only triage.
- Operator reconciliation for remediation plans and runs.
- Narrow real controller execution for Tier A `apply_resource_governance`.
- Console updates for safe fixes, verified fixes, risk reduced, evidence freshness, typed diff, evidence bundle summaries, and integration readiness.

## Deliberate Boundaries

- No raw shell, SSH, or generated `kubectl` execution path.
- No autonomous destructive deletes.
- No autonomous broad admission, network, RBAC, node, or control-plane mutation.
- Higher-risk remediation remains approval-gated and proposal-first until explicit executors and rollback policies are implemented.
