# Community roadmap

## Shipped in 0.2.0

- Fail-closed OIDC/JWT authorization with namespace and cluster scopes.
- CRD-backed typed remediation workflow and safe direct executors.
- Trivy, Kyverno, Kubescape, and native posture ingestion.
- Explicit correlation, explainable risk, exceptions, rollback snapshots, and
  secure Helm defaults.
- Opt-in durable Chaos Mesh approval, execution, abort, cleanup, expiry, and
  recovery verification with preflight-only secure defaults.

## Next

- A separately reviewed model gateway. Until then provider records are
  inventory-only and planning is deterministic.
- GitOps proposal export and real Falco/Tetragon runtime adapters.
- More upgrade/e2e environments and performance testing at large cluster scale.

Roadmap items are intentions, not commitments. Track accepted work in public
issues and do not rely on an item until it appears in a signed release.
