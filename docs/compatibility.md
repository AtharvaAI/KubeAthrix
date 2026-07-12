# Compatibility matrix

| KubeAthrix | Kubernetes | Helm | Postgres | Report APIs |
| --- | --- | --- | --- | --- |
| 0.2.x | 1.28-1.34 | 3.14+ | 16 | Trivy Operator `aquasecurity.github.io/v1alpha1`; Kyverno `wgpolicyk8s.io/v1alpha2` and `openreports.io/v1alpha1`; Kubescape `spdx.softwarecomposition.kubescape.io/v1beta1` |

The CI Kind smoke test is the minimum installation proof. Managed Kubernetes
distributions may impose extra admission, storage, or network-policy rules.
CRDs use `v1alpha1`; back up CRs and Postgres before upgrades. Skipping minor
versions is not supported until an explicit upgrade test says otherwise.
