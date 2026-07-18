# FAQ

**Does KubeAthrix run arbitrary commands?** No. Direct execution is restricted
to versioned typed actions. Unsupported categories are proposal-only.

**Is AI required?** No. Planning and risk scoring are deterministic by default.
Optional AI decision support can explain typed plans when explicitly enabled,
but it cannot execute actions or bypass safety gates.

**Does enabling a scanner flag mean it is healthy?** No. Health is based on
discovering and querying a supported report API.

**Can KubeAthrix read Secret values?** The native inspector does not request
Secret objects. It detects risky Secret permissions from RBAC rules, and Trivy
exposed-secret findings deliberately omit matched secret material.

**Can it inspect cloud IAM and other external resources?** Only when an
administrator explicitly allowlists CRDs that represent those resources in the
single connected Kubernetes cluster. Access is read-only; KubeAthrix does not
call cloud APIs or read core Secret payloads. IAM remediation is proposal-only
and human-approved, and accepted changes must be made at the controller or
GitOps source of truth.

**Can it run chaos experiments?** Execution is disabled by default. An
explicitly configured Chaos Mesh installation can run only allowlisted,
namespace-scoped, selector-bounded experiments after durable preflight,
separate approval, and explicit execution. KubeAthrix owns cleanup and reports
success only after target recovery is observed.

**Why is mutation off by default?** Operators must review OIDC roles, RBAC,
namespaces, diffs, verification, and rollback policy before allowing writes.

**Is bundled Postgres production-ready?** It is a portable evaluation default.
Use managed external Postgres with TLS, backups, monitoring, and HA in production.
