# FAQ

**Does KubeAthrix run arbitrary commands?** No. Direct execution is restricted
to versioned typed actions. Unsupported categories are proposal-only.

**Is AI required?** No. Version 0.2.0 does not call a model. Planning and risk
scoring are deterministic.

**Does enabling a scanner flag mean it is healthy?** No. Health is based on
discovering and querying a supported report API.

**Can KubeAthrix read Secret values?** The native inspector does not request
Secret objects. It detects risky Secret permissions from RBAC rules, and Trivy
exposed-secret findings deliberately omit matched secret material.

**Can it run chaos experiments?** Execution is disabled by default. An
explicitly configured Chaos Mesh installation can run only allowlisted,
namespace-scoped, selector-bounded experiments after durable preflight,
separate approval, and explicit execution. KubeAthrix owns cleanup and reports
success only after target recovery is observed.

**Why is mutation off by default?** Operators must review OIDC roles, RBAC,
namespaces, diffs, verification, and rollback policy before allowing writes.

**Is bundled Postgres production-ready?** It is a portable evaluation default.
Use managed external Postgres with TLS, backups, monitoring, and HA in production.
