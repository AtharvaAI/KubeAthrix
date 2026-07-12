# Contributing

Thank you for improving KubeAthrix. By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md) and license your contribution under
Apache-2.0.

1. Open an issue for behavioral, API, CRD, RBAC, or security-model changes.
2. Fork the repository and keep each pull request focused.
3. Preserve secure defaults. New mutations require a typed catalog entry,
   server-side dry-run, exact diff, verification, rollback, and tests.
4. Run `make verify` and update documentation and the OpenAPI contract.
5. Include tests that prove states such as succeeded, verified, and resolved
   are backed by observed cluster state.

Use Conventional Commit-style titles (`feat:`, `fix:`, `docs:`, `chore:`).
Generated files, vendored secrets, raw scanner secret matches, and credentials
must never be committed. Maintainers may request a threat-model note for
security-sensitive changes. See [GOVERNANCE.md](GOVERNANCE.md) for review and
decision rules.
