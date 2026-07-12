# Deprecation policy

Stable API or configuration behavior will be deprecated for at least one minor
release before removal. The deprecation appears in the changelog, documentation,
logs where practical, and compatibility matrix. Security vulnerabilities may
require faster removal; the release notes will explain the exception.

Alpha CRD fields may evolve, but upgrades preserve stored objects where
possible. Destructive migrations require backup, explicit operator action, and
rollback instructions. Unsupported typed actions are rejected rather than
silently translated.
