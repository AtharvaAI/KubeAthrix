# Changelog policy

`CHANGELOG.md` is generated from Conventional Commit-style pull request titles
by Release Please. User-visible behavior, security changes, breaking changes,
deprecations, and migration steps must be called out. Pure refactors may be
omitted. Security entries may be delayed until coordinated disclosure.

Release tags, chart `version`/`appVersion`, API OpenAPI version, package versions,
image labels, and component tags must match. CI rejects unformatted or invalid
artifacts; the release workflow produces checksums, digests, SBOMs, provenance,
and signatures.
