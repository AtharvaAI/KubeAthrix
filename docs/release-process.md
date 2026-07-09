# Release Process

KubeAthrix uses Release Please to keep release versioning automatic and consistent.

## How Versioning Works

- Commit messages follow Conventional Commits.
- Release Please reads commits merged to `main`.
- It opens or updates a release PR with the next SemVer version and changelog.
- Merging that release PR creates the Git tag and GitHub Release.
- The Docker publishing workflow builds and pushes images to Docker Hub from that published release.

Version impact:

| Commit style | Version impact |
| --- | --- |
| `fix: correct approval status` | Patch |
| `feat: add runtime adapter` | Minor |
| `feat!: change remediation API` | Major |
| Commit body with `BREAKING CHANGE:` | Major |

Release Please also updates version references in the Helm chart, chart image tags, package manifests, and Docker docs.

## Required GitHub Secrets

Configure these repository secrets before publishing images:

| Secret | Purpose |
| --- | --- |
| `DOCKERHUB_USERNAME` | Docker Hub username with access to `prashantdey/kubeathrix`. |
| `DOCKERHUB_TOKEN` | Docker Hub access token or password. Prefer an access token. |

## Workflows

- `CI`: runs tests, console build, Helm lint/template, and Docker build smoke checks.
- `Release Please`: creates release PRs and GitHub Releases.
- `Publish Docker Images`: runs when a GitHub Release is published and pushes the API, console, and operator images.

## Image Tags

<!-- x-release-please-start-version -->
For release `v0.2.0`, the publish workflow pushes:

```text
docker.io/prashantdey/kubeathrix:api-0.2.0
docker.io/prashantdey/kubeathrix:api-0.1
docker.io/prashantdey/kubeathrix:api-0
docker.io/prashantdey/kubeathrix:api-latest
docker.io/prashantdey/kubeathrix:api-sha-<short_sha>
```
<!-- x-release-please-end -->

The same tag shape is used for `console` and `operator`.

Prereleases do not receive `*-latest`, major, or minor rolling tags.

## Manual Publish

Use manual publishing only to recover from a failed Docker Hub publish after a release already exists.

1. Open GitHub Actions.
2. Run `Publish Docker Images`.
<!-- x-release-please-start-version -->
3. Enter the release version, for example `0.2.0`.
<!-- x-release-please-end -->
4. Leave `push_latest` enabled only for stable releases.

Do not hand-edit chart image tags or docs after a release. Let Release Please update them in the release PR.
