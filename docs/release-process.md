# Release Process

KubeAthrix uses Release Please to keep release versioning automatic and consistent.

## How Versioning Works

- Commit messages follow Conventional Commits.
- Release Please reads commits merged to `main`.
- It opens or updates a release PR with the next SemVer version and changelog.
- Merging that release PR updates the version and changelog but does not create
  a tag or GitHub Release.
- A maintainer then runs `Publish Verified Release` for that exact version. The
  workflow reruns every required gate, publishes and signs immutable images and
  the OCI chart, and creates the Git tag and GitHub Release only as its final
  successful step.

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
- `Release Please`: creates and updates release PRs only.
- `Publish Verified Release`: is manually dispatched after the release PR is
  merged; it verifies, publishes, signs, and finally creates the GitHub Release.

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

## Publish A Verified Release

After the release PR is merged:

1. Open GitHub Actions.
2. Run `Publish Verified Release` from the release commit on `main`.
<!-- x-release-please-start-version -->
3. Enter the release version, for example `0.2.0`.
<!-- x-release-please-end -->
4. Leave `push_latest` enabled only for stable releases.

The workflow rejects a version that differs from the source manifests and
refuses to replace an existing GitHub Release. If any verification, scan,
signature, image publication, or chart publication step fails, no GitHub
Release is created. Recover a partial registry publication by fixing the cause
and deliberately rerunning the same workflow before a GitHub Release exists.

Do not hand-edit chart image tags or docs after a release. Let Release Please update them in the release PR.
