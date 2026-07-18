# Release Process

KubeAthrix uses Release Please to keep release versioning automatic and consistent.

## How Versioning Works

- Commit messages follow Conventional Commits.
- Release Please reads commits merged to `main`.
- It opens or updates a release PR with the next SemVer version and changelog.
- Merging that release PR updates the version and changelog, creates the Git tag
  and GitHub Release, and directly starts `Publish Verified Release`.
- The publish workflow reads the version from `package.json`, requires the
  generated release tag to match it, reruns every required gate, and publishes
  and signs immutable images and the OCI chart.
- A maintainer can also manually run `Publish Verified Release` as an atomic
  release or recovery path. Manual runs derive the version from `package.json`
  and create the Git tag and GitHub Release only after publication succeeds.

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
- `Release Please`: creates and updates release PRs, then creates the GitHub
  Release and invokes the image publisher when its release PR is merged.
- `Publish Verified Release`: runs automatically when a GitHub Release is
  published, or can be manually dispatched after the release PR is merged. It
  derives all image tags from the source version, verifies, publishes, signs,
  and attaches the release artifacts.

## Image Tags

<!-- x-release-please-start-version -->
For release `v0.2.1`, the publish workflow pushes:

```text
docker.io/prashantdey/kubeathrix:api-0.2.1
docker.io/prashantdey/kubeathrix:api-0.2
docker.io/prashantdey/kubeathrix:api-0
docker.io/prashantdey/kubeathrix:api-latest
docker.io/prashantdey/kubeathrix:api-sha-<short_sha>
```
<!-- x-release-please-end -->

The same tag shape is used for `console` and `operator`.

Prereleases do not receive `*-latest`, major, or minor rolling tags.

## Publish A Verified Release

To publish a release:

1. Merge conventional commits into `main`.
2. Review and merge the `Release Please` pull request. GitHub then creates the
   version tag and Release and directly runs the verified Docker Hub publisher.
   Stable releases automatically advance the rolling image tags.
3. For recovery, open GitHub Actions and manually run
   `Publish Verified Release` from the release commit on `main`. The version is
   read automatically from `package.json`; leave `push_latest` enabled only for
   stable releases.

The workflow rejects a release tag that differs from the source version. If a
manual run fails during verification, scanning, signing, image publication, or
chart publication, no GitHub Release is created. Recover a partial registry
publication by fixing the cause and deliberately rerunning the same workflow.

Do not hand-edit chart image tags or docs after a release. Let Release Please update them in the release PR.
