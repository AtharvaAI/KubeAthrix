# Published Docker Images

KubeAthrix publishes all runtime images to one Docker Hub repository:

```text
docker.io/prashantdey/kubeathrix
```

Each component uses a tag prefix.

<!-- x-release-please-start-version -->
| Component | Versioned tag | Rolling tag |
| --- | --- | --- |
| API | `api-0.2.2` | `api-latest` |
| Console | `console-0.2.2` | `console-latest` |
| Operator | `operator-0.2.2` | `operator-latest` |
<!-- x-release-please-end -->

## Pull Images

<!-- x-release-please-start-version -->
```powershell
docker pull docker.io/prashantdey/kubeathrix:api-0.2.2
docker pull docker.io/prashantdey/kubeathrix:console-0.2.2
docker pull docker.io/prashantdey/kubeathrix:operator-0.2.2
```
<!-- x-release-please-end -->

## Run Published API And Console Locally

```powershell
docker compose -f deploy/docker-compose.images.yaml up
```

Then open:

- Console: http://127.0.0.1:5173
- API readiness: http://127.0.0.1:8080/health/ready

To use rolling tags instead of a pinned version, override the compose image tags:

```powershell
$env:KUBEATHRIX_API_TAG = "api-latest"
$env:KUBEATHRIX_CONSOLE_TAG = "console-latest"
docker compose -f deploy/docker-compose.images.yaml up
```

## Install Published Images With Helm

The chart defaults to image tags that match the chart release. For example,
chart `<version>` defaults to `api-<version>`, `console-<version>`, and
`operator-<version>`.

```powershell
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix --create-namespace `
  --dependency-update `
  --reset-values `
  --atomic --cleanup-on-fail --timeout 10m `
  --set auth.insecureDevelopmentMode=true
```

To override to a specific release:

<!-- x-release-please-start-version -->
```powershell
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix --create-namespace `
  --dependency-update `
  --reset-values `
  --atomic --cleanup-on-fail --timeout 10m `
  --set auth.insecureDevelopmentMode=true `
  --set image.api.tag=api-0.2.2 `
  --set image.api.pullPolicy=IfNotPresent `
  --set image.console.tag=console-0.2.2 `
  --set image.console.pullPolicy=IfNotPresent `
  --set image.operator.tag=operator-0.2.2 `
  --set image.operator.pullPolicy=IfNotPresent
```
<!-- x-release-please-end -->

Use signed digests for production environments when you need immutable runtime
inputs. The `*-latest` aliases are available for demos, sandboxes, or
intentionally rolling environments.
