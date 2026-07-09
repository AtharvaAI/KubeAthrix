# Published Docker Images

KubeAthrix publishes all runtime images to one Docker Hub repository:

```text
docker.io/prashantdey/kubeathrix
```

Each component uses a tag prefix.

<!-- x-release-please-start-version -->
| Component | Versioned tag | Rolling tag |
| --- | --- | --- |
| API | `api-0.2.0` | `api-latest` |
| Console | `console-0.2.0` | `console-latest` |
| Operator | `operator-0.2.0` | `operator-latest` |
<!-- x-release-please-end -->

## Pull Images

<!-- x-release-please-start-version -->
```powershell
docker pull docker.io/prashantdey/kubeathrix:api-0.2.0
docker pull docker.io/prashantdey/kubeathrix:console-0.2.0
docker pull docker.io/prashantdey/kubeathrix:operator-0.2.0
```
<!-- x-release-please-end -->

## Run Published API And Console Locally

```powershell
docker compose -f deploy/docker-compose.images.yaml up
```

Then open:

- Console: http://127.0.0.1:5173
- API health: http://127.0.0.1:8080/api/health

To use rolling tags instead of a pinned version, override the compose image tags:

```powershell
$env:KUBEATHRIX_API_TAG = "api-latest"
$env:KUBEATHRIX_CONSOLE_TAG = "console-latest"
docker compose -f deploy/docker-compose.images.yaml up
```

## Install Published Images With Helm

The chart defaults to the pinned published image tags.

<!-- x-release-please-start-version -->
```powershell
helm dependency build charts/kubeathrix
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix --create-namespace `
  --set image.api.repository=docker.io/prashantdey/kubeathrix `
  --set image.api.tag=api-0.2.0 `
  --set image.console.repository=docker.io/prashantdey/kubeathrix `
  --set image.console.tag=console-0.2.0 `
  --set image.operator.repository=docker.io/prashantdey/kubeathrix `
  --set image.operator.tag=operator-0.2.0
```
<!-- x-release-please-end -->

To track the most recent stable release:

```powershell
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix --create-namespace `
  --set image.api.tag=api-latest `
  --set image.console.tag=console-latest `
  --set image.operator.tag=operator-latest
```

Use pinned version tags for production environments. Use `*-latest` only for demos, sandboxes, or intentionally rolling environments.
