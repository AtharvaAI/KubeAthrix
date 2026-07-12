# Dockerize From Source

Use this when you want to build KubeAthrix locally from a fresh clone without pulling published KubeAthrix images.

## Prerequisites

- Docker Desktop or Docker Engine with BuildKit.
- Docker Compose v2.
- Optional: `kind`, `kubectl`, and Helm for Kubernetes smoke tests.

## Build All Images

From the repository root:

<!-- x-release-please-start-version -->
```powershell
docker build -t prashantdey/kubeathrix:api-0.2.0 -f services/api/Dockerfile .
docker build -t prashantdey/kubeathrix:console-0.2.0 -f apps/console/Dockerfile .
docker build -t prashantdey/kubeathrix:operator-0.2.0 -f operator/Dockerfile .
```
<!-- x-release-please-end -->

For local development tags:

```powershell
docker build -t prashantdey/kubeathrix:api-dev -f services/api/Dockerfile .
docker build -t prashantdey/kubeathrix:console-dev -f apps/console/Dockerfile .
docker build -t prashantdey/kubeathrix:operator-dev -f operator/Dockerfile .
```

## Push Manually To Docker Hub

CI should publish official release images. Use this only when testing the Docker Hub repository setup or recovering from CI failure.

<!-- x-release-please-start-version -->
```powershell
docker login
docker push prashantdey/kubeathrix:api-0.2.0
docker push prashantdey/kubeathrix:console-0.2.0
docker push prashantdey/kubeathrix:operator-0.2.0
```
<!-- x-release-please-end -->

## Run API And Console With Compose

```powershell
docker compose -f deploy/docker-compose.source.yaml up --build
```

Then open:

- Console: http://127.0.0.1:5173
- API readiness: http://127.0.0.1:8080/health/ready

Stop and remove local containers:

```powershell
docker compose -f deploy/docker-compose.source.yaml down
```

Remove the Postgres volume too:

```powershell
docker compose -f deploy/docker-compose.source.yaml down -v
```

## Load Local Images Into Kind

```powershell
kind create cluster --name kubeathrix
kind load docker-image prashantdey/kubeathrix:api-dev --name kubeathrix
kind load docker-image prashantdey/kubeathrix:console-dev --name kubeathrix
kind load docker-image prashantdey/kubeathrix:operator-dev --name kubeathrix
helm dependency build charts/kubeathrix
$imageRepository = "prashantdey/kubeathrix"
helm upgrade --install kubeathrix ./charts/kubeathrix `
  -n kubeathrix --create-namespace `
  --set auth.insecureDevelopmentMode=true `
  --set image.api.repository=$imageRepository `
  --set image.api.tag=api-dev `
  --set image.console.repository=$imageRepository `
  --set image.console.tag=console-dev `
  --set image.operator.repository=$imageRepository `
  --set image.operator.tag=operator-dev `
  --set image.api.pullPolicy=IfNotPresent `
  --set image.console.pullPolicy=IfNotPresent `
  --set image.operator.pullPolicy=IfNotPresent
```

Access the console:

```powershell
kubectl -n kubeathrix port-forward svc/kubeathrix-console 8080:80
```
