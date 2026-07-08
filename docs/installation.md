# Installation Guide

## Prerequisites

- Kubernetes 1.28 or newer.
- Helm 3.
- A namespace for KubeAthrix.
- Optional external Postgres for production.
- Optional OIDC provider for production login.

## Development Install

```powershell
helm dependency update charts/kubeathrix
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix --create-namespace
kubectl -n kubeathrix port-forward svc/kubeathrix-console 8080:80
```

The default install uses `ClusterIP` services and dev-mode auth. The API seeds demo data when no database is reachable.

## Production-Oriented Values

```yaml
postgres:
  external: true
  host: postgres.example.internal
  port: 5432
  database: kubeathrix
  username: kubeathrix
  existingSecret: kubeathrix-postgres
  passwordKey: password

auth:
  devAuthEnabled: false
  oidc:
    enabled: true
    issuerURL: https://issuer.example.com
    clientID: kubeathrix
    existingSecret: kubeathrix-oidc

modelProviders:
  - name: primary
    type: openai-compatible
    model: gpt-5
    apiKeySecretRef:
      name: kubeathrix-llm
      key: api-key

service:
  type: ClusterIP
```

## Access

KubeAthrix is internal by default:

```powershell
kubectl -n kubeathrix port-forward svc/kubeathrix-console 8080:80
kubectl -n kubeathrix port-forward svc/kubeathrix-api 8081:8080
```

Enable `ingress.enabled` only after OIDC and network policy are configured.

## Engine Toggles

```yaml
engines:
  trivyOperator:
    enabled: true
  kyverno:
    enabled: true
  kubescape:
    enabled: true
  falco:
    enabled: false
  tetragon:
    enabled: false
  chaosMesh:
    enabled: false
  litmus:
    enabled: false
```
