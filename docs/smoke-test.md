# Kind Smoke Test

This smoke test validates the MVP install shape.

```powershell
kind create cluster --name kubeathrix
helm dependency update charts/kubeathrix
helm upgrade --install kubeathrix ./charts/kubeathrix -n kubeathrix --create-namespace --set auth.insecureDevelopmentMode=true
kubectl -n kubeathrix wait --for=condition=available deployment/kubeathrix-api --timeout=180s
kubectl -n kubeathrix wait --for=condition=available deployment/kubeathrix-console --timeout=180s
kubectl -n kubeathrix get crds | Select-String kubeathrix
kubectl -n kubeathrix port-forward svc/kubeathrix-api 8081:8080
```

In another shell:

```powershell
curl http://127.0.0.1:8081/health/ready
curl http://127.0.0.1:8081/api/dashboard
curl -X POST http://127.0.0.1:8081/api/remediation-plans `
  -H 'Content-Type: application/json' `
  -d '{"findingId":"finding-namespace-quota"}'
```

Expected result: the API reports healthy, dashboard data is present, and remediation plan creation returns a typed action with no shell command field.
