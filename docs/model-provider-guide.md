# Model Provider Guide

KubeAthrix supports OpenAI-compatible model providers through references to secrets. The product does not store raw API keys in the UI settings schema.

## Kubernetes Secret Reference

```yaml
modelProviders:
  - name: primary
    type: openai-compatible
    model: gpt-5
    apiKeySecretRef:
      name: kubeathrix-llm
      key: api-key
```

Create the secret separately:

```powershell
kubectl -n kubeathrix create secret generic kubeathrix-llm --from-literal=api-key='REDACTED'
```

## External Secret Reference

```yaml
modelProviders:
  - name: primary
    type: openai-compatible
    model: gpt-5
    externalSecretRef:
      store: vault
      path: secret/data/kubeathrix/model-provider
      key: api-key
```

Use this mode for production when an external secret store is already available.

## Safety Notes

- Do not commit model keys into Helm values.
- Scope provider keys to the minimum needed model API access.
- Treat scanner output and logs as untrusted model input.
- Monitor prompt-injection attempts as security events.
