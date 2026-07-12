# Uninstall and data deletion

Back up evidence and Postgres first if retention is required.

```powershell
helm uninstall kubeathrix -n kubeathrix
kubectl delete namespace kubeathrix
```

Helm intentionally does not delete CRDs. After verifying no other installation
uses them, delete KubeAthrix custom resources and CRDs explicitly:

```powershell
kubectl delete findings,remediationplans,remediationruns,approvalrequests,exceptions -A --all
kubectl delete crd findings.security.kubeathrix.io remediationplans.security.kubeathrix.io remediationruns.security.kubeathrix.io approvalrequests.security.kubeathrix.io exceptions.security.kubeathrix.io
```

Delete external Postgres tables/database, external Secret objects, backups,
exported evidence bundles, image caches, and OIDC client registration according
to organizational retention policy. KubeAthrix does not control scanner CRDs,
scanner data, or identity-provider logs; remove those at their owning systems.
