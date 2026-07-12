# Optional model providers

KubeAthrix 0.2.0 is deterministic by default and does not invoke a model. The
administrator-only provider settings API accepts Kubernetes Secret or external
secret references as inventory metadata, but the application does not resolve
those references, read the secret payload, send evidence to a provider, or use
model output in remediation.

Raw API keys are deliberately absent from the API schema, logs, database, Helm
defaults, and browser state. Do not create a model credential for this release.

A future model gateway must ship with strict structured output validation,
prompt-injection defenses, explicit egress policy, timeouts and cost bounds,
evaluation fixtures, and a deterministic fallback before this guide will
document provider setup. Regardless of that future work, model output will not
be permitted to bypass the versioned typed action catalog.
