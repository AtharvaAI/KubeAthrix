# Security policy

## Supported versions

Only the latest released minor version receives security fixes. This
repository is pre-release until a signed release and digest-pinned OCI chart
are published by the release workflow.

## Reporting a vulnerability

Do not open a public issue. Use GitHub private vulnerability reporting for this
repository. If that facility is unavailable, contact the maintainers listed in
[MAINTAINERS.md](MAINTAINERS.md) and ask for a private reporting channel without
including exploit details in the first message.

Include affected versions, impact, reproduction, and suggested mitigation.
The project aims to acknowledge reports within three business days, provide a
triage result within seven, and coordinate disclosure after a fix is available.

Never include real cluster credentials, token values, Secret payloads, or
customer evidence. The threat model is documented in
[docs/threat-model.md](docs/threat-model.md).
