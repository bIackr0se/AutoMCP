# Security reports

Report suspected security defects privately to
[jaafer.rahmani@owasp.org](mailto:jaafer.rahmani@owasp.org).
Include the affected commit, the relevant code path, the expected boundary,
and enough sanitized evidence to assess the issue. Avoid posting credentials,
private alert data, internal network details, or unpublished research artifacts
in a public issue.

## Scope

The evidence workbench is a local synthetic demonstration. It serves fixed
fictional data on `127.0.0.1`; its review decisions stay in the browser page.
Loopback is not authentication: a local process or user can reach the same
synthetic data. There is no live-service connection or provider action in this
path.

The research graph has separate service, network, and operator requirements.
Read its [security posture](KisteGraph/KisteAgent/README.md#security-posture)
before adapting it to another deployment. Protected network ranges and alert
schema assumptions are deployment-specific.
