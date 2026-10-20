# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately to the maintainers (security contact to be
published with the first public release). Do not open public issues for security
reports. Include affected versions, a description and, if possible, a reproduction.
We aim to acknowledge reports within 2 business days.

## Scope

The runtime decides whether agent effects may happen. Bugs that let an effect be
dispatched without current authority, policy allowance, required approval, budget or
an operation claim, that let a dispatch happen twice, that let one tenant read or act
on another tenant's state, or that let audit records be altered undetectably are
critical. See [docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md).

## Supported versions

Pre-release: only `main` receives fixes.
