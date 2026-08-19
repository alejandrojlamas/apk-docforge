# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through this repository's
GitHub **Security** tab using **Report a vulnerability**, when available. Do not
include secrets, private APKs, credentials, or exploit details in a public issue.

Include the affected version or commit, the smallest safe reproduction, expected
and observed behavior, and the security impact. Maintainers can then coordinate
validation and disclosure. This project does not currently operate a bug bounty.

## Supported versions

Security fixes are applied to the current default branch. Historical snapshots
and unmaintained forks are not supported.

## Security model

`apk-docforge` treats APKs, archives, download metadata, HTTP responses, and
analysis strings as untrusted input. Its principal safeguards are:

- a loopback-only API with a client-address check, exact trusted hosts, and
  loopback CORS origins;
- quarantine-first intake and provenance records;
- HTTPS and source-host policy checks before each download request, redirect,
  and final response;
- byte, redirect, archive-member, expanded-size, and manifest-read limits;
- static analysis by default and explicit authorized-device selection for
  dynamic analysis;
- local secret storage in an atomic mode-`0600` `.env` file;
- no implementation of authentication, payment, DRM, license, pinning, or
  anti-tamper bypasses.

The API is not designed for remote or multi-user deployment and has no remote
authentication. Starting the ASGI application directly with a non-loopback
server configuration bypasses the CLI bind guard and is unsupported.

## Handling sensitive artifacts

- Use only artifacts you are authorized to inspect.
- Keep `.env`, quarantine, outputs, downloads, databases, and Docker data out of
  version control.
- Rotate a credential immediately if it is committed, logged, or shared.
- Review generated reports before sharing; they can contain package names,
  endpoints, local paths, and evidence extracted from the application.
- Use a disposable emulator or test device for dynamic analysis and never enter
  production credentials.
