# Security Policy

## Reporting a vulnerability in C2FF

If you find a vulnerability in C2FF itself (e.g. the local HTTP API binding, path handling, or persistence layer), please open a private security advisory at https://github.com/C2FF/C2FF/security/advisories, or contact the maintainers directly.

- Include reproduction steps and affected version (commit SHA is ideal).
- Please allow reasonable time for a fix before any public disclosure.

## Scope

- In scope: anything served by `server.js` on the local host, persistence in `data/`, the probe engine's request handling.
- Out of scope: how the tool could be misused against third-party targets. C2FF ships read-only probing with a strict scope/budget design on purpose; misuse against systems you are not authorized to test is the operator's responsibility and is not a C2FF security issue.

## Hardening notes for operators

- The console binds to `127.0.0.1`. If you expose it beyond localhost, put it behind an authenticating proxy and use TLS.
- `data/` holds your programs, findings and chat messages - treat it as sensitive and back it up accordingly.