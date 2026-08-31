# Contributing to C2FF

Thanks for considering a contribution.

## Ground rules

1. **Authorized targets only.** Any feature that must interact with a target must keep the explicit-scope design (one host per wildcard, fixed request budget, read-only GETs). PRs adding mass scanning, credential brute force or write attacks against arbitrary targets will not be merged.
2. **Zero runtime dependencies.** C2FF is Node core + curl. No npm packages.
3. **Keep it local-first.** No telemetry, no cloud calls, no accounts.

## Workflow

```bash
git clone https://github.com/C2FF/C2FF.git && cd C2FF
./install.sh          # sanity check on your machine
node --check server.js && node --check fleet.js && node --check app.js
bash -n watchdog.sh install.sh
```

- One feature or fix per PR, with a short description of the behavior change.
- UI changes: keep the element IDs in `index.html` stable - `app.js` binds to them.
- New engine modules go in `fleet.js` following the existing module shape: `async (ctx) => ...` with `ctx = {host, program, header}`, emitting findings via the ctx callback.

## Code style

- Plain modern JavaScript (Node >= 18), no build step.
- Comments in the language of the file (French or English both fine); identifiers in English.