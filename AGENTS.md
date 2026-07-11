# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Build / vendoring (`.build.sh`)

- `splunk-sdk` is sdist-only pure Python: install it directly with `--no-dependencies`, not via `lib/requirements.txt`.
- `lib/requirements.txt` lists only the HTTP/TLS stack (`requests`, `certifi`, `charset-normalizer`, `idna`, `urllib3`), installed with `--platform manylinux2014_x86_64 --python-version 3.9 --only-binary=:all:` so the add-on is self-contained on Splunk Cloud indexers/HFs regardless of build host OS.
- charset-normalizer's mypyc speedup (`.so`) is x86_64-only and fails AppInspect's AArch64 check; `.build.sh` deletes it after the pip installs so it falls back to pure Python.
- Execute bits must be stripped from `lib/` *after* the pip installs (pip-installed wheels can ship files with the execute bit set); the top-of-script chmod runs before pip and misses them.
- CI (`.github/workflows/validate.yml`) calls `Bre77/splunk_nats`'s reusable build+AppInspect workflow in `build_command` mode; reference `Bre77/atlassian_audit`'s `validate.yml`/`.build.sh` for the proven shape.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
