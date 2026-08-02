# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Build / vendoring (`.build.sh`)

- This app runs on `splunk_input_runtime` (https://github.com/Bre77/splunk-input-runtime), not `splunklib`/`splunk-sdk`. `lib/requirements.txt` pins it to an exact commit archive URL with a `sha256:` hash recorded in a comment above it (no PyPI package exists yet, so there is no `==version` line to pin against). Bump both the commit and the recorded hash together when the runtime releases a new version; never point at a branch.
- `lib/requirements.txt` also lists `requests`; `.build.sh` installs both in one `pip install -t lib -r lib/requirements.txt --no-dependencies` pass.
- The `chmod` calls at the top of `.build.sh` run *before* the pip install, so they do not cover files pip writes into `lib/`.
- CI (`.github/workflows/validate.yml`) calls `Bre77/splunk_nats`'s reusable build+AppInspect workflow in `build_command` mode.

## Credentials and checkpoints (`bin/extrahop.py`)

- Credential handling goes through `self.context.credentials.protect_input_fields(...)` for the `apikey` field, not manual `storage_passwords` list/delete/create calls. This preserves the credential identity `(owner=nobody, app=TA_extrahop, realm=<stanza name>, username=apikey)` that existing installs already have - do not change that tuple without a captain-level decision; it strands users' stored secrets.
- This app has two independent file checkpoints, `<checkpoint_dir>/<stanza>_audit` and `<checkpoint_dir>/<stanza>_detections`, one per collection stream (`collectaudit`/`collectdetections`). Any change to `stream_events` must keep both paths intact - a reset on either silently re-ingests or skips data for the user.
- The runner (`Script.run_script`) owns `EventWriter.close()`; app code must not call it explicitly. `splunk_input_runtime`'s `close()` is idempotent by design, but an explicit extra call is redundant and was removed from this app.
- `Bre77/SplunkUI-devcontainer`'s `test-harness/verify-splunklib-app.sh` is app-agnostic and gives a `dependency=splunk_input_runtime` build+import check on both Python 3.9 and 3.13. `test-harness/credential-continuity-gate.sh` is parameterised (`--app-id`, `--kind`, `--field`, `--extra-field`, `--old-app`/`--new-app`) and can be pointed at this app's real `extrahop` modular-input kind directly.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
