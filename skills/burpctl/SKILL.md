---
name: burpctl
description: Read authorized Burp Suite proxy history through the native Windows BurpCTL CLI, check scope, and retrieve exact message bytes. Use when a BurpCTL extension is available; v1 does not send traffic or mutate projects.
---

Use the short-lived `burpctl.exe`; from WSL invoke the Windows executable, not the Linux development build. Discover syntax with `--help` and `<command> --help` rather than guessing flags.

Start with `instance list --format json`. Select explicitly with `--instance ID` when several instances exist. `status` reports identity and permissions. History access is disabled until the operator enables it in Burp Settings (search for `BurpCTL`); raw access has a separate control. Do not modify policy or scope to bypass a denial.

Prefer small server-side projections:

```text
burpctl.exe --instance INSTANCE history list --limit 10 --fields id,method,path,status --format json
burpctl.exe --instance INSTANCE history list --host example.com --status 500 --fields id,path --format json
burpctl.exe --instance INSTANCE scope check https://example.com/admin --format json
```

Keep `meta.provenance.instance_id` and `project_id` with every history ID. Retrieval requires both source identities:

```text
burpctl.exe --instance INSTANCE history get ROW --project-id PROJECT --fields id,status --format json
burpctl.exe --instance INSTANCE history get ROW --project-id PROJECT --part response.body --base64 --body-max-bytes 4096 --format json
burpctl.exe --instance INSTANCE history get ROW --project-id PROJECT --part request.body --raw --output evidence.bin
```

Bodies are bytes. UTF-8 previews reject invalid sequences; Base64 previews can be truncated, as indicated in metadata. Raw exports require an explicit destination, verify byte count and SHA-256, and reject existing files unless `--force` is authorized. Preserve evidence as bytes; do not decode lossily or print binary to a terminal.

History traversal may visit the entire collection. A row limit bounds accepted results, not Montoya allocations or scan time. Ordering is unspecified; a limit hit does not prove more matches exist. `path` omits query strings. Empty lists succeed. Scope membership does not grant engagement authorization.

Check exit codes and structured errors. Do not treat denial, timeout, truncation, stale context, or an incomplete export as a completed retrieval. Reloads invalidate instance IDs and reset permissions; relist and obtain fresh references.
