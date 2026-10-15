# CLI reference

Examples use `burpctl`; substitute `burpctl.exe` on Windows. `INSTANCE`, `PROJECT` and `ROW` are placeholders from discovery and history provenance. Quote URLs and paths for the current shell. From WSL, the Windows executable needs a Windows-resolvable output path; `/tmp/evidence.bin` is not a Windows destination.

## History and scope

```text
burpctl instance list --format json
burpctl --instance INSTANCE status --format json
burpctl --instance INSTANCE scope check "https://example.com/api/" --format json
burpctl --instance INSTANCE history list --host example.com --method POST --status 500 --path-contains /api/ --limit 10 --fields id,path,status --format json
burpctl --instance INSTANCE history get ROW --project-id PROJECT --fields id,status,has_response --format json
```

Do not pass `--instance` to `instance list`. Status includes `cli_version`, `extension_version`, `burp_version`, `instance_id`, `project_id`, `methods` and `permissions`.

History needs `history_metadata` and returns only permitted in-scope entries. Scope check accepts HTTP(S) URLs with a host, at most 4,096 characters, without userinfo, fragment or control characters. `in_scope:false` is a successful result; neither result sends traffic or authorizes testing.

List filters combine with AND:

| Option | Meaning |
|---|---|
| `--host` | Exact service hostname, case insensitive; no scheme, port or path |
| `--method` | Exact case-sensitive method, such as `POST` |
| `--status` | HTTP status 100–599 |
| `--path-contains` | Literal substring of path excluding query; no regex or wildcard |
| `--limit` | Default 10, range 1–100; bounds returned rows only |

Metadata fields for list/get: `id,method,host,path,status,has_response,port,secure`. Defaults: `id,method,host,path,status`. Missing response gives `status:null` and `has_response:false`. There is no query, headers or body field in this namespace.

JSON list rows are at `result.items`; get returns `result.item`. Retain `meta.provenance.instance_id` and `project_id`. Even with one live instance, get needs explicit source `--instance` and `--project-id`. Row IDs range from 0 to 2,147,483,647.

Ordering is unspecified. `meta.selection_limit_reached` means the cap was reached, not proof of additional matches. There is no offset, cursor, exact count or latest command. A request for the latest 200 or an exhaustive inventory cannot be fulfilled by `--limit 200`; explain the limit and offer a filtered, bounded sample. Do not emulate pagination through repeated broad scans.

## Message bytes

All selected-message access, including text/Base64 previews, needs both `history_metadata` and `history_raw`.

| `--part` | Representation |
|---|---|
| `request` / `response` | Full Montoya HTTP message, headers and body |
| `request.body` / `response.body` | Payload only |

There is no headers-only part. These are Montoya bytes, not proof of original network framing, particularly for HTTP/2. A missing response returns `NOT_FOUND` when selected.

```text
burpctl --instance INSTANCE history get ROW --project-id PROJECT --part response --body-max-bytes 2048 --format json
burpctl --instance INSTANCE history get ROW --project-id PROJECT --part response.body --base64 --body-max-bytes 4096 --fields data --format json
burpctl --instance INSTANCE history get ROW --project-id PROJECT --part response --raw --output "response.bin" --format json
```

The first command is a strict UTF-8 preview of the full-message prefix; it may end within the headers before reaching any body. Invalid UTF-8, including a prefix cut mid-character, fails; use Base64 rather than replacement decoding. Preview byte limit defaults to 4,096, range 1–65,536. Base64 is still a preview, not automatically a full export.

With `--part`, fields change to `size_bytes,returned_bytes,encoding,data,truncated` (all by default); do not mix metadata fields such as `id,status`. With `--fields data`, completeness information remains in `meta`: `original_size_bytes`, `returned_bytes`, `encoding`, `truncated`. For example, 4,096 returned bytes out of 10,000 with `truncated:true` is incomplete even if `meta.complete` is true.

`--raw` requires `--part` and `--output`, conflicts with `--base64`, and rejects `--fields` and `--body-max-bytes`. Choose the requested representation: full response uses `response`, payload-only uses `response.body`. The selected representation must be at most 32 MiB, including for previews; there is no range/resume feature.

Exports verify total bytes, SHA-256 and transfer completion before publication. Successful output reports `result.bytes_written` and `sha256` with provenance. Partial transfer is failure; incomplete temporary files are cleaned up. Never assemble evidence from partial files. Existing destinations require `--force`, only when replacement is authorized. Keep secrets and body contents out of diagnostics.

## Repeater screenshots

```text
burpctl --instance INSTANCE repeater screenshot --output "repeater.png" --format json
```

Requires only `repeater_screenshot`, not history grants. Capture must be authorized for the visible contents: the viewport and tab labels may contain secrets or out-of-scope material. Scope check on one URL cannot authorize the entire image.

The command renders the initialized main-window Repeater pane offscreen; another main tool may stay selected. If uninitialized, ask the operator to open Repeater once. It does not send requests, navigate or change tabs. No tab-ID, URL or field selector exists. Detached/minimized or unrecognized layouts may be unavailable; do not force UI changes to bypass a failure or promise every layout/language works.

Limits: 4,194,304 pixels, 8 MiB PNG, one capture/export at a time. Oversized views are rejected, never silently scaled. The EDT wait is two seconds: queued work can be cancelled, but an already-running paint may finish after timeout. Do not retry in a tight loop or claim the paint stopped. File publication and `--force` follow byte-export rules.

## Output and recovery

Global options: `--instance ID`, `--format compact|json`, `--max-bytes N`. There is no `--json` flag. Compact is default; JSON preserves the protocol envelope (`ok`, `result`, `meta` or `error`). Compact has no reliable top-level `ok` contract.

`--max-bytes` controls rendered/control output: default 32,768, range 1,024–262,144 bytes. It does not increase preview or raw-export limits. Narrow fields, rows or preview bytes before increasing it.

Check process exit, stdout and stderr. Local discovery, argument or transport failures can leave stdout empty even with `--format json`. Parse JSON only when present and valid; read `error.code` for server errors, otherwise preserve the diagnostic. Never assume every failure has a JSON envelope.

| Exit | Codes / next step |
|---|---|
| 0 | Success, including empty history or scope false |
| 1 | Other controlled failure; inspect diagnostic |
| 2 | `INVALID_ARGUMENT` / parser failure: check help, field namespace and flag combinations |
| 3 | `INSTANCE_NOT_FOUND`, `AMBIGUOUS_INSTANCE`, `STALE_REFERENCE`: rediscover, resolve ambiguity, obtain fresh provenance |
| 4 | `AUTH_FAILED`, `PERMISSION_DENIED`, `OUT_OF_SCOPE`: distinguish local file protection from server grants; ask for only a missing required grant, never bypass policy |
| 5 | `FEATURE_UNAVAILABLE`, `INCOMPATIBLE_PROTOCOL`, `UNKNOWN_METHOD`: inspect versions/methods and layout support; report unsupported capability |
| 6 | `BUSY`, `TIMEOUT`, `RESOURCE_LIMIT`, `OUTPUT_LIMIT`: distinguish the code; wait, narrow the operation or report the limit |
| 7 | `IPC_ERROR`, `PARTIAL_TRANSFER`: report failed retrieval/export, inspect connection; no evidence-completeness claim |

For `BUSY`, serialize work and allow at most two spaced retries, then report it. Timeout does not prove backend cancellation; allow prior work to settle before any safe retry. Do not automatically repeat capture/export after timeout; a subsequent `BUSY` does not restart that retry allowance. There is no documented completion probe or guaranteed settling interval. For output limits, reduce output; for resource limits, choose a smaller representation/query where supported, without inventing chunking. `NOT_FOUND` can mean a missing row or response: inspect context and `has_response`, rather than blindly retrying.

Reload resets identities and grants. Never rewrite old provenance to make a reference current. Authentication/version failures require checking the correct client and loaded extension, not reading tokens or changing ACLs. Report what was retrieved; do not turn errors, denied data or truncated samples into findings about the target.
