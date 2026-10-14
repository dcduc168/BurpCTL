# BurpCTL — IPC & CLI Specification v1.0 (design contract)

> Status: **Protocol 1.0 implemented; release verification is incomplete (see [README verification](../README.md#verification))**. Date: 2026-10-14. The five v1 commands are implemented. Target: Rust stable (`burpctl.exe`) ↔ Java 21 Burp Extension ↔ Montoya API. Security goal: authorized local tooling on an operator-controlled Windows workstation, NOT secure isolation from a malicious process running as the same user.

## 1. Non-negotiable invariants

1. **CLI-first** and short-lived; Rust owns CLI parsing, instance selection, UDS client and presentation only. Burp feature logic and final policy enforcement stay in Java Extension.
2. On-demand Montoya queries. No SQLite, no background HTTP-history mirroring, no always-on cache/index, no background disk export. Only tiny, private per-instance rendezvous metadata is persisted while running.
3. A command implements one meaningful operation; flags filter or project results. Unknown flag/field/method fails explicitly. A CLI argument does not override extension authorization.
4. The extension must reject unauthenticated or out-of-policy requests **before** invoking Montoya. Scope rules and operator authorization are independent.
5. HTTP bodies are **bytes** first. UTF-8 preview is a display representation. No lossy conversion in raw retrieval. JSON and terminal must remain well formed for arbitrary payloads.
6. All request/response and stream allocations have maximum limits; Montoya's internal allocations are not falsely claimed bounded.
7. Empty, partial, truncated, unavailable, denied, failed and timeout are different states. The CLI never pretends a timeout canceled a network action.
8. Multiple Burp processes/projects are disambiguated; no selection by “last opened”.

## 2. Process topology / lifecycle

```text
Windows Codex / Claude Code / OpenCode, or WSL calling burpctl.exe
        │ spawn per command
        ▼
Rust burpctl.exe → private instance metadata → authenticated Windows AF_UNIX socket
        │                                            │
        └───────── 1 request/connection ─────────────┤
                                                     ▼
        Java 21 Burp Extension: IPC acceptor → decode → auth → policy → resource limiter
                                                     ▼
                                  feature handler → Montoya API → projection
                                                     ▼
                         framed JSON response or bounded binary data frames
```

- Windows UDS server: JDK `ServerSocketChannel.open(StandardProtocolFamily.UNIX)` + `UnixDomainSocketAddress` (confirm operationally on target JVM/Windows). Rust client: Windows UDS crate compatible with Rust stable (e.g. `uds_windows`), lock version after spike.
- One request per UDS connection for v1. No multiplexing, persistent CLI daemon, async Rust runtime or protocol extension engine.
- Java accepts on a dedicated thread off Swing EDT. Small bounded worker executor + reject-on-overload; do not create one unbounded thread per connection.
- Shutdown: stop accepting → close listener and in-flight clients → cancel owned cancelable tasks → close resources → remove only owned socket/registry files. Handle abrupt JVM crash/stale socket without deleting a live endpoint owned by another process.

## 3. Instance identity and rendezvous

- On extension load create ephemeral cryptographically random `instance_id` plus per-instance secret token; obtain `project_id = api.project().id()` and `project_name = api.project().name()` (optional to expose; possible sensitive project metadata).
- Use a **short**, user-private Windows runtime root; validate `AF_UNIX` path length on that host. Proposed default `%LOCALAPPDATA%\\burpctl\\r\\<short-random>.sock` *if it fits*. If it does not fit, require a safe configurable private root. Do not silently fall back to a world-writable directory.
- A small ephemeral registry entry: `{instance_id, project_id, project_name?, pid?, socket_path, protocol_major, created_at}`. No auth token in the publicly enumerated entry. Token stays in private per-instance credential file. Create files with explicit/current-user NTFS ACL and check creation failures; do not assume POSIX chmod works identically on Windows.
- Before listing an instance as usable, attempt authenticated `status`/ping; stale entries are **not** trusted. Clean up only entries whose ownership/liveness can be safely established. Take care with reparse points and races.
- `burpctl instance list` enumerates valid discovered instances. If one: it is selected. If several: `--instance <instance_id>` (or safely stored selection via explicit command). If none: `INSTANCE_NOT_FOUND`.
- `project_id` is important for evidence provenance, but two Burp windows can still refer to the same project. Attach both `instance_id` and `project_id` to evidence references. A reference is invalid across a change in `project_id` or extension instance identity unless explicit remapping is proven safe.
- Threat-model boundary: private Windows same-user processes might still read instance files and invoke the service; UDS ACL/token do not guarantee protection from malicious same-user code. Side-effect permissions should remain explicit.

## 4. Framing, bytes and versioning

### 4.1 Frame format

```
+--------------------+-----------+-----------------------------------+
| uint32 big-endian  | uint8 tag | payload (0..MAX_FRAME_PAYLOAD)    |
| frame_len          |           |                                   |
+--------------------+-----------+-----------------------------------+
```

- `frame_len` is total bytes **after** the 4-byte length header, including the one-byte `tag`; `frame_len >= 1`, `frame_len <= 262145` (256 KiB payload + tag) in v1.
- `tag=0x01`: payload is a complete UTF-8 JSON object; strict decode (no invalid UTF-8, duplicate JSON object keys rejected if parser supports it, nesting bound, no unbounded numbers). `tag=0x02`: raw binary chunk, only legal within an already-approved stream.
- Short JSON control responses only. For control content exceeding the single-frame maximum, return an output limit error or a stream response. No partially emitted/truncated JSON documents.
- Reads and writes are partial: loop until expected length; EOF mid-frame is protocol error, not successful empty content.
- Exactly one request per connection. Binary stream state means no need for a stream ID in each chunk, but the opening/closing control frames reference the request `id`.
- Strict `major=1`, `minor=0` compatibility negotiated in `status` and validated in each message. Unknown major fails with `INCOMPATIBLE_PROTOCOL`; minor may add optional fields without changing established meanings. No silent downgrade.

### 4.2 JSON request

```json
{
  "version": {"major": 1, "minor": 0},
  "id": "r-42",
  "auth": "<private-per-instance-token>",
  "method": "history.list",
  "params": {"limit": 10, "fields": ["id", "method", "path", "status"], "filters": {"status": 500}},
  "context": {"instance_id": "<ephemeral-id>", "project_id": "<Montoya-project-id>"}
}
```

- Version and `id` always required. `auth` is accepted only over the protected local IPC and never logged/echoed. Context values are checked against server identity; client-provided identity is not authority.
- `method` is explicit, stable, dot-separated (`history.list`, `history.get`, `history.match`, `scope.check`, `http.send`). Exact allowlist in dispatcher, no arbitrary Montoya method invocation, reflection, class names or command execution.
- `params` is strictly validated per operation; unknown fields/invalid enum/options fail with `INVALID_ARGUMENT`. No oversized values, regex without bounds or path traversal.
- For local `status` discovery, credential file must be accessible to authorized CLI; no unauthenticated introspection exposing project metadata by default.

### 4.3 JSON normal response

```json
{
  "version": {"major": 1, "minor": 0},
  "id": "r-42",
  "ok": true,
  "result": {
    "items": [{"id": 123, "method": "GET", "path": "/api/users", "status": 200}]
  },
  "meta": {
    "complete": true,
    "truncated": false,
    "selection_limit_reached": false,
    "ordering": "unspecified",
    "source": "proxy_history"
  }
}
```

- `complete=true` means the **requested operation** completed, not that every history entry was returned. `selection_limit_reached=true` means the configured row cap was hit, NOT proof that more matches exist.
- `truncated=true` means output data was shortened. For each truncated body include `original_size_bytes` (only when known), `returned_bytes`, and `encoding`. Never truncate silently.
- `ordering` must match what the implementation can guarantee. Default `unspecified` for Proxy History unless verified. No implicit “last N/latest”.
- When `--fields` is supplied, **result payload** includes only the requested fields. The fixed outer envelope `version/id/ok/meta` is always permitted and defined separately; compact output may omit nonessential metadata only when no ambiguity arises.
- Missing response is not necessarily an error: `has_response=false` and nullable status must be represented precisely; do not output `0` as an HTTP status.

### 4.4 Error response

```json
{
  "version": {"major": 1, "minor": 0},
  "id": "r-42",
  "ok": false,
  "error": {
    "code": "PERMISSION_DENIED",
    "message": "HTTP body access is not permitted",
    "retryable": false
  }
}
```

Stable codes: `INVALID_ARGUMENT`, `UNKNOWN_METHOD`, `AUTH_FAILED`, `PERMISSION_DENIED`, `OUT_OF_SCOPE`, `FEATURE_UNAVAILABLE`, `INSTANCE_NOT_FOUND`, `AMBIGUOUS_INSTANCE`, `STALE_REFERENCE`, `INCOMPATIBLE_PROTOCOL`, `RESOURCE_LIMIT`, `OUTPUT_LIMIT`, `BUSY`, `TIMEOUT`, `NOT_FOUND`, `INTERNAL_ERROR`, `PARTIAL_TRANSFER`.

- Empty success: `{items: []}`, `ok=true`; **never** represent it as `NOT_FOUND` for a list operation.
- A missing specific ID → `NOT_FOUND`; an explicitly outdated/other-project reference → `STALE_REFERENCE`; if the reason cannot be established, use `NOT_FOUND` without claiming stale.
- Timeouts on operations with side effects must report `outcome: "unknown"` unless there is proof the operation did not start or was canceled successfully.
- No raw stack traces, secrets, HTTP bodies or token values in user-facing errors.

### 4.5 Streaming bytes for explicit exports

- Only activated by a command such as `history get <id> --part request.body --raw --output file.bin`, after authorization.
- Initial `0x01` JSON control frame: `{id, ok:true, stream:{kind:"raw_bytes", size_bytes:<known-or-null>, chunk_max:65536, source:"montoya_request_body"}}`.
- Follow with `0x02` binary frames with **at most 64 KiB data**. End with `0x01` JSON `{id,stream_end:{bytes_sent:N,sha256:"<hex>",complete:true}}`.
- If interrupted, send terminal `stream_error` control frame where possible; otherwise EOF means incomplete. Client must verify byte count/hash and reject partial export. When user explicitly names `--output`, a same-directory `.part` file for atomic replacement is permitted and deleted on failure; without `--output` do not write temp/cache files. Never overwrite an existing file without `--force`.
- This is *not* a guarantee that Montoya streams payload from its backing storage; IPC can bound additional allocations, while Montoya may still materialize message bodies.
- JSON Base64 is allowed for small selected body fields only; cap raw bytes **before** base64 encoding (4/3 expansion). No unbounded binary field on `history list`.

## 5. Text, Unicode, terminal safety and provenance

- Valid Unicode/UTF-8 in headers/body is normal. Binary data and invalid UTF-8 are distinct. Text previews use an explicit decoding policy; strict decoder reports invalid sequence instead of silently inserting U+FFFD into evidence.
- If binary or uncertain, show safe metadata (`size_bytes`, MIME/content type, encoding, hash on demand) or base64 for requested small data. Raw output preserves byte sequence returned by the Montoya `ByteArray` representation.
- Compact terminal renderer escapes C0/C1 control codes, NUL, ESC/ANSI/OSC, carriage returns, bidi format-control characters that can spoof display, and newlines when they could break row alignment. JSON serializer must escape JSON control characters; raw binary must not go straight to interactive terminal.
- A multipart request may contain text and file bytes. Default history listing never reads its body. No implicit decompression, MIME heuristics presented as certainty, line-ending normalization or replay mutations.
- `provenance`: include `instance_id/project_id`, history ID when available, representation (`request`, `final_request`, `response`, `original_response`), and transformation (`none`, `utf8_preview`, `base64`, `truncated`) for commands returning evidence. Montoya parsed HTTP/2 is **not** proof of exact network wire bytes.
- Default summaries redact or omit sensitive headers/bodies. `--raw`/`--include-secrets` is controlled by extension policy; CLI flag alone confers no extra rights. Policy must not modify bytes in explicitly authorized raw export.

## 6. Resource limits (initial *configuration choices*, not benchmark claims)

| Limit | Proposed conservative v1 default | Rationale |
|---|---|---|
| CLI `history list --limit` | 10; hard max 100 | Agent context stays small; not backend early-stop claim |
| Control JSON frame | 256 KiB payload | Avoid big eager control buffers |
| Raw data frame | 64 KiB | Bounded copies and write buffer |
| `--body-max-bytes` preview | 4 KiB default, opt-in more | Do not dump upload/body by default |
| Total rendered text | 32 KiB default | Token and terminal guard |
| Concurrent expensive history scans | 1 | Prefer RAM/GUI stability to seconds latency |
| Concurrent light operations | Small bounded executor | No unbounded queue; tune after measurement |
| Per-request deadline | Operation-specific, explicit | Must not claim to abort blocking Montoya calls |
| In-flight binary stream | 1 per connection | Simple and bounded |
| Files on disk | Only rendezvous metadata and explicit user exports | No history cache or indexing |

These values are **proposals**, adjustable from measured workload and policies. Do not advertise JVM peak-heap hard bounds or guarantee constant memory for Montoya `history(filter)`.

## 7. CLI command grammar

```text
burpctl [--instance ID] [--format compact|json] [--max-bytes N] <command> <subcommand> [args/options]
```

- Command namespaces follow actual capabilities; no `--action=list|get|stats` mega-switch.
- `--fields` is per-operation; no generic arbitrary nested reflection. Explicit field allowlist, documented defaults.
- Global `--format compact|json` (default compact); `--json` optional alias to `--format json`, but do not implement conflicting ways to specify formats.
- Stdout is ONLY data. Stderr is human diagnostics; exit code reflects failure. **A successful empty query still exits 0.** Avoid ANSI colors in non-TTY output. No banners/progress in machine-readable output.
- Raw requires `--output PATH` by default; no piping raw bytes to untrusted console. Output path resolved on CLI side, not accepted as arbitrary write path in Extension.
- For a positional `history get <id>` produced by previous `list`, pass scoped project/instance context alongside ID. `status` prints current context if requested.
- Options like `--limit`, `--status`, `--host`, `--fields`, `--part`, `--contains`, `--body-max-bytes` have stable meanings; unsupported combinations fail rather than being ignored.
- User-provided `--regex` (if implemented later) must have pattern/input/CPU budgets; safer literal `--contains` first.

### Proposed examples

```powershell
burpctl status --format json
burpctl instance list
burpctl history list --limit 10 --fields id,method,path,status
burpctl history list --status 500 --host example.com --fields id,path,status --format json
burpctl --instance INSTANCE history get 123 --project-id PROJECT --fields id,status
burpctl history match 123 --part response.body --contains Exception --snippet-bytes 80
burpctl --instance INSTANCE history get 123 --project-id PROJECT --part request.body --raw --output upload.bin
burpctl scope check https://example.com/admin
# later:
burpctl repeater open --request-file request.http
```

### Exit code policy (proposed)

| Exit | Meaning |
|---|---|
| `0` | Completed, including an empty list or `matched=false` |
| `2` | CLI argument or option misuse |
| `3` | No/ambiguous/stale instance or reference |
| `4` | Permission, authentication or scope failure |
| `5` | Unsupported feature/edition or IPC protocol incompatibility |
| `6` | Busy, time/resource/output limit exceeded |
| `7` | IO/protocol failure or incomplete binary stream |
| `1` | Other controlled operation failure |

Stderr error messages include stable error code; JSON mode emits valid structured error on stdout ONLY when there was a valid server response and output format is JSON; do not mix partial success JSON with a diagnostic suffix.

## 8. Authorization model

At minimum evaluate: authenticated client + capability enabled + operator permission + requested data sensitivity + target allowlist/scope + body/output budget + concurrency. Always enforce in Java before Montoya. Listing a tool/command or choosing read-only label is not itself authorization. Network sends can hit localhost/private services: no user-supplied `Host`/DNS trick may bypass validated target policy.

Read classes: metadata, sensitive raw. Side effects: UI mutation, network send, project mutation, long-running scan, file export. Policy applies even to malformed/replayed hand-crafted IPC frames, not only invocations from official CLI. No general `--unsafe` to disable checks.

## Implemented v1 operation contracts

All requests require the complete envelope. JSON numbers are signed 64-bit integers; duplicate keys, invalid UTF-8/Unicode, trailing documents, more than 16 nesting levels, and arrays/objects over 1,024 members are rejected. Major/minor must be exactly 1/0 in this implementation. Control payloads are capped at 262,144 bytes. Framing failures without a trustworthy ID close the connection.

Every operation accepts `params.max_bytes` (1,024–262,144; default 32,768), covering the encoded control response. The CLI also caps rendered output including its newline and escapes terminal controls in both formats. Raw export bytes have a separate 32 MiB hard limit. Unknown envelope/parameter/filter/field keys fail.

| RPC | Params besides `max_bytes` | Result / policy |
|---|---|---|
| `status` | None | Instance/project IDs, extension/Burp versions, methods and permissions; CLI adds its own version. No project name/path by default. |
| `scope.check` | Required `url`: HTTP(S), host required, at most 4,096 characters, no credentials/fragment/control characters | `{url,in_scope}`; authenticated membership query; no target traffic. |
| `history.list` | `limit`: 1–100, default 10; `fields`; `filters` with exact case-insensitive `host`, exact case-sensitive `method`, HTTP `status` 100–599, literal `path_contains` | `{items:[...]}`; metadata permission plus per-row scope; one expensive operation at a time. |
| `history.get` | Required `id`: 0–2,147,483,647; optional `fields`; optional `part`, `encoding`, `body_max_bytes` | `{item:{...}}` or approved stream; metadata permission; selected message/bytes additionally require raw permission. |

Metadata field allowlist: `id,method,host,path,status,has_response,port,secure`; defaults `id,method,host,path,status`. **Intentional contract refinement:** `path` uses `finalRequest().pathWithoutQuery()` to omit potentially sensitive query values; `path_contains` uses the same representation. Response metadata is accessed only when required by selected fields or filters. Scope validation necessarily accesses request URL metadata.

For a selected `part=request|response|request.body|response.body`, field allowlist/defaults are `size_bytes,returned_bytes,encoding,data,truncated`. `encoding=utf8|base64|raw`, default `utf8`; `body_max_bytes` defaults to 4,096, maximum 65,536. Invalid UTF-8 in the selected prefix fails; even a cut mid-character is not decoded lossily. `raw` rejects fields/preview limits and requires CLI `--output`. Without `part`, encoding and body limits are invalid. Missing response is `NOT_FOUND` for response retrieval; metadata status is null.

History responses carry source identity in outer `meta.provenance`. Byte responses also carry representation, transformation, history ID, original/returned byte counts and encoding even with narrow field projection. **Intentional CLI refinement:** `history get ID` requires both `--instance INSTANCE` and `--project-id PROJECT`; context is never inferred for numeric evidence references. A changed project ID requires extension reload; old references fail rather than being remapped.

The live callback spike observed serial callbacks on Burp Professional 2026.10. An atomic acceptance counter caps the returned List independently of callback ordering; parallel fixture callbacks also passed. Neither observation establishes a permanent Montoya threading/ordering guarantee. Recheck scope before projecting or streaming; raw streams retain the single history permit until completion. Bodies are obtained once and copied with `getByte` into at most 64 KiB IPC chunks; Montoya materialization is outside that additional-allocation bound.

The runtime uses a blocking acceptor, at most two request workers, no work queue, and one short-lived overload worker that authenticates and returns `BUSY`. When even that worker is occupied, new sockets close. Idle workers expire. Unload closes listener, clients and selectors, revokes history permissions, cancels workers and removes only owned files; a blocking Montoya call is not guaranteed cancelable.

Java connection deadline is 30 seconds, history callback deadline 20 seconds, overload decoding 1 second. The CLI has a 30-second framing/stream deadline; discovery budgets 3 seconds overall and at most 1 second per status probe. Deadlines do not guarantee interruption of Montoya or an OS-level blocking connect/file operation. Timeouts/busy probes are not silently treated as a stale instance, preventing accidental selection among incompletely checked instances.

Raw opening/end controls include protocol version and request ID. The client rejects extra frames, wrong count/hash, EOF or stream error, and cleans `.part` files on failure. Exports do not overwrite without `--force`; no export path is sent to Java. Tiny ephemeral rendezvous files are the only production writes without an explicit export.

The client validates exclusive response variants: a normal success requires an object result and completion metadata, an error requires code/message/retryable, and a raw export success requires an opening stream followed by verified bytes and a terminal control. A normal success cannot complete a requested raw export. Extension status and tab name use the JAR's `Implementation-Version` build metadata; source-classpath development runs report `development`.

## 9. Protocol change discipline

- Freeze v1 envelope and basic codes once Rust↔Java interoperability is demonstrated. Use `minor` additive changes only; fields never silently change semantics.
- Source of truth is this `SPEC.md`, **plus a few golden JSON/frame vectors** under `protocol/examples` once implementation starts; one schema generator is optional, not mandatory at day one.
- Compatible CLI/server versions should be reported by `status`. Reject incompatible majors with actionable error.
- No “MCP compatibility layer” in v1; add an adapter over existing operation handlers later if demand is real.

## References

- Java 21 AF_UNIX NIO: https://docs.oracle.com/en/java/javase/21/core/internet-protocol-and-unix-domain-sockets-nio-example.html
- Rust Windows UDS crate: https://docs.rs/uds_windows/latest/uds_windows/
- Javadoc Montoya: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html
- Burp Extension lifecycle: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/extension/Extension.html
- CLI patterns: https://clig.dev/ and https://cli.github.com/manual/gh_help_formatting
