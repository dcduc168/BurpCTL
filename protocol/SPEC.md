# BurpCTL protocol 1.0

The native Windows, Linux or macOS Rust CLI communicates with the Java 21 extension over authenticated Unix domain sockets. This reference describes the implemented protocol and CLI. Release verification remains incomplete; see [verified behavior and limits](../README.md#verification).

The service is intended for authorized local tooling on an operator-controlled workstation. Filesystem permissions and authentication do not isolate it from malicious processes running as the same user.

## 1. Invariants

1. CLI-first and short-lived; Rust owns CLI parsing, instance selection, UDS client and presentation only. Burp feature logic and final policy enforcement stay in Java Extension.
2. On-demand Montoya queries. No SQLite, no background HTTP-history mirroring, no always-on cache/index, no background disk export. Only tiny, private per-instance rendezvous metadata is persisted while running.
3. A command implements one meaningful operation; flags filter or project results. Unknown flag/field/method fails explicitly. A CLI argument does not override extension authorization.
4. The extension must reject unauthenticated or out-of-policy requests before invoking Montoya. Scope rules and operator authorization are independent.
5. HTTP bodies are bytes first. UTF-8 preview is a display representation. No lossy conversion in raw retrieval. JSON and terminal must remain well formed for arbitrary payloads.
6. All request/response and stream allocations have maximum limits; Montoya's internal allocations are not falsely claimed bounded.
7. Empty, partial, truncated, unavailable, denied, failed and timeout are different states. The CLI never pretends a timeout canceled a network action.
8. Multiple Burp processes/projects are disambiguated; no selection by "last opened".

## 2. Processes and lifecycle

```text
Local automation on Windows/Linux/macOS, or WSL calling Windows burpctl.exe
        │ spawn per command
        ▼
Native Rust CLI → private instance metadata → authenticated AF_UNIX socket
        │                                            │
        └───────── 1 request/connection ─────────────┤
                                                     ▼
        Java 21 Burp Extension: IPC acceptor → decode → auth → policy → resource limiter
                                                     ▼
                                  feature handler → Montoya API → projection
                                                     ▼
                         framed JSON response or bounded binary data frames
```

- Java uses `ServerSocketChannel.open(StandardProtocolFamily.UNIX)` and `UnixDomainSocketAddress`. Rust uses `uds_windows` 1.2.1 on Windows and `std::os::unix::net::UnixStream` on Linux/macOS. CLI and extension must run on the same OS; Windows and WSL sockets are separate. Windows interoperability checks are described in the [verification guide](../verification/README.md).
- One request per UDS connection for v1. No multiplexing, persistent CLI daemon, async Rust runtime or protocol extension engine.
- Java accepts on a dedicated thread off Swing EDT. Small bounded worker executor + reject-on-overload; do not create one unbounded thread per connection.
- Shutdown: stop accepting → close listener and in-flight clients → cancel owned cancelable tasks → close resources → remove only owned socket/registry files. Handle abrupt JVM crash/stale socket without deleting a live endpoint owned by another process.

## 3. Instance identity and rendezvous

- Each load creates a random 32-hex-character `instance_id` and a 256-bit token encoded as 64 hex characters. `project_id` comes from `api.project().id()`; project names and paths are omitted.
- The socket path is `%LOCALAPPDATA%\burpctl\r\<first-12-instance-id-characters>\s`. Startup requires current-user NTFS ACLs and a path of at most 100 UTF-8 bytes. Relocation is not implemented; an overlong path fails explicitly.
- On Linux/macOS, the root is the canonical `/tmp/burpctl-<uid>` (usually `/private/tmp/burpctl-<uid>` on macOS), with the same `r/<first-12-instance-id-characters>/s` layout. This short, UID-based path deliberately avoids GUI/shell environment differences; it does not use XDG_RUNTIME_DIR or TMPDIR. Both peers validate current-user ownership, directory mode 0700, regular-file/socket mode 0600, object type and non-symlink paths. Regular runtime files with multiple hard links are rejected. Unsafe existing paths are not repaired. A pre-created foreign root causes denial, never deletion or ownership takeover. Unix startup requires the JDK `jdk.security.auth` module for OS user identity. The 100-byte socket-path limit applies on every OS.
- POSIX permission checks assume a trusted OS-managed temporary parent and local filesystem. Custom extended ACLs and adversarial filesystem replacement races have not been comprehensively verified; tokens/permissions do not exclude malicious same-user code. Runtime files are ephemeral, not configuration or caches.
- Newly created Windows runtime directories, files and sockets have their owner explicitly set to the current user before validation. Existing objects with unexpected owners or ACLs are rejected without changing ownership, including when running elevated.
- Each private instance directory contains `instance.json`, `credential` and socket `s`. Registry metadata contains `instance_id`, `project_id`, `pid`, `socket_path`, `protocol_major` and `created_at`. The credential is separate and never returned by discovery.
- Discovery validates private paths and metadata, then probes authenticated `status`. Unusable entries are excluded. Discovery does not delete stale files; unload removes only that instance's files. Adversarial reparse-point races remain an open verification item.
- `instance list` succeeds with an empty list when none are usable. Other commands require one live instance: select with `--instance` when several exist, or receive `AMBIGUOUS_INSTANCE`. No usable instance returns `INSTANCE_NOT_FOUND`. Numeric history retrieval always requires explicit instance and project IDs.
- `project_id` is important for evidence provenance, but two Burp windows can still refer to the same project. Attach both `instance_id` and `project_id` to evidence references. A reference is invalid across a change in `project_id` or extension instance identity unless explicit remapping is proven safe.
- Threat-model boundary: same-user processes might still read instance files and invoke the service; UDS permissions/token do not guarantee protection from malicious same-user code. Side-effect permissions should remain explicit.

## 4. Framing, bytes and versioning

### 4.1 Frame format

```
+--------------------+-----------+-----------------------------------+
| uint32 big-endian  | uint8 tag | payload (0..MAX_FRAME_PAYLOAD)    |
| frame_len          |           |                                   |
+--------------------+-----------+-----------------------------------+
```

- `frame_len` is total bytes after the 4-byte length header, including the one-byte `tag`; `frame_len >= 1`, `frame_len <= 262145` (256 KiB payload + tag) in v1.
- `tag=0x01`: payload is a complete UTF-8 JSON object; strict decode (no invalid UTF-8, duplicate JSON object keys rejected, bounded nesting and signed 64-bit integer numbers). `tag=0x02`: raw binary chunk, only legal within an already-approved stream.
- Short JSON control responses only. For control content exceeding the single-frame maximum, return an output limit error or a stream response. No partially emitted/truncated JSON documents.
- Reads and writes are partial: loop until expected length; EOF mid-frame is protocol error, not successful empty content.
- Exactly one request per connection. Binary stream state means no need for a stream ID in each chunk, but the opening/closing control frames reference the request `id`.
- Every message must use `major=1`, `minor=0`. Other versions return `INCOMPATIBLE_PROTOCOL`. There is no downgrade or minor-version negotiation in this implementation.

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
- `method` is explicit, stable, dot-separated (`status`, `scope.check`, `history.list`, `history.get`, `repeater.screenshot`). Exact allowlist in dispatcher, no arbitrary Montoya method invocation, reflection, class names or command execution.
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
    "source": "proxy_history",
    "provenance": {"instance_id": "<ephemeral-id>", "project_id": "<Montoya-project-id>"}
  }
}
```

- `complete=true` means the requested operation completed, not that every history entry was returned. `selection_limit_reached=true` means the configured row cap was hit, not proof that more matches exist.
- `truncated=true` means output data was shortened. For each truncated body include `original_size_bytes` (only when known), `returned_bytes`, and `encoding`. Never truncate silently.
- `ordering` must match what the implementation can guarantee. Default `unspecified` for Proxy History unless verified. No implicit "last N/latest".
- When `--fields` is supplied, result payload includes only the requested fields. The fixed outer envelope `version/id/ok/meta` is always permitted and defined separately; compact output may omit nonessential metadata only when no ambiguity arises.
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

Stable codes: `INVALID_ARGUMENT`, `UNKNOWN_METHOD`, `AUTH_FAILED`, `PERMISSION_DENIED`, `OUT_OF_SCOPE`, `FEATURE_UNAVAILABLE`, `INSTANCE_NOT_FOUND`, `AMBIGUOUS_INSTANCE`, `AMBIGUOUS_REFERENCE`, `STALE_REFERENCE`, `INCOMPATIBLE_PROTOCOL`, `RESOURCE_LIMIT`, `OUTPUT_LIMIT`, `BUSY`, `TIMEOUT`, `NOT_FOUND`, `INTERNAL_ERROR`, `IPC_ERROR`, `PARTIAL_TRANSFER`.

- Empty success: `{items: []}`, `ok=true`; never represent it as `NOT_FOUND` for a list operation.
- A missing specific ID → `NOT_FOUND`; an explicitly outdated/other-project reference → `STALE_REFERENCE`; if the reason cannot be established, use `NOT_FOUND` without claiming stale.
- A timeout does not prove backend work stopped. The CLI diagnostic reports that backend completion is unknown. No operation sends target traffic. `repeater.open` creates a UI tab; after timeout its completion is unknown, so it must not be retried automatically.
- No raw stack traces, secrets, HTTP bodies or token values in user-facing errors.

### 4.5 Streaming bytes for explicit exports

- Activated by an explicit history raw export or `repeater screenshot --output file.png`, after operation-specific authorization.
- The opening `0x01` control includes `version`, `id`, `ok:true`, `stream` and `meta`. `stream` has `kind:"raw_bytes"`, a known integer `size_bytes`, `chunk_max:65536` and a representation source. `meta` carries provenance, representation and transformation (`none` for history, `swing_rendered_png` for screenshots). The client preserves this metadata in the export result.
- Follow with `0x02` frames containing at most 64 KiB of data. The terminal `0x01` control has `version`, `id` and `stream_end:{bytes_sent:N,sha256:"<hex>",complete:true}`.
- After a successful terminal control, the peer must close the connection. The client rejects trailing bytes; on Windows it waits for EOF using nonblocking recv and deadline-bounded Winsock select. Unix reads, writes and EOF use nonblocking I/O and deadline-bounded poll; socket receive/send timeouts were unreliable in native macOS fixture checks.
- If interrupted, send terminal `stream_error` control frame where possible; otherwise EOF means incomplete. Client must verify byte count/hash and reject partial export. When user explicitly names `--output`, a same-directory `.part` file for atomic replacement is permitted and deleted on failure; without `--output` do not write temp/cache files. Never overwrite an existing file without `--force`.
- This is *not* a guarantee that Montoya streams payload from its backing storage; IPC can bound additional allocations, while Montoya may still materialize message bodies.
- JSON Base64 is allowed for small selected body fields only; cap raw bytes before base64 encoding (4/3 expansion). No unbounded binary field on `history list`.

## 5. Text, Unicode, terminal safety and provenance

- Valid Unicode/UTF-8 in headers/body is normal. Binary data and invalid UTF-8 are distinct. Text previews use an explicit decoding policy; strict decoder reports invalid sequence instead of silently inserting U+FFFD into evidence.
- Use size/encoding metadata or bounded Base64 for arbitrary bytes. Raw retrieval preserves bytes returned by the Montoya `ByteArray` representation.
- Compact terminal renderer escapes C0/C1 control codes, NUL, ESC/ANSI/OSC, carriage returns, bidi format-control characters that can spoof display, and newlines when they could break row alignment. JSON serializer must escape JSON control characters; raw binary must not go straight to interactive terminal.
- A multipart request may contain text and file bytes. Default history listing never reads its body. No implicit decompression, MIME heuristics presented as certainty, line-ending normalization or replay mutations.
- `provenance`: include `instance_id/project_id`, history ID when available, the selected final-request or response representation, and its preview/export transformation for commands returning evidence. Montoya parsed HTTP/2 is not proof of exact network wire bytes.
- Default metadata omits headers and bodies. The extension controls raw permission; `--raw` grants no extra rights. Authorized raw exports preserve bytes.

## 6. Resource limits

| Limit | Implemented limit | Rationale |
|---|---|---|
| CLI `history list --limit` | 10; hard max 100 | Agent context stays small; not backend early-stop claim |
| Control JSON frame | 256 KiB payload | Avoid big eager control buffers |
| Raw data frame | 64 KiB | Bounded copies and write buffer |
| `--body-max-bytes` preview | 4 KiB default; 64 KiB maximum | Do not dump upload/body by default |
| Raw export | 32 MiB maximum | Separate from control output budget |
| Total rendered text | 32 KiB default; 256 KiB maximum | Token and terminal guard |
| Concurrent expensive history scans | 1 | Prefer RAM/GUI stability to seconds latency |
| Screenshot image / encoded PNG | 4,194,304 pixels / 8 MiB | Reject oversized views; never silently scale or truncate |
| Screenshot capture/export | 1 per instance | Hold permit through rendering, encoding and transfer |
| Screenshot EDT wait | 2 seconds | Cancel queued capture; an already-running paint may finish later |
| Request workers | At most 2, no work queue; 1 overload worker | Bounded concurrency |
| Connection / history callback deadline | 30 seconds / 20 seconds | Does not guarantee cancellation of Montoya |
| In-flight binary stream | 1 per connection | Simple and bounded |
| Files on disk | Only rendezvous metadata and explicit user exports | No history cache or indexing |

These bounds cover protocol output, accepted results and extension-owned buffers. Montoya may traverse the entire history and allocate additional memory. They do not bound JVM peak heap.

## 7. CLI command grammar

```text
burpctl [--instance ID] [--format compact|json] [--max-bytes N] <command> [<subcommand>] [args/options]
```

- Command namespaces follow actual capabilities; no `--action=list|get|stats` mega-switch.
- `--fields` is per-operation; no generic arbitrary nested reflection. Explicit field allowlist, documented defaults.
- Global `--format compact|json`, default `compact`. There is no `--json` alias.
- Stdout is only data. Stderr is human diagnostics; exit code reflects failure. A successful empty query still exits 0. Avoid ANSI colors in non-TTY output. No banners/progress in machine-readable output.
- Raw requires `--output PATH` by default; no piping raw bytes to untrusted console. Output path resolved on CLI side, not accepted as arbitrary write path in Extension.
- `history get <id>` requires `--instance` and `--project-id` from the source result. `status` reports the current instance and project IDs.
- List filters are `--host`, `--method`, `--status` and `--path-contains`. Unsupported fields, flags and combinations fail explicitly. History list filters do not inspect bodies or accept regex. `history match` separately searches one explicitly selected representation for literal bytes.

### Examples

```powershell
burpctl status --format json
burpctl instance list
burpctl history list --limit 10 --fields id,method,path,status
burpctl history list --status 500 --host example.com --fields id,path,status --format json
burpctl --instance INSTANCE history get 123 --project-id PROJECT --fields id,status
burpctl --instance INSTANCE history get 123 --project-id PROJECT --part request.body --raw --output upload.bin
burpctl scope check https://example.com/admin
burpctl --instance INSTANCE repeater screenshot --output repeater.png
burpctl --instance INSTANCE history stats --host example.com --by status
burpctl --instance INSTANCE history endpoints --host example.com --limit 20 --fields method,path,count,sample_id
burpctl --instance INSTANCE history match 123 --project-id PROJECT --part response.body --text "example"
burpctl --instance INSTANCE sitemap issues list --host example.com --severity high
burpctl --instance INSTANCE sitemap issues get ISSUE --project-id PROJECT --fields name,detail
burpctl --instance INSTANCE repeater open 123 --project-id PROJECT --name "Review"
```

### Exit codes

| Exit | Meaning |
|---|---|
| `0` | Completed, including an empty list |
| `2` | CLI argument or option misuse |
| `3` | No/ambiguous/stale instance or reference |
| `4` | Permission, authentication or scope failure |
| `5` | Unsupported feature/edition or IPC protocol incompatibility |
| `6` | Busy, time/resource/output limit exceeded |
| `7` | IO/protocol failure or incomplete binary stream |
| `1` | Other controlled operation failure |

Stderr error messages include stable error code; JSON mode emits valid structured error on stdout ONLY when there was a valid server response and output format is JSON; do not mix partial success JSON with a diagnostic suffix.

## 8. Authorization model

Java enforces authentication, instance/project context, operation-specific permissions, history scope, output/body/image budgets and concurrency. Handcrafted IPC requests pass through the same dispatcher and policy as official CLI requests. There is no `--unsafe` bypass.

Permissions are configured in a Montoya settings panel inside Burp Settings (search for `BurpCTL`). They remain in memory and reset on extension reload; there is no suite tab or settings persistence. Disabling metadata also revokes raw access and Repeater-open permission; disabling raw revokes Repeater-open permission. The panel is created once on the EDT when Burp requests its component; it has no polling or history queries.

Status and scope checks require authentication. Stats/endpoints use the history metadata grant without reading bodies. History requires metadata permission and in-scope rows; byte retrieval also requires raw permission. Scope membership does not establish engagement authorization. The CLI writes an export only when the operator supplies an output path.

Screenshots require the independent `repeater_screenshot` permission (Settings: “Allow Repeater screenshots”), off by default and revoked on unload. This is a sensitive UI read, not a scope-filtered HTTP query: Montoya does not expose the selected Repeater request, so the extension cannot verify its scope. The opt-in permits Repeater pane content while its main tool is active or hidden, including headers, bodies, tab labels and out-of-scope data. History permissions remain independent. No URL supplied by a client is accepted as proof of the displayed request's identity or scope.

Scanner issue reads require the independent `sitemap_issues` grant, off by default. It permits potentially sensitive issue metadata, HTML detail and remediation for in-scope issue base URLs, but never attached HTTP messages or Collaborator interactions. This build conservatively gates them to Professional; live API behavior still requires verification.

Opening Repeater requires `repeater_open`, metadata and raw grants, all off by default. The CLI selects an existing history ID with source context; no arbitrary request file, host override or external input is accepted. The extension checks scope, project, size (32 MiB selected request) and grants immediately before `sendToRepeater(finalRequest,name)`. This call runs on a request worker and leaves network sending to the user. It can create a tab even if a later timeout/project change prevents a successful response; do not auto-retry. Screenshot remains independent.

### Operation contracts

All requests require the complete envelope. JSON numbers are signed 64-bit integers; duplicate keys, invalid UTF-8/Unicode, trailing documents, more than 16 nesting levels, and arrays/objects over 1,024 members are rejected. Major/minor must be exactly 1/0 in this implementation. Control payloads are capped at 262,144 bytes. Framing failures without a trustworthy ID close the connection.

Every operation accepts `params.max_bytes` (1,024 to 262,144; default 32,768), covering the encoded control response. The CLI also caps rendered output including its newline and escapes terminal controls in both formats. Raw export bytes have a separate 32 MiB hard limit. Unknown envelope/parameter/filter/field keys fail.

| RPC | Params besides `max_bytes` | Result / policy |
|---|---|---|
| `status` | None | Instance/project IDs, extension/Burp versions, methods and permissions; CLI adds its own version. No project name/path by default. |
| `scope.check` | Required `url`: HTTP(S), host required, at most 4,096 characters, no credentials/fragment/control characters | `{url,in_scope}`; authenticated membership query; no target traffic. |
| `history.list` | `limit`: 1 to 100, default 10; `fields`; `filters` with exact case-insensitive `host`, exact case-sensitive `method`, HTTP `status` 100 to 599, literal `path_contains` | `{items:[...]}`; metadata permission plus per-row scope; one expensive operation at a time. |
| `history.get` | Required `id`: 0 to 2,147,483,647; optional `fields`; optional `part`, `encoding`, `body_max_bytes` | `{item:{...}}` or approved stream; metadata permission; selected message/bytes additionally require raw permission. |
| `history.stats` | Optional `filters` (same as list), `by=status|method` (default status) | `{by,matched,buckets}`; metadata and scope, full on-demand traversal with fixed buckets. |
| `history.endpoints` | Optional `filters`, `limit` 1–100 (default 20), `fields` | `{items:[...]}`; metadata and scope, bounded unique service/method/path keys and sample references. |
| `history.match` | Required `id`, `part`, exactly one of `text` or `base64`; optional `scan_max_bytes` 1–1,048,576 (default 65,536), `context_bytes` 0–256 (default 0) | `{matched,offset,inspected_bytes,size_bytes,search_complete}` plus optional bounded Base64 snippet; metadata/raw, scope, explicit source context. |
| `sitemap.issues.list` | Optional `limit` 1–100 (default 10), `host`, `severity`, `confidence`, `fields` | `{items:[...]}`; independent issues grant, per-issue scope, Professional only. |
| `sitemap.issues.get` | Required 64-character lowercase hex `id`; optional `fields` | `{item:{...}}`; issues grant, scope, Professional; explicit source instance/project required by CLI. Duplicate metadata references fail. |
| `repeater.open` | Required history `id`; optional `name` (nonblank, at most 80 characters, no ISO controls) | `{opened:true,history_id}`; metadata/raw plus separate Repeater-open grant, scope, explicit source context. Creates a tab without sending HTTP. |
| `repeater.screenshot` | None | Approved PNG stream; independent screenshot permission; current Repeater view in the main Burp window only. CLI requires `--output`; optional `--force`. |

Derived history operations share the single expensive-query permit with history list/get/exports and issue reads. Stats/endpoints use `proxy().history(filter)` callbacks that aggregate and return false, avoiding a second retained result List. Callback state is synchronized for possible parallel invocation; this does not constrain Montoya's own traversal or allocations. Every matching row is scope-checked. Deadline is 20 seconds; expiration or revoked permission fails rather than publishing partial counts. No result is an atomic snapshot of a changing project.

Stats return observed `matched` and counts grouped by exact status (100–599 plus `no_response` and `OTHER`) or fixed standard methods (`GET,HEAD,POST,PUT,DELETE,CONNECT,OPTIONS,TRACE,PATCH` plus `OTHER`). No arbitrary group keys, body access, total-history claim or cache. Empty counts succeed. `meta.atomic_snapshot=false`.

Endpoints use exact method, case-folded service host, port, TLS and path without query as the unique key. Fields/defaults: `method,host,port,secure,path,count,sample_id`. `sample_id` is an arbitrary contributing history ID, not latest. At most `limit` keys are retained; an additional distinct key sets `meta.truncated=true` and `inventory_complete=false`. Counts continue for retained keys through the traversal, not just the first N rows. No exact total unique count or pagination is claimed. Method/host/path strings are capped at 64/1,024/8,192 characters; the retained sample scope URL is capped at 8,192. Overlong values fail `RESOURCE_LIMIT`, never normalize or truncate evidence paths. Query variants collapse into one key. Sample scope is rechecked before output; concurrent changes remain outside an atomic-snapshot guarantee.

Match uses an exact byte needle: UTF-8 encoded `text` or decoded `base64`, length 1–4,096 bytes, no regex/case folding. KMP scans up to `scan_max_bytes` without copying the full message and stops on the first match. `offset` is zero-based or null. `search_complete=true` means a match was established or the whole representation was inspected; negative results with false apply only to the inspected prefix. `meta.truncated` reports uninspected bytes even after a positive match. Optional context returns `snippet`, `snippet_encoding:base64`, `snippet_offset`, at most 512 bytes within the allowed prefix; it may omit part of a long match. No snippet by default. The existing 32 MiB representation cap and missing-response errors apply; Montoya may materialize more than the scan prefix. Scope and raw permission are rechecked after search. Provenance includes source history ID, representation and `literal_byte_match` transformation.

Issue list fields/defaults are `id,name,host,path,severity,confidence`; optional `port,secure`. Get additionally allows `detail,remediation`, with defaults `id,name,severity,confidence,detail,remediation`. Detail/remediation remain nullable HTML strings; they are untrusted data. Metadata strings are capped at 8,192 characters, detail/remediation at 65,536; over-budget output fails, never silently truncates. List filters are exact case-insensitive `host`, lowercase severity (`high,medium,low,information,false_positive`) and confidence (`certain,firm,tentative`), combined with AND. Scope uses each issue's validated HTTP(S) `baseUrl`; output path omits query. No scan is started.

Montoya has no public stable audit-issue ID. Issue reference is lowercase SHA-256 of UTF-8 compact JSON array `[name,baseUrl,typeIndex,severity.name(),confidence.name(),service.host(),service.port(),service.secure()]`. It is metadata-derived, not a stable finding UUID. CLI get requires original `--instance` and `--project-id`. Metadata changes can yield `NOT_FOUND`; multiple distinct records with that fingerprint yield `AMBIGUOUS_REFERENCE` (exit 3), never an arbitrary detail. Duplicate callbacks for the same Java object are ignored for get. No ordinal, persistent identity cache or attached HTTP data is used. Get metadata always includes `issue_id` independently of field projection. List may expose duplicate fingerprints. Get scans to establish uniqueness before reading detail.

Issue queries aggregate through `siteMap().issues(filter)` with `node.issues()` inside a serialized predicate and return false to avoid an additional matching-issues List. The returned metadata/detail buffers are bounded; node issue Lists and internal API allocation remain unbounded by CLI flags. The 20-second callback deadline, shared permit, permission and project checks apply. List selection cap is not proof of additional findings; live callback semantics and edition support are integration gates.

Screenshot discovery starts from the documented `suiteFrame()` and inspects standard Swing containers on the EDT. It requires a unique main tab pane containing the exact English titles `Target`, `Proxy`, `Repeater`, and obtains the Repeater component directly without selecting it. Detached, minimized or unrecognized layouts fail `FEATURE_UNAVAILABLE`; a Repeater component with no usable dimensions also fails and asks the operator to open it once. Tree traversal is capped at 8,192 component/title visits and depth 32. The existing component dimensions/layout are used even when the main Repeater tab is hidden; no layout or visibility is forced. Only that viewport area is rendered; offscreen scrolled content and desktop overlays are excluded. The command does not navigate tabs, change viewport/layout or send traffic.

PNG stream metadata includes `media_type:image/png`, width/height, `representation:repeater_viewport`, `transformation:swing_rendered_png` and instance/project provenance. This is a Swing-rendered view, not raw HTTP evidence or a desktop pixel capture. Rendering briefly occupies the EDT; PNG encoding and IPC/file I/O run off the EDT. Encoding uses memory-only ImageIO streams, not disk caches. Queued timed-out captures are canceled; the permit stays held until the EDT runnable drains, so further captures can return `BUSY`. Pixel/PNG limits do not guarantee paint duration, provider allocation bounds or immediate cancellation of custom UI painting. Screenshot permission and source project are rechecked during rendering and before every stream chunk.

Metadata field allowlist: `id,method,host,path,status,has_response,port,secure`; defaults `id,method,host,path,status`. `path` uses `finalRequest().pathWithoutQuery()` to omit potentially sensitive query values; `path_contains` uses the same representation. Response metadata is accessed only when required by selected fields or filters. Scope validation necessarily accesses request URL metadata.

For a selected `part=request|response|request.body|response.body`, field allowlist/defaults are `size_bytes,returned_bytes,encoding,data,truncated`. `encoding=utf8|base64|raw`, default `utf8`; `body_max_bytes` defaults to 4,096, maximum 65,536. Invalid UTF-8 in the selected prefix fails; even a cut mid-character is not decoded lossily. `raw` rejects fields/preview limits and requires CLI `--output`. Without `part`, encoding and body limits are invalid. Missing response is `NOT_FOUND` for response retrieval; metadata status is null.

History responses carry source identity in outer `meta.provenance`. Byte responses also carry representation, transformation, history ID, original/returned byte counts and encoding even with narrow field projection. `history get ID` requires both `--instance INSTANCE` and `--project-id PROJECT`; context is never inferred for numeric evidence references. A changed project ID requires extension reload; old references fail rather than being remapped.

The live callback spike observed serial callbacks on Burp Professional 2026.10. An atomic acceptance counter caps the returned List independently of callback ordering; parallel fixture callbacks also passed. Neither observation establishes a permanent Montoya threading/ordering guarantee. Recheck scope before projecting or streaming; raw streams retain the single history permit until completion. Bodies are obtained once and copied with `getByte` into at most 64 KiB IPC chunks; Montoya materialization is outside that additional-allocation bound.

The runtime uses a blocking acceptor, at most two request workers, no work queue, and one short-lived overload worker that authenticates and returns `BUSY`. When even that worker is occupied, new sockets close. Idle workers expire. Unload closes listener, clients and selectors, revokes history permissions, cancels workers and removes only owned files; a blocking Montoya call is not guaranteed cancelable.

Java connection deadline is 30 seconds, history callback deadline 20 seconds, overload decoding 1 second. The CLI has a 30-second framing/stream deadline; discovery budgets 3 seconds overall and at most 1 second per status probe. Deadlines do not guarantee interruption of Montoya or an OS-level blocking connect/file operation. Timeouts/busy probes are not silently treated as a stale instance, preventing accidental selection among incompletely checked instances.

Raw opening/end controls include protocol version and request ID. The client rejects extra frames, wrong count/hash, EOF or stream error, and cleans `.part` files on failure. Exports do not overwrite without `--force`; no export path is sent to Java. Tiny ephemeral rendezvous files are the only production writes without an explicit export.

The client validates exclusive response variants: a normal success requires an object result and completion metadata, an error requires code/message/retryable, and a raw export success requires an opening stream followed by verified bytes and a terminal control. A normal success cannot complete a requested raw export. The extension display name is `BurpCTL`; status reports the JAR's `Implementation-Version` build metadata. Source-classpath development runs report `development`. Product versions and IPC protocol versions are independent; the IPC version remains 1.0.

## 9. Protocol change discipline

- Keep the v1 envelope and error semantics stable. Specify and verify compatibility before introducing a new protocol version; the current implementation accepts only 1.0.
- This reference and the golden JSON/frame vectors under `protocol/examples` define the contract. Update them together when behavior changes.
- Compatible CLI/server versions should be reported by `status`. Reject incompatible majors with actionable error.
- The v1 service has no MCP adapter.

## References

- Java 21 AF_UNIX NIO: https://docs.oracle.com/en/java/javase/21/core/internet-protocol-and-unix-domain-sockets-nio-example.html
- Rust Windows UDS crate: https://docs.rs/uds_windows/latest/uds_windows/
- Javadoc Montoya: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html
- Burp Extension lifecycle: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/extension/Extension.html
- CLI patterns: https://clig.dev/ and https://cli.github.com/manual/gh_help_formatting
