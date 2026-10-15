# BurpCTL

A lightweight command-line interface to Burp Suite. Query proxy history and scope, export HTTP message bytes, and capture the Repeater pane from your terminal.

BurpCTL pairs a native Rust CLI with a Java Montoya extension. Queries run on demand without a separate daemon or history cache. Filtering and field selection happen inside Burp before results reach the CLI.

## Installation

Download the CLI for your platform and the shared [burpctl-extension.jar](https://github.com/dcduc168/BurpCTL/releases/latest/download/burpctl-extension.jar) from the [latest release](https://github.com/dcduc168/BurpCTL/releases/latest).

| Platform | CLI |
|---|---|
| Windows x86_64 | [burpctl-windows-x86_64.exe](https://github.com/dcduc168/BurpCTL/releases/latest/download/burpctl-windows-x86_64.exe) |
| Linux x86_64 | [burpctl-linux-x86_64](https://github.com/dcduc168/BurpCTL/releases/latest/download/burpctl-linux-x86_64) |
| Linux ARM64 | [burpctl-linux-aarch64](https://github.com/dcduc168/BurpCTL/releases/latest/download/burpctl-linux-aarch64) |
| macOS Intel | [burpctl-macos-x86_64](https://github.com/dcduc168/BurpCTL/releases/latest/download/burpctl-macos-x86_64) |
| macOS Apple Silicon | [burpctl-macos-aarch64](https://github.com/dcduc168/BurpCTL/releases/latest/download/burpctl-macos-aarch64) |

1. Rename the CLI to `burpctl.exe` on Windows or `burpctl` on Linux/macOS, and add its directory to PATH. On Linux/macOS, make it executable with `chmod +x burpctl`.
2. Load the JAR as a Java extension in Burp. It requires Java 21 or later and Montoya 2026.7 APIs. Custom Unix runtimes must include `jdk.security.auth`.
3. Open Burp Settings, search for **BurpCTL**, and enable metadata reads for history you authorize the CLI to access. Enable raw reads separately for message and body exports.

Permissions start disabled and reset when the extension reloads. History reads also require Burp scope membership. These commands do not send target traffic or change scope.

Platform notes:

- Windows: keep the CLI on local NTFS. The MSVC build requires `VCRUNTIME140.dll`.
- Linux: binaries use GNU libc and are built on Ubuntu 24.04. Older distributions are unverified.
- macOS: binaries are not Developer ID signed or notarized; downloaded executables may require approval in macOS.

The CLI and Burp must run on the same OS. If Burp runs on Windows, invoke the Windows CLI from WSL, for example `/mnt/c/Tools/burpctl.exe status`.

## Usage

Examples use `burpctl`; `burpctl.exe` works on Windows. Start by discovering live instances:

```sh
burpctl instance list --format json
burpctl --instance INSTANCE status
```

Replace `INSTANCE` with an ID from the result. A single live instance is selected automatically; multiple instances require an explicit selection.

Filter history and choose the fields you need:

```sh
burpctl --instance INSTANCE history list --host example.com --limit 10 --fields id,method,path,status --format json
burpctl --instance INSTANCE scope check https://example.com/admin
```

Compact output is the default. Use `--format json` for the full response envelope, including evidence provenance. Stdout carries results; stderr and exit codes distinguish failures. Discover other options with `burpctl --help` or `<command> --help`.

### Export HTTP bytes

Use the row ID and `meta.provenance.instance_id` / `project_id` from the same history result. Replace `ID`, `INSTANCE` and `PROJECT` below:

```sh
burpctl --instance INSTANCE history get ID --project-id PROJECT --fields id,status
burpctl --instance INSTANCE history get ID --project-id PROJECT --part response.body --base64 --body-max-bytes 4096 --format json
burpctl --instance INSTANCE history get ID --project-id PROJECT --part request.body --raw --output evidence.bin
```

Raw exports verify the byte count and SHA-256 before publishing the file. Incomplete transfers are cleaned up; replacing an existing file requires `--force`. UTF-8 previews reject invalid sequences, while Base64 previews report truncation. Reloading the extension invalidates previous instance references.

### Capture Repeater

Enable **Allow Repeater screenshots** in BurpCTL settings, then run:

```sh
burpctl --instance INSTANCE repeater screenshot --output repeater.png
```

Capture works while another main tool is selected, provided Repeater already has a usable layout. Open Repeater once if it has not been initialized. Detached/minimized windows and unrecognized layouts are unsupported.

The PNG includes the current viewport and tab labels, which may contain sensitive or out-of-scope data. Screenshot permission is independent of history permissions and has no scope guarantee. Capture does not switch tools or send requests.

## Behavior and limits

History queries may traverse the entire collection. `--limit` caps returned rows, not Burp's internal allocations or scan time. Ordering is unspecified, `path` excludes query strings, and an empty list is a successful result.

HTTP exports preserve Montoya's message bytes. They do not preserve HTTP/2 wire framing, decompress bodies or normalize line endings. Screenshot output is a rendered view, not an HTTP evidence export.

Authentication, permissions and history scope checks run inside the extension. Runtime files use current-user Windows ACLs or private POSIX ownership and modes. These controls do not isolate BurpCTL from malicious processes running as the same user.

See the [protocol reference](protocol/SPEC.md) for fields, size budgets, runtime paths and error codes. The [Agent Skill](skills/burpctl/SKILL.md) covers instance selection and evidence retrieval for local coding agents.

To install the skill, copy the entire `skills/burpctl/` directory, including `references/`, into your agent's skill directory.

## Verification

[Release CI](.github/workflows/release.yml) builds and checks all five native targets, including authenticated Rust/Java IPC, permissions, byte integrity and unload cleanup. Fixtures use synthetic data and do not establish live Burp or UI compatibility.

Live checks have used Burp Suite Professional 2026.10 on Windows. Linux/macOS Burp integration, Community edition and real Burp on Java 21 remain unverified. Retained extension RAM and per-operation Burp peak memory have not been isolated. The [verification guide](verification/README.md) records checks and remaining integration gaps.

## Development

Use stable Rust and JDK 21, with `JAVA_HOME` set to the JDK. Build with the pinned Gradle wrapper and locked dependencies:

```sh
cargo build --manifest-path cli/Cargo.toml --release --locked
./extension/gradlew -p extension build --no-daemon
```

On Windows, use `extension\gradlew.bat -p extension build --no-daemon` and an MSVC development environment. Outputs are `cli/target/release/burpctl` (`burpctl.exe` on Windows) and `extension/build/libs/burpctl-extension.jar`.

Run the relevant [verification checks](verification/README.md) before submitting changes. Version tags trigger native GitHub builds and a draft release after all platforms pass; see the [release workflow](.github/workflows/release.yml).

Report reproducible problems in [GitHub Issues](https://github.com/dcduc168/BurpCTL/issues). Include Burp/Java versions, CLI/extension versions, the command and error code. Remove credentials and HTTP evidence before posting.

Repeater capture uses Swing component rendering, as demonstrated by [BurpSuiteSharpenerEx](https://github.com/irsdl/BurpSuiteSharpenerEx/blob/main/src/main/java/ninja/burpsuite/extension/sharpener/uiControllers/subTabs/SubTabsActions.java).
