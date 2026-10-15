mod instance;
mod ipc;
mod private_files;
mod strict_json;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = env!("CARGO_PKG_DESCRIPTION")
)]
struct Cli {
    /// Full live instance ID from instance list.
    #[arg(long, global = true)]
    instance: Option<String>,
    /// Result rendering; JSON preserves the protocol envelope.
    #[arg(long, global = true, value_enum, default_value = "compact")]
    format: Format,
    /// Maximum control/result output bytes, including rendered newline.
    #[arg(long, global = true, default_value_t = 32768, value_parser = clap::value_parser!(u32).range(1024..=262144))]
    max_bytes: u32,
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Compact,
    Json,
}
#[derive(Subcommand)]
enum Command {
    /// Report authenticated extension, Burp and project identity.
    Status,
    /// Read authorized in-scope proxy history on demand.
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    /// Capture the Repeater pane without switching tools or sending traffic.
    Repeater {
        #[command(subcommand)]
        command: RepeaterCommand,
    },
    /// Check Burp scope membership without sending traffic.
    Scope {
        #[command(subcommand)]
        command: ScopeCommand,
    },
    /// Discover live authenticated Burp instances.
    Instance {
        #[command(subcommand)]
        command: InstanceCommand,
    },
}
#[derive(Subcommand)]
enum HistoryCommand {
    /// Return up to N metadata rows; ordering and traversal length are unspecified.
    List {
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
        /// Comma-separated fields; metadata: id,method,host,path,status,has_response,port,secure.
        #[arg(long, value_delimiter = ',')]
        fields: Option<Vec<String>>,
        /// Exact service host, matched without case.
        #[arg(long)]
        host: Option<String>,
        /// Exact final-request method (case-sensitive).
        #[arg(long)]
        method: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(u16).range(100..=599))]
        status: Option<u16>,
        /// Literal substring of path without its query string.
        #[arg(long)]
        path_contains: Option<String>,
    },
    /// Retrieve one ID using explicit source instance and project identity.
    Get {
        #[arg(value_parser = clap::value_parser!(u32).range(0..=2147483647))]
        id: u32,
        /// Source project ID from history provenance; --instance is also required.
        #[arg(long)]
        project_id: String,
        /// Comma-separated fields; metadata: id,method,host,path,status,has_response,port,secure.
        #[arg(long, value_delimiter = ',')]
        fields: Option<Vec<String>>,
        /// Explicit byte selection; fields: size_bytes,returned_bytes,encoding,data,truncated.
        #[arg(long, value_enum)]
        part: Option<Part>,
        #[arg(
            long,
            requires = "part",
            conflicts_with = "base64",
            requires = "output"
        )]
        raw: bool,
        #[arg(long, requires = "part", conflicts_with = "raw")]
        base64: bool,
        #[arg(long, requires = "part", conflicts_with = "raw", value_parser = clap::value_parser!(u32).range(1..=65536))]
        body_max_bytes: Option<u32>,
        /// Publish this file only after byte-count and SHA-256 verification.
        #[arg(long, requires = "raw")]
        output: Option<PathBuf>,
        /// Allow replacement of an existing explicit destination.
        #[arg(long, requires = "output")]
        force: bool,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum Part {
    Request,
    Response,
    #[value(name = "request.body")]
    RequestBody,
    #[value(name = "response.body")]
    ResponseBody,
}
impl Part {
    fn name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::RequestBody => "request.body",
            Self::ResponseBody => "response.body",
        }
    }
}
#[derive(Subcommand)]
enum ScopeCommand {
    Check { url: String },
}
#[derive(Subcommand)]
enum RepeaterCommand {
    /// Save the current main-window Repeater view as a verified PNG.
    Screenshot {
        #[arg(long)]
        output: PathBuf,
        /// Allow replacement of an existing explicit destination.
        #[arg(long)]
        force: bool,
    },
}
#[derive(Subcommand)]
enum InstanceCommand {
    List,
}
fn code_exit(code: &str) -> i32 {
    match code {
        "INVALID_ARGUMENT" => 2,
        "INSTANCE_NOT_FOUND" | "AMBIGUOUS_INSTANCE" | "STALE_REFERENCE" => 3,
        "AUTH_FAILED" | "PERMISSION_DENIED" | "OUT_OF_SCOPE" => 4,
        "FEATURE_UNAVAILABLE" | "INCOMPATIBLE_PROTOCOL" | "UNKNOWN_METHOD" => 5,
        "BUSY" | "TIMEOUT" | "RESOURCE_LIMIT" | "OUTPUT_LIMIT" => 6,
        "IPC_ERROR" | "PARTIAL_TRANSFER" => 7,
        _ => 1,
    }
}
fn run(cli: &Cli) -> Result<Value, &'static str> {
    let instances =
        instance::discover(cli.instance.as_deref()).map_err(|error| match error.kind() {
            std::io::ErrorKind::Unsupported => "FEATURE_UNAVAILABLE",
            std::io::ErrorKind::PermissionDenied => "PERMISSION_DENIED",
            std::io::ErrorKind::WouldBlock => "BUSY",
            std::io::ErrorKind::TimedOut => "TIMEOUT",
            std::io::ErrorKind::InvalidInput => "STALE_REFERENCE",
            _ => "IPC_ERROR",
        })?;
    if matches!(cli.command, Command::Instance { .. }) {
        if cli.instance.is_some() {
            return Err("INVALID_ARGUMENT");
        }
        let items: Vec<Value> = instances.iter().map(|instance| json!({
            "instance_id":instance.metadata["instance_id"],"project_id":instance.metadata["project_id"],
            "protocol_major":instance.metadata["protocol_major"]})).collect();
        return Ok(
            json!({"version":{"major":1,"minor":0},"id":"local","ok":true,"result":{"items":items},"meta":{"complete":true,"truncated":false}}),
        );
    }
    if let Command::History {
        command: HistoryCommand::Get { project_id, .. },
    } = &cli.command
    {
        if cli.instance.is_none() {
            return Err("INVALID_ARGUMENT");
        }
        if !instances.iter().any(|instance| {
            instance.metadata["instance_id"].as_str() == cli.instance.as_deref()
                && instance.metadata["project_id"].as_str() == Some(project_id)
        }) {
            return Err("STALE_REFERENCE");
        }
    }
    let instance = if let Some(id) = &cli.instance {
        instances
            .iter()
            .find(|instance| instance.metadata["instance_id"].as_str() == Some(id))
            .ok_or("INSTANCE_NOT_FOUND")?
    } else {
        match instances.len() {
            0 => return Err("INSTANCE_NOT_FOUND"),
            1 => &instances[0],
            _ => return Err("AMBIGUOUS_INSTANCE"),
        }
    };
    let (method, params) = match &cli.command {
        Command::History {
            command:
                HistoryCommand::List {
                    limit,
                    fields,
                    host,
                    method,
                    status,
                    path_contains,
                },
        } => {
            let mut filters = json!({});
            for (name, value) in [
                ("host", host),
                ("method", method),
                ("path_contains", path_contains),
            ] {
                if let Some(value) = value {
                    filters[name] = json!(value);
                }
            }
            if let Some(value) = status {
                filters["status"] = json!(value);
            }
            let mut params = json!({"limit":limit,"filters":filters,"max_bytes":cli.max_bytes});
            if let Some(value) = fields {
                params["fields"] = json!(value);
            }
            ("history.list", params)
        }
        Command::History {
            command:
                HistoryCommand::Get {
                    id,
                    fields,
                    part,
                    raw,
                    base64,
                    body_max_bytes,
                    ..
                },
        } => {
            let mut params = json!({"id":id,"max_bytes":cli.max_bytes});
            if let Some(value) = fields {
                params["fields"] = json!(value);
            }
            if let Some(part) = part {
                params["part"] = json!(part.name());
                params["encoding"] = json!(if *raw {
                    "raw"
                } else if *base64 {
                    "base64"
                } else {
                    "utf8"
                });
                if let Some(maximum) = body_max_bytes {
                    params["body_max_bytes"] = json!(maximum);
                }
            }
            if *raw && fields.is_some() {
                return Err("INVALID_ARGUMENT");
            }
            ("history.get", params)
        }
        Command::Scope {
            command: ScopeCommand::Check { url },
        } => ("scope.check", json!({"url":url,"max_bytes":cli.max_bytes})),
        Command::Repeater {
            command: RepeaterCommand::Screenshot { .. },
        } => ("repeater.screenshot", json!({"max_bytes":cli.max_bytes})),
        _ => ("status", json!({"max_bytes":cli.max_bytes})),
    };
    let destination = match &cli.command {
        Command::History {
            command:
                HistoryCommand::Get {
                    output: Some(output),
                    force,
                    ..
                },
        } => Some((output, force)),
        Command::Repeater {
            command: RepeaterCommand::Screenshot { output, force },
        } => Some((output, force)),
        _ => None,
    };
    let export = if let Some((output, force)) = destination {
        if !*force && output.try_exists().map_err(|_| "IPC_ERROR")? {
            return Err("INVALID_ARGUMENT");
        }
        Some(ipc::ExportOptions {
            output: output.clone(),
            force: *force,
        })
    } else {
        None
    };
    let mut response = instance
        .call_export(method, params, export.as_ref())
        .map_err(|error| {
            if ipc::is_partial(&error) {
                "PARTIAL_TRANSFER"
            } else if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                "TIMEOUT"
            } else {
                "IPC_ERROR"
            }
        })?;
    if matches!(cli.command, Command::Status) && response["ok"] == true {
        response["result"]["cli_version"] = json!(env!("CARGO_PKG_VERSION"));
    }
    Ok(response)
}
fn safe_terminal(value: String) -> String {
    let unsafe_char = |ch: char| {
        ch.is_control()
            || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    };
    let Some((offset, _)) = value.char_indices().find(|(_, ch)| unsafe_char(*ch)) else {
        return value;
    };
    let mut result = String::with_capacity(value.len());
    result.push_str(&value[..offset]);
    for ch in value[offset..].chars() {
        if unsafe_char(ch) {
            result.push_str(&format!("\\u{:04x}", ch as u32));
        } else {
            result.push(ch);
        }
    }
    result
}
fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(response) => {
            let ok = response["ok"] == true;
            let display = match cli.format {
                Format::Json => safe_terminal(response.to_string()),
                Format::Compact => {
                    let mut result = response.get("result").unwrap_or(&response).clone();
                    if response["meta"].get("provenance").is_some() {
                        result["meta"] = response["meta"].clone();
                    }
                    safe_terminal(result.to_string())
                }
            };
            if display.len() + 1 > cli.max_bytes as usize {
                eprintln!("OUTPUT_LIMIT: result exceeds output budget");
                std::process::exit(6);
            }
            if ok || matches!(cli.format, Format::Json) {
                println!("{display}");
            }
            if !ok {
                let code = response["error"]["code"]
                    .as_str()
                    .unwrap_or("INTERNAL_ERROR");
                let message = response["error"]["message"]
                    .as_str()
                    .unwrap_or("command failed");
                eprintln!(
                    "{}: {}",
                    safe_terminal(code.to_owned()),
                    safe_terminal(message.to_owned())
                );
                std::process::exit(code_exit(code));
            }
        }
        Err(code) => {
            let message = match code {
                "AMBIGUOUS_INSTANCE" => "select --instance from instance list",
                "INSTANCE_NOT_FOUND" => {
                    "no matching live authenticated instance; check extension load and runtime files"
                }
                "STALE_REFERENCE" => {
                    "instance or project changed; obtain a fresh history reference"
                }
                "PERMISSION_DENIED" => {
                    "runtime files must belong to the current user with private permissions"
                }
                "PARTIAL_TRANSFER" => "export incomplete; no destination was published",
                "INVALID_ARGUMENT" => {
                    "check options and source context; an existing export requires --force"
                }
                "FEATURE_UNAVAILABLE" => "check platform and runtime support",
                "BUSY" => "instance is busy; retry or select an explicit instance",
                "TIMEOUT" => "IPC deadline exceeded; backend completion is unknown",
                _ => "command failed",
            };
            eprintln!("{code}: {message}");
            std::process::exit(code_exit(code));
        }
    }
}

#[cfg(test)]
mod output_checks {
    use super::safe_terminal;

    #[test]
    fn terminal_output_reuses_safe_text_and_escapes_controls() {
        let plain = String::from("{\"path\":\"/café\"}");
        let original_buffer = plain.as_ptr();
        let safe = safe_terminal(plain);
        assert_eq!(safe, "{\"path\":\"/café\"}");
        assert_eq!(safe.as_ptr(), original_buffer);
        assert_eq!(
            safe_terminal("café\u{202e}x\n\u{001b}y\u{2069}".to_owned()),
            "café\\u202ex\\u000a\\u001by\\u2069"
        );
    }
}
