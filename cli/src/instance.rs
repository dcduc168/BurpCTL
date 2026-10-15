use crate::{ipc, private_files};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
};

pub struct Instance {
    pub metadata: Value,
    token: String,
    socket: PathBuf,
}
impl Instance {
    pub fn probe(&self, timeout: std::time::Duration) -> io::Result<Value> {
        ipc::request_timeout(
            &self.socket,
            &json!({"version":{"major":1,"minor":0},"id":"probe",
            "auth":self.token,"method":"status","params":{},
            "context":{"instance_id":self.metadata["instance_id"],"project_id":self.metadata["project_id"]}}),
            None,
            timeout,
        )
    }
    pub fn call_export(
        &self,
        method: &str,
        params: Value,
        export: Option<&ipc::ExportOptions>,
    ) -> io::Result<Value> {
        ipc::request(
            &self.socket,
            &json!({"version":{"major":1,"minor":0},"id":"r-1",
            "auth":self.token,"method":method,"params":params,
            "context":{"instance_id":self.metadata["instance_id"],"project_id":self.metadata["project_id"]}}),
            export,
        )
    }
}
fn bounded_file(path: &std::path::Path, maximum: u64) -> io::Result<Vec<u8>> {
    private_files::check(path, false)?;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Runtime file too large",
        ));
    }
    Ok(bytes)
}
pub fn discover(selected: Option<&str>) -> io::Result<Vec<Instance>> {
    let root = private_files::runtime_root()?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    private_files::check(&root, false)?;
    let runtime = root.join("r");
    private_files::check(&runtime, false)?;
    let mut instances = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    for (index, entry) in fs::read_dir(runtime)?.enumerate() {
        if index >= 128 {
            return Err(io::Error::other("Registry entry limit exceeded"));
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Discovery deadline exceeded",
            ));
        }
        let entry = entry?;
        let path = entry.path();
        if private_files::check(&path, false).is_err() {
            continue;
        }
        let read = || -> io::Result<Instance> {
            let metadata: Value =
                crate::strict_json::parse(&bounded_file(&path.join("instance.json"), 8192)?)?;
            let token = String::from_utf8(bounded_file(&path.join("credential"), 64)?)
                .map_err(|_| io::Error::other("Invalid credential"))?;
            if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(io::Error::other("Invalid credential"));
            }
            let id = metadata["instance_id"]
                .as_str()
                .ok_or_else(|| io::Error::other("Invalid identity"))?;
            if id.len() != 32
                || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
                || path.file_name().and_then(|name| name.to_str()) != Some(&id[..12])
                || !metadata["project_id"].is_string()
                || metadata["protocol_major"] != 1
            {
                return Err(io::Error::other("Invalid identity"));
            }
            let socket = path.join("s");
            if metadata["socket_path"].as_str() != socket.to_str() {
                return Err(io::Error::other("Invalid socket path"));
            }
            private_files::check(&socket, true)?;
            Ok(Instance {
                metadata,
                token,
                socket,
            })
        };
        let Ok(instance) = read() else {
            continue;
        };
        if selected.is_some_and(|id| instance.metadata["instance_id"].as_str() != Some(id)) {
            continue;
        }
        let status = match instance.probe(
            deadline
                .saturating_duration_since(std::time::Instant::now())
                .min(std::time::Duration::from_secs(1)),
        ) {
            Ok(status) => status,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(error);
            }
            Err(_) => continue,
        };
        if status["error"]["code"] == "BUSY" {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "Instance busy"));
        }
        if selected.is_some() && status["error"]["code"] == "STALE_REFERENCE" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "STALE_REFERENCE",
            ));
        }
        if status["ok"] != true
            || status["result"]["instance_id"] != instance.metadata["instance_id"]
            || status["result"]["project_id"] != instance.metadata["project_id"]
        {
            continue;
        }
        instances.push(instance);
    }
    instances.sort_by(|left, right| {
        left.metadata["instance_id"]
            .as_str()
            .cmp(&right.metadata["instance_id"].as_str())
    });
    Ok(instances)
}
