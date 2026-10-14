use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use uds_windows::UnixStream;

pub const MAX_PAYLOAD: usize = 262144;

pub struct ExportOptions {
    pub output: std::path::PathBuf,
    pub force: bool,
}

#[derive(Debug)]
struct PartialTransfer;
impl std::fmt::Display for PartialTransfer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("PARTIAL_TRANSFER")
    }
}
impl std::error::Error for PartialTransfer {}
pub fn is_partial(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<PartialTransfer>())
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid IPC response")
}
fn read_frame(client: &mut UnixStream, deadline: Instant) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0; 4];
    read_until(client, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if !(1..=MAX_PAYLOAD + 1).contains(&length) {
        return Err(invalid());
    }
    let mut tag_buffer = [0];
    read_until(client, &mut tag_buffer, deadline)?;
    let tag = tag_buffer[0];
    if tag == 2 && length > 65537 {
        return Err(invalid());
    }
    let mut frame = vec![0; length];
    frame[0] = tag;
    read_until(client, &mut frame[1..], deadline)?;
    if tag != 1 && tag != 2 {
        return Err(invalid());
    }
    Ok((tag, frame))
}
fn control(frame: &[u8], request: &serde_json::Value) -> io::Result<serde_json::Value> {
    if frame[0] != 1 {
        return Err(invalid());
    }
    let result = crate::strict_json::parse(&frame[1..])?;
    if result.get("version") != Some(&serde_json::json!({"major":1,"minor":0}))
        || result.get("id") != request.get("id")
    {
        return Err(invalid());
    }
    Ok(result)
}
fn eof(client: &mut UnixStream, deadline: Instant) -> io::Result<()> {
    let mut trailing = [0];
    client.set_read_timeout(Some(remaining(deadline)?))?;
    if client.read(&mut trailing)? != 0 {
        return Err(invalid());
    }
    Ok(())
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "IPC deadline exceeded"))
}
fn read_until(client: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        client.set_read_timeout(Some(remaining(deadline)?))?;
        match client.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Incomplete frame",
                ));
            }
            Ok(length) => bytes = &mut bytes[length..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn write_until(client: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        client.set_write_timeout(Some(remaining(deadline)?))?;
        match client.write(bytes) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "Incomplete frame")),
            Ok(length) => bytes = &bytes[length..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
pub fn request(
    socket: &Path,
    value: &serde_json::Value,
    export: Option<&ExportOptions>,
) -> io::Result<serde_json::Value> {
    request_timeout(socket, value, export, Duration::from_secs(30))
}
pub fn request_timeout(
    socket: &Path,
    value: &serde_json::Value,
    export: Option<&ExportOptions>,
    timeout: Duration,
) -> io::Result<serde_json::Value> {
    let deadline = Instant::now() + timeout;
    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_PAYLOAD {
        return Err(invalid());
    }
    let mut client = UnixStream::connect(socket)?;
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    client.set_write_timeout(Some(Duration::from_secs(30)))?;
    write_until(
        &mut client,
        &((payload.len() + 1) as u32).to_be_bytes(),
        deadline,
    )?;
    write_until(&mut client, &[1], deadline)?;
    write_until(&mut client, &payload, deadline)?;
    let (_, frame) = read_frame(&mut client, deadline)?;
    let result = control(&frame, value)?;
    validate_response(&result, export.is_some())?;
    if result.get("stream").is_some() {
        let export = export.ok_or_else(invalid)?;
        return receive_export(&mut client, value, result, export, deadline)
            .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, PartialTransfer));
    }
    eof(&mut client, deadline)?;
    Ok(result)
}
fn validate_response(response: &serde_json::Value, export: bool) -> io::Result<()> {
    let ok = response["ok"].as_bool().ok_or_else(invalid)?;
    let allowed: &[&str] = if !ok {
        let error = &response["error"];
        if !error.is_object()
            || error["code"].as_str().is_none_or(str::is_empty)
            || !error["message"].is_string()
            || !error["retryable"].is_boolean()
        {
            return Err(invalid());
        }
        &["version", "id", "ok", "error"]
    } else if response.get("stream").is_some() {
        if !export || !response["stream"].is_object() || !response["meta"].is_object() {
            return Err(invalid());
        }
        &["version", "id", "ok", "stream", "meta"]
    } else {
        if export
            || !response["result"].is_object()
            || !response["meta"]["complete"].is_boolean()
            || !response["meta"]["truncated"].is_boolean()
        {
            return Err(invalid());
        }
        &["version", "id", "ok", "result", "meta"]
    };
    if response
        .as_object()
        .ok_or_else(invalid)?
        .keys()
        .any(|key| !allowed.contains(&key.as_str()))
    {
        return Err(invalid());
    }
    Ok(())
}
fn receive_export(
    client: &mut UnixStream,
    request: &serde_json::Value,
    opening: serde_json::Value,
    options: &ExportOptions,
    deadline: Instant,
) -> io::Result<serde_json::Value> {
    use sha2::{Digest, Sha256};
    let size = opening["stream"]["size_bytes"]
        .as_u64()
        .filter(|size| *size <= 32 * 1024 * 1024)
        .ok_or_else(invalid)?;
    if opening["stream"]["kind"] != "raw_bytes" || opening["stream"]["chunk_max"] != 65536 {
        return Err(invalid());
    }
    if !options.force && options.output.try_exists()? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Destination exists",
        ));
    }
    let parent = options
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".burpctl-")
        .suffix(".part")
        .tempfile_in(parent)?;
    let mut digest = Sha256::new();
    let mut received = 0u64;
    loop {
        let (tag, frame) = read_frame(client, deadline)?;
        if tag == 2 {
            let bytes = &frame[1..];
            if bytes.is_empty() || bytes.len() > 65536 || bytes.len() as u64 > size - received {
                return Err(invalid());
            }
            file.write_all(bytes)?;
            digest.update(bytes);
            received += bytes.len() as u64;
            continue;
        }
        let ending = control(&frame, request)?;
        let hash = format!("{:x}", digest.finalize());
        if ending
            .as_object()
            .ok_or_else(invalid)?
            .keys()
            .any(|key| !matches!(key.as_str(), "version" | "id" | "stream_end"))
            || ending["stream_end"]["complete"] != true
            || ending["stream_end"]["bytes_sent"] != received
            || received != size
            || ending["stream_end"]["sha256"].as_str() != Some(&hash)
        {
            return Err(invalid());
        }
        eof(client, deadline)?;
        file.flush()?;
        file.as_file().sync_all()?;
        if options.force {
            file.persist(&options.output).map_err(|error| error.error)?;
        } else {
            file.persist_noclobber(&options.output)
                .map_err(|error| error.error)?;
        }
        return Ok(
            serde_json::json!({"version":opening["version"],"id":opening["id"],"ok":true,
            "result":{"bytes_written":received,"sha256":hash},
            "meta":{"complete":true,"truncated":false,"provenance":opening["meta"]["provenance"],
                "representation":opening["meta"]["representation"],"transformation":"none"}}),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    #[cfg(windows)]
    use uds_windows::UnixListener;

    #[test]
    fn response_variants_cannot_report_an_export_without_a_stream() {
        let normal = serde_json::json!({"version":{"major":1,"minor":0},"id":"audit","ok":true,
            "result":{},"meta":{"complete":true,"truncated":false}});
        let error = serde_json::json!({"version":{"major":1,"minor":0},"id":"audit","ok":false,
            "error":{"code":"PERMISSION_DENIED","message":"denied","retryable":false}});
        for (reply, export, valid) in [
            (normal.clone(), false, true),
            (normal, true, false),
            (error, true, true),
            (
                serde_json::json!({"version":{"major":1,"minor":0},"id":"audit","ok":true}),
                false,
                false,
            ),
            (
                serde_json::json!({"version":{"major":1,"minor":0},"id":"audit","ok":false}),
                false,
                false,
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("s");
            let listener = UnixListener::bind(&socket).unwrap();
            let server = std::thread::spawn(move || {
                let (mut client, _) = listener.accept().unwrap();
                let (_, request) =
                    read_frame(&mut client, Instant::now() + Duration::from_secs(5)).unwrap();
                assert_eq!(request[0], 1);
                let payload = serde_json::to_vec(&reply).unwrap();
                client
                    .write_all(&((payload.len() + 1) as u32).to_be_bytes())
                    .unwrap();
                client.write_all(&[1]).unwrap();
                client.write_all(&payload).unwrap();
            });
            let options = ExportOptions {
                output: directory.path().join("evidence.bin"),
                force: false,
            };
            let response = request(
                &socket,
                &serde_json::json!({"id":"audit"}),
                export.then_some(&options),
            );
            server.join().unwrap();
            assert_eq!(response.is_ok(), valid);
            assert!(!options.output.exists());
        }
    }
}
