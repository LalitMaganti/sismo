// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Node/V8 heap-snapshot trigger for the `memory-deep` focus preset.
//!
//! Node opens its inspector on SIGUSR1 (127.0.0.1:9229), after which the
//! DevTools protocol's `HeapProfiler.takeHeapSnapshot` streams the
//! `.heapsnapshot` JSON back as `addHeapSnapshotChunk` notifications. This
//! module is a dependency-free client for exactly that flow: signal, poll the
//! port, `GET /json/list` for the WebSocket URL, then a minimal RFC 6455
//! client that unescapes the chunk strings straight to the destination file.
//!
//! Caveats, accepted for v1: the port is the default 9229 (a second Node
//! process would race for it); the inspector stays listening afterwards
//! (there is no protocol to close it); and the dump pauses the JS thread for
//! its duration, like every V8 snapshot.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const INSPECTOR_ADDR: &str = "127.0.0.1:9229";

/// Whether `path`'s basename looks like a Node binary.
pub fn is_node_exe(exe_basename: &str) -> bool {
    let b = exe_basename.to_ascii_lowercase();
    b == "node" || b.starts_with("node-") || b == "node.exe"
}

/// Trigger a heap snapshot of Node `pid` into `dest`. Returns the snapshot
/// size in bytes on success.
pub fn take_heap_snapshot(pid: i32, dest: &str) -> Option<u64> {
    // SIGUSR1 asks Node to start the inspector; harmless if already running.
    if unsafe { libc::kill(pid, libc::SIGUSR1) } != 0 {
        eprintln!("v8 heap dump: kill(SIGUSR1) failed for pid {pid}");
        return None;
    }
    let ws_path = match wait_for_inspector(Duration::from_secs(3)) {
        Some(p) => p,
        None => {
            eprintln!("v8 heap dump: inspector did not open on {INSPECTOR_ADDR} (is pid {pid} a Node process?)");
            return None;
        }
    };
    match snapshot_over_ws(&ws_path, dest) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            eprintln!("v8 heap dump: {e}");
            let _ = std::fs::remove_file(dest);
            None
        }
    }
}

/// Poll until the inspector answers `/json/list`, returning the WebSocket
/// path (the part after host:port).
fn wait_for_inspector(timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(url) = query_ws_url() {
            // ws://127.0.0.1:9229/<uuid> — keep the path.
            let path = url.splitn(4, '/').nth(3).map(|p| format!("/{p}"))?;
            return Some(path);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `GET /json/list` → the `webSocketDebuggerUrl` value, if the server is up.
/// Reads incrementally and stops as soon as the URL appears: Node's inspector
/// server ignores `Connection: close`, so waiting for EOF would just time out.
fn query_ws_url() -> Option<String> {
    let mut sock = TcpStream::connect(INSPECTOR_ADDR).ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok()?;
    sock.write_all(b"GET /json/list HTTP/1.1\r\nHost: 127.0.0.1:9229\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut body = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut tmp = [0u8; 4096];
    while Instant::now() < deadline {
        match sock.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                body.extend_from_slice(&tmp[..n]);
                if let Some(url) = extract_ws_url(&body) {
                    return Some(url);
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
    }
    extract_ws_url(&body)
}

fn extract_ws_url(body: &[u8]) -> Option<String> {
    let body = String::from_utf8_lossy(body);
    let key = "\"webSocketDebuggerUrl\"";
    let at = body.find(key)? + key.len();
    let rest = &body[at..];
    let open = rest.find('"')?;
    let rest = &rest[open + 1..];
    let close = rest.find('"')?;
    Some(rest[..close].to_string())
}

/// Take the snapshot over an established inspector WebSocket, writing the
/// unescaped chunks to `dest`. Returns bytes written.
fn snapshot_over_ws(ws_path: &str, dest: &str) -> Result<u64, String> {
    let mut sock = TcpStream::connect(INSPECTOR_ADDR).map_err(|e| format!("connect: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(30))).map_err(|e| e.to_string())?;
    sock.set_nodelay(true).ok();

    // RFC 6455 client handshake. The server doesn't verify key randomness;
    // any base64 of 16 bytes is a valid nonce.
    let req = format!(
        "GET {ws_path} HTTP/1.1\r\nHost: 127.0.0.1:9229\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4PEA==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    sock.write_all(req.as_bytes()).map_err(|e| format!("handshake write: {e}"))?;
    // Read headers byte-at-a-time so no frame bytes are consumed.
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        sock.read_exact(&mut b).map_err(|e| format!("handshake read: {e}"))?;
        headers.push(b[0]);
        if headers.len() > 16 * 1024 {
            return Err("handshake response too large".into());
        }
    }
    if !headers.starts_with(b"HTTP/1.1 101") {
        return Err("inspector refused the WebSocket upgrade".into());
    }

    send_text_frame(
        &mut sock,
        br#"{"id":1,"method":"HeapProfiler.takeHeapSnapshot","params":{"reportProgress":false}}"#,
    )
    .map_err(|e| format!("request write: {e}"))?;

    let mut out = std::io::BufWriter::new(std::fs::File::create(dest).map_err(|e| e.to_string())?);
    let mut written: u64 = 0;
    let mut message: Vec<u8> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if Instant::now() >= deadline {
            return Err("timed out waiting for the snapshot".into());
        }
        let (fin, opcode, payload) = read_frame(&mut sock).map_err(|e| format!("frame read: {e}"))?;
        match opcode {
            0x1 | 0x0 => {
                message.extend_from_slice(&payload);
                if !fin {
                    continue;
                }
                let msg = std::mem::take(&mut message);
                if let Some(chunk) = extract_json_string(&msg, b"\"chunk\"") {
                    out.write_all(&chunk).map_err(|e| e.to_string())?;
                    written += chunk.len() as u64;
                } else if find(&msg, b"\"id\":1").is_some() {
                    break; // the response arrives after the final chunk
                }
            }
            0x9 => send_frame(&mut sock, 0xA, &payload).map_err(|e| format!("pong: {e}"))?,
            0x8 => return Err("inspector closed the connection mid-snapshot".into()),
            _ => {}
        }
    }
    out.flush().map_err(|e| e.to_string())?;
    // Best-effort close frame; the snapshot is already on disk.
    let _ = send_frame(&mut sock, 0x8, &[]);
    Ok(written)
}

// ---- WebSocket framing -------------------------------------------------------

/// Send a masked client frame (mask key all-zeros: the XOR masking is then
/// the identity, which is spec-valid and servers accept).
fn send_frame(sock: &mut TcpStream, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut hdr = Vec::with_capacity(14);
    hdr.push(0x80 | opcode); // FIN
    let len = payload.len();
    if len < 126 {
        hdr.push(0x80 | len as u8);
    } else if len < 65536 {
        hdr.push(0x80 | 126);
        hdr.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        hdr.push(0x80 | 127);
        hdr.extend_from_slice(&(len as u64).to_be_bytes());
    }
    hdr.extend_from_slice(&[0, 0, 0, 0]); // mask key
    sock.write_all(&hdr)?;
    sock.write_all(payload)
}

fn send_text_frame(sock: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    send_frame(sock, 0x1, payload)
}

/// Read one (unmasked) server frame: (fin, opcode, payload).
fn read_frame(sock: &mut TcpStream) -> std::io::Result<(bool, u8, Vec<u8>)> {
    let mut h = [0u8; 2];
    sock.read_exact(&mut h)?;
    let fin = h[0] & 0x80 != 0;
    let opcode = h[0] & 0x0F;
    let mut len = (h[1] & 0x7F) as u64;
    if len == 126 {
        let mut ext = [0u8; 2];
        sock.read_exact(&mut ext)?;
        len = u16::from_be_bytes(ext) as u64;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        sock.read_exact(&mut ext)?;
        len = u64::from_be_bytes(ext);
    }
    if len > 512 * 1024 * 1024 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "oversized frame"));
    }
    let mut payload = vec![0u8; len as usize];
    sock.read_exact(&mut payload)?;
    Ok((fin, opcode, payload))
}

// ---- Minimal JSON helpers ------------------------------------------------------

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extract and unescape the JSON string value for `key` (e.g. `"chunk"`) from
/// a one-level message like `{"method":...,"params":{"chunk":"..."}}`.
fn extract_json_string(msg: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let at = find(msg, key)? + key.len();
    let rest = &msg[at..];
    let open = find(rest, b"\"")?;
    let rest = &rest[open + 1..];
    let mut out = Vec::with_capacity(rest.len());
    let mut i = 0;
    while i < rest.len() {
        match rest[i] {
            b'"' => return Some(out),
            b'\\' => {
                i += 1;
                match *rest.get(i)? {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'u' => {
                        let hi = parse_u16_hex(rest.get(i + 1..i + 5)?)?;
                        i += 4;
                        let cp = if (0xD800..0xDC00).contains(&hi) {
                            // Surrogate pair: expect \uDC00-\uDFFF next.
                            if rest.get(i + 1..i + 3)? != b"\\u" {
                                return None;
                            }
                            let lo = parse_u16_hex(rest.get(i + 3..i + 7)?)?;
                            i += 6;
                            0x10000 + (((hi as u32 - 0xD800) << 10) | (lo as u32 - 0xDC00))
                        } else {
                            hi as u32
                        };
                        let ch = char::from_u32(cp).unwrap_or('\u{FFFD}');
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    }
                    _ => return None,
                }
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    None // unterminated string
}

fn parse_u16_hex(s: &[u8]) -> Option<u16> {
    u16::from_str_radix(std::str::from_utf8(s).ok()?, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_extraction_unescapes() {
        // \u00e9 is e-acute; \ud83d\ude00 is a surrogate pair (emoji).
        let msg = br#"{"method":"HeapProfiler.addHeapSnapshotChunk","params":{"chunk":"{\"snapshot\":{\n\t\"x\":1}} \u00e9 \ud83d\ude00"}}"#;
        let got = extract_json_string(msg, b"\"chunk\"").expect("chunk");
        assert_eq!(got, "{\"snapshot\":{\n\t\"x\":1}} \u{e9} \u{1F600}".as_bytes());
    }

    #[test]
    fn chunk_extraction_rejects_unterminated() {
        assert!(extract_json_string(br#"{"chunk":"abc"#, b"\"chunk\"").is_none());
    }

    #[test]
    fn node_basename_matching() {
        assert!(is_node_exe("node"));
        assert!(is_node_exe("node.exe"));
        assert!(!is_node_exe("nodemon"));
        assert!(!is_node_exe("java"));
    }
}
