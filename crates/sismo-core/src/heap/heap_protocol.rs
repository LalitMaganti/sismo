// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Heap-profiler control channel, recorder side (migrated from
//! heap_protocol_posix.zig). sismo connects to the target's per-PID Unix
//! socket (`/tmp/sismo-heap-{pid}.sock`), which the heap-preload listener
//! thread binds, and sends the shm ring fd (via SCM_RIGHTS) plus a fixed
//! `AttachConfig` header. Detach = close the returned control fd (the preload
//! sees EOF and goes dormant).
//!
//! This is the recorder half; the target's Zig preload is the listener half,
//! sharing this fixed wire (AttachConfig layout + the SCM_RIGHTS framing).
//! macOS constants; the module is macOS-gated in lib.rs.

use std::os::raw::{c_int, c_void};

// macOS socket constants.
const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const SOL_SOCKET: c_int = 0xffff;
const SCM_RIGHTS: c_int = 0x01;

// cmsghdr on Darwin: u32 cmsg_len + i32 cmsg_level + i32 cmsg_type = 12 bytes;
// data follows at the usize-aligned offset (16 on 64-bit).
const CMSGHDR_BYTES: usize = 12;
const CMSG_DATA_OFFSET: usize = (CMSGHDR_BYTES + 7) & !7;

#[repr(C)]
struct SockaddrUn {
    sun_len: u8,
    sun_family: u8,
    sun_path: [u8; 104], // Darwin
}

#[repr(C)]
struct Iovec {
    base: *const c_void,
    len: usize,
}

#[repr(C)]
struct Msghdr {
    name: *mut c_void,
    namelen: u32,
    iov: *mut Iovec,
    iovlen: c_int,
    control: *mut c_void,
    controllen: u32,
    flags: c_int,
}

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    fn sendmsg(fd: c_int, msg: *const Msghdr, flags: c_int) -> isize;
    fn close(fd: c_int) -> c_int;
    fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> c_int;
}

/// First message sismo sends to the dormant client. Fixed 32 bytes, matching
/// the Zig `AttachConfig` ABI.
#[repr(C)]
pub struct AttachConfig {
    pub version: u32,
    pub ring_size: u32,
    pub sample_interval: u64,
    pub reserved: [u8; 16],
}

pub enum AttachError {
    PathTooLong,
    SocketCreate,
    Connect,
    Send,
}

/// Build `/tmp/sismo-heap-{pid}.sock` into `buf`, NUL-terminated. Returns the
/// path length (excluding NUL), or None if it doesn't fit. `/tmp` (not TMPDIR)
/// so a sudo recorder and the target agree on the path.
pub fn socket_path(pid: i32, buf: &mut [u8]) -> Option<usize> {
    let s = format!("/tmp/sismo-heap-{pid}.sock");
    let bytes = s.as_bytes();
    if bytes.len() + 1 > buf.len() || bytes.len() >= 104 {
        return None;
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;
    Some(bytes.len())
}

fn fill_sockaddr(pid: i32) -> Option<SockaddrUn> {
    let mut sa = SockaddrUn { sun_len: 0, sun_family: AF_UNIX as u8, sun_path: [0; 104] };
    let n = socket_path(pid, &mut sa.sun_path)?;
    sa.sun_len = (2 + n + 1) as u8; // Darwin sizes the addr from sun_len
    Some(sa)
}

/// Connect to the target's heap socket and send the shm fd + config. Retries
/// the connect on a 25ms cadence up to ~3s (the preload's listener binds only
/// after dyld maps the inserted dylib — later than any fixed settle). Returns
/// the control fd (close it to detach); the caller owns it.
///
/// `max_attempts` connect tries at 25ms spacing (the worker passes 120 = ~3s).
///
/// # Safety
/// `shm_fd` must be a valid open fd for the shm ring.
pub unsafe fn connect_and_attach(pid: i32, shm_fd: c_int, config: &AttachConfig, max_attempts: usize) -> Result<c_int, AttachError> {
    let sa = fill_sockaddr(pid).ok_or(AttachError::PathTooLong)?;
    let retry = Timespec { tv_sec: 0, tv_nsec: 25 * 1_000_000 };

    let fd = {
        let mut i = 0;
        loop {
            let s = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
            if s < 0 {
                return Err(AttachError::SocketCreate);
            }
            let rc = unsafe {
                connect(s, &sa as *const SockaddrUn as *const c_void, std::mem::size_of::<SockaddrUn>() as u32)
            };
            if rc == 0 {
                break s;
            }
            unsafe { close(s) };
            i += 1;
            if i >= max_attempts {
                return Err(AttachError::Connect);
            }
            unsafe { nanosleep(&retry, std::ptr::null_mut()) };
        }
    };

    // SCM_RIGHTS control buffer carrying shm_fd.
    let mut cbuf = [0u8; CMSG_DATA_OFFSET + std::mem::size_of::<c_int>()];
    // cmsg_len (u32) @0, cmsg_level (i32) @4, cmsg_type (i32) @8.
    cbuf[0..4].copy_from_slice(&((CMSG_DATA_OFFSET + 4) as u32).to_ne_bytes());
    cbuf[4..8].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
    cbuf[8..12].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
    cbuf[CMSG_DATA_OFFSET..CMSG_DATA_OFFSET + 4].copy_from_slice(&shm_fd.to_ne_bytes());

    let mut iov = Iovec {
        base: config as *const AttachConfig as *const c_void,
        len: std::mem::size_of::<AttachConfig>(),
    };
    let msg = Msghdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: &mut iov,
        iovlen: 1,
        control: cbuf.as_mut_ptr() as *mut c_void,
        controllen: cbuf.len() as u32,
        flags: 0,
    };
    let n = unsafe { sendmsg(fd, &msg, 0) };
    if n != std::mem::size_of::<AttachConfig>() as isize {
        unsafe { close(fd) };
        return Err(AttachError::Send);
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_config_is_32_bytes() {
        assert_eq!(std::mem::size_of::<AttachConfig>(), 32);
    }

    #[test]
    fn socket_path_format() {
        let mut buf = [0u8; 128];
        let n = socket_path(4242, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"/tmp/sismo-heap-4242.sock");
        assert_eq!(buf[n], 0);
    }

    #[test]
    fn connect_to_absent_socket_fails() {
        // No target listening for this pid — connect_and_attach should fail
        // cleanly (the retry loop runs, then errors). Use a low retry via a
        // pid whose socket surely doesn't exist; this exercises the sockaddr +
        // socket path. (Full send is e2e-gated — needs the preload peer.)
        let cfg = AttachConfig { version: 1, ring_size: 4096, sample_interval: 0, reserved: [0; 16] };
        // fd -1 is fine: we never reach sendmsg (connect fails first). 2 attempts
        // keeps the test fast.
        let r = unsafe { connect_and_attach(0x7FFF_FFFE, -1, &cfg, 2) };
        assert!(matches!(r, Err(AttachError::Connect)));
    }
}
