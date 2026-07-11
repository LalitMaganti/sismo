// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Heap control channel — **preload (server) side**. The preload binds the
//! per-PID socket
//! (`/tmp/sismo-heap-{pid}.sock`) at load time and blocks on `accept`; when the
//! recorder connects it sends a 32-byte `AttachConfig` + the shm ring fd via
//! SCM_RIGHTS. Detach = the recorder closes the connection (EOF on `conn_fd`).
//!
//! Wire-compatible with the recorder's connect side
//! (sismo-core/src/heap_protocol.rs). macOS constants.

use libc::{c_char, c_int, c_void};

// cmsghdr on the target: u32 len + i32 level + i32 type = 12; data at the
// usize-aligned offset (16 on 64-bit).
const CMSGHDR_BYTES: usize = 12;
const CMSG_DATA_OFFSET: usize = (CMSGHDR_BYTES + 7) & !7;

/// First message the recorder sends — fixed 32 bytes, matching the recorder's
/// `AttachConfig` ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AttachConfig {
    pub version: u32,
    pub ring_size: u32,
    pub sample_interval: u64,
    pub reserved: [u8; 16],
}

#[derive(Debug)]
pub enum ProtocolError {
    PathTooLong,
    SocketCreate,
    SocketBind,
    SocketListen,
    SocketAccept,
    RecvFailed,
    NoFdReceived,
}

/// Build `/tmp/sismo-heap-{pid}.sock` into `buf`, NUL-terminated. Returns the
/// length (excluding NUL), or None if it doesn't fit.
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

fn fill_sockaddr(pid: i32) -> Option<libc::sockaddr_un> {
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as _;
    // sun_path is [c_char; N] (104 on Darwin, 108 on Linux); write bytes into it.
    let cap = sa.sun_path.len();
    let path = unsafe { std::slice::from_raw_parts_mut(sa.sun_path.as_mut_ptr() as *mut u8, cap) };
    let n = socket_path(pid, path)?;
    // Darwin sizes the addr from sun_len; Linux has no such field (bind/connect
    // get the length via socklen_t).
    #[cfg(target_os = "macos")]
    {
        sa.sun_len = (2 + n + 1) as u8;
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = n;
    }
    Some(sa)
}

/// The bound per-PID listening socket. `close` unlinks + closes.
pub struct Listener {
    fd: c_int,
    path: [u8; 128], // NUL-terminated socket path, for unlink
}

impl Listener {
    #[allow(dead_code)]
    pub fn close(&mut self) {
        unsafe {
            libc::unlink(self.path.as_ptr() as *const c_char);
            libc::close(self.fd);
        }
    }
}

/// Bind + listen on the per-PID socket. Called once at preload load.
pub fn listen_for_attach(pid: i32) -> Result<Listener, ProtocolError> {
    let mut path = [0u8; 128];
    socket_path(pid, &mut path).ok_or(ProtocolError::PathTooLong)?;
    // Pre-clean a stale socket from a prior run.
    unsafe { libc::unlink(path.as_ptr() as *const c_char) };

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(ProtocolError::SocketCreate);
    }
    let sa = fill_sockaddr(pid).ok_or(ProtocolError::PathTooLong)?;
    let sa_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe { libc::bind(fd, &sa as *const libc::sockaddr_un as *const libc::sockaddr, sa_len) } != 0 {
        unsafe { libc::close(fd) };
        return Err(ProtocolError::SocketBind);
    }
    if unsafe { libc::listen(fd, 1) } != 0 {
        unsafe { libc::close(fd) };
        return Err(ProtocolError::SocketListen);
    }
    Ok(Listener { fd, path })
}

/// The result of a successful attach: the control connection (close ⇒ EOF ⇒
/// detach), the SCM_RIGHTS-received shm fd (caller owns), and the config.
pub struct AttachState {
    pub conn_fd: c_int,
    pub shm_fd: c_int,
    pub config: AttachConfig,
}

impl AttachState {
    #[allow(dead_code)]
    pub fn close_all(&mut self) {
        unsafe {
            libc::close(self.conn_fd);
            libc::close(self.shm_fd);
        }
    }
}

/// Block until the recorder connects + sends the handshake. Returns the config
/// + the received shm fd.
///
/// # Safety
/// `listener` must be a live listener from `listen_for_attach`.
pub unsafe fn accept_and_receive(listener: &Listener) -> Result<AttachState, ProtocolError> {
    let conn = unsafe { libc::accept(listener.fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if conn < 0 {
        return Err(ProtocolError::SocketAccept);
    }

    let mut config = AttachConfig { version: 0, ring_size: 0, sample_interval: 0, reserved: [0; 16] };
    let mut iov = libc::iovec {
        iov_base: &mut config as *mut AttachConfig as *mut c_void,
        iov_len: std::mem::size_of::<AttachConfig>(),
    };
    let mut cbuf = [0u8; CMSG_DATA_OFFSET + std::mem::size_of::<c_int>()];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut c_void;
    // msg_controllen is size_t on Linux, socklen_t on macOS; `as _` covers both.
    #[allow(clippy::unnecessary_cast)]
    {
        msg.msg_controllen = cbuf.len() as _;
    }

    let n = unsafe { libc::recvmsg(conn, &mut msg, 0) };
    if n != std::mem::size_of::<AttachConfig>() as isize {
        unsafe { libc::close(conn) };
        return Err(ProtocolError::RecvFailed);
    }
    // msg_controllen is size_t on Linux, socklen_t on macOS; normalize to usize.
    #[allow(clippy::unnecessary_cast)]
    let controllen = msg.msg_controllen as usize;
    if controllen < CMSG_DATA_OFFSET + std::mem::size_of::<c_int>() {
        unsafe { libc::close(conn) };
        return Err(ProtocolError::NoFdReceived);
    }
    let shm_fd = i32::from_ne_bytes(cbuf[CMSG_DATA_OFFSET..CMSG_DATA_OFFSET + 4].try_into().unwrap());
    if shm_fd < 0 {
        unsafe { libc::close(conn) };
        return Err(ProtocolError::NoFdReceived);
    }
    Ok(AttachState { conn_fd: conn, shm_fd, config })
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

    // Full SCM_RIGHTS roundtrip: bind a listener, connect from a thread that
    // sends an AttachConfig + a real fd, and confirm accept_and_receive gets a
    // working fd (reads back the bytes the sender wrote through it). macOS-gated:
    // exercises the whole socket roundtrip, which is the target-OS behavior (it
    // deadlocks on the Linux host's unix-socket connect semantics).
    #[cfg(target_os = "macos")]
    #[test]
    fn scm_rights_roundtrip_transfers_a_working_fd() {
        let pid: i32 = 0x5EED; // unlikely to collide with a real recorder socket
        let listener = listen_for_attach(pid).expect("listen");

        let sender = std::thread::spawn(move || {
            // Give the main thread a beat to reach accept().
            std::thread::sleep(std::time::Duration::from_millis(20));
            // A pipe whose READ end we hand over; we keep the write end.
            let mut fds = [0 as c_int; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let (rd, wr) = (fds[0], fds[1]);

            let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            let sa = fill_sockaddr(pid).unwrap();
            let sa_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
            assert_eq!(
                unsafe { libc::connect(s, &sa as *const libc::sockaddr_un as *const libc::sockaddr, sa_len) },
                0
            );
            let cfg = AttachConfig { version: 1, ring_size: 65536, sample_interval: 4096, reserved: [0; 16] };
            let mut iov = libc::iovec { iov_base: &cfg as *const AttachConfig as *mut c_void, iov_len: 32 };
            let mut cbuf = [0u8; CMSG_DATA_OFFSET + 4];
            cbuf[0..4].copy_from_slice(&((CMSG_DATA_OFFSET + 4) as u32).to_ne_bytes());
            cbuf[4..8].copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
            cbuf[8..12].copy_from_slice(&libc::SCM_RIGHTS.to_ne_bytes());
            cbuf[CMSG_DATA_OFFSET..CMSG_DATA_OFFSET + 4].copy_from_slice(&rd.to_ne_bytes());
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf.as_mut_ptr() as *mut c_void;
            msg.msg_controllen = cbuf.len() as _;
            assert_eq!(unsafe { libc::sendmsg(s, &msg, 0) }, 32);
            // Write through our end; the received fd (the read end) sees it.
            let payload = b"HEAPFD";
            unsafe { libc::write(wr, payload.as_ptr() as *const c_void, payload.len()) };
            (s, wr, rd)
        });

        let attach = unsafe { accept_and_receive(&listener) }.expect("accept");
        assert_eq!(attach.config.ring_size, 65536);
        assert_eq!(attach.config.sample_interval, 4096);
        assert!(attach.shm_fd >= 0);
        // Read through the SCM_RIGHTS-received fd → the sender's bytes.
        let mut got = [0u8; 6];
        let n = unsafe { libc::read(attach.shm_fd, got.as_mut_ptr() as *mut c_void, got.len()) };
        assert_eq!(n, 6);
        assert_eq!(&got, b"HEAPFD");

        let _ = sender.join();
        let _ = attach.shm_fd; // owned; closed at process exit in the test
        let mut listener = listener;
        listener.close();
    }
}
