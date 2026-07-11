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

use std::os::raw::{c_int, c_void};

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;

// cmsghdr on Darwin: u32 len + i32 level + i32 type = 12; data at the
// usize-aligned offset (16 on 64-bit).
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
    base: *mut c_void,
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

extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    fn listen(fd: c_int, backlog: c_int) -> c_int;
    fn accept(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int;
    fn recvmsg(fd: c_int, msg: *mut Msghdr, flags: c_int) -> isize;
    fn close(fd: c_int) -> c_int;
    fn unlink(path: *const u8) -> c_int;
}

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

fn fill_sockaddr(pid: i32) -> Option<SockaddrUn> {
    let mut sa = SockaddrUn { sun_len: 0, sun_family: AF_UNIX as u8, sun_path: [0; 104] };
    let n = socket_path(pid, &mut sa.sun_path)?;
    sa.sun_len = (2 + n + 1) as u8;
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
            unlink(self.path.as_ptr());
            close(self.fd);
        }
    }
}

/// Bind + listen on the per-PID socket. Called once at preload load.
pub fn listen_for_attach(pid: i32) -> Result<Listener, ProtocolError> {
    let mut path = [0u8; 128];
    socket_path(pid, &mut path).ok_or(ProtocolError::PathTooLong)?;
    // Pre-clean a stale socket from a prior run.
    unsafe { unlink(path.as_ptr()) };

    let fd = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(ProtocolError::SocketCreate);
    }
    let sa = fill_sockaddr(pid).ok_or(ProtocolError::PathTooLong)?;
    if unsafe { bind(fd, &sa as *const SockaddrUn as *const c_void, std::mem::size_of::<SockaddrUn>() as u32) } != 0 {
        unsafe { close(fd) };
        return Err(ProtocolError::SocketBind);
    }
    if unsafe { listen(fd, 1) } != 0 {
        unsafe { close(fd) };
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
            close(self.conn_fd);
            close(self.shm_fd);
        }
    }
}

/// Block until the recorder connects + sends the handshake. Returns the config
/// + the received shm fd.
///
/// # Safety
/// `listener` must be a live listener from `listen_for_attach`.
pub unsafe fn accept_and_receive(listener: &Listener) -> Result<AttachState, ProtocolError> {
    let conn = unsafe { accept(listener.fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if conn < 0 {
        return Err(ProtocolError::SocketAccept);
    }

    let mut config = AttachConfig { version: 0, ring_size: 0, sample_interval: 0, reserved: [0; 16] };
    let mut iov = Iovec { base: &mut config as *mut AttachConfig as *mut c_void, len: std::mem::size_of::<AttachConfig>() };
    let mut cbuf = [0u8; CMSG_DATA_OFFSET + std::mem::size_of::<c_int>()];
    let mut msg = Msghdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: &mut iov,
        iovlen: 1,
        control: cbuf.as_mut_ptr() as *mut c_void,
        controllen: cbuf.len() as u32,
        flags: 0,
    };

    let n = unsafe { recvmsg(conn, &mut msg, 0) };
    if n != std::mem::size_of::<AttachConfig>() as isize {
        unsafe { close(conn) };
        return Err(ProtocolError::RecvFailed);
    }
    if (msg.controllen as usize) < CMSG_DATA_OFFSET + std::mem::size_of::<c_int>() {
        unsafe { close(conn) };
        return Err(ProtocolError::NoFdReceived);
    }
    let shm_fd = i32::from_ne_bytes(cbuf[CMSG_DATA_OFFSET..CMSG_DATA_OFFSET + 4].try_into().unwrap());
    if shm_fd < 0 {
        unsafe { close(conn) };
        return Err(ProtocolError::NoFdReceived);
    }
    Ok(AttachState { conn_fd: conn, shm_fd, config })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use std::os::raw::c_char;

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
    // the socket bind + sockaddr layout use Darwin values (the listener only runs
    // inside the injected dylib on macOS).
    #[cfg(target_os = "macos")]
    const SOL_SOCKET: c_int = 0xffff;
    #[cfg(target_os = "macos")]
    const SCM_RIGHTS: c_int = 0x01;
    #[cfg(target_os = "macos")]
    extern "C" {
        fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        fn sendmsg(fd: c_int, msg: *const Msghdr, flags: c_int) -> isize;
        fn pipe(fds: *mut c_int) -> c_int;
        fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
        fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    }

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
            assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
            let (rd, wr) = (fds[0], fds[1]);

            let s = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
            let sa = fill_sockaddr(pid).unwrap();
            assert_eq!(
                unsafe { connect(s, &sa as *const SockaddrUn as *const c_void, std::mem::size_of::<SockaddrUn>() as u32) },
                0
            );
            let cfg = AttachConfig { version: 1, ring_size: 65536, sample_interval: 4096, reserved: [0; 16] };
            let mut iov = Iovec { base: &cfg as *const AttachConfig as *mut c_void, len: 32 };
            let mut cbuf = [0u8; CMSG_DATA_OFFSET + 4];
            cbuf[0..4].copy_from_slice(&((CMSG_DATA_OFFSET + 4) as u32).to_ne_bytes());
            cbuf[4..8].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
            cbuf[8..12].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
            cbuf[CMSG_DATA_OFFSET..CMSG_DATA_OFFSET + 4].copy_from_slice(&rd.to_ne_bytes());
            let msg = Msghdr {
                name: std::ptr::null_mut(),
                namelen: 0,
                iov: &mut iov,
                iovlen: 1,
                control: cbuf.as_mut_ptr() as *mut c_void,
                controllen: cbuf.len() as u32,
                flags: 0,
            };
            assert_eq!(unsafe { sendmsg(s, &msg, 0) }, 32);
            // Write through our end; the received fd (the read end) sees it.
            let payload = b"HEAPFD";
            unsafe { write(wr, payload.as_ptr() as *const c_void, payload.len()) };
            (s, wr, rd)
        });

        let attach = unsafe { accept_and_receive(&listener) }.expect("accept");
        assert_eq!(attach.config.ring_size, 65536);
        assert_eq!(attach.config.sample_interval, 4096);
        assert!(attach.shm_fd >= 0);
        // Read through the SCM_RIGHTS-received fd → the sender's bytes.
        let mut got = [0u8; 6];
        let n = unsafe { read(attach.shm_fd, got.as_mut_ptr() as *mut c_void, got.len()) };
        assert_eq!(n, 6);
        assert_eq!(&got, b"HEAPFD");

        let _ = sender.join();
        let _ = attach.shm_fd; // owned; closed at process exit in the test
        let mut listener = listener;
        listener.close();
        let _ = std::mem::size_of::<c_char>();
    }
}
