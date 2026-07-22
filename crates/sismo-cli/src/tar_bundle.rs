// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Minimal ustar writer for the record-output bundle (trace + dump sidecars).
//!
//! trace_processor opens tars natively (its `TarTraceReader`), so a recording
//! that produced heap dumps ships as one tar of `trace.pftrace` + the raw
//! `.hprof` files — zero conversion. TP's tar parser is stricter than POSIX:
//! numeric header fields must be pure octal digits terminated by NUL (bsdtar's
//! space-terminated fields are rejected), which is exactly what this writer
//! emits (the same convention as Python's `tarfile`).

use std::io::{self, Read, Write};

const BLOCK: usize = 512;

/// Write one octal numeric field: `width-1` zero-padded digits + NUL.
fn octal_field(dst: &mut [u8], value: u64) {
    let width = dst.len();
    let s = format!("{:0>digits$o}", value, digits = width - 1);
    dst[..width - 1].copy_from_slice(s.as_bytes());
    dst[width - 1] = 0;
}

fn header_for(name: &str, size: u64, mtime: u64) -> io::Result<[u8; BLOCK]> {
    let mut h = [0u8; BLOCK];
    let name_bytes = name.as_bytes();
    if name_bytes.len() > 100 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("tar member name too long: {name}")));
    }
    if size > 0o77777777777 {
        // 11 octal digits = 8 GiB - 1. Base-256 encoding is a follow-up.
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("tar member too large: {name} ({size} bytes)")));
    }
    h[..name_bytes.len()].copy_from_slice(name_bytes);
    octal_field(&mut h[100..108], 0o644); // mode
    octal_field(&mut h[108..116], 0); // uid
    octal_field(&mut h[116..124], 0); // gid
    octal_field(&mut h[124..136], size);
    octal_field(&mut h[136..148], mtime);
    h[156] = b'0'; // typeflag: regular file
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00"); // version
    octal_field(&mut h[329..337], 0); // devmajor
    octal_field(&mut h[337..345], 0); // devminor

    // Checksum: sum of all header bytes with the checksum field as spaces,
    // written as 6 octal digits + NUL + space.
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&b| b as u64).sum();
    let s = format!("{sum:06o}");
    h[148..154].copy_from_slice(s.as_bytes());
    h[154] = 0;
    h[155] = b' ';
    Ok(h)
}

/// Bundle an already-written trace with a heap dump: replace the file at
/// `trace_path` with a tar of it (as `trace.pftrace`) + the dump (as
/// `member_name`). Written via a temp file + rename, so a failure leaves the
/// plain trace intact. Returns the bundle size.
pub fn bundle_trace_with_heap_dump(trace_path: &str, hprof_src: &str, member_name: &str) -> io::Result<u64> {
    let members = vec![
        ("trace.pftrace".to_string(), trace_path.to_string()),
        (member_name.to_string(), hprof_src.to_string()),
    ];
    let tmp = format!("{trace_path}.sismo-bundle-tmp");
    let bytes = match write_tar(&tmp, &members) {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    std::fs::rename(&tmp, trace_path)?;
    Ok(bytes)
}

/// Write a ustar archive at `out_path` containing `members` as
/// `(archive_name, source_path)` pairs, in order. Returns total bytes written.
pub fn write_tar(out_path: &str, members: &[(String, String)]) -> io::Result<u64> {
    let mut out = io::BufWriter::new(std::fs::File::create(out_path)?);
    let mut total: u64 = 0;
    for (arcname, src) in members {
        let meta = std::fs::metadata(src)?;
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let header = header_for(arcname, size, mtime)?;
        out.write_all(&header)?;
        total += BLOCK as u64;

        let mut f = std::fs::File::open(src)?;
        let mut copied: u64 = 0;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            copied += n as u64;
        }
        if copied != size {
            return Err(io::Error::other(format!("{src} changed size while tarring")));
        }
        total += copied;
        let pad = (BLOCK - (copied as usize % BLOCK)) % BLOCK;
        out.write_all(&vec![0u8; pad])?;
        total += pad as u64;
    }
    // End of archive: two zero blocks.
    out.write_all(&[0u8; 2 * BLOCK])?;
    total += 2 * BLOCK as u64;
    out.flush()?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse-back helper mirroring TP's strict reader: octal digits until NUL.
    fn parse_octal(field: &[u8]) -> u64 {
        let mut v = 0u64;
        for &b in field {
            if b == 0 {
                break;
            }
            assert!((b'0'..=b'7').contains(&b), "non-octal byte {b:#x} in numeric field");
            v = v * 8 + (b - b'0') as u64;
        }
        v
    }

    #[test]
    fn header_fields_are_tp_strict() {
        let h = header_for("trace.pftrace", 1234, 1_700_000_000).unwrap();
        assert_eq!(&h[..13], b"trace.pftrace");
        assert_eq!(&h[257..263], b"ustar\0");
        assert_eq!(parse_octal(&h[124..136]), 1234);
        assert_eq!(parse_octal(&h[136..148]), 1_700_000_000);
        assert_eq!(h[156], b'0');
        // Checksum round-trips.
        let stored = parse_octal(&h[148..156]);
        let mut copy = h;
        copy[148..156].fill(b' ');
        let sum: u64 = copy.iter().map(|&b| b as u64).sum();
        assert_eq!(stored, sum);
    }

    #[test]
    fn archive_layout_and_padding() {
        let dir = std::env::temp_dir().join("sismo-tar-selftest");
        let _ = std::fs::create_dir_all(&dir);
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        std::fs::write(&a, vec![7u8; 700]).unwrap(); // needs 324 pad
        std::fs::write(&b, vec![9u8; 512]).unwrap(); // exactly one block
        let out = dir.join("out.tar");
        let members = vec![
            ("a.bin".to_string(), a.to_str().unwrap().to_string()),
            ("b.bin".to_string(), b.to_str().unwrap().to_string()),
        ];
        let total = write_tar(out.to_str().unwrap(), &members).unwrap();
        // 512 hdr + 1024 data (700 padded) + 512 hdr + 512 data + 1024 end.
        assert_eq!(total, 512 + 1024 + 512 + 512 + 1024);
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(bytes.len() as u64, total);
        // Second member's header sits right after the padded first member.
        assert_eq!(&bytes[512 + 1024..512 + 1024 + 5], b"b.bin");
        // Archive ends with two zero blocks.
        assert!(bytes[bytes.len() - 1024..].iter().all(|&x| x == 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversize_name_and_size_are_rejected() {
        assert!(header_for(&"x".repeat(101), 1, 0).is_err());
        assert!(header_for("ok", u64::MAX, 0).is_err());
    }
}
