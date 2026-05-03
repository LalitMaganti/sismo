// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Module enumeration via dyld's `all_image_infos`. Walks the target's
//! loaded mach-o image list to produce `(base_avma, path)` tuples — the
//! inputs framehop needs in `add_module`.
//!
//! Same data path samply uses (`proc_maps.rs::DyldInfoManager`):
//!   1. `task_info(target, TASK_DYLD_INFO)` returns the address of the
//!      target's `dyld_all_image_infos` struct.
//!   2. `mach_vm_read_overwrite` that struct → grab `infoArrayCount`
//!      and `infoArray` (a pointer in the target's address space).
//!   3. `mach_vm_read_overwrite` the array → for each
//!      `dyld_image_info` we get `imageLoadAddress` (= base avma) and
//!      `imageFilePath` (a `const char*` we then read separately).
//!
//! Works on `taskSelf()` without root (you always have full access to
//! your own task). For sibling tasks via `task_for_pid` it requires the
//! same root/entitlement that the sampler does.

const std = @import("std");
const sampler = @import("mach_sampler.zig");

/// `task_info` flavor for `task_dyld_info_data_t`.
pub const TASK_DYLD_INFO: c_uint = 17;

/// Returned by `task_info(TASK_DYLD_INFO)`.
pub const TaskDyldInfoData = extern struct {
    all_image_info_addr: u64, // mach_vm_address_t
    all_image_info_size: u64, // mach_vm_size_t
    all_image_info_format: c_int, // integer_t
};

pub const TASK_DYLD_INFO_COUNT: u32 =
    @sizeOf(TaskDyldInfoData) / @sizeOf(u32);

/// First three fields of `dyld_all_image_infos` (in the target's address
/// space). The struct is much larger but we only need the head.
pub const DyldAllImageInfosHeader = extern struct {
    version: u32,
    info_array_count: u32,
    info_array: u64, // const dyld_image_info*
};

/// 64-bit `dyld_image_info` entry.
pub const DyldImageInfo64 = extern struct {
    image_load_address: u64, // const mach_header* — base avma
    image_file_path: u64, // const char*
    image_file_mod_date: u64,
};

pub const Error = error{
    TaskInfoFailed,
    EmptyImageList,
} || sampler.SamplerError || std.mem.Allocator.Error;

pub const Image = struct {
    base_avma: u64,
    /// Caller-owned bytes (allocated via the allocator passed to
    /// `enumerateImages`). Free via `freeImages`.
    path: []u8,
};

/// Enumerate all loaded mach-o images in `task`. Returned slice and
/// each `Image.path` are caller-owned; release with `freeImages`.
pub fn enumerateImages(
    task: sampler.task_t,
    gpa: std.mem.Allocator,
) Error![]Image {
    var dyld_info: TaskDyldInfoData = undefined;
    var count: u32 = TASK_DYLD_INFO_COUNT;
    if (std.c.task_info(task, TASK_DYLD_INFO, @ptrCast(&dyld_info), &count) != sampler.KERN_SUCCESS) {
        return error.TaskInfoFailed;
    }
    if (dyld_info.all_image_info_addr == 0) return error.EmptyImageList;

    var head: DyldAllImageInfosHeader = undefined;
    const got_head = try sampler.vmReadInto(
        task,
        dyld_info.all_image_info_addr,
        std.mem.asBytes(&head),
    );
    if (got_head < @sizeOf(DyldAllImageInfosHeader)) return error.VmReadFailed;
    if (head.info_array == 0 or head.info_array_count == 0) return error.EmptyImageList;

    const n = head.info_array_count;
    const entries = try gpa.alloc(DyldImageInfo64, n);
    defer gpa.free(entries);
    const got_arr = try sampler.vmReadInto(
        task,
        head.info_array,
        std.mem.sliceAsBytes(entries),
    );
    const usable = got_arr / @sizeOf(DyldImageInfo64);

    var out = try gpa.alloc(Image, usable);
    var written: usize = 0;
    errdefer {
        for (out[0..written]) |img| gpa.free(img.path);
        gpa.free(out);
    }
    for (entries[0..usable]) |entry| {
        const path = try readCString(task, entry.image_file_path, gpa);
        out[written] = .{
            .base_avma = entry.image_load_address,
            .path = path,
        };
        written += 1;
    }
    return out;
}

/// Same as `enumerateImages` but retries on `EmptyImageList`. Useful
/// when the target was just spawned by `posix_spawn` and may not have
/// finished its dyld load phase yet — `dyld_all_image_infos` exists
/// (so `task_info` succeeds) but `info_array_count` is still 0 for a
/// brief window. `should_abort`, if non-null, is polled between
/// retries with `abort_ctx` — return true to bail (e.g., for shutdown).
pub fn enumerateImagesWaitReady(
    task: sampler.task_t,
    gpa: std.mem.Allocator,
    poll_interval_ns: u64,
    max_total_ns: u64,
    abort_ctx: ?*anyopaque,
    should_abort: ?*const fn (?*anyopaque) bool,
) Error![]Image {
    const poll_ts: std.c.timespec = .{
        .sec = @intCast(poll_interval_ns / std.time.ns_per_s),
        .nsec = @intCast(poll_interval_ns % std.time.ns_per_s),
    };
    const max_attempts = if (poll_interval_ns == 0) 1 else max_total_ns / poll_interval_ns;
    var attempt: u64 = 0;
    while (true) : (attempt += 1) {
        if (enumerateImages(task, gpa)) |imgs| return imgs else |err| {
            if (err != error.EmptyImageList or attempt + 1 >= max_attempts) return err;
            if (should_abort) |cb| if (cb(abort_ctx)) return error.EmptyImageList;
            _ = std.c.nanosleep(&poll_ts, null);
        }
    }
}

pub fn freeImages(gpa: std.mem.Allocator, images: []Image) void {
    for (images) |img| gpa.free(img.path);
    gpa.free(images);
}

/// Read a C string from `addr` in `task`'s address space. Reads up to
/// `max_path` bytes, stops at first NUL. On read failure, returns "?".
fn readCString(
    task: sampler.task_t,
    addr: u64,
    gpa: std.mem.Allocator,
) ![]u8 {
    if (addr == 0) return try gpa.dupe(u8, "");
    const max_path = 1024;
    var buf: [max_path]u8 = undefined;
    const got = sampler.vmReadInto(task, addr, &buf) catch {
        return try gpa.dupe(u8, "?");
    };
    const slice = buf[0..got];
    const nul = std.mem.indexOfScalar(u8, slice, 0) orelse got;
    return try gpa.dupe(u8, slice[0..nul]);
}

// ---- Mach-o image reading (3b) -----------------------------------------

const MH_MAGIC_64: u32 = 0xfeedfacf;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;

pub const MachHeader64 = extern struct {
    magic: u32,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
};

pub const ImageReadError = error{
    NotMachO64,
    NoTextSegment,
} || sampler.SamplerError || std.mem.Allocator.Error;

/// Result of `readImageMachO`. `bytes` is the in-memory `__TEXT`
/// segment slab (caller-owned, free with `gpa.free`). `text_vmsize` is
/// the `__TEXT` segment's vmsize from its LC_SEGMENT_64 — i.e. the size
/// of the *executable* footprint of this image, NOT the total image
/// extent.
///
/// We deliberately do not use the max-of-all-segments span here:
/// dyld_shared_cache members report inflated `vmsize` values for their
/// non-__TEXT segments (the values describe the cache layout, not the
/// dylib's own footprint). Using __TEXT.vmsize matches what samply's
/// `proc_maps.rs::DyldInfoManager` does and gives correct, contiguous,
/// non-overlapping ranges for symbolication of code addresses.
pub const ImageRead = struct {
    bytes: []u8,
    text_vmsize: u64,
    /// Mach-O `cputype` from the header (e.g. CPU_TYPE_ARM64 = 0x0100000C).
    cputype: u32,
    /// Mach-O `cpusubtype` (with feature bits masked off by caller as
    /// needed). For arm64 macOS: 0 = arm64 (plain), 2 = arm64e (PAC).
    cpusubtype: u32,
    /// LC_UUID from the in-memory image. wholesym uses this as a
    /// `DebugId` disambiguator to pick the right slice from a fat
    /// archive on disk — necessary because samply-symbols' fat archive
    /// `arch` field doesn't distinguish arm64 from arm64e (both report
    /// "arm64") so the Arch disambiguator can't pick arm64e. UUID lookup
    /// works regardless. All-zeros means the image had no LC_UUID load
    /// command (rare; shouldn't happen for normal dylibs).
    uuid: [16]u8,
};

/// Map (cputype, cpusubtype) to wholesym's arch string. Returns `null`
/// for unknown archs. Used to disambiguate fat binaries on disk: the
/// in-memory image is a single arch; we tell wholesym which one to pick.
pub fn archString(cputype: u32, cpusubtype: u32) ?[]const u8 {
    // Mach-O constants (from <mach/machine.h>):
    //   CPU_TYPE_X86_64 = 0x01000007, CPU_TYPE_ARM64 = 0x0100000C
    //   CPU_SUBTYPE_MASK strips feature bits (top byte).
    const sub = cpusubtype & 0x00FFFFFF;
    return switch (cputype) {
        0x01000007 => switch (sub) {
            0, 3 => "x86_64",
            8 => "x86_64h",
            else => null,
        },
        0x0100000C => switch (sub) {
            0, 1 => "arm64",
            2 => "arm64e",
            else => null,
        },
        else => null,
    };
}

/// Read enough of the in-memory mach-o image at `base_avma` for framehop
/// to consume — at minimum the full `__TEXT` segment, which holds
/// `__unwind_info` / `__eh_frame` / `__text` / `__stubs`. Other segments
/// are not fetched; framehop tolerates `data()` returning out-of-buffer
/// for them and only needs their svma ranges, which it gets from the load
/// commands at the start of the buffer.
///
/// Caller owns `result.bytes`; release with `gpa.free`.
pub fn readImageMachO(
    task: sampler.task_t,
    base_avma: u64,
    gpa: std.mem.Allocator,
) ImageReadError!ImageRead {
    // 1. Header (32 B).
    var hdr: MachHeader64 = undefined;
    const got_hdr = try sampler.vmReadInto(task, base_avma, std.mem.asBytes(&hdr));
    if (got_hdr < @sizeOf(MachHeader64)) return error.VmReadFailed;
    if (hdr.magic != MH_MAGIC_64) return error.NotMachO64;

    // 2. Load commands.
    const cmds = try gpa.alloc(u8, hdr.sizeofcmds);
    defer gpa.free(cmds);
    const got_cmds = try sampler.vmReadInto(task, base_avma + @sizeOf(MachHeader64), cmds);
    if (got_cmds < hdr.sizeofcmds) return error.VmReadFailed;

    // 3. Find LC_SEGMENT_64 __TEXT to learn vmsize — the size of the
    //    image's executable footprint, used by callers as the strict
    //    end of this image's address range. samply does this same
    //    thing in `proc_maps.rs::DyldInfoManager::get_dyld_image_info`.
    //    Reads fields by offset to avoid alignment hassles on the byte
    //    buffer.
    var text_vmsize: u64 = 0;
    var uuid: [16]u8 = @splat(0);
    var off: usize = 0;
    var i: u32 = 0;
    while (i < hdr.ncmds) : (i += 1) {
        if (off + 8 > cmds.len) break;
        const cmd = std.mem.readInt(u32, cmds[off..][0..4], .little);
        const cmdsize = std.mem.readInt(u32, cmds[off..][4..8], .little);
        if (cmdsize == 0 or off + cmdsize > cmds.len) break;
        if (cmd == LC_SEGMENT_64 and cmdsize >= 72) {
            // segment_command_64 layout:
            //   cmd:u32 cmdsize:u32 segname[16] vmaddr:u64 vmsize:u64 ...
            const seg_segname = cmds[off + 8 ..][0..16];
            const seg_vmsize = std.mem.readInt(u64, cmds[off + 32 ..][0..8], .little);
            const segname_len = std.mem.indexOfScalar(u8, seg_segname, 0) orelse 16;
            if (std.mem.eql(u8, seg_segname[0..segname_len], "__TEXT")) {
                text_vmsize = seg_vmsize;
            }
        } else if (cmd == LC_UUID and cmdsize >= 24) {
            // uuid_command layout: cmd:u32 cmdsize:u32 uuid[16]
            @memcpy(&uuid, cmds[off + 8 ..][0..16]);
        }
        off += cmdsize;
    }
    if (text_vmsize == 0) return error.NoTextSegment;

    // 4. Read the full __TEXT segment in one shot. Short reads can
    //    happen near the end of a mapping — return whatever we got;
    //    framehop's mach-o parser tolerates partial section data.
    const buf = try gpa.alloc(u8, @intCast(text_vmsize));
    errdefer gpa.free(buf);
    const got = try sampler.vmReadInto(task, base_avma, buf);
    const final_buf = if (got < text_vmsize) try gpa.realloc(buf, got) else buf;
    return .{
        .bytes = final_buf,
        .text_vmsize = text_vmsize,
        .cputype = hdr.cputype,
        .cpusubtype = hdr.cpusubtype,
        .uuid = uuid,
    };
}
