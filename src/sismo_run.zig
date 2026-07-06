// sismo-run: a capability-stable launcher for the BPF collector.
//
// `sismo` needs CAP_BPF/CAP_PERFMON/CAP_SYS_RESOURCE to load its BPF program
// (the thread_ctrs task-storage map fails -EINVAL without CAP_BPF). File caps
// attach to an inode, and `zig build` relinks `sismo` on every change, so caps
// granted with `setcap` evaporate on the next build.
//
// This launcher breaks that cycle: setcap the caps onto THIS binary once (it
// rebuilds only when this file changes, which is ~never). At startup it raises
// the three caps into the *ambient* set — ambient caps survive execve into a
// binary that carries no file caps of its own — then exec's the freshly built
// `sismo` next to it. Net: `sismo-run record …` works with no sudo and no
// re-setcap, ever.
//
//   sudo setcap cap_bpf,cap_perfmon,cap_sys_resource=eip zig-out/bin/sismo-run
//   zig-out/bin/sismo-run record --output trace.pftrace ./workload

const std = @import("std");
const linux = std.os.linux;

const PR_CAP_AMBIENT: i32 = @intFromEnum(linux.PR.CAP_AMBIENT);
const PR_CAP_AMBIENT_RAISE: usize = linux.PR.CAP_AMBIENT_RAISE;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

// uapi/linux/capability.h capability numbers.
const CAPS = [_]u6{ CAP_BPF, CAP_PERFMON, CAP_SYS_RESOURCE };
const CAP_SYS_RESOURCE: u6 = 24;
const CAP_PERFMON: u6 = 38;
const CAP_BPF: u6 = 39;

fn ok(rc: usize) bool {
    return @as(isize, @bitCast(rc)) == 0;
}

pub fn main(init: std.process.Init.Minimal) !void {
    // File caps put the three caps in our PERMITTED set, but execve leaves the
    // process INHERITABLE set empty — and PR_CAP_AMBIENT_RAISE needs each cap
    // in both permitted and inheritable. So first copy them into inheritable
    // (allowed since they're in permitted), then raise them into ambient, which
    // is what survives the exec into the file-cap-less `sismo`. Caps 32-63
    // (CAP_PERFMON=38, CAP_BPF=39) live in the second 32-bit word, so this uses
    // the v3 (64-bit) capability ABI with a two-element data array.
    var hdr = linux.cap_user_header_t{ .version = LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    var data: [2]linux.cap_user_data_t = undefined;
    if (!ok(linux.capget(&hdr, &data[0]))) return error.Capget;
    for (CAPS) |cap| data[cap >> 5].inheritable |= @as(u32, 1) << @intCast(cap & 31);
    if (!ok(linux.capset(&hdr, &data[0]))) return error.Capset;
    for (CAPS) |cap| {
        _ = linux.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, @as(usize, cap), 0, 0);
    }

    // `sismo` is the cargo-built binary (rust-host/). This launcher installs
    // to zig-out/bin, so the binary is ../../rust-host/target/debug/sismo
    // relative to it. execve resolves the `..` components.
    var exebuf: [4096]u8 = undefined;
    const rc = linux.readlinkat(linux.AT.FDCWD, "/proc/self/exe", &exebuf, exebuf.len);
    if (@as(isize, @bitCast(rc)) <= 0) return error.SelfExePath;
    const dir = std.fs.path.dirname(exebuf[0..rc]) orelse return error.NoBinDir;
    var pathbuf: [4096]u8 = undefined;
    const sismo = try std.fmt.bufPrintZ(&pathbuf, "{s}/../../rust-host/target/debug/sismo", .{dir});

    // Forward our argv to sismo, replacing argv[0] with sismo's own path.
    const argv = init.args.vector;
    var new_argv: [256]?[*:0]const u8 = undefined;
    if (argv.len + 1 > new_argv.len) return error.TooManyArgs;
    new_argv[0] = sismo.ptr;
    for (argv[1..], 1..) |arg, i| new_argv[i] = arg;
    new_argv[argv.len] = null;

    _ = linux.execve(sismo.ptr, @ptrCast(&new_argv), @ptrCast(std.c.environ));
    return error.ExecFailed; // execve only returns on failure
}
