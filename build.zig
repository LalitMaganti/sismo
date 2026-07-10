// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

const std = @import("std");

// ---- Single source of truth for C/C++ inputs -----------------------------
//
// Both the per-OS build pipelines and the `compile-db` step iterate over
// this table. To add a new C/C++ source: append an entry here and pick the
// right component; the build wires it into the appropriate binary.

const Component = enum {
    sample_target, // sample-target binary; built on every OS we support
};

const Language = enum { c, cpp };

const CSource = struct {
    path: []const u8,
    language: Language,
    component: Component,
};

// The Perfetto C/C++ glue (sismo_traced/consumer/trace_query/perfetto_ds/
// traced_probes) is compiled by rust-host/build.rs with `zig c++`, not here,
// so the C/C++ no longer rides the Zig build. Only sample-target's C SDK shim
// remains (it's part of the Zig sample-target binary).
const c_sources = [_]CSource{
    .{ .path = "src/c/sample_target_sdk.c", .language = .c, .component = .sample_target },
};

// Linux gets `-D_GNU_SOURCE` so Perfetto's public headers (which call
// `syscall(__NR_gettid)`) compile against glibc.
// -fno-omit-frame-pointer is mandatory: sismo's perf data source uses kernel-
// side frame-pointer unwinding (UNWIND_FRAME_POINTER), so any C/C++ frame in
// the call chain must keep its FP.
const c_flags_macos: []const []const u8 = &.{ "-std=c11", "-fno-omit-frame-pointer" };
const c_flags_linux: []const []const u8 = &.{ "-std=c11", "-D_GNU_SOURCE", "-fno-omit-frame-pointer" };
const cpp_flags_macos: []const []const u8 = &.{ "-std=c++17", "-fno-exceptions", "-fno-rtti", "-DNDEBUG", "-fno-omit-frame-pointer" };
const cpp_flags_linux: []const []const u8 = &.{ "-std=c++17", "-fno-exceptions", "-fno-rtti", "-DNDEBUG", "-D_GNU_SOURCE", "-fno-omit-frame-pointer" };

fn flagsFor(lang: Language, is_macos: bool) []const []const u8 {
    return switch (lang) {
        .c => if (is_macos) c_flags_macos else c_flags_linux,
        .cpp => if (is_macos) cpp_flags_macos else cpp_flags_linux,
    };
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const os_tag = target.result.os.tag;

    // -------------------------------------------------------------------------
    // `zig build compile-db` — emits compile_commands.json at the repo
    // root for clangd / clang-tidy / IDE tooling. Driven by the
    // `c_sources` table above so it can't drift from the build itself.
    // Emits entries for every source regardless of host OS so clangd can
    // reason about Linux-only producers from a macOS workstation.
    // -------------------------------------------------------------------------
    {
        const compile_db = CompileDbStep.create(b);
        const step = b.step("compile-db", "Generate compile_commands.json at the repo root");
        step.dependOn(&compile_db.step);
    }

    // -------------------------------------------------------------------------
    // The `sismo` binary and the sample-target workload are produced by cargo
    // (the rust-host crate); see rust-host/build.rs. This Zig build only emits
    // the compiler_rt shim archive (all OSes) and the Linux sismo-run cap
    // launcher.
    // -------------------------------------------------------------------------
    switch (os_tag) {
        .macos, .linux => addUnixPipeline(b, target, optimize),
        else => {},
    }
}

fn addUnixPipeline(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const os_tag = target.result.os.tag;
    const is_linux = os_tag == .linux;

    // Perfetto's C++ SDK and the sample-target workload are built by cargo
    // (rust-host/build.rs). This Zig build now only produces the compiler_rt
    // shim archive and the sismo-run cap launcher.

    // -------------------------------------------------------------------------
    // libsismo_zig.a — compiler_rt for the cargo-linked binary. The `sismo`
    // binary is produced by cargo (rust-host/), and all of sismo's Zig has been
    // ported to Rust. This archive now exists only to supply Zig's bundled
    // compiler_rt (__zig_probe_stack etc.) that the perfetto C/C++ shims —
    // compiled with `zig c++` in rust-host/build.rs — reference at the final
    // link. `zig build sismo-staticlib` emits zig-out/lib/libsismo_zig.a.
    // -------------------------------------------------------------------------
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("src/sismo_entry.zig"),
            .target = target,
            .optimize = optimize,
            // The cargo binary links as PIE, so the bundled compiler_rt the
            // C/C++ shims pull from this archive must be position-independent.
            .pic = true,
        });
        const lib = b.addLibrary(.{
            .name = "sismo_zig",
            .root_module = mod,
            .linkage = .static,
        });
        lib.bundle_compiler_rt = true;
        const step = b.step("sismo-staticlib", "Build libsismo_zig.a (compiler_rt for the cargo binary)");
        step.dependOn(&b.addInstallArtifact(lib, .{}).step);
    }

    // sismo-run: capability-stable launcher (Linux only). File caps live on
    // this tiny binary (it rebuilds only when its own source changes), so
    // `sismo` never needs re-setcap after a build — the launcher raises the
    // BPF caps to ambient and exec's the sibling `sismo`. See src/sismo_run.zig.
    if (is_linux) {
        const run_mod = b.createModule(.{
            .root_source_file = b.path("src/sismo_run.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        const run_exe = b.addExecutable(.{ .name = "sismo-run", .root_module = run_mod });
        b.installArtifact(run_exe);
        const run_step = b.step("sismo-run", "Build the capability-stable BPF launcher");
        run_step.dependOn(&b.addInstallArtifact(run_exe, .{}).step);
    }
}

// ---- compile_commands.json emitter ---------------------------------------
//
// Walks `c_sources` and writes <repo_root>/compile_commands.json. Treats
// every source as host-targeted (Linux producers get included even on
// macOS so clangd can reason about them). Doesn't depend on Perfetto
// being built — the include paths reference the host out dir
// (`third_party/src/perfetto/out/sismo`); paths that don't exist yet are
// fine, clangd just shows missing-header diagnostics until you run
// `tools/setup-perfetto`.

const CompileDbStep = struct {
    step: std.Build.Step,

    fn create(b: *std.Build) *CompileDbStep {
        const self = b.allocator.create(CompileDbStep) catch @panic("OOM");
        self.* = .{
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = "compile-db",
                .owner = b,
                .makeFn = make,
            }),
        };
        return self;
    }

    fn make(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
        _ = options;
        const b = step.owner;
        const repo_root = b.build_root.path orelse ".";
        const host_is_linux = @import("builtin").os.tag == .linux;
        const host_is_macos = @import("builtin").os.tag == .macos;

        const join = std.fs.path.join;
        // Mirrors `buildtools/BUILD.gn`'s `libunwindstack` source_set
        // (Linux profiler dep). The Linux producers transitively reach
        // `<unwindstack/Error.h>` and friends via
        // `src/profiling/perf/unwinding.h`.
        const buildtools_libunwindstack_includes = [_][]const u8{
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/buildtools/android-unwinding/libunwindstack/include" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/buildtools/android-unwinding/libunwindstack" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/buildtools/android-libbase/include" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/buildtools/android-logging/liblog/include" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/buildtools/android-libprocinfo/include" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/buildtools/android-core/include" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/buildtools/android-core/libcutils/include" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/buildtools/bionic/libc/async_safe/include" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/buildtools/bionic/libc/platform" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/buildtools/lzma/C" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/buildtools/zstd/lib" }),
        };
        const perfetto_includes = [_][]const u8{
            repo_root,
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/include" }),
            // Non-public Perfetto headers (src/profiling/perf/, src/traced/
            // probes/) resolve from the Perfetto repo root.
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/out/sismo/gen" }),
            try join(b.allocator, &.{ repo_root, "third_party/src/perfetto/out/sismo/gen/build_config" }),
        };

        // Concat: per-file we emit perfetto_includes first, then the
        // libunwindstack/buildtools transitively for files that reach
        // them. clangd tolerates -I directories that don't exist, so
        // unconditional inclusion is fine.
        var includes: std.ArrayList([]const u8) = .empty;
        defer includes.deinit(b.allocator);
        try includes.appendSlice(b.allocator, &perfetto_includes);
        try includes.appendSlice(b.allocator, &buildtools_libunwindstack_includes);

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(b.allocator);
        try buf.appendSlice(b.allocator, "[\n");
        for (c_sources, 0..) |src, i| {
            if (i > 0) try buf.appendSlice(b.allocator, ",\n");
            try writeEntry(b.allocator, &buf, repo_root, src, includes.items, host_is_macos, host_is_linux);
        }
        try buf.appendSlice(b.allocator, "\n]\n");

        const out_path = try std.Io.Dir.path.join(b.allocator, &.{ repo_root, "compile_commands.json" });
        const io = b.graph.io;
        try std.Io.Dir.cwd().writeFile(io, .{
            .sub_path = out_path,
            .data = buf.items,
        });
        std.debug.print("Wrote {s} ({d} entries)\n", .{ out_path, c_sources.len });
    }

    fn writeEntry(
        allocator: std.mem.Allocator,
        buf: *std.ArrayList(u8),
        repo_root: []const u8,
        src: CSource,
        includes: []const []const u8,
        host_is_macos: bool,
        host_is_linux: bool,
    ) !void {
        const file_abs = try std.fs.path.join(allocator, &.{ repo_root, src.path });
        const compiler: []const u8 = if (src.language == .cpp) "clang++" else "clang";
        // Use macOS flags as the default for non-Linux hosts (Windows
        // host doesn't need _GNU_SOURCE either).
        const flags = flagsFor(src.language, host_is_macos or !host_is_linux);

        try buf.appendSlice(allocator, "  {\n    \"directory\": ");
        try appendJsonString(allocator, buf, repo_root);
        try buf.appendSlice(allocator, ",\n    \"file\": ");
        try appendJsonString(allocator, buf, file_abs);
        try buf.appendSlice(allocator, ",\n    \"arguments\": [\n      ");
        try appendJsonString(allocator, buf, compiler);
        for (includes) |inc| {
            try buf.appendSlice(allocator, ",\n      \"-I\",\n      ");
            try appendJsonString(allocator, buf, inc);
        }
        for (flags) |flag| {
            try buf.appendSlice(allocator, ",\n      ");
            try appendJsonString(allocator, buf, flag);
        }
        try buf.appendSlice(allocator, ",\n      \"-c\",\n      ");
        try appendJsonString(allocator, buf, file_abs);
        try buf.appendSlice(allocator, "\n    ]\n  }");
    }

    fn appendJsonString(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), s: []const u8) !void {
        try buf.append(allocator, '"');
        for (s) |c| switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            else => try buf.append(allocator, c),
        };
        try buf.append(allocator, '"');
    }
};
