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
    sismo_unix, // sismo binary; macOS + Linux
    sismo_linux, // sismo binary; Linux only
};

const Language = enum { c, cpp };

const CSource = struct {
    path: []const u8,
    language: Language,
    component: Component,
};

const c_sources = [_]CSource{
    .{ .path = "src/c/sample_target_sdk.c", .language = .c, .component = .sample_target },
    .{ .path = "src/c/sismo_traced.cc", .language = .cpp, .component = .sismo_unix },
    .{ .path = "src/c/sismo_consumer.cc", .language = .cpp, .component = .sismo_unix },
    .{ .path = "src/c/perfetto_ds.cc", .language = .cpp, .component = .sismo_unix },
    .{ .path = "src/c/sismo_traced_probes.cc", .language = .cpp, .component = .sismo_linux },
    .{ .path = "src/c/sismo_traced_perf.cc", .language = .cpp, .component = .sismo_linux },
};

// Linux gets `-D_GNU_SOURCE` so Perfetto's public headers (which call
// `syscall(__NR_gettid)`) compile against glibc.
const c_flags_macos: []const []const u8 = &.{"-std=c11"};
const c_flags_linux: []const []const u8 = &.{ "-std=c11", "-D_GNU_SOURCE" };
const cpp_flags_macos: []const []const u8 = &.{ "-std=c++17", "-fno-exceptions", "-fno-rtti", "-DNDEBUG" };
const cpp_flags_linux: []const []const u8 = &.{ "-std=c++17", "-fno-exceptions", "-fno-rtti", "-DNDEBUG", "-D_GNU_SOURCE" };

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
    // `zig build check [-Dtarget=…]` — cross-platform compile sentinel.
    //
    // Builds src/check.zig (a module index that references every
    // OS-portable module in src/) for the requested target. Lets us
    // catch cross-platform regressions on macOS without booting a Linux
    // or Windows machine, and without dragging in Perfetto or
    // rust-bridge — both of which are macOS-only today.
    //
    // Wired up before the per-OS branches below so it works on every OS,
    // including ones where we don't yet have a full sismo build.
    // -------------------------------------------------------------------------
    {
        const check_mod = b.createModule(.{
            .root_source_file = b.path("src/check.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        // The cmd_* subcommands import the perfetto_shim.h cImport;
        // semantic analysis fails without the include path. We only
        // need the headers (the shim is header-light, no link step).
        // Includes are root-qualified, so the include root is the repo.
        check_mod.addIncludePath(b.path("."));
        check_mod.addIncludePath(b.path("third_party/src/perfetto/include"));
        const check_obj = b.addObject(.{
            .name = "sismo_check",
            .root_module = check_mod,
        });
        const check_step = b.step("check", "Cross-platform compile check of OS-portable modules");
        check_step.dependOn(&check_obj.step);
    }

    // -------------------------------------------------------------------------
    // rust-bridge: Cargo staticlib produced by an external `cargo build`
    // step. Linked into the sismo binary on every OS where we have a
    // full pipeline.
    // -------------------------------------------------------------------------
    const cargo_profile: []const u8 = switch (optimize) {
        .Debug => "dev",
        .ReleaseSafe, .ReleaseFast, .ReleaseSmall => "release",
    };
    const cargo_target_subdir: []const u8 = switch (optimize) {
        .Debug => "debug",
        .ReleaseSafe, .ReleaseFast, .ReleaseSmall => "release",
    };

    const cargo = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--manifest-path",
        b.pathFromRoot("rust-bridge/Cargo.toml"),
        "--profile",
        cargo_profile,
    });

    // -------------------------------------------------------------------------
    // Per-OS pipelines.
    //
    // macOS:   sample-target + heap-preload + sismo (full data-source set)
    // Linux:   sample-target + sismo (cmd_record/datasource print "not yet
    //          implemented" for the macOS-specific data sources; the SDK
    //          and tracing service do work). Heap preload is macOS-only —
    //          a Linux LD_PRELOAD variant will land alongside the Linux
    //          producers.
    // Windows: sample-target only — the orchestrator's POSIX bits
    //          (sismo_paths' flock-based session lock, posix_spawnp,
    //          POSIX Args.iterate) need Windows analogs first. The
    //          Perfetto SDK and tracing service themselves work on
    //          Windows so the sample-target consumer is enough to verify
    //          the SDK link surface.
    // -------------------------------------------------------------------------
    switch (os_tag) {
        .macos, .linux => addUnixPipeline(b, target, optimize, cargo, cargo_target_subdir),
        .windows => addWindowsPipeline(b, target, optimize),
        else => {},
    }
}

fn addUnixPipeline(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cargo: *std.Build.Step.Run,
    cargo_target_subdir: []const u8,
) void {
    const os_tag = target.result.os.tag;
    const is_macos = os_tag == .macos;

    // Perfetto out dir per target. Cross-compiled targets live in
    // sibling dirs so a macOS host can keep both `out/sismo` (native)
    // and `out/sismo_linux_x64` (cross via zig cc) populated. The
    // names match what tools/setup_perfetto.sh derives from
    // SISMO_TARGET; build.zig and the script have to agree.
    const sismo_target = perfettoTargetTriple(target);
    const perfetto_out_name = if (sismo_target == null)
        "sismo"
    else switch (target.result.cpu.arch) {
        .x86_64 => switch (os_tag) {
            .linux => "sismo_linux_x64",
            .windows => "sismo_windows_x64",
            else => "sismo",
        },
        .aarch64 => switch (os_tag) {
            .linux => "sismo_linux_arm64",
            .windows => "sismo_windows_arm64",
            else => "sismo",
        },
        else => "sismo",
    };

    // -------------------------------------------------------------------------
    // libperfetto.a — the comprehensive Perfetto C++ SDK static archive.
    // sismo's producer-side glue is `src/c/perfetto_ds.cc` (templated
    // DataSource slots over the public C++ SDK) and consumer-side is
    // `src/c/sismo_consumer.cc`. Both compile directly into the sismo
    // binary, not as a separate static library.
    //
    // Build pipeline:
    //   1. tools/build_perfetto.sh runs ninja to produce libperfetto.a
    //      in third_party/src/perfetto/out/<perfetto_out_name>/.
    //      Cross-compile uses zig cc as a clang drop-in.
    //   2. Each consumer addCSourceFile()s the relevant .cc shims +
    //      addObjectFile(libperfetto.a) + OS-specific frameworks/libs.
    // -------------------------------------------------------------------------
    const perfetto_build = b.addSystemCommand(&.{ "bash", b.pathFromRoot("tools/build_perfetto.sh") });
    if (sismo_target) |trip| perfetto_build.setEnvironmentVariable("SISMO_TARGET", trip);
    const perfetto_root = b.path("third_party/src/perfetto");
    const perfetto_out = b.path(b.fmt("third_party/src/perfetto/out/{s}", .{perfetto_out_name}));

    // Includes for our own headers are root-qualified (e.g.
    // `#include "src/c/perfetto_shim.h"`), so the include root is the
    // repo root.
    const repo_root_include = b.path(".");
    const lib_a = perfetto_out.path(b, "libperfetto.a");

    // Workload binary — uses the Perfetto C SDK directly via
    // src/c/sample_target_sdk.c. Cross-platform; the SDK headers are
    // identical on every OS Perfetto supports.
    {
        const target_mod = b.createModule(.{
            .root_source_file = b.path("src/sample_target.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        });
        addComponentSources(b, target_mod, .sample_target, is_macos);
        target_mod.addIncludePath(perfetto_root.path(b, "include"));

        const target_exe = b.addExecutable(.{
            .name = "sample-target",
            .root_module = target_mod,
        });
        linkPerfetto(target_mod, &target_exe.step, repo_root_include, lib_a, &perfetto_build.step, os_tag);
        b.installArtifact(target_exe);

        const target_step = b.step("sample-target", "Build the sample-target workload binary");
        target_step.dependOn(&b.addInstallArtifact(target_exe, .{}).step);
    }

    // Heap preload dylib — macOS only. DYLD_INSERT_LIBRARIES + the
    // `__DATA,__interpose` mechanism are macOS-specific. The Linux
    // analog (LD_PRELOAD + GLIBC malloc hooks) lives in a sibling
    // `heap_preload_linux.zig` once we get there.
    if (is_macos) {
        const heap_mod = b.createModule(.{
            .root_source_file = b.path("src/heap_preload_macos.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        const heap_lib = b.addLibrary(.{
            .name = "sismo_heap",
            .root_module = heap_mod,
            .linkage = .dynamic,
        });
        b.installArtifact(heap_lib);

        const heap_step = b.step("heap-preload", "Build the macOS heap preload dylib (Q2-macOS)");
        heap_step.dependOn(&b.addInstallArtifact(heap_lib, .{}).step);
    }

    // -------------------------------------------------------------------------
    // sismo: the top-level CLI. Dispatches subcommands (`sismo record`,
    // `sismo datasource <name>`, ...). On macOS hosts the kdebug / Mach
    // sampler / heap consumer in-process; on Linux the macOS data
    // sources stub out and only the SDK + tracing service path is wired
    // (perf_event-based producers TBD).
    //
    // Link surface: perfetto C++ + shim, the C++ ServiceIPCHost wrapper,
    // and the rust-bridge staticlib (framehop unwinding + wholesym
    // symbolication).
    // -------------------------------------------------------------------------
    {
        const sismo_mod = b.createModule(.{
            .root_source_file = b.path("src/sismo.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        });
        addComponentSources(b, sismo_mod, .sismo_unix, is_macos);
        // Linux-only: embedded Perfetto producers run in-process as
        // worker threads (mirroring sismo_traced.cc). traced_probes
        // covers ftrace + procfs; traced_perf covers perf_event_open
        // CPU sampling. Both are gated `is_linux` upstream — their
        // source sets aren't built on macOS.
        if (!is_macos) addComponentSources(b, sismo_mod, .sismo_linux, is_macos);
        sismo_mod.addIncludePath(perfetto_root.path(b, "include"));
        // Linux producer shims include "src/profiling/perf/perf_producer.h"
        // and "src/traced/probes/probes_producer.h" — both are
        // non-public headers that resolve from Perfetto's repo root.
        if (!is_macos) {
            sismo_mod.addIncludePath(perfetto_root);
        }
        sismo_mod.addIncludePath(perfetto_out.path(b, "gen"));
        sismo_mod.addIncludePath(perfetto_out.path(b, "gen/build_config"));
        sismo_mod.addLibraryPath(b.path(b.fmt("rust-bridge/target/{s}", .{cargo_target_subdir})));
        sismo_mod.linkSystemLibrary("rust_bridge", .{});
        // wholesym pulls in CoreFoundation/Security via core_foundation-rs
        // and uses Spotlight (CoreServices) to locate dSYM bundles —
        // all macOS-specific. On Linux wholesym uses /usr/lib/debug and
        // .gnu_debuglink; no extra system libs needed for the symbolizer.
        if (is_macos) {
            sismo_mod.linkFramework("Foundation", .{});
            sismo_mod.linkFramework("Security", .{});
            sismo_mod.linkFramework("CoreServices", .{});
        }
        const sismo_exe = b.addExecutable(.{
            .name = "sismo",
            .root_module = sismo_mod,
        });
        linkPerfetto(sismo_mod, &sismo_exe.step, repo_root_include, lib_a, &perfetto_build.step, os_tag);
        sismo_exe.step.dependOn(&cargo.step);
        b.installArtifact(sismo_exe);
        const sismo_step = b.step("sismo", "Build the sismo CLI (subcommand dispatcher)");
        sismo_step.dependOn(&b.addInstallArtifact(sismo_exe, .{}).step);
    }
}

fn addComponentSources(
    b: *std.Build,
    mod: *std.Build.Module,
    component: Component,
    is_macos: bool,
) void {
    for (c_sources) |src| {
        if (src.component != component) continue;
        mod.addCSourceFile(.{
            .file = b.path(src.path),
            .flags = flagsFor(src.language, is_macos),
            .language = if (src.language == .c) .c else .cpp,
        });
    }
}

/// SISMO_TARGET value to pass to tools/setup_perfetto.sh + build_perfetto.sh
/// when cross-compiling. Returns null when targeting the build host
/// (use the default out/sismo dir + Perfetto's hermetic clang).
fn perfettoTargetTriple(target: std.Build.ResolvedTarget) ?[]const u8 {
    const host_tag = @import("builtin").os.tag;
    const host_arch = @import("builtin").cpu.arch;
    if (target.result.os.tag == host_tag and target.result.cpu.arch == host_arch) return null;
    return switch (target.result.cpu.arch) {
        .x86_64 => switch (target.result.os.tag) {
            .linux => "x86_64-linux-gnu",
            .windows => "x86_64-windows-gnu",
            else => null,
        },
        .aarch64 => switch (target.result.os.tag) {
            .linux => "aarch64-linux-gnu",
            .windows => "aarch64-windows-gnu",
            else => null,
        },
        else => null,
    };
}

fn linkPerfetto(
    mod: *std.Build.Module,
    step: *std.Build.Step,
    inc: std.Build.LazyPath,
    lib_a: std.Build.LazyPath,
    build_step: *std.Build.Step,
    os_tag: std.Target.Os.Tag,
) void {
    mod.addIncludePath(inc);
    // libperfetto.a is comprehensive: service code (traced) +
    // client API (shared_lib + tracing/client_api + backends).
    // Single archive — see sismo-local additions in
    // third_party/src/perfetto/BUILD.gn.
    mod.addObjectFile(lib_a);
    switch (os_tag) {
        .macos => {
            mod.linkFramework("CoreFoundation", .{});
            mod.linkSystemLibrary("dl", .{});
        },
        .linux => {
            mod.linkSystemLibrary("dl", .{});
            mod.linkSystemLibrary("pthread", .{});
            mod.linkSystemLibrary("rt", .{});
        },
        else => {},
    }
    step.dependOn(build_step);
}

fn addWindowsPipeline(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    // Windows: sample-target only for now. Builds the same Zig source
    // and the same Perfetto C SDK shim; the only Windows-specific bit
    // is the link surface (no CoreFoundation, no libdl — Winsock2 +
    // ntdll come from the Perfetto archive itself).
    //
    // Requires `tools/setup_perfetto.sh` to have produced a Windows
    // libperfetto.a. The setup script doesn't gen for Windows yet
    // (`uname -s` only knows Darwin/Linux), so this branch is wired up
    // for the day that's fixed — running it before then will fail at
    // the perfetto build step.
    const perfetto_build = b.addSystemCommand(&.{ "bash", b.pathFromRoot("tools/build_perfetto.sh") });
    const perfetto_root = b.path("third_party/src/perfetto");
    const perfetto_out = b.path("third_party/src/perfetto/out/sismo");

    const target_mod = b.createModule(.{
        .root_source_file = b.path("src/sample_target.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    // Windows uses the same `c_flags_macos` (no -D_GNU_SOURCE) — the
    // value isn't macos-specific, just "non-Linux".
    target_mod.addCSourceFile(.{
        .file = b.path("src/c/sample_target_sdk.c"),
        .flags = c_flags_macos,
        .language = .c,
    });
    target_mod.addIncludePath(perfetto_root.path(b, "include"));
    target_mod.addIncludePath(b.path("."));
    target_mod.addObjectFile(perfetto_out.path(b, "libperfetto.a"));

    const target_exe = b.addExecutable(.{
        .name = "sample-target",
        .root_module = target_mod,
    });
    target_exe.step.dependOn(&perfetto_build.step);
    b.installArtifact(target_exe);

    const target_step = b.step("sample-target", "Build the sample-target workload binary");
    target_step.dependOn(&b.addInstallArtifact(target_exe, .{}).step);
}

// ---- compile_commands.json emitter ---------------------------------------
//
// Walks `c_sources` and writes <repo_root>/compile_commands.json. Treats
// every source as host-targeted (Linux producers get included even on
// macOS so clangd can reason about them). Doesn't depend on Perfetto
// being built — the include paths reference the host out dir
// (`third_party/src/perfetto/out/sismo`); paths that don't exist yet are
// fine, clangd just shows missing-header diagnostics until you run
// `tools/setup_perfetto.sh`.

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
