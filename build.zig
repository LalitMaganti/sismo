const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const os_tag = target.result.os.tag;

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
        check_mod.addIncludePath(b.path("src/c"));
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
    // libperfetto.a + sismo's C shim (perfetto_shim.c). The shim wraps
    // the Perfetto C SDK with sismo-flavoured helpers (hand-rolled
    // proto encoding for messages the C SDK doesn't expose builders
    // for; mode-aware TraceConfig builder; etc.).
    //
    // Build pipeline:
    //   1. tools/build_perfetto.sh runs ninja to produce libperfetto.a
    //      in third_party/src/perfetto/out/<perfetto_out_name>/.
    //      Cross-compile uses zig cc as a clang drop-in.
    //   2. perfetto_shim_lib compiles src/c/perfetto_shim.c against the
    //      vendored public headers (no amalgamation).
    //   3. Each consumer linkLibrary(perfetto_shim_lib) +
    //      addObjectFile(libperfetto.a) + OS-specific frameworks/libs.
    // -------------------------------------------------------------------------
    const perfetto_build = b.addSystemCommand(&.{ "bash", b.pathFromRoot("tools/build_perfetto.sh") });
    if (sismo_target) |trip| perfetto_build.setEnvironmentVariable("SISMO_TARGET", trip);
    const perfetto_root = b.path("third_party/src/perfetto");
    const perfetto_out = b.path(b.fmt("third_party/src/perfetto/out/{s}", .{perfetto_out_name}));

    const perfetto_shim_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    perfetto_shim_mod.addIncludePath(b.path("src/c"));
    perfetto_shim_mod.addIncludePath(perfetto_root.path(b, "include"));
    // Perfetto's public headers (thread_utils.h on Linux) reach for
    // `syscall(__NR_gettid)`, which is gated behind `_GNU_SOURCE` in
    // glibc's <unistd.h>. The header is included transitively from
    // both perfetto_shim.c and sample_target_sdk.c so the define has
    // to be set on every C source file that pulls in Perfetto.
    const c_flags: []const []const u8 = if (is_macos)
        &.{"-std=c11"}
    else
        &.{ "-std=c11", "-D_GNU_SOURCE" };

    perfetto_shim_mod.addCSourceFile(.{
        .file = b.path("src/c/perfetto_shim.c"),
        .flags = c_flags,
        .language = .c,
    });
    const perfetto_shim_lib = b.addLibrary(.{
        .name = "perfetto_shim",
        .root_module = perfetto_shim_mod,
        .linkage = .static,
    });
    perfetto_shim_lib.step.dependOn(&perfetto_build.step);

    const shim_include = b.path("src/c");
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
        target_mod.addCSourceFile(.{
            .file = b.path("src/c/sample_target_sdk.c"),
            .flags = c_flags,
            .language = .c,
        });
        target_mod.addIncludePath(perfetto_root.path(b, "include"));

        const target_exe = b.addExecutable(.{
            .name = "sample-target",
            .root_module = target_mod,
        });
        linkPerfetto(target_mod, &target_exe.step, perfetto_shim_lib, shim_include, lib_a, &perfetto_build.step, os_tag);
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
        const cpp_flags: []const []const u8 = if (is_macos)
            &.{ "-std=c++17", "-fno-exceptions", "-fno-rtti", "-DNDEBUG" }
        else
            &.{ "-std=c++17", "-fno-exceptions", "-fno-rtti", "-DNDEBUG", "-D_GNU_SOURCE" };
        sismo_mod.addCSourceFile(.{
            .file = b.path("src/c/sismo_traced.cc"),
            .flags = cpp_flags,
            .language = .cpp,
        });
        sismo_mod.addCSourceFile(.{
            .file = b.path("src/c/sismo_consumer.cc"),
            .flags = cpp_flags,
            .language = .cpp,
        });
        sismo_mod.addIncludePath(perfetto_root.path(b, "include"));
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
        linkPerfetto(sismo_mod, &sismo_exe.step, perfetto_shim_lib, shim_include, lib_a, &perfetto_build.step, os_tag);
        sismo_exe.step.dependOn(&cargo.step);
        b.installArtifact(sismo_exe);
        const sismo_step = b.step("sismo", "Build the sismo CLI (subcommand dispatcher)");
        sismo_step.dependOn(&b.addInstallArtifact(sismo_exe, .{}).step);
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
    shim_lib: *std.Build.Step.Compile,
    inc: std.Build.LazyPath,
    lib_a: std.Build.LazyPath,
    build_step: *std.Build.Step,
    os_tag: std.Target.Os.Tag,
) void {
    mod.addIncludePath(inc);
    mod.linkLibrary(shim_lib);
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

    const perfetto_shim_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    perfetto_shim_mod.addIncludePath(b.path("src/c"));
    perfetto_shim_mod.addIncludePath(perfetto_root.path(b, "include"));
    perfetto_shim_mod.addCSourceFile(.{
        .file = b.path("src/c/perfetto_shim.c"),
        .flags = &.{"-std=c11"},
        .language = .c,
    });
    const perfetto_shim_lib = b.addLibrary(.{
        .name = "perfetto_shim",
        .root_module = perfetto_shim_mod,
        .linkage = .static,
    });
    perfetto_shim_lib.step.dependOn(&perfetto_build.step);

    const target_mod = b.createModule(.{
        .root_source_file = b.path("src/sample_target.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    target_mod.addCSourceFile(.{
        .file = b.path("src/c/sample_target_sdk.c"),
        .flags = &.{"-std=c11"},
        .language = .c,
    });
    target_mod.addIncludePath(perfetto_root.path(b, "include"));
    target_mod.addIncludePath(b.path("src/c"));
    target_mod.linkLibrary(perfetto_shim_lib);
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
