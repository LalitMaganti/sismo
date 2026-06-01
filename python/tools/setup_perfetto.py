# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Bootstrap the Perfetto checkout at third_party/src/perfetto/ and gen a
per-target build output dir.

Steps:
  1. Ensure the perfetto source clone + sismo patches/overlays are in place
     (delegates to tools/install-build-deps).
  2. Run Perfetto's install-build-deps to fetch gn, ninja, clang, protoc.
  3. gn gen the sismo build output dir with our args.

By default targets the host (out/sismo). Pass a target triple via
--target or the SISMO_TARGET env var:

    tools/setup-perfetto                                # host (out/sismo)
    tools/setup-perfetto --target x86_64-linux-gnu      # cross (out/sismo_linux_x64)
    tools/setup-perfetto --target aarch64-linux-gnu     # (out/sismo_linux_arm64)
    SISMO_TARGET=x86_64-linux-gnu tools/setup-perfetto

Cross-compile uses `zig cc` / `zig c++` / `zig ar` as a hermetic clang
drop-in (libc, libc++, lld all bundled with Zig). The user must have
`zig` on $PATH.

After this runs, `tools/build-perfetto [--target SISMO_TARGET]` will
incrementally build the targets sismo needs (traced, traced_perf,
trace_processor_shell, the libperfetto.a static archive).
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys

from python.tools.run_zig import get_platform_dir

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PERFETTO_DIR: str = os.path.join(ROOT_DIR, "third_party", "src", "perfetto")


def resolve_zig() -> str:
    """Absolute path to the zig binary to feed GN as cc/cxx/ar. Prefer system
    zig (matches what `tools/zig` picks at runtime); fall back to the
    bundled copy in third_party/bin. Bail loudly if neither exists."""
    system = shutil.which("zig")
    if system:
        return system
    os_dir, ext = get_platform_dir()
    if os_dir is None:
        sys.exit(f"unsupported host for bundled zig: {platform.system()}")
    bundled = os.path.join(ROOT_DIR, "third_party", "bin", os_dir, "zig", "zig") + ext
    if not os.path.exists(bundled):
        sys.exit(
            f"no zig on $PATH and bundled zig missing at {bundled}; "
            "run tools/install-build-deps first"
        )
    return bundled

# Map of SISMO_TARGET → (out_name, target_os, target_cpu).
TARGET_RESOLUTION: dict[str, tuple[str, str, str]] = {
    "x86_64-linux-gnu":   ("sismo_linux_x64",     "linux", "x64"),
    "x86_64-linux-musl":  ("sismo_linux_x64",     "linux", "x64"),
    "aarch64-linux-gnu":  ("sismo_linux_arm64",   "linux", "arm64"),
    "aarch64-linux-musl": ("sismo_linux_arm64",   "linux", "arm64"),
    "x86_64-windows-gnu":  ("sismo_windows_x64",   "win",   "x64"),
    "aarch64-windows-gnu": ("sismo_windows_arm64", "win",   "arm64"),
}


def host_target_os() -> str:
    sys_name = platform.system()
    if sys_name == "Darwin":
        return "mac"
    if sys_name == "Linux":
        return "linux"
    sys.exit(f"unsupported host: {sys_name}")


def args_gn_native(target_os: str) -> str:
    # Linux native: use zig as the compiler driver (same as cross-compile,
    # minus the -target flags) so sismo and Perfetto agree on libc++.
    # Perfetto's default `use_custom_libcxx = is_linux && is_hermetic_clang`
    # (gn/standalone/libc++/libc++.gni) bundles libc++ into the static
    # archive when hermetic clang is in use, and those symbols then collide
    # with zig's own libc++ at the final link step. Flipping
    # is_hermetic_clang=false flips use_custom_libcxx off, leaving a single
    # libc++ (zig's) in the link.
    if target_os == "linux":
        zig = resolve_zig()
        return f"""# sismo's GN args for Perfetto (Linux native via zig cc).
is_debug = false
is_clang = true
is_system_compiler = true   # collapse host+target toolchain to one cc/cxx
is_hermetic_clang = false   # don't fetch a vendored Linux clang
target_os = "{target_os}"

# Default on Linux is libperfetto.so; sismo links the static archive,
# matching the macOS / Windows defaults.
monolithic_binaries = true

cc = "{zig} cc"
cxx = "{zig} c++"
ar = "{zig} ar"

enable_perfetto_traced_perf = true
enable_perfetto_traced_probes = true
enable_perfetto_trace_processor_sqlite = true
enable_perfetto_trace_processor_json = false
enable_perfetto_ui = false
enable_perfetto_integration_tests = false
enable_perfetto_unittests = false
"""

    return f"""# sismo's GN args for Perfetto. Keep this minimal; sismo doesn't need
# the chromium / android / system-perfetto bits.
is_debug = false
is_clang = true
target_os = "{target_os}"

# We need:
#   - traced + ServiceIPCHost (linkable as in-process)
#   - traced_perf (Linux CPU sampler, in-process thread)
#   - traced_probes (Linux ftrace + procfs producer, in-process thread)
#   - trace_processor_shell (validation in tools/e2e-all-sources)
#   - libperfetto.a (data source registration in sismo's bespoke producers)
enable_perfetto_traced_perf = true
enable_perfetto_traced_probes = true
enable_perfetto_trace_processor_sqlite = true
enable_perfetto_trace_processor_json = false
enable_perfetto_ui = false
enable_perfetto_integration_tests = false
enable_perfetto_unittests = false
"""


def args_gn_cross(sismo_target: str, target_os: str, target_cpu: str) -> str:
    zig = resolve_zig()
    return f"""# Cross-compile {sismo_target} via `zig cc` (clang drop-in with bundled
# libc / libc++ / lld). Generated by tools/setup-perfetto.

is_debug = false
is_clang = true
is_system_compiler = true   # collapse host+target toolchain to one cc/cxx
is_hermetic_clang = false   # don't fetch a vendored Linux clang

target_os = "{target_os}"
target_cpu = "{target_cpu}"

# Default on Linux is libperfetto.so; sismo links the static archive,
# matching the macOS / Windows defaults.
monolithic_binaries = true

cc = "{zig} cc"
cxx = "{zig} c++"
ar = "{zig} ar"

# Cross flags applied only to the target toolchain. Host tools (protoc
# + plugins) are built for the build machine's native arch — leave
# extra_host_*flags empty so zig cc picks up the native target.
extra_target_cflags = "-target {sismo_target}"
extra_target_cxxflags = "-target {sismo_target}"
extra_target_asmflags = "-target {sismo_target}"
extra_target_ldflags = "-target {sismo_target} -fuse-ld=lld"

enable_perfetto_traced_perf = true
enable_perfetto_traced_probes = true
enable_perfetto_trace_processor_sqlite = true
enable_perfetto_trace_processor_json = false
enable_perfetto_ui = false
enable_perfetto_integration_tests = false
enable_perfetto_unittests = false
"""


def ensure_perfetto_source_and_patches() -> None:
    """Idempotently clones perfetto at the pinned SHA + applies patches and
    overlays. Delegates to install_build_deps so the source-of-truth for
    SOURCE_DEPS, the patches list, and overlay copy logic stays there."""
    from python.tools.install_build_deps import (
        SOURCE_DEPS,
        apply_perfetto_patches,
        install_perfetto_overlays,
        install_source_dep,
    )
    print(f"==> Perfetto checkout at {PERFETTO_DIR}")
    for dep in SOURCE_DEPS:
        if dep.name != "perfetto":
            continue
        if not install_source_dep(dep):
            sys.exit("perfetto source install failed")
    print("==> applying sismo bridge patches as a git am commit series "
          "(third_party/patches/perfetto/*.patch)")
    if not apply_perfetto_patches():
        sys.exit("perfetto patch apply failed")
    if not install_perfetto_overlays():
        sys.exit("perfetto overlay install failed")


def link_sismo_gn_target() -> None:
    # Symlink sismo's GN target file into the Perfetto checkout so GN sees
    # it as //sismo:sismo_libperfetto without any modification to Perfetto's
    # own BUILD.gn files. The directory is gitignored from Perfetto's
    # perspective (it lives under the gitignored Perfetto checkout, but the
    # real file is checked in to the sismo repo at infra/perfetto-build/sismo).
    sismo_gn_link = os.path.join(PERFETTO_DIR, "sismo")
    sismo_gn_target = os.path.join(ROOT_DIR, "infra", "perfetto-build", "sismo")

    if os.path.islink(sismo_gn_link):
        # Refresh idempotently so a re-pin can update the target if needed.
        os.unlink(sismo_gn_link)
    elif os.path.exists(sismo_gn_link):
        sys.exit(
            f"==> {sismo_gn_link} exists and is not a symlink; "
            f"refusing to overwrite"
        )
    os.symlink(sismo_gn_target, sismo_gn_link)
    print(f"==> linked //sismo -> {sismo_gn_target}")


def run_perfetto_install_build_deps() -> None:
    print("==> running install-build-deps "
          "(fetches gn/ninja/clang/protoc into the subtree)")
    # Default scope (no flags) installs the toolchain + dev tools needed for
    # native builds. We don't pass --android / --ui / --bazel — they're opt-in.
    subprocess.check_call(
        [os.path.join(PERFETTO_DIR, "tools", "install-build-deps")]
    )


def write_args_gn(out_dir: str, sismo_target: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    if sismo_target:
        _, target_os, target_cpu = TARGET_RESOLUTION[sismo_target]
        contents = args_gn_cross(sismo_target, target_os, target_cpu)
    else:
        contents = args_gn_native(host_target_os())
    with open(os.path.join(out_dir, "args.gn"), "w") as f:
        f.write(contents)


def gn_gen(out_name: str) -> None:
    # gn gen needs to be invoked with Perfetto's repo as the source root.
    # --root-target=//sismo points GN at the symlinked sismo BUILD.gn as the
    # entry point so the build graph is rooted at sismo's :default group
    # (sismo_libperfetto + traced + trace_processor_shell) instead of
    # Perfetto's full standalone build (UI, perfetto_cmd, traceconv, etc.).
    subprocess.check_call(
        ["tools/gn", "gen", f"out/{out_name}", "--root-target=//sismo"],
        cwd=PERFETTO_DIR,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--target",
        default=os.environ.get("SISMO_TARGET", ""),
        help="Target triple for cross-compile (also honored via SISMO_TARGET env)",
    )
    args = parser.parse_args()

    sismo_target = args.target
    if sismo_target and sismo_target not in TARGET_RESOLUTION:
        sys.exit(f"unsupported SISMO_TARGET '{sismo_target}'")

    if sismo_target:
        out_name = TARGET_RESOLUTION[sismo_target][0]
    else:
        out_name = "sismo"

    ensure_perfetto_source_and_patches()
    link_sismo_gn_target()
    run_perfetto_install_build_deps()

    out_dir = os.path.join(PERFETTO_DIR, "out", out_name)
    target_os = (TARGET_RESOLUTION[sismo_target][1]
                 if sismo_target else host_target_os())
    target_cpu = (TARGET_RESOLUTION[sismo_target][2] if sismo_target else "")
    suffix = f" target_cpu={target_cpu}" if target_cpu else ""
    print(f"==> gn gen {out_dir} (target_os={target_os}{suffix})")

    write_args_gn(out_dir, sismo_target)
    gn_gen(out_name)

    print()
    print("==> setup complete")
    print(f"    args.gn:  {os.path.join(out_dir, 'args.gn')}")
    next_invocation = (
        f"tools/build-perfetto --target {sismo_target}"
        if sismo_target else "tools/build-perfetto"
    )
    print(f"    next:     {next_invocation}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
