# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Wrapper to run cargo, rustc and other Rust binaries from third_party/."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_platform_dir() -> tuple[str | None, str]:
    """Returns the platform-specific buildtools subdirectory name."""
    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"

    if sys_name == "darwin":
        return "mac-" + arch, ""
    elif sys_name == "linux":
        return "linux-" + arch, ""
    elif sys_name == "windows":
        return "win-" + arch, ".exe"
    else:
        return None, ""


def run_rust_binary(binary_name: str, args: list[str] | None = None, cwd: str | None = None) -> int | None:
    if args is None:
        args = []

    set_sysroot = True
    if "--no-sysroot" in args:
        set_sysroot = False
        args = [a for a in args if a != "--no-sysroot"]

    hermetic = False
    if "--hermetic" in args:
        hermetic = True
        args = [a for a in args if a != "--hermetic"]

    system_binary = shutil.which(binary_name)
    if system_binary and not hermetic:
        if cwd or platform.system().lower() == "windows":
            sys.exit(subprocess.call([system_binary] + args, cwd=cwd))
        else:
            os.execl(system_binary, os.path.basename(system_binary), *args)

    os_dir, ext = get_platform_dir()
    if os_dir is None:
        print("OS not supported: %s" % platform.system())
        return 1

    rust_root = os.path.join(ROOT_DIR, "third_party", "bin", os_dir, "rust")

    component = binary_name  # cargo or rustc
    exe_path = os.path.join(rust_root, component, "bin", binary_name) + ext

    if not os.path.exists(exe_path):
        print("Rust binary not found: %s" % exe_path)
        print("Run tools/install-build-deps to install the Rust toolchain.")
        return 1

    rustc_path = os.path.join(rust_root, "rustc", "bin", "rustc") + ext
    if os.path.exists(rustc_path):
        os.environ["RUSTC"] = rustc_path

    if set_sysroot:
        rustc_sysroot = os.path.join(rust_root, "rustc")
        os.environ["RUSTFLAGS"] = f"--sysroot {rustc_sysroot}"

    if cwd or platform.system().lower() == "windows":
        sys.exit(subprocess.call([exe_path] + args, cwd=cwd))
    else:
        os.execl(exe_path, os.path.basename(exe_path), *args)
