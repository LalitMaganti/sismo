# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Wrapper to run the Zig compiler from third_party/.

Prefers a system zig if one is on PATH; falls back to third_party/bin/{platform}/zig/zig.
Pass --hermetic to force the third_party copy (e.g. for CI where the system
toolchain version isn't pinned).
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys


ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_platform_dir() -> tuple[str | None, str]:
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


def run_zig(args: list[str] | None = None, cwd: str | None = None) -> int | None:
    if args is None:
        args = []

    hermetic = False
    if "--hermetic" in args:
        hermetic = True
        args = [a for a in args if a != "--hermetic"]

    if not hermetic:
        system_binary = shutil.which("zig")
        if system_binary:
            if cwd or platform.system().lower() == "windows":
                sys.exit(subprocess.call([system_binary] + args, cwd=cwd))
            else:
                os.execl(system_binary, os.path.basename(system_binary), *args)

    os_dir, ext = get_platform_dir()
    if os_dir is None:
        print("OS not supported: %s" % platform.system())
        return 1

    zig_exe = os.path.join(ROOT_DIR, "third_party", "bin", os_dir, "zig", "zig") + ext
    if not os.path.exists(zig_exe):
        print("Zig binary not found: %s" % zig_exe)
        print("Run tools/install-build-deps to install Zig.")
        return 1

    if cwd or platform.system().lower() == "windows":
        sys.exit(subprocess.call([zig_exe] + args, cwd=cwd))
    else:
        os.execl(zig_exe, os.path.basename(zig_exe), *args)
