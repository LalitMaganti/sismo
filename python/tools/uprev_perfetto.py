# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Uprev the pinned Perfetto checkout and rebase sismo's bridge patches.

Usage:
    python3 python/tools/uprev_perfetto.py [SHA|latest]

Steps, in order:
  1. Resolve the target SHA (an explicit 40-char SHA, or `latest` =
     google/perfetto refs/heads/main).
  2. Rewrite PERFETTO_PIN in install_build_deps.py to the target SHA.
  3. Re-checkout the perfetto subtree at the new SHA (hard reset + clean via
     install_source_dep — this wipes the previously-applied patch commits so
     they can be re-applied cleanly).
  4. Re-apply the bridge patch series with `git am --3way` (the patches are a
     git format-patch commit series; see the patches README). Either the whole
     series applies as commits, or am stops at the first patch that conflicts
     and leaves a half-applied am session for manual resolution.
  5. Re-link the overlays (install_perfetto_overlays).

If a patch conflicts, the script reports which one, leaves the `git am`
session open in the checkout, exits non-zero, and never runs the build. Resolve
the conflict, `git am --continue` (repeat for any further conflicts), then
re-capture the rebased series with
`python3 python/tools/capture_perfetto_patches.py`.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT_DIR: str = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, ROOT_DIR)

DEPS_FILE: str = os.path.join(ROOT_DIR, "python", "tools", "install_build_deps.py")
PERFETTO_GIT: str = "https://github.com/google/perfetto.git"
SHA_RE = re.compile(r"[0-9a-f]{40}")
PIN_RE = re.compile(r'pin="[0-9a-f]{40}"')


def latest_main_sha() -> str:
    out = subprocess.check_output(
        ["git", "ls-remote", PERFETTO_GIT, "refs/heads/main"]
    ).decode()
    return out.split()[0]


def current_pin() -> str | None:
    m = re.search(r'pin="([0-9a-f]{40})"', open(DEPS_FILE).read())
    return m.group(1) if m else None


def set_pin(new_sha: str) -> None:
    txt = open(DEPS_FILE).read()
    if not PIN_RE.search(txt):
        sys.exit("could not find PERFETTO_PIN (pin=\"...\") in install_build_deps.py")
    open(DEPS_FILE, "w").write(PIN_RE.sub(f'pin="{new_sha}"', txt, count=1))


def am_failing_patch(perfetto_dir: str, patch_paths: list[str]) -> str | None:
    """When a `git am` session is stuck mid-series, the basename of the patch
    it choked on (read from .git/rebase-apply/next); None if no session."""
    next_file = os.path.join(perfetto_dir, ".git", "rebase-apply", "next")
    try:
        idx = int(open(next_file).read().strip())
    except (FileNotFoundError, ValueError):
        return None
    if 1 <= idx <= len(patch_paths):
        return os.path.basename(patch_paths[idx - 1])
    return "<unknown>"


def reapply_patches(perfetto_dir: str, patch_paths: list[str]) -> bool:
    """Apply the whole bridge series as commits via `git am --3way`. Returns
    True on success; on conflict leaves the am session open for manual
    resolution and returns False."""
    am = subprocess.run(
        ["git", "-C", perfetto_dir,
         "-c", "user.name=sismo-bridge",
         "-c", "user.email=sismo-bridge@localhost",
         "-c", "commit.gpgsign=false",
         "am", "--keep-cr", "--3way", *patch_paths],
    )
    return am.returncode == 0


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "latest"
    if target == "latest":
        target = latest_main_sha()
    if not SHA_RE.fullmatch(target):
        sys.exit(f"target must be a 40-char SHA or 'latest', got: {target}")

    old = current_pin()
    print(f"==> uprev perfetto: {(old or '?')[:10]} -> {target[:10]}")
    if old == target:
        print("    (pin unchanged; re-checking out + re-applying anyway)")
    set_pin(target)

    from python.tools.install_build_deps import (  # noqa: E402
        SOURCE_DEPS,
        install_perfetto_overlays,
        install_source_dep,
        perfetto_patch_files,
    )
    # The GN target symlink (//sismo -> infra/perfetto-build/sismo) is a
    # generated, untracked file, so the checkout's `git clean -fd` wipes it.
    # Re-link it or the perfetto GN build can't find //sismo:sismo_libperfetto.
    from python.tools.setup_perfetto import link_sismo_gn_target  # noqa: E402

    perfetto_dir = None
    for dep in SOURCE_DEPS:
        if dep.name != "perfetto":
            continue
        assert dep.pin == target, "pin rewrite did not take effect"
        print(f"==> checking out perfetto @ {target[:10]} (hard reset + clean)")
        if not install_source_dep(dep):
            sys.exit("perfetto checkout failed")
        perfetto_dir = os.path.join(ROOT_DIR, dep.target_dir)
    if perfetto_dir is None:
        sys.exit("no perfetto SOURCE_DEP found")

    patch_paths = perfetto_patch_files()
    print(f"==> re-applying {len(patch_paths)} bridge patch(es) via git am")
    am_ok = reapply_patches(perfetto_dir, patch_paths)

    if not am_ok:
        # Conflict: the am session is left open in the checkout. Skip overlays
        # and the GN link — the dev resolves first, then re-captures.
        failing = am_failing_patch(perfetto_dir, patch_paths)
        print(
            f"\n==> CONFLICT applying {failing}. The `git am` session is left "
            f"open in third_party/src/perfetto."
        )
        print(
            "    Resolve it, then:\n"
            "      git -C third_party/src/perfetto am --continue   "
            "(repeat per conflict; or --skip a now-upstreamed patch)\n"
            "      python3 python/tools/capture_perfetto_patches.py   "
            "(rewrite the rebased series back to patch files)\n"
            "      python3 python/tools/install_build_deps.py --patches-only "
            "  (re-link overlays)"
        )
        return 1

    print("==> re-linking overlays")
    if not install_perfetto_overlays():
        sys.exit("overlay link failed")

    print("==> re-linking //sismo GN target")
    link_sismo_gn_target()

    print(f"\n==> done. perfetto @ {target[:10]}, all patches applied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
