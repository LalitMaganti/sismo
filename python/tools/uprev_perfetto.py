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
     install_source_dep — this wipes the previously-applied patches so they
     can be re-applied cleanly).
  4. Re-apply each third_party/patches/perfetto/*.patch:
       - already applied      -> skipped
       - applies cleanly      -> applied
       - context drift        -> `git apply --reject` lands what it can and
                                 writes .rej hunks; reported as NEEDS-REBASE.
  5. Re-link the overlays (install_perfetto_overlays).

On any NEEDS-REBASE patch the script exits non-zero after doing everything
else, so the .rej files can be resolved, the patch regenerated, and the script
re-run. It never runs the UI/native build.
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
PATCHES_DIR: str = os.path.join(ROOT_DIR, "third_party", "patches", "perfetto")
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


def reapply_patch(perfetto_dir: str, path: str) -> str:
    # Already applied (post-state matches working tree)?
    if subprocess.run(
        ["git", "-C", perfetto_dir, "apply", "--reverse", "--check", path],
        capture_output=True,
    ).returncode == 0:
        return "already-applied"
    # Clean forward apply?
    if subprocess.run(
        ["git", "-C", perfetto_dir, "apply", "--check", path],
        capture_output=True,
    ).returncode == 0:
        subprocess.run(["git", "-C", perfetto_dir, "apply", path], check=True)
        return "applied"
    # Drifted: land what we can, leave .rej for the rest.
    subprocess.run(
        ["git", "-C", perfetto_dir, "apply", "--reject", path],
        capture_output=True,
    )
    return "NEEDS-REBASE"


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

    print("==> re-applying bridge patches")
    results = []
    for name in sorted(p for p in os.listdir(PATCHES_DIR) if p.endswith(".patch")):
        status = reapply_patch(perfetto_dir, os.path.join(PATCHES_DIR, name))
        results.append((name, status))
        print(f"    {status:16} {name}")

    print("==> re-linking overlays")
    if not install_perfetto_overlays():
        sys.exit("overlay link failed")

    print("==> re-linking //sismo GN target")
    link_sismo_gn_target()

    conflicts = [n for n, s in results if s == "NEEDS-REBASE"]
    if conflicts:
        print(
            f"\n==> {len(conflicts)} patch(es) need manual rebase "
            f"(.rej files written in the checkout):"
        )
        for n in conflicts:
            print(f"     - {n}")
        print(
            "    Resolve the .rej hunks, regenerate the patch with\n"
            "    `git -C third_party/src/perfetto diff <files> > "
            "third_party/patches/perfetto/<name>`, then re-run this script."
        )
        return 1

    print(f"\n==> done. perfetto @ {target[:10]}, all patches applied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
