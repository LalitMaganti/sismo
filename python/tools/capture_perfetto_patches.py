# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Re-capture the Perfetto bridge patch series from the checkout's git history.

The bridge patches in third_party/patches/perfetto/ are a `git format-patch`
commit series applied on top of PERFETTO_PIN via `git am` (see
install_build_deps.py / the patches README). This tool regenerates those
*.patch files from the commits currently sitting in
`PERFETTO_PIN..HEAD` of the checkout.

Workflow:
  1. Edit / add / split / reorder the patch commits directly in the checkout
     at third_party/src/perfetto:
       - tweak a patch:   edit files, then `git commit --fixup <sha>` +
                          `git rebase -i --autosquash PERFETTO_PIN`, or just
                          `git commit --amend` if it's the top commit.
       - add a patch:     commit your new change on top.
       - split a patch:   `git rebase -i PERFETTO_PIN`, mark `edit`, then
                          `git reset HEAD^` and re-commit in pieces.
  2. Run this tool to write the commit series back out as patch files.
  3. `git status` in the sismo repo shows exactly which patch files changed.

Anything still uncommitted in the checkout is NOT captured — commit it first.
This tool flags uncommitted edits to non-overlay files so they aren't missed.

Usage:
    python3 python/tools/capture_perfetto_patches.py
"""

from __future__ import annotations

import os
import subprocess
import sys

ROOT_DIR: str = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, ROOT_DIR)

from python.tools.install_build_deps import (  # noqa: E402
    PERFETTO_DIR,
    PERFETTO_OVERLAYS_DIR,
    PERFETTO_PATCHES_DIR,
    perfetto_pin,
)

# Same flags the series was generated with — keep them in sync so unchanged
# commits round-trip to byte-identical patch files:
#   -k             keep the subject verbatim (no `[PATCH n/m]` prefix, so the
#                  files don't churn when the patch count changes)
#   --zero-commit  zero the `From <sha>` line (no churn from commit SHAs)
#   --no-signature drop the trailing `-- \n<git version>` footer
FORMAT_PATCH_FLAGS: list[str] = ["-k", "--zero-commit", "--no-signature"]


def _overlay_rel_paths() -> set[str]:
    """Repo-relative paths the overlays manage in the checkout. Working-tree
    changes to these are expected (overlay symlinks replacing tracked files)
    and not something `git format-patch` would capture, so they're excluded
    from the 'uncommitted edits' warning."""
    paths: set[str] = set()
    for src_dir, _, files in os.walk(PERFETTO_OVERLAYS_DIR):
        for name in files:
            src = os.path.join(src_dir, name)
            paths.add(os.path.relpath(src, PERFETTO_OVERLAYS_DIR))
    return paths


def _uncommitted_non_overlay() -> list[str]:
    """Tracked files with uncommitted changes that aren't overlay-managed —
    i.e. real patch edits the dev probably meant to commit before capturing."""
    res = subprocess.run(
        ["git", "-C", PERFETTO_DIR, "diff", "--name-only", "HEAD"],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        return []
    overlays = _overlay_rel_paths()
    return [p for p in res.stdout.splitlines() if p and p not in overlays]


def main() -> int:
    pin = perfetto_pin()
    if pin is None:
        sys.exit("no perfetto SOURCE_DEP pin found in install_build_deps.py")

    subjects = subprocess.run(
        ["git", "-C", PERFETTO_DIR, "log", "--reverse", "--format=%h %s",
         f"{pin}..HEAD"],
        capture_output=True, text=True,
    )
    if subjects.returncode != 0:
        sys.exit(
            f"could not read {pin[:10]}..HEAD — is the checkout present and "
            f"the pin fetched? Run tools/install-build-deps first."
        )
    commits = [c for c in subjects.stdout.splitlines() if c]
    if not commits:
        sys.exit(
            f"no commits in {pin[:10]}..HEAD — nothing to capture. The bridge "
            f"patches are applied as commits on top of the pin; apply them "
            f"first (tools/install-build-deps) or commit your changes."
        )

    stray = _uncommitted_non_overlay()
    if stray:
        print("WARNING: uncommitted changes to non-overlay files — these will "
              "NOT be captured (commit them into a patch first):")
        for p in stray:
            print(f"    {p}")
        print()

    print(f"==> capturing {len(commits)} commit(s) on {pin[:10]}:")
    for c in commits:
        print(f"    {c}")

    # Regenerate from scratch so dropped/renumbered patches don't leave stale
    # files behind. format-patch rewrites the NNNN-*.patch set in full.
    for old in sorted(os.listdir(PERFETTO_PATCHES_DIR)):
        if old.endswith(".patch"):
            os.remove(os.path.join(PERFETTO_PATCHES_DIR, old))

    fmt = subprocess.run(
        ["git", "-C", PERFETTO_DIR, "format-patch", *FORMAT_PATCH_FLAGS,
         f"{pin}..HEAD", "-o", PERFETTO_PATCHES_DIR],
        capture_output=True, text=True,
    )
    if fmt.returncode != 0:
        print(fmt.stdout, file=sys.stderr)
        print(fmt.stderr, file=sys.stderr)
        sys.exit("git format-patch failed")

    written = [os.path.basename(p) for p in fmt.stdout.splitlines() if p]
    print(f"\n==> wrote {len(written)} patch file(s) to "
          f"third_party/patches/perfetto/:")
    for w in written:
        print(f"    {w}")
    print("\nReview with: git -C "
          f"{os.path.relpath(ROOT_DIR)} status third_party/patches/perfetto/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
