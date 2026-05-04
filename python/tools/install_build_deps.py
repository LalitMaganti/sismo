# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Installs build dependencies under third_party/, clones the upstream
Perfetto repo at a pinned SHA, and applies sismo's bridge patches and
overlays to it.

Binary deps land as pinned, checksummed tarballs under
third_party/bin/{platform_dir}/, idempotent via per-dep .stamp files.
Source deps land as pinned git checkouts under third_party/src/, idempotent
by checking HEAD against the pin.

Sismo deps:
  - Zig 0.16.0 (binary tarball from ziglang.org)
  - Rust 1.94.0 (binary tarball from static.rust-lang.org)
  - Perfetto (git clone of google/perfetto, pinned to PERFETTO_PIN below)

Perfetto is checked out at third_party/src/perfetto/. The clone is shallow
(--depth 200) and detached at PERFETTO_PIN. Bumping the pin to a newer
upstream SHA only requires editing the constant; on the next run the
function fetches and checks out the new SHA.

Patches in third_party/patches/perfetto/*.patch are applied on top via
`git apply`. These are bridge patches for in-flight upstream PRs only;
each patch is idempotent and gets deleted when the corresponding upstream
PR merges.

Overlays in third_party/overlays/perfetto/<perfetto-relative-path> are
copied into the Perfetto checkout after patches apply. Overlays are
sismo-permanent additions (e.g. ui/src/core/embedder/sismo_embedder.ts)
that don't correspond to any upstream PR — they live as normal
TypeScript/Python/whatever files in this repo and only land in the
Perfetto checkout at install time.

See third_party/patches/perfetto/README.md for the patches/overlays
convention.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass

VERBOSITY: int = 0


def vprint(level: int, *args: object, **kwargs: object) -> None:
    if VERBOSITY >= level:
        print(*args, **kwargs)


ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
THIRD_PARTY_DIR: str = os.path.join(ROOT_DIR, "third_party")
THIRD_PARTY_BIN_DIR: str = os.path.join(THIRD_PARTY_DIR, "bin")

ZIG_VERSION: str = "0.16.0"
RUST_VERSION: str = "1.94.0"


@dataclass
class BinaryDep:
    """Binary dependency (platform-specific)."""
    name: str
    version: str
    url: str
    sha256: str
    target_os: str  # darwin, linux, windows, or all
    target_arch: str  # x64, arm64, or all
    format: str = "zip"
    strip_prefix: str = ""  # Directory prefix to strip from archive


@dataclass
class SourceDep:
    """Source dependency: a git checkout pinned to a specific commit."""
    name: str
    target_dir: str  # Relative to ROOT_DIR.
    git_url: str
    pin: str  # Full SHA1 commit hash.
    fetch_depth: int = 200


SOURCE_DEPS: list[SourceDep] = [
    # Perfetto. Bump `pin` to roll forward; the next install-build-deps run
    # fetches and detaches at the new SHA. Sismo's bridge patches in
    # third_party/patches/perfetto/ must apply cleanly against this SHA —
    # see third_party/patches/perfetto/README.md.
    SourceDep(
        name="perfetto",
        target_dir="third_party/src/perfetto",
        git_url="https://github.com/google/perfetto.git",
        pin="0eb65d89f0b0eb1dc512d519ff15457bcfc86ed8",
    ),
]


# fmt: off
BINARY_DEPS: list[BinaryDep] = [
    # Zig 0.16.0 from ziglang.org. SHA256s from
    # https://ziglang.org/download/index.json.
    BinaryDep("zig", ZIG_VERSION,
              f"https://ziglang.org/download/{ZIG_VERSION}/zig-aarch64-macos-{ZIG_VERSION}.tar.xz",
              "b23d70deaa879b5c2d486ed3316f7eaa53e84acf6fc9cc747de152450d401489",
              "darwin", "arm64", "tar.xz",
              f"zig-aarch64-macos-{ZIG_VERSION}"),
    BinaryDep("zig", ZIG_VERSION,
              f"https://ziglang.org/download/{ZIG_VERSION}/zig-x86_64-macos-{ZIG_VERSION}.tar.xz",
              "0387557ed1877bc6a2e1802c8391953baddba76081876301c522f52977b52ba7",
              "darwin", "x64", "tar.xz",
              f"zig-x86_64-macos-{ZIG_VERSION}"),
    BinaryDep("zig", ZIG_VERSION,
              f"https://ziglang.org/download/{ZIG_VERSION}/zig-x86_64-linux-{ZIG_VERSION}.tar.xz",
              "70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00",
              "linux", "x64", "tar.xz",
              f"zig-x86_64-linux-{ZIG_VERSION}"),
    BinaryDep("zig", ZIG_VERSION,
              f"https://ziglang.org/download/{ZIG_VERSION}/zig-aarch64-linux-{ZIG_VERSION}.tar.xz",
              "ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17",
              "linux", "arm64", "tar.xz",
              f"zig-aarch64-linux-{ZIG_VERSION}"),
    BinaryDep("zig", ZIG_VERSION,
              f"https://ziglang.org/download/{ZIG_VERSION}/zig-x86_64-windows-{ZIG_VERSION}.zip",
              "68659eb5f1e4eb1437a722f1dd889c5a322c9954607f5edcf337bc3684a75a7e",
              "windows", "x64", "zip",
              f"zig-x86_64-windows-{ZIG_VERSION}"),

    # Rust toolchain. SHA256s from https://static.rust-lang.org/dist/channel-rust-1.94.0.toml.
    BinaryDep("rust", RUST_VERSION,
              f"https://static.rust-lang.org/dist/2026-03-05/rust-{RUST_VERSION}-aarch64-apple-darwin.tar.gz",
              "94903e93a4334d42bb6d92377a39903349c07f3709c792864bcdf7959f3c8c7d",
              "darwin", "arm64", "tar.gz",
              f"rust-{RUST_VERSION}-aarch64-apple-darwin"),
    BinaryDep("rust", RUST_VERSION,
              f"https://static.rust-lang.org/dist/2026-03-05/rust-{RUST_VERSION}-x86_64-apple-darwin.tar.gz",
              "97724032da92646194a802a7991f1166c4dc9f0a63f3bb01a53860e98f31d08c",
              "darwin", "x64", "tar.gz",
              f"rust-{RUST_VERSION}-x86_64-apple-darwin"),
    BinaryDep("rust", RUST_VERSION,
              f"https://static.rust-lang.org/dist/2026-03-05/rust-{RUST_VERSION}-x86_64-unknown-linux-gnu.tar.gz",
              "3bb1925a0a5ad2c17be731ee6e977e4a68490ab2182086db897bd28be21e965f",
              "linux", "x64", "tar.gz",
              f"rust-{RUST_VERSION}-x86_64-unknown-linux-gnu"),
    BinaryDep("rust", RUST_VERSION,
              f"https://static.rust-lang.org/dist/2026-03-05/rust-{RUST_VERSION}-aarch64-unknown-linux-gnu.tar.gz",
              "a0dc5a65ab337421347533e5be11d3fab11f119683a0dbd257ef3fe968bd2d72",
              "linux", "arm64", "tar.gz",
              f"rust-{RUST_VERSION}-aarch64-unknown-linux-gnu"),
    BinaryDep("rust", RUST_VERSION,
              f"https://static.rust-lang.org/dist/2026-03-05/rust-{RUST_VERSION}-x86_64-pc-windows-msvc.tar.gz",
              "b349a6eace4063e4a89d9be1de2e77b20bd0193016a43036522f453be709c0f8",
              "windows", "x64", "tar.gz",
              f"rust-{RUST_VERSION}-x86_64-pc-windows-msvc"),
]
# fmt: on


def get_platform() -> tuple[str, str, str]:
    """Returns (os, arch, platform_dir)."""
    sys_name = platform.system().lower()
    machine = platform.machine().lower()

    if sys_name == "darwin":
        host_os, prefix = "darwin", "mac"
    elif sys_name == "linux":
        host_os, prefix = "linux", "linux"
    elif sys_name == "windows":
        host_os, prefix = "windows", "win"
    else:
        sys.exit(f"Unsupported OS: {sys_name}")

    host_arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
    platform_dir = f"{prefix}-{'arm64' if host_arch == 'arm64' else 'amd64'}"

    return host_os, host_arch, platform_dir


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def extract(archive_path: str, dest_dir: str, fmt: str) -> None:
    if fmt == "zip":
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(dest_dir)
    elif fmt == "tar.gz":
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(dest_dir)
    elif fmt == "tar.xz":
        with tarfile.open(archive_path, "r:xz") as tf:
            tf.extractall(dest_dir)
    else:
        sys.exit(f"Unsupported format: {fmt}")


def download(url: str, out_path: str) -> bool:
    curl_args = ["curl", "-fL", "-o", out_path, url]
    if VERBOSITY == 0:
        curl_args.insert(2, "--progress-bar")
    return subprocess.run(curl_args).returncode == 0


def install_zig(dep: BinaryDep, target_dir: str) -> bool:
    """Install Zig: drop the toolchain at target_dir/zig/."""
    zig_dir = os.path.join(target_dir, "zig")
    stamp_path = os.path.join(target_dir, ".zig.stamp")

    if os.path.exists(stamp_path) and os.path.isdir(zig_dir):
        with open(stamp_path) as f:
            if f.read().strip() == dep.version:
                return True

    vprint(1, f"Downloading Zig {dep.version}...")
    os.makedirs(target_dir, exist_ok=True)

    suffix = ".tar.xz" if dep.format == "tar.xz" else ".zip"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = tmp.name

    try:
        if not download(dep.url, tmp_path):
            print("Download failed", file=sys.stderr)
            return False

        actual = sha256_file(tmp_path)
        if actual != dep.sha256:
            print(f"SHA256 mismatch for zig: expected {dep.sha256}, got {actual}", file=sys.stderr)
            return False

        with tempfile.TemporaryDirectory() as extract_dir:
            extract(tmp_path, extract_dir, dep.format)
            src = os.path.join(extract_dir, dep.strip_prefix) if dep.strip_prefix else extract_dir
            if os.path.exists(zig_dir):
                shutil.rmtree(zig_dir)
            shutil.move(src, zig_dir)

        zig_exe = os.path.join(zig_dir, "zig.exe" if dep.target_os == "windows" else "zig")
        if os.path.exists(zig_exe):
            os.chmod(zig_exe, 0o755)

        with open(stamp_path, "w") as f:
            f.write(dep.version)

        return True
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def install_rust(dep: BinaryDep, target_dir: str) -> bool:
    """Install Rust toolchain: rustc + cargo + rust-std merged into target_dir/rust/."""
    rust_dir = os.path.join(target_dir, "rust")
    stamp_path = os.path.join(target_dir, ".rust.stamp")

    if os.path.exists(stamp_path) and os.path.isdir(rust_dir):
        with open(stamp_path) as f:
            if f.read().strip() == dep.version:
                return True

    vprint(1, f"Downloading Rust {dep.version}...")
    os.makedirs(target_dir, exist_ok=True)

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        if not download(dep.url, tmp_path):
            print("Download failed", file=sys.stderr)
            return False

        actual = sha256_file(tmp_path)
        if actual != dep.sha256:
            print(f"SHA256 mismatch for rust: expected {dep.sha256}, got {actual}", file=sys.stderr)
            return False

        vprint(1, "Extracting Rust tarball (this may take a minute)...")
        with tempfile.TemporaryDirectory() as extract_dir:
            extract(tmp_path, extract_dir, dep.format)
            src_dir = os.path.join(extract_dir, dep.strip_prefix)

            if os.path.exists(rust_dir):
                vprint(1, "Removing old Rust installation...")
                shutil.rmtree(rust_dir)
            os.makedirs(rust_dir)

            for component in ("rustc", "cargo"):
                comp_dir = os.path.join(src_dir, component)
                if os.path.exists(comp_dir):
                    shutil.copytree(comp_dir, os.path.join(rust_dir, component))

            std_dirs = [d for d in os.listdir(src_dir) if d.startswith("rust-std-")]
            if not std_dirs:
                print("Warning: rust-std component not found", file=sys.stderr)
                return False

            src_std_rustlib = os.path.join(src_dir, std_dirs[0], "lib", "rustlib")
            dest_rustlib = os.path.join(rust_dir, "rustc", "lib", "rustlib")

            for item_name in os.listdir(src_std_rustlib):
                src_path = os.path.join(src_std_rustlib, item_name)
                dest_path = os.path.join(dest_rustlib, item_name)

                if not os.path.isdir(src_path):
                    shutil.copy2(src_path, dest_path)
                    continue

                if not os.path.exists(dest_path):
                    shutil.copytree(src_path, dest_path)
                    continue

                for sub_name in os.listdir(src_path):
                    src_sub = os.path.join(src_path, sub_name)
                    dest_sub = os.path.join(dest_path, sub_name)
                    if os.path.exists(dest_sub):
                        if os.path.isdir(dest_sub):
                            shutil.rmtree(dest_sub)
                        else:
                            os.unlink(dest_sub)
                    shutil.move(src_sub, dest_sub)

            for bindir in ("cargo/bin", "rustc/bin"):
                bin_path = os.path.join(rust_dir, bindir)
                if os.path.exists(bin_path):
                    for exe in os.listdir(bin_path):
                        exe_path = os.path.join(bin_path, exe)
                        if os.path.isfile(exe_path):
                            os.chmod(exe_path, 0o755)

        with open(stamp_path, "w") as f:
            f.write(dep.version)

        return True
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def install_binary_dep(dep: BinaryDep, target_dir: str) -> bool:
    if dep.name == "rust":
        return install_rust(dep, target_dir)
    if dep.name == "zig":
        return install_zig(dep, target_dir)
    sys.exit(f"No installer for binary dep: {dep.name}")


PERFETTO_DIR: str = os.path.join(THIRD_PARTY_DIR, "src", "perfetto")
PERFETTO_PATCHES_DIR: str = os.path.join(THIRD_PARTY_DIR, "patches", "perfetto")
PERFETTO_OVERLAYS_DIR: str = os.path.join(
    THIRD_PARTY_DIR, "overlays", "perfetto")


def _is_git_repo(path: str) -> bool:
    """Returns True if `path` is a git working tree (a regular clone with a
    .git directory, or a checkout with a .git pointer file)."""
    return os.path.exists(os.path.join(path, ".git"))


def _git_head(repo: str) -> str:
    return subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "HEAD"], text=True
    ).strip()


def install_source_dep(dep: SourceDep) -> bool:
    """Idempotent git checkout: clone the repo on first run, fetch+detach at
    `dep.pin` if HEAD diverges, otherwise no-op. Patches/overlays applied on
    top of the working tree are preserved as long as HEAD already matches.
    """
    abs_dir = os.path.join(ROOT_DIR, dep.target_dir)

    if not _is_git_repo(abs_dir):
        vprint(1, f"Cloning {dep.git_url} -> {dep.target_dir}")
        os.makedirs(os.path.dirname(abs_dir), exist_ok=True)
        rc = subprocess.run(
            ["git", "clone", "--depth", str(dep.fetch_depth), dep.git_url,
             abs_dir]
        ).returncode
        if rc != 0:
            print(f"Clone failed: {dep.git_url}", file=sys.stderr)
            return False

    current = _git_head(abs_dir)
    if current == dep.pin:
        vprint(2, f"{dep.target_dir}: at pin {dep.pin[:10]}")
        return True

    vprint(1, f"{dep.target_dir}: {current[:10]} -> {dep.pin[:10]}")
    # The pinned SHA may not be in the existing shallow clone. Fetch it
    # specifically; most forges allow fetching reachable SHAs in want.
    fetch = subprocess.run(
        ["git", "-C", abs_dir, "fetch", "--depth", str(dep.fetch_depth),
         "origin", dep.pin],
        capture_output=True,
    )
    if fetch.returncode != 0:
        # Servers that reject SHA-in-want — fall back to a deeper full fetch.
        rc = subprocess.run(
            ["git", "-C", abs_dir, "fetch", "--depth",
             str(dep.fetch_depth * 2), "origin"],
        ).returncode
        if rc != 0:
            print(f"Fetch failed: {dep.git_url}", file=sys.stderr)
            return False
    rc = subprocess.run(
        ["git", "-C", abs_dir, "checkout", "--detach", dep.pin]
    ).returncode
    if rc != 0:
        print(
            f"{dep.target_dir}: checkout of {dep.pin[:10]} failed — working "
            f"tree may have local changes (patches/overlays). Stash or reset "
            f"and re-run.",
            file=sys.stderr,
        )
        return False
    return True


def apply_perfetto_patches() -> bool:
    """Applies *.patch files from third_party/patches/perfetto/ to the
    Perfetto checkout. Idempotent: skips patches that are already applied.
    """
    if not os.path.isdir(PERFETTO_PATCHES_DIR):
        return True

    if not _is_git_repo(PERFETTO_DIR):
        vprint(1, "Perfetto checkout missing; skipping patch apply.")
        vprint(1, "Run `tools/install-build-deps` first to clone it.")
        return True

    patches = sorted(
        p for p in os.listdir(PERFETTO_PATCHES_DIR) if p.endswith(".patch")
    )
    if not patches:
        return True

    applied_count = 0
    for name in patches:
        patch_path = os.path.join(PERFETTO_PATCHES_DIR, name)

        # Already applied? `git apply --reverse --check` succeeds iff the
        # patch's post-state matches the working tree, i.e. it would apply
        # cleanly if reversed.
        already = subprocess.run(
            ["git", "-C", PERFETTO_DIR, "apply", "--reverse", "--check",
             patch_path],
            capture_output=True,
        )
        if already.returncode == 0:
            vprint(2, f"  {name}: already applied")
            continue

        # Not applied — but make sure it *would* apply before doing it, so
        # we get a clean error rather than a half-applied state.
        check = subprocess.run(
            ["git", "-C", PERFETTO_DIR, "apply", "--check", patch_path],
            capture_output=True,
        )
        if check.returncode != 0:
            print(f"Patch {name} does not apply cleanly:", file=sys.stderr)
            print(check.stderr.decode(), file=sys.stderr)
            print(
                f"\nPERFETTO_PIN may have moved underneath this patch. "
                f"Either re-base the patch against the current pin, or "
                f"delete it if the upstream PR has merged.",
                file=sys.stderr,
            )
            return False

        result = subprocess.run(
            ["git", "-C", PERFETTO_DIR, "apply", patch_path],
            capture_output=True,
        )
        if result.returncode != 0:
            print(f"Failed to apply {name}:", file=sys.stderr)
            print(result.stderr.decode(), file=sys.stderr)
            return False
        vprint(1, f"applied perfetto patch: {name}")
        applied_count += 1

    if applied_count == 0:
        vprint(2, f"all {len(patches)} perfetto patch(es) already applied")
    return True


def install_perfetto_overlays() -> bool:
    """Copies sismo-permanent overlay files from third_party/overlays/perfetto/
    into the Perfetto checkout. Overlay files are sismo additions that don't
    correspond to any in-flight upstream PR — typically new files like
    ui/src/core/embedder/{external_embedder,sismo_embedder}.ts that override
    perfetto's defaults. Each overlay's path inside the overlays dir mirrors
    its destination inside the perfetto checkout.
    """
    if not os.path.isdir(PERFETTO_OVERLAYS_DIR):
        return True

    if not _is_git_repo(PERFETTO_DIR):
        vprint(1, "Perfetto checkout missing; skipping overlay copy.")
        return True

    copied = 0
    for src_dir, _, files in os.walk(PERFETTO_OVERLAYS_DIR):
        for name in files:
            src = os.path.join(src_dir, name)
            rel = os.path.relpath(src, PERFETTO_OVERLAYS_DIR)
            dst = os.path.join(PERFETTO_DIR, rel)

            # Skip if already up to date (same content). Idempotent so a
            # subsequent run doesn't churn mtimes and trigger needless
            # rebuilds in build systems that mtime-track inputs.
            if (os.path.exists(dst)
                    and os.path.getsize(dst) == os.path.getsize(src)):
                with open(src, "rb") as fa, open(dst, "rb") as fb:
                    if fa.read() == fb.read():
                        vprint(2, f"  {rel}: up to date")
                        continue

            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            vprint(1, f"installed perfetto overlay: {rel}")
            copied += 1

    if copied == 0:
        vprint(2, "all perfetto overlays already up to date")
    return True


def main() -> int:
    global VERBOSITY

    parser = argparse.ArgumentParser(description="Install build dependencies to third_party/")
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be repeated: -v, -vv)"
    )
    parser.add_argument(
        "--no-rust",
        action="store_true",
        help="Skip Rust toolchain installation"
    )
    parser.add_argument(
        "--no-zig",
        action="store_true",
        help="Skip Zig installation"
    )
    parser.add_argument(
        "--no-source",
        action="append",
        default=[],
        metavar="NAME",
        help="Skip a source dep by name (repeatable). Use 'all' to skip all "
             f"({', '.join(d.name for d in SOURCE_DEPS)})."
    )
    parser.add_argument(
        "--no-patches",
        action="store_true",
        help="Skip applying Perfetto bridge patches and overlays"
    )
    parser.add_argument(
        "--patches-only",
        action="store_true",
        help="Only apply Perfetto patches and overlays; skip toolchain "
             "installs. Useful in CI where Perfetto's own install-build-deps "
             "handles tooling"
    )
    args = parser.parse_args()
    VERBOSITY = args.verbose

    success = True

    if not args.patches_only:
        host_os, host_arch, platform_dir = get_platform()
        bin_target_dir = os.path.join(THIRD_PARTY_BIN_DIR, platform_dir)

        for dep in BINARY_DEPS:
            if dep.name == "rust" and args.no_rust:
                continue
            if dep.name == "zig" and args.no_zig:
                continue
            os_match = dep.target_os == "all" or dep.target_os == host_os
            arch_match = (
                dep.target_arch == "all" or dep.target_arch == host_arch
            )
            if os_match and arch_match:
                if not install_binary_dep(dep, bin_target_dir):
                    success = False

    if not args.patches_only:
        skip_all_sources = "all" in args.no_source
        for dep in SOURCE_DEPS:
            if skip_all_sources or dep.name in args.no_source:
                continue
            if not install_source_dep(dep):
                success = False

    if not args.no_patches:
        if not apply_perfetto_patches():
            success = False
        if not install_perfetto_overlays():
            success = False

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
