# Perfetto patches

Bridge patches applied to the `third_party/src/perfetto` checkout at
`tools/install-build-deps` time. The checkout is a shallow git clone of
`google/perfetto` pinned to `PERFETTO_PIN` in
`python/tools/install_build_deps.py`.

These `*.patch` files are a **`git format-patch` commit series**: each is a
mailbox-format patch applied as a real commit on top of the pin via
`git am`. So the applied-patch state is literally
`git -C third_party/src/perfetto log PERFETTO_PIN..HEAD` — one commit per
patch file, in numeric order.

Why commits instead of raw `git apply` working-tree edits:

- **Is a patch applied?** `git log PERFETTO_PIN..HEAD` shows the stack.
- **What's not yet captured?** Uncommitted changes in the checkout are work
  the patch files don't have yet — commit, then re-capture.
- **Split / reorder / edit patches** with `git rebase -i PERFETTO_PIN`.

## What belongs here

**Only upstream-pending changes** — patches whose final destination is
google/perfetto, which we want locally before they merge. When the upstream
PR lands and we bump `PERFETTO_PIN` past the merge, the patch becomes a
no-op and we delete the file.

## What does NOT belong here

Sismo-permanent additions (the `SismoEmbedder`, the `external_embedder.ts`
override that wires it in, the sismo plugins) live as overlay files under
`third_party/overlays/perfetto/<mirror-of-perfetto-path>` and are symlinked
into the checkout *after* the patches apply. They are not patches — they are
sismo's own content, browsable as normal source files in this tree.

## File naming

`NNNN-pr<num>-<short-description>.patch` (or `NNNN-nopr-<desc>.patch` for
sismo-local changes with no upstream PR yet). The leading number is the apply
order; `git format-patch` assigns it sequentially from the commit order. The
rest comes from the commit subject (e.g. subject `pr5712: ui embedder hooks`
→ `0001-pr5712-ui-embedder-hooks.patch`).

## How install applies them (idempotency)

`apply_perfetto_patches()` in `install_build_deps.py`:

1. Compares each patch's `Subject:` against the applied commit subjects in
   `PERFETTO_PIN..HEAD`. If they already match, it's a no-op.
2. Otherwise it `git reset --hard PERFETTO_PIN`, `git clean -fd` (dropping
   stale patch commits and untracked overlay symlinks; gitignored caches like
   `node_modules`/`out` survive), and `git am` the whole series fresh.

`git am` runs with a fixed committer identity and `commit.gpgsign=false`, so
it works headlessly in CI regardless of local git config. The author comes
from each patch's `From:` line, so the patch files never churn on re-capture.

## Workflow

**Edit / add / split a patch** — work directly in the checkout:

```sh
cd third_party/src/perfetto
# edit files, then either amend the top patch commit…
git commit --amend
# …or fix a lower one and autosquash:
git commit --fixup <sha> && git rebase -i --autosquash PERFETTO_PIN
# add a new patch: just commit on top.
```

**Capture** the commit series back to patch files:

```sh
python3 python/tools/capture_perfetto_patches.py
```

This rewrites the `NNNN-*.patch` set from `PERFETTO_PIN..HEAD` (stable flags:
`-k --zero-commit --no-signature`). `git status` then shows exactly which
patch files changed. Uncommitted edits to non-overlay files are flagged — they
won't be captured, so commit them first.

**Cherry-pick an in-flight upstream PR** locally:

```sh
cd third_party/src/perfetto
gh pr diff <num> --repo google/perfetto | git am   # or apply + commit
python3 ../../../python/tools/capture_perfetto_patches.py
```

**Upstream PR merges** — bump `PERFETTO_PIN` in `install_build_deps.py` past
the merge and `rm` the patch file. Run `python3
python/tools/uprev_perfetto.py <sha>` to re-checkout and re-`git am` the
remaining series; on a conflict it stops with the am session open for manual
`git am --continue`, then re-capture.
