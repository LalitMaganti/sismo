# Perfetto patches

Bridge patches applied to the `third_party/src/perfetto` checkout at
`tools/install-build-deps` time. The checkout is a shallow git clone of
`google/perfetto` pinned to `PERFETTO_PIN` in
`python/tools/install_build_deps.py`. Each `*.patch` file in this directory
is a unified diff applied with `git apply` (in `LANG=C.UTF-8 -p1` form) by
`python/tools/install_build_deps.py`.

## What belongs here

**Only upstream-pending changes** — i.e. patches whose final destination is
google/perfetto, which we want to use locally before they merge. When the
upstream PR lands and we merge upstream into the `sismo-perfetto` fork, the
patch becomes a no-op and we delete the file from this directory.

## What does NOT belong here

Sismo-permanent additions (the `SismoEmbedder`, the `external_embedder.ts`
override that wires it in, future sismo plugins) live as overlay files
under `third_party/overlays/perfetto/<mirror-of-perfetto-path>` and are
copied into the perfetto checkout by `tools/install-build-deps` after
patches are applied. They are not patches — they are sismo's own
content, browsable as normal source files in this tree.

## File naming

`NNNN-pr<num>-<short-description>.patch` — leading number controls apply
order, `pr<num>` is the upstream PR these patches are tracking. Example:
`0001-pr5712-ui-embedder-hooks.patch`.

## Idempotency

`install-build-deps` checks each patch with `git apply --reverse --check`
before applying. A patch that's already applied (e.g. because it landed in
the fork via an upstream merge) is skipped silently. A patch that fails to
apply is a hard error — re-base it against the current submodule HEAD or
delete it if it's been subsumed.

## Workflow

- Cherry-picking an in-flight PR locally:
  `gh pr diff <num> --repo google/perfetto > NNNN-pr<num>-<desc>.patch`,
  then commit in sismo.
- Upstream PR merges:
  bump `PERFETTO_PIN` in `python/tools/install_build_deps.py` to a SHA past
  the merge, then `rm` the patch file. The next `install-build-deps` run
  fetches and detaches at the new SHA; the deleted patch leaves no trace.
