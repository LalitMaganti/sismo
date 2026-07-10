#!/usr/bin/env python3
# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.

"""Generate the collector's PMU event-encoding table from Intel's perfmon DB.

Reads the vendored third_party/perfmon (mapfile.csv + per-model core event JSON)
and, for the small set of events sismo's Top-Down + vitals analysis needs (the
SPEC below, addressed by ROLE with per-model name fallbacks), emits a Zig table
mapping each CPU model to the resolved perf_event_open `config` for each role.

The collector reads CPUID at record time, finds its model here, and opens those
events — so PMU encodings come from Intel's source of truth per microarchitecture
instead of hardcoded raw values, and per-model name differences (e.g.
UOPS_RETIRED.SLOTS on Golden Cove vs .RETIRE_SLOTS on Skylake) resolve cleanly.

Run via `tools/gen-pmu-events` (after install-build-deps has vendored perfmon).
Intel-only; ARM PMU events come from a different source.
"""

import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PERFMON = os.path.join(ROOT, "third_party", "perfmon")
OUT = os.path.join(ROOT, "rust-bridge", "src", "pmu_events.rs")

# sismo role -> candidate perfmon event names, most-preferred first. The first
# candidate present in a model's event list wins. A role absent from a model is
# simply omitted (the collector / UI degrade to whatever's available).
# Prefer the programmable (_P) variants of the two architectural fixed-counter
# events: the collector opens every counter via PERF_TYPE_RAW, and the fixed-
# counter pseudo-encodings (EventCode 0x00 / UMask 0x01,0x02) don't count on
# that path (cycles read 0). The _P encodings (0x3c, 0xc0) do, and the kernel
# still auto-routes these architectural events onto the fixed counters so they
# don't consume a general-purpose counter.
SPEC = {
    "cycles": ["CPU_CLK_UNHALTED.THREAD_P", "CPU_CLK_UNHALTED.THREAD"],
    "instructions": ["INST_RETIRED.ANY_P", "INST_RETIRED.ANY"],
    "slots": ["TOPDOWN.SLOTS"],
    "retired": ["UOPS_RETIRED.SLOTS", "UOPS_RETIRED.RETIRE_SLOTS"],
    "fetch_bubbles": ["IDQ_UOPS_NOT_DELIVERED.CORE"],
    "cache_miss": ["LONGEST_LAT_CACHE.MISS"],
    "branch_miss": ["BR_MISP_RETIRED.ALL_BRANCHES"],
    # Cache-focus sampler leader: a precise (PEBS) load-retirement event that
    # carries Data_LA, so a sample's PERF_SAMPLE_ADDR is the linear address of
    # the missed load. LONGEST_LAT_CACHE.MISS (the cache_miss counter role)
    # counts references, not load uops, and has no Data_LA — it can't drive the
    # data-address attribution.
    "l3_miss_load": ["MEM_LOAD_RETIRED.L3_MISS"],
}
ROLES = list(SPEC.keys())


def hx(v, default=0):
    if v is None or v == "":
        return default
    return int(str(v), 16)


def config_of(ev: dict) -> int:
    """perf_event_open RAW config from a perfmon event's fields."""
    cfg = hx(ev.get("EventCode")) | (hx(ev.get("UMask")) << 8)
    cfg |= hx(ev.get("CounterMask")) << 24          # cmask
    if str(ev.get("EdgeDetect", "0")) not in ("0", "", None):
        cfg |= 1 << 18
    if str(ev.get("Invert", "0")) not in ("0", "", None):
        cfg |= 1 << 23
    if str(ev.get("AnyThread", "0")) not in ("0", "", None):
        cfg |= 1 << 21
    return cfg


def load_events(rel_path: str) -> dict:
    """Map EventName -> event dict for one perfmon events file."""
    p = os.path.join(PERFMON, rel_path.lstrip("/"))
    with open(p) as f:
        doc = json.load(f)
    evs = doc["Events"] if isinstance(doc, dict) and "Events" in doc else doc
    out = {}
    for e in evs:
        name = e.get("EventName")
        if name and name not in out:
            out[name] = e
    return out


def resolve(events: dict):
    """[(role, name, config)] for the roles this model can satisfy."""
    found = []
    for role in ROLES:
        for cand in SPEC[role]:
            if cand in events:
                found.append((role, cand, config_of(events[cand])))
                break
    return found


def parse_id(model_id: str):
    """'GenuineIntel-6-97' / 'GenuineIntel-6-55-[01234]' -> (family, model,
    [steppings]). family/model are decimal ints (model is hex in the id, hence
    base 16); steppings are the hex digits in the [..] set ([] = any)."""
    parts = model_id.split("-")
    if len(parts) < 3 or parts[0] != "GenuineIntel":
        return None
    family = int(parts[1])
    model = int(parts[2], 16)
    steppings = []
    if len(parts) >= 4:
        tok = parts[3]
        if tok.startswith("[") and tok.endswith("]"):
            steppings = [int(c, 16) for c in tok[1:-1]]
        else:
            steppings = [int(tok, 16)]
    return family, model, steppings


def main() -> int:
    mapfile = os.path.join(PERFMON, "mapfile.csv")
    if not os.path.exists(mapfile):
        print("perfmon not vendored — run tools/install-build-deps", file=sys.stderr)
        return 1

    # (model_id, core_role) -> resolved events, deduped (mapfile repeats files).
    models = []
    seen = set()
    with open(mapfile) as f:
        for row in csv.DictReader(f):
            if row["EventType"] not in ("core", "hybridcore"):
                continue
            model_id = row["Family-model"]
            core = row.get("Core Role Name", "") or ""
            key = (model_id, core)
            if key in seen:
                continue
            try:
                events = load_events(row["Filename"])
            except (FileNotFoundError, json.JSONDecodeError):
                continue
            parsed = parse_id(model_id)
            if parsed is None:
                continue
            resolved = resolve(events)
            if not any(r[0] == "cycles" for r in resolved):
                continue  # not a usable core table
            seen.add(key)
            family, model, steppings = parsed
            models.append((family, model, steppings, core, resolved))

    models.sort()
    lines = [
        "// @generated by python/tools/gen_pmu_events.py from third_party/perfmon.",
        "// DO NOT EDIT — run tools/gen-pmu-events to regenerate.",
        "//",
        "// PMU event encodings per Intel CPU model, resolved from Intel's perfmon",
        "// database. The collector matches its CPUID (`id`, and `core` for hybrid",
        "// parts) and opens these as PERF_TYPE_RAW `config` values — no hardcoded",
        "// encodings, and per-model event-name differences are handled at codegen.",
        "",
        "#![allow(non_camel_case_types, dead_code)]",
        "",
        "#[derive(Clone, Copy, PartialEq, Eq)]",
        "pub enum Role {",
    ]
    for role in ROLES:
        lines.append(f"    {role},")
    lines += [
        "}",
        "",
        "pub struct Event {",
        "    pub role: Role,",
        "    pub config: u64,",
        "    pub name: &'static str,",
        "}",
        "pub struct Model {",
        "    pub family: u16,",
        "    pub model: u16,",
        "    /// CPUID steppings this row applies to; empty matches any stepping.",
        "    pub steppings: &'static [u8],",
        "    /// Hybrid core role: \"\" (non-hybrid), \"Core\" (P-core), \"Atom\" (E-core).",
        "    pub core: &'static str,",
        "    pub events: &'static [Event],",
        "}",
        "",
        "pub static MODELS: &[Model] = &[",
    ]
    for family, model, steppings, core, resolved in models:
        st = ", ".join(str(s) for s in steppings)
        lines.append(
            f"    Model {{ family: {family}, model: {model}, "
            f"steppings: &[{st}], core: \"{core}\", events: &["
        )
        for role, name, cfg in resolved:
            lines.append(
                f"        Event {{ role: Role::{role}, config: 0x{cfg:x}, "
                f'name: "{name}" }},'
            )
        lines.append("    ] },")
    lines += ["];", ""]

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        f.write("\n".join(lines))
    print(f"wrote {OUT}: {len(models)} models")
    return 0


if __name__ == "__main__":
    sys.exit(main())
