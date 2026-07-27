// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

#include "sismo_trace_query.h"

#include <cstdio>
#include <memory>
#include <string>

#include "perfetto/trace_processor/basic_types.h"
#include "perfetto/trace_processor/iterator.h"
#include "perfetto/trace_processor/read_trace.h"
#include "perfetto/trace_processor/trace_processor.h"

namespace {

// Mirror of trace_processor's own kQueryUnsymbolized
// (src/trace_processor/util/symbolizer/symbolize_database.cc), with an
// ORDER BY so rows arrive grouped per mapping. Selecting the same columns
// keeps the address conventions identical: spf.rel_pc is what an emitted
// AddressSymbols.address must equal for trace_processor to match it back.
constexpr char kQueryUnsymbolized[] =
    R"(
      select
        spm.name,
        spm.build_id,
        spf.rel_pc,
        spm.load_bias,
        spm.address_kind
      from __intrinsic_stack_profile_frame spf
      join __intrinsic_stack_profile_mapping spm on spf.mapping = spm.id
      where (
          spm.build_id != ''
          or spm.name GLOB '[[]kernel.kallsyms]*'
        )
        and spf.symbol_set_id IS NULL
      order by spm.name, spm.build_id, spm.load_bias, spm.address_kind
    )";

// Per-module stack shape (DIA-0/DIA-1). For every module, count the samples
// whose innermost frame lands in it, and how many of those had a single user
// frame (leaf callsite at depth 0) — the frame-pointer-omission truncation
// marker. Grouped by the same (name, build_id, load_bias) key the symbolizer
// reports modules under, so the Rust side can correlate the two.
constexpr char kQueryStackQuality[] =
    R"(
      select
        spm.name,
        spm.build_id,
        spm.load_bias,
        spm.address_kind,
        count(*) as total,
        sum(case when c.depth = 0 then 1 else 0 end) as single_frame
      from perf_sample p
      join __intrinsic_stack_profile_callsite c on p.callsite_id = c.id
      join __intrinsic_stack_profile_frame f on c.frame_id = f.id
      join __intrinsic_stack_profile_mapping spm on f.mapping = spm.id
      group by spm.name, spm.build_id, spm.load_bias, spm.address_kind
    )";

// Load a trace into a fresh TraceProcessor, or return nullptr and log why.
std::unique_ptr<perfetto::trace_processor::TraceProcessor> LoadTrace(
    const char* trace_path) {
  using perfetto::trace_processor::Config;
  using perfetto::trace_processor::TraceProcessor;
  std::unique_ptr<TraceProcessor> tp = TraceProcessor::CreateInstance(Config());
  perfetto::base::Status status =
      perfetto::trace_processor::ReadTrace(tp.get(), trace_path);
  if (!status.ok()) {
    fprintf(stderr, "sismo symbolize: failed to read %s: %s\n", trace_path,
            status.c_message());
    return nullptr;
  }
  return tp;
}

}  // namespace

extern "C" int sismo_trace_query_unsymbolized(const char* trace_path,
                                              sismo_unsym_row_cb cb,
                                              void* ctx) {
  if (trace_path == nullptr || cb == nullptr) {
    return -1;
  }

  using perfetto::trace_processor::Iterator;
  using perfetto::trace_processor::SqlValue;
  using perfetto::trace_processor::TraceProcessor;

  std::unique_ptr<TraceProcessor> tp = LoadTrace(trace_path);
  if (tp == nullptr) {
    return -1;
  }
  perfetto::base::Status status;

  Iterator it = tp->ExecuteQuery(kQueryUnsymbolized);
  while (it.Next()) {
    SqlValue name = it.Get(0);
    SqlValue build_id = it.Get(1);
    SqlValue rel_pc = it.Get(2);
    SqlValue load_bias = it.Get(3);
    SqlValue address_kind = it.Get(4);
    if (rel_pc.is_null() || load_bias.is_null() || address_kind.is_null()) {
      continue;
    }
    const char* name_str = name.is_null() ? "" : name.AsString();
    const char* build_id_str = build_id.is_null() ? "" : build_id.AsString();
    cb(ctx, name_str, name_str ? std::char_traits<char>::length(name_str) : 0,
       build_id_str,
       build_id_str ? std::char_traits<char>::length(build_id_str) : 0,
       static_cast<uint64_t>(rel_pc.AsLong()),
       static_cast<uint64_t>(load_bias.AsLong()),
       static_cast<uint32_t>(address_kind.AsLong()));
  }
  status = it.Status();
  if (!status.ok()) {
    fprintf(stderr, "sismo symbolize: query failed: %s\n", status.c_message());
    return -1;
  }
  return 0;
}

extern "C" int sismo_trace_query_stack_quality(const char* trace_path,
                                               sismo_stack_quality_cb cb,
                                               void* ctx) {
  if (trace_path == nullptr || cb == nullptr) {
    return -1;
  }

  using perfetto::trace_processor::Iterator;
  using perfetto::trace_processor::SqlValue;
  using perfetto::trace_processor::TraceProcessor;

  std::unique_ptr<TraceProcessor> tp = LoadTrace(trace_path);
  if (tp == nullptr) {
    return -1;
  }

  Iterator it = tp->ExecuteQuery(kQueryStackQuality);
  while (it.Next()) {
    SqlValue name = it.Get(0);
    SqlValue build_id = it.Get(1);
    SqlValue load_bias = it.Get(2);
    SqlValue address_kind = it.Get(3);
    SqlValue total = it.Get(4);
    SqlValue single_frame = it.Get(5);
    if (total.is_null()) {
      continue;
    }
    const char* name_str = name.is_null() ? "" : name.AsString();
    const char* build_id_str = build_id.is_null() ? "" : build_id.AsString();
    cb(ctx, name_str, name_str ? std::char_traits<char>::length(name_str) : 0,
       build_id_str,
       build_id_str ? std::char_traits<char>::length(build_id_str) : 0,
       load_bias.is_null() ? 0 : static_cast<uint64_t>(load_bias.AsLong()),
       address_kind.is_null() ? 0
                              : static_cast<uint32_t>(address_kind.AsLong()),
       static_cast<uint64_t>(total.AsLong()),
       single_frame.is_null() ? 0
                              : static_cast<uint64_t>(single_frame.AsLong()));
  }
  perfetto::base::Status status = it.Status();
  if (!status.ok()) {
    fprintf(stderr, "sismo symbolize: stack-quality query failed: %s\n",
            status.c_message());
    return -1;
  }
  return 0;
}
