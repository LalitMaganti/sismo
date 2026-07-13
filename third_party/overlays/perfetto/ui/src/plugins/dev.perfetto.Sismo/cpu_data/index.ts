// Copyright (C) 2026 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Public surface of the CPU data layer. Loaders and result shapes are grouped
// by domain into sibling modules; this barrel re-exports what the views and
// tabs consume so importers keep a single `./cpu_data` entry point.

export {
  type FocusWindow,
  tsRangeClause,
  overlapClause,
  clipDurExpr,
  focusKey,
} from './focus_window';

export {
  type HeaviestFunctionRow,
  type RepresentativeSample,
  type SampleListRow,
  loadHeaviestFunctions,
  loadRepresentativeSample,
  loadSampleList,
} from './calltree';

export {
  type ConcurrencyDist,
  type CpuDetail,
  type CpuSummary,
  type LatencyDetail,
  loadCpuDetail,
  loadCpuSummary,
  loadLatencyDetail,
} from './overview';

export {
  type CoreActivityRow,
  type CoreContentionRow,
  type CoreSeries,
  type CoreThreadDetail,
  type CoreThreadRow,
  type CpuCoreRow,
  type CpuIdleStateRow,
  type CpuProcessRow,
  type CpuThreadRow,
  type CpuRuntimeTotals,
  type ThreadStateRow,
  type OccupantShare,
  type RunnableDelay,
  type RunnableSummary,
  type WakerRow,
  type WakerSummary,
  type LockRow,
  type LockContention,
  type LockDetail,
  type LockSiteRow,
  type LockWaiterRow,
  type WaitTypeRow,
  type WaitBreakdown,
  type NetPeerRow,
  type NetworkPeers,
  type NetWaiterRow,
  type NetPeerDetail,
  type DiskFileRow,
  type DiskFiles,
  type DiskReaderRow,
  type DiskFileDetail,
  loadCoreActivity,
  loadCoreContention,
  loadCoreSeries,
  loadCoreThreads,
  loadCpuTotals,
  loadLockContention,
  loadLockDetail,
  loadNetworkPeers,
  loadNetPeerDetail,
  loadDiskFiles,
  loadDiskFileDetail,
  loadWaitBreakdown,
  loadPerCore,
  loadProcessRows,
  loadRunnableSummary,
  loadThreadRows,
  loadThreadStates,
} from './cores';

export {
  type ActivityBoard,
  type ActivityBucket,
  type WindowThreadRow,
  loadActivityBoard,
  loadWindowConsumers,
} from './activity';

export {
  type EntitySplitRow,
  type FunctionDetail,
  SPLIT_LIMIT,
  loadFunctionDetail,
} from './entity_detail';

export {type Butterfly, type ButterflyEdge, loadButterfly} from './butterfly';

export {
  type AnnInsn,
  type AnnRow,
  type SourceAsm,
  loadSourceAsm,
} from './annotation';

export {type CpuTriage, loadCpuTriage} from './triage';

export {
  type FunctionMicroarch,
  type HotMappingRow,
  type HotSymbolRow,
  type MicroarchCounters,
  type MicroarchData,
  type MicroarchFuncRow,
  type TmaBucket,
  type TmaModel,
  type UarchSeriesPoint,
  computeTma,
  loadFunctionMicroarch,
  loadMicroarch,
  loadMicroarchCounters,
} from './microarch';
