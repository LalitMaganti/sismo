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
  type CallTree,
  type CallTreeNode,
  type CallTreeDirection,
  type HeaviestFunctionRow,
  type RepresentativeSample,
  type SampleListRow,
  loadCallTree,
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
  type CpuBlameRow,
  type CpuCoreRow,
  type CpuIdleStateRow,
  type CpuProcessRow,
  type CpuThreadBlameRow,
  type CpuThreadRow,
  type CpuRuntimeTotals,
  type ThreadStateRow,
  loadCoreActivity,
  loadCoreContention,
  loadCoreSeries,
  loadCoreThreads,
  loadCpuTotals,
  loadPerCore,
  loadProcessRows,
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


export {type CpuTriage, loadCpuTriage} from './triage';

export {
  type DrillLens,
  type Observation,
  type ObservationDrill,
  type ObservationKind,
  loadObservations,
} from './observations';

export {
  type HotMappingRow,
  type HotSymbolRow,
  type MicroarchCounters,
  type MicroarchData,
  type MicroarchFuncRow,
  type MicroarchGrouping,
  type MicroarchGroupRow,
  type MicroarchGroups,
  type RealCycles,
  type TmaBucket,
  type TmaModel,
  computeTma,
  loadMicroarch,
  loadMicroarchByGroup,
  loadMicroarchCounters,
  loadRealCycles,
} from './microarch';
