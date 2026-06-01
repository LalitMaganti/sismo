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
  type CallTree,
  type CallTreeNode,
  type HeaviestFunctionRow,
  type SampleListRow,
  loadCallTree,
  loadHeaviestFunctions,
  loadSampleList,
} from './calltree';

export {
  type ConcurrencyDist,
  type CpuDetail,
  type CpuSummary,
  type LatencyDetail,
  loadCpuDetail,
  loadLatencyDetail,
} from './overview';

export {
  type CoreActivityRow,
  type CoreSeries,
  type CpuBlameRow,
  type CpuCoreRow,
  type CpuIdleStateRow,
  type CpuProcessRow,
  type CpuThreadBlameRow,
  type CpuThreadRow,
  type ThreadStateRow,
  loadCoreActivity,
  loadCoreSeries,
  loadThreadStates,
} from './cores';

export {
  type ActivityBoard,
  type ActivityBucket,
  loadActivityBoard,
} from './activity';

export {type CpuTriage, loadCpuTriage} from './triage';

export {
  type HotMappingRow,
  type HotSymbolRow,
  type MicroarchCounters,
  type MicroarchData,
  type MicroarchFuncRow,
  type RealCycles,
  type TmaBucket,
  type TmaModel,
  computeTma,
  loadMicroarchCounters,
  loadRealCycles,
} from './microarch';
