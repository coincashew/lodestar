import {AbortSignal} from "@chainsafe/abort-controller";
import {phase0, Slot, allForks, RootHex} from "@chainsafe/lodestar-types";
import {IForkChoice, IProtoBlock} from "@chainsafe/lodestar-fork-choice";
import {
  CachedBeaconState,
  CachedBeaconStateAllForks,
  computeEpochAtSlot,
} from "@chainsafe/lodestar-beacon-state-transition";
import {CheckpointHex, CheckpointStateCache, StateContextCache, toCheckpointHex} from "../stateCache";
import {IMetrics} from "../../metrics";
import {JobItemQueue} from "../../util/queue";
import {IStateRegenerator, IStateRegeneratorInternal, RegenCaller, RegenFnName} from "./interface";
import {StateRegenerator, RegenModules} from "./regen";
import {RegenError, RegenErrorCode} from "./errors";
import {toHexString} from "@chainsafe/ssz";

const REGEN_QUEUE_MAX_LEN = 256;

type QueuedStateRegeneratorModules = RegenModules & {
  signal: AbortSignal;
};

type RegenRequestKey = keyof IStateRegeneratorInternal;
type RegenRequestByKey = {[K in RegenRequestKey]: {key: K; args: Parameters<IStateRegeneratorInternal[K]>}};
export type RegenRequest = RegenRequestByKey[RegenRequestKey];

/**
 * Regenerates states that have already been processed by the fork choice
 *
 * All requests are queued so that only a single state at a time may be regenerated at a time
 */
export class QueuedStateRegenerator implements IStateRegenerator {
  readonly jobQueue: JobItemQueue<[RegenRequest], CachedBeaconStateAllForks>;
  private regen: StateRegenerator;

  private forkChoice: IForkChoice;
  private stateCache: StateContextCache;
  private checkpointStateCache: CheckpointStateCache;
  private metrics: IMetrics | null;

  private headStateRootHex: string | null = null;
  private headState: CachedBeaconState<allForks.BeaconState> | null = null;

  constructor(modules: QueuedStateRegeneratorModules) {
    this.regen = new StateRegenerator(modules);
    this.jobQueue = new JobItemQueue<[RegenRequest], CachedBeaconStateAllForks>(
      this.jobQueueProcessor,
      {maxLength: REGEN_QUEUE_MAX_LEN, signal: modules.signal},
      modules.metrics ? modules.metrics.regenQueue : undefined
    );
    this.forkChoice = modules.forkChoice;
    this.stateCache = modules.stateCache;
    this.checkpointStateCache = modules.checkpointStateCache;
    this.metrics = modules.metrics;
  }

  /**
   * Get the state to run with `block`.
   * - State after `block.parentRoot` dialed forward to block.slot
   */
  async getPreState(block: allForks.BeaconBlock, rCaller: RegenCaller): Promise<CachedBeaconStateAllForks> {
    this.metrics?.regenFnCallTotal.inc({caller: rCaller, entrypoint: RegenFnName.getPreState});

    // First attempt to fetch the state from caches before queueing
    const parentRoot = toHexString(block.parentRoot);
    const parentBlock = this.forkChoice.getBlockHex(parentRoot);
    if (!parentBlock) {
      throw new RegenError({
        code: RegenErrorCode.BLOCK_NOT_IN_FORKCHOICE,
        blockRoot: block.parentRoot,
      });
    }

    const parentEpoch = computeEpochAtSlot(parentBlock.slot);
    const blockEpoch = computeEpochAtSlot(block.slot);

    // Check the checkpoint cache (if the pre-state is a checkpoint state)
    if (parentEpoch < blockEpoch) {
      const checkpointState = this.checkpointStateCache.getLatest(parentRoot, blockEpoch);
      if (checkpointState) {
        return checkpointState;
      }
    }

    // Check the state cache, only if the state doesn't need to go through an epoch transition.
    // Otherwise the state transition may not be cached and wasted. Queue for regen since the
    // work required will still be significant.
    if (parentEpoch === blockEpoch) {
      const state = this.stateCache.get(parentBlock.stateRoot);
      if (state) {
        return state;
      }
    }

    // The state is not immediately available in the caches, enqueue the job
    this.metrics?.regenFnQueuedTotal.inc({caller: rCaller, entrypoint: RegenFnName.getPreState});
    return this.jobQueue.push({key: "getPreState", args: [block, rCaller]});
  }

  async getCheckpointState(cp: phase0.Checkpoint, rCaller: RegenCaller): Promise<CachedBeaconStateAllForks> {
    this.metrics?.regenFnCallTotal.inc({caller: rCaller, entrypoint: RegenFnName.getCheckpointState});

    // First attempt to fetch the state from cache before queueing
    const checkpointState = this.checkpointStateCache.get(toCheckpointHex(cp));
    if (checkpointState) {
      return checkpointState;
    }

    // The state is not immediately available in the caches, enqueue the job
    this.metrics?.regenFnQueuedTotal.inc({caller: rCaller, entrypoint: RegenFnName.getCheckpointState});
    return this.jobQueue.push({key: "getCheckpointState", args: [cp, rCaller]});
  }

  async getBlockSlotState(blockRoot: RootHex, slot: Slot, rCaller: RegenCaller): Promise<CachedBeaconStateAllForks> {
    this.metrics?.regenFnCallTotal.inc({caller: rCaller, entrypoint: RegenFnName.getBlockSlotState});

    // The state is not immediately available in the caches, enqueue the job
    return this.jobQueue.push({key: "getBlockSlotState", args: [blockRoot, slot, rCaller]});
  }

  async getState(stateRoot: RootHex, rCaller: RegenCaller): Promise<CachedBeaconStateAllForks> {
    this.metrics?.regenFnCallTotal.inc({caller: rCaller, entrypoint: RegenFnName.getState});

    // First attempt to fetch the state from cache before queueing
    const state = this.stateCache.get(stateRoot);
    if (state) {
      return state;
    }

    // The state is not immediately available in the cache, enqueue the job
    this.metrics?.regenFnQueuedTotal.inc({caller: rCaller, entrypoint: RegenFnName.getState});
    return this.jobQueue.push({key: "getState", args: [stateRoot, rCaller]});
  }

  getHeadState(): CachedBeaconState<allForks.BeaconState> | null {
    return (
      this.headState ||
      // Fallback, check if head state is in cache
      (this.headStateRootHex ? this.stateCache.get(this.headStateRootHex) : null)
    );
  }

  setHead(head: IProtoBlock, potentialHeadState?: CachedBeaconState<allForks.BeaconState>): void {
    this.headStateRootHex = head.stateRoot;

    const headState =
      potentialHeadState && head.stateRoot === toHexString(potentialHeadState.hashTreeRoot())
        ? potentialHeadState
        : this.checkpointStateCache.getLatest(head.blockRoot, Infinity) || this.stateCache.get(head.stateRoot);

    // State is available syncronously =D
    // Note: almost always the headState should be in the cache since it should be from a block recently processed
    if (headState) {
      this.headState = headState;
      return;
    }

    this.headState = null;
    this.getState(head.stateRoot, RegenCaller.produceBlock)
      .then((state) => {
        this.headState = state;
      })
      .catch((e) => {
        throw Error(`Head state slot ${head.slot} root ${head.stateRoot} not available in caches`);
      });

    // TODO: Use regen to get the state if not available
    if (!this.headState) throw Error(`Head state slot ${head.slot} root ${head.stateRoot} not available in caches`);
  }

  addPostState(postState: CachedBeaconState<allForks.BeaconState>): void {
    this.stateCache.add(postState);
  }

  getCheckpointStateSync(cp: CheckpointHex): CachedBeaconState<allForks.BeaconState> | null {
    return this.checkpointStateCache.get(cp);
  }

  getStateSync(stateRootHex: string): CachedBeaconState<allForks.BeaconState> | null {
    return this.stateCache.get(stateRootHex);
  }

  private jobQueueProcessor = async (regenRequest: RegenRequest): Promise<CachedBeaconStateAllForks> => {
    const metricsLabels = {
      caller: regenRequest.args[regenRequest.args.length - 1] as RegenCaller,
      entrypoint: regenRequest.key,
    };
    let timer;
    try {
      timer = this.metrics?.regenFnCallDuration.startTimer(metricsLabels);
      switch (regenRequest.key) {
        case "getPreState":
          return await this.regen.getPreState(...regenRequest.args);
        case "getCheckpointState":
          return await this.regen.getCheckpointState(...regenRequest.args);
        case "getBlockSlotState":
          return await this.regen.getBlockSlotState(...regenRequest.args);
        case "getState":
          return await this.regen.getState(...regenRequest.args);
      }
    } catch (e) {
      this.metrics?.regenFnTotalErrors.inc(metricsLabels);
      throw e;
    } finally {
      if (timer) timer();
    }
  };
}
