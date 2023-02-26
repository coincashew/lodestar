import {peerIdFromString} from "@libp2p/peer-id";
import {toHexString} from "@chainsafe/ssz";
import {BeaconConfig} from "@lodestar/config";
import {phase0, ssz, deneb, allForks, RootHex} from "@lodestar/types";
import {Logger, prettyBytes} from "@lodestar/utils";
import {ForkName, ForkSeq} from "@lodestar/params";
import {Metrics} from "../../../metrics/index.js";
import {OpSource} from "../../../metrics/validatorMonitor.js";
import {IBeaconChain} from "../../../chain/index.js";
import {
  AttestationError,
  AttestationErrorCode,
  BlockError,
  BlockErrorCode,
  BlockGossipError,
  GossipAction,
  GossipActionError,
  SyncCommitteeError,
} from "../../../chain/errors/index.js";
import {GossipHandlers, GossipType} from "../interface.js";
import {
  validateGossipAggregateAndProof,
  validateGossipAttestation,
  validateGossipAttesterSlashing,
  validateGossipBlock,
  validateGossipProposerSlashing,
  validateGossipSyncCommittee,
  validateSyncCommitteeGossipContributionAndProof,
  validateGossipVoluntaryExit,
  validateBlsToExecutionChange,
} from "../../../chain/validation/index.js";
import {NetworkEvent, NetworkEventBus} from "../../events.js";
import {PeerAction, PeerRpcScoreStore} from "../../peers/index.js";
import {validateLightClientFinalityUpdate} from "../../../chain/validation/lightClientFinalityUpdate.js";
import {validateLightClientOptimisticUpdate} from "../../../chain/validation/lightClientOptimisticUpdate.js";
import {validateGossipBlobSidecar} from "../../../chain/validation/blobSidecar.js";
import {BlockInput, getBlockInput} from "../../../chain/blocks/types.js";
import {AttnetsService} from "../../subnets/attnetsService.js";

/**
 * Gossip handler options as part of network options
 */
export type GossipHandlerOpts = {
  dontSendGossipAttestationsToForkchoice: boolean;
};

/**
 * By default:
 * + pass gossip attestations to forkchoice
 */
export const defaultGossipHandlerOpts = {
  dontSendGossipAttestationsToForkchoice: false,
};

type ValidatorFnsModules = {
  attnetsService: AttnetsService;
  chain: IBeaconChain;
  config: BeaconConfig;
  logger: Logger;
  metrics: Metrics | null;
  networkEventBus: NetworkEventBus;
  peerRpcScores: PeerRpcScoreStore;
};

enum GossipedInputType {
  block = "block",
  blob = "blob",
}
type GossipedBlockInput =
  | {type: GossipedInputType.block; signedBlock: allForks.SignedBeaconBlock}
  | {type: GossipedInputType.blob; signedBlob: deneb.SignedBlobSidecar};
type BlockInputCacheType = {block?: allForks.SignedBeaconBlock; blobs: Map<number, deneb.BlobSidecar>};

const MAX_UNKNOWN_BLOCK_ROOT_RETRIES = 1;

/**
 * Gossip handlers perform validation + handling in a single function.
 * - This gossip handlers MUST only be registered as validator functions. No handler is registered for any topic.
 * - All `chain/validation/*` functions MUST throw typed GossipActionError instances so they gossip action is captured
 *   by `getGossipValidatorFn()` try catch block.
 * - This gossip handlers should not let any handling errors propagate to the caller. Only validation errors must be thrown.
 *
 * Note: `libp2p/js-libp2p-interfaces` would normally indicate to register separate validator functions and handler functions.
 * This approach is not suitable for us because:
 * - We do expensive processing on the object in the validator function that we need to re-use in the handler function.
 * - The validator function produces extra data that is needed for the handler function. Making this data available in
 *   the handler function scope is hard to achieve without very hacky strategies
 * - Ethereum Consensus gossipsub protocol strictly defined a single topic for message
 */
export function getGossipHandlers(modules: ValidatorFnsModules, options: GossipHandlerOpts): GossipHandlers {
  const {attnetsService, chain, config, metrics, networkEventBus, peerRpcScores, logger} = modules;
  const blockInputCache = new Map<RootHex, BlockInputCacheType>();

  function getFullBlockInput(gossipedInput: GossipedBlockInput): BlockInput | null {
    let blockHex;
    let blockCache;
    if (gossipedInput.type === GossipedInputType.block) {
      const {signedBlock} = gossipedInput;
      blockHex = toHexString(
        config.getForkTypes(signedBlock.message.slot).BeaconBlock.hashTreeRoot(signedBlock.message)
      );
      blockCache = blockInputCache.get(blockHex) ?? {blobs: new Map<number, deneb.BlobSidecar>()};
      blockCache.block = signedBlock;
    } else {
      const {signedBlob} = gossipedInput;
      blockHex = toHexString(signedBlob.message.blockRoot);
      blockCache = blockInputCache.get(blockHex) ?? {blobs: new Map<number, deneb.BlobSidecar>()};
      // TODO: freetheblobs check if its the same blob or a duplicate and throw/take actions
      blockCache.blobs.set(signedBlob.message.index, signedBlob.message);
    }
    blockInputCache.set(blockHex, blockCache);
    const {block: signedBlock} = blockCache;
    if (signedBlock !== undefined) {
      const {blobKzgCommitments} = (signedBlock as deneb.SignedBeaconBlock).message.body;
      if (blobKzgCommitments.length > blockCache.blobs.size) {
        throw Error("Received more blobs than commitments");
      }
      if (blobKzgCommitments.length === blockCache.blobs.size) {
        const blobSidecars = [];
        for (let index = 0; index < blobKzgCommitments.length; index++) {
          const blobSidecar = blockCache.blobs.get(index);
          if (blobSidecar === undefined) {
            throw Error("Missing blobSidecar");
          }
          blobSidecars.push(blobSidecar);
        }
        return getBlockInput.postDeneb(config, signedBlock, blobSidecars);
      }
    }
    return null;
  }

  async function validateBeaconBlock(
    blockInput: BlockInput,
    fork: ForkName,
    peerIdStr: string,
    seenTimestampSec: number
  ): Promise<void> {
    const signedBlock = blockInput.block;
    const slot = signedBlock.message.slot;
    const forkTypes = config.getForkTypes(slot);
    const blockHex = prettyBytes(forkTypes.BeaconBlock.hashTreeRoot(signedBlock.message));
    const delaySec = chain.clock.secFromSlot(slot, seenTimestampSec);
    const recvToVal = Date.now() / 1000 - seenTimestampSec;
    metrics?.gossipBlock.receivedToGossipValidate.observe(recvToVal);
    logger.verbose("Received gossip block", {
      slot: slot,
      root: blockHex,
      curentSlot: chain.clock.currentSlot,
      peerId: peerIdStr,
      delaySec,
      recvToVal,
    });

    try {
      await validateGossipBlock(config, chain, signedBlock, fork);
    } catch (e) {
      if (e instanceof BlockGossipError) {
        if (e instanceof BlockGossipError && e.type.code === BlockErrorCode.PARENT_UNKNOWN) {
          logger.debug("Gossip block has error", {slot, root: blockHex, code: e.type.code});
          networkEventBus.emit(NetworkEvent.unknownBlockParent, blockInput, peerIdStr);
        }
      }

      if (e instanceof BlockGossipError && e.action === GossipAction.REJECT) {
        chain.persistInvalidSszValue(forkTypes.SignedBeaconBlock, signedBlock, `gossip_reject_slot_${slot}`);
      }

      throw e;
    }
  }

  function handleValidBeaconBlock(blockInput: BlockInput, peerIdStr: string, seenTimestampSec: number): void {
    const signedBlock = blockInput.block;

    // Handler - MUST NOT `await`, to allow validation result to be propagated

    metrics?.registerBeaconBlock(OpSource.gossip, seenTimestampSec, signedBlock.message);

    chain
      .processBlock(blockInput, {
        // proposer signature already checked in validateBeaconBlock()
        validProposerSignature: true,
        // blobsSidecar needs to be validated for block
        validBlobSidecars: true,
        // It's critical to keep a good number of mesh peers.
        // To do that, the Gossip Job Wait Time should be consistently <3s to avoid the behavior penalties in gossip
        // Gossip Job Wait Time depends on the BLS Job Wait Time
        // so `blsVerifyOnMainThread = true`: we want to verify signatures immediately without affecting the bls thread pool.
        // otherwise we can't utilize bls thread pool capacity and Gossip Job Wait Time can't be kept low consistently.
        // See https://github.com/ChainSafe/lodestar/issues/3792
        blsVerifyOnMainThread: true,
        // to track block process steps
        seenTimestampSec,
      })
      .then(() => {
        // Returns the delay between the start of `block.slot` and `current time`
        const delaySec = chain.clock.secFromSlot(signedBlock.message.slot);
        metrics?.gossipBlock.elapsedTimeTillProcessed.observe(delaySec);
      })
      .catch((e) => {
        if (e instanceof BlockError) {
          switch (e.type.code) {
            case BlockErrorCode.ALREADY_KNOWN:
            case BlockErrorCode.PARENT_UNKNOWN:
            case BlockErrorCode.PRESTATE_MISSING:
            case BlockErrorCode.EXECUTION_ENGINE_ERROR:
              break;
            default:
              peerRpcScores.applyAction(peerIdFromString(peerIdStr), PeerAction.LowToleranceError, "BadGossipBlock");
          }
        }
        logger.error("Error receiving block", {slot: signedBlock.message.slot, peer: peerIdStr}, e as Error);
      });
  }

  return {
    [GossipType.beacon_block]: async (signedBlock, topic, peerIdStr, seenTimestampSec) => {
      let blockInput;
      if (config.getForkSeq(signedBlock.message.slot) >= ForkSeq.deneb) {
        blockInput = getFullBlockInput({type: GossipedInputType.block, signedBlock});
      } else {
        blockInput = getBlockInput.preDeneb(config, signedBlock);
      }
      if (blockInput !== null) {
        await validateBeaconBlock(blockInput, topic.fork, peerIdStr, seenTimestampSec);
        handleValidBeaconBlock(blockInput, peerIdStr, seenTimestampSec);
      }
    },

    [GossipType.blob_sidecar]: async (signedBlob, topic, peerIdStr, seenTimestampSec) => {
      if (config.getForkSeq(signedBlob.message.slot) < ForkSeq.deneb) {
        throw new GossipActionError(GossipAction.REJECT, {code: "PRE_DENEB_BLOCK"});
      }

      // Validate block + blob. Then forward, then handle both
      validateGossipBlobSidecar(config, chain, signedBlob, topic.index);
      const blockInput = getFullBlockInput({type: GossipedInputType.blob, signedBlob});
      if (blockInput !== null) {
        await validateBeaconBlock(blockInput, topic.fork, peerIdStr, seenTimestampSec);
        handleValidBeaconBlock(blockInput, peerIdStr, seenTimestampSec);
      }
    },

    [GossipType.beacon_aggregate_and_proof]: async (signedAggregateAndProof, _topic, _peer, seenTimestampSec) => {
      let validationResult: {indexedAttestation: phase0.IndexedAttestation; committeeIndices: number[]};
      try {
        validationResult = await validateGossipAggregateAndProofRetryUnknownRoot(chain, signedAggregateAndProof);
      } catch (e) {
        if (e instanceof AttestationError && e.action === GossipAction.REJECT) {
          chain.persistInvalidSszValue(ssz.phase0.SignedAggregateAndProof, signedAggregateAndProof, "gossip_reject");
        }
        throw e;
      }

      // Handler
      const {indexedAttestation, committeeIndices} = validationResult;
      metrics?.registerGossipAggregatedAttestation(seenTimestampSec, signedAggregateAndProof, indexedAttestation);
      const aggregatedAttestation = signedAggregateAndProof.message.aggregate;

      chain.aggregatedAttestationPool.add(
        aggregatedAttestation,
        indexedAttestation.attestingIndices.length,
        committeeIndices
      );

      if (!options.dontSendGossipAttestationsToForkchoice) {
        try {
          chain.forkChoice.onAttestation(indexedAttestation);
        } catch (e) {
          logger.debug(
            "Error adding gossip aggregated attestation to forkchoice",
            {slot: aggregatedAttestation.data.slot},
            e as Error
          );
        }
      }
    },

    [GossipType.beacon_attestation]: async (attestation, {subnet}, _peer, seenTimestampSec) => {
      let validationResult: {indexedAttestation: phase0.IndexedAttestation; subnet: number};
      try {
        validationResult = await validateGossipAttestationRetryUnknownRoot(chain, attestation, subnet);
      } catch (e) {
        if (e instanceof AttestationError && e.action === GossipAction.REJECT) {
          chain.persistInvalidSszValue(ssz.phase0.Attestation, attestation, "gossip_reject");
        }
        throw e;
      }

      // Handler
      const {indexedAttestation} = validationResult;
      metrics?.registerGossipUnaggregatedAttestation(seenTimestampSec, indexedAttestation);

      // Node may be subscribe to extra subnets (long-lived random subnets). For those, validate the messages
      // but don't import them, to save CPU and RAM
      if (!attnetsService.shouldProcess(subnet, attestation.data.slot)) {
        return;
      }

      try {
        const insertOutcome = chain.attestationPool.add(attestation);
        metrics?.opPool.attestationPoolInsertOutcome.inc({insertOutcome});
      } catch (e) {
        logger.error("Error adding unaggregated attestation to pool", {subnet}, e as Error);
      }

      if (!options.dontSendGossipAttestationsToForkchoice) {
        try {
          chain.forkChoice.onAttestation(indexedAttestation);
        } catch (e) {
          logger.debug("Error adding gossip unaggregated attestation to forkchoice", {subnet}, e as Error);
        }
      }
    },

    [GossipType.attester_slashing]: async (attesterSlashing) => {
      await validateGossipAttesterSlashing(chain, attesterSlashing);

      // Handler

      try {
        chain.opPool.insertAttesterSlashing(attesterSlashing);
        chain.forkChoice.onAttesterSlashing(attesterSlashing);
      } catch (e) {
        logger.error("Error adding attesterSlashing to pool", {}, e as Error);
      }
    },

    [GossipType.proposer_slashing]: async (proposerSlashing) => {
      await validateGossipProposerSlashing(chain, proposerSlashing);

      // Handler

      try {
        chain.opPool.insertProposerSlashing(proposerSlashing);
      } catch (e) {
        logger.error("Error adding attesterSlashing to pool", {}, e as Error);
      }
    },

    [GossipType.voluntary_exit]: async (voluntaryExit) => {
      await validateGossipVoluntaryExit(chain, voluntaryExit);

      // Handler

      try {
        chain.opPool.insertVoluntaryExit(voluntaryExit);
      } catch (e) {
        logger.error("Error adding voluntaryExit to pool", {}, e as Error);
      }
    },

    [GossipType.sync_committee_contribution_and_proof]: async (contributionAndProof) => {
      const {syncCommitteeParticipantIndices} = await validateSyncCommitteeGossipContributionAndProof(
        chain,
        contributionAndProof
      ).catch((e) => {
        if (e instanceof SyncCommitteeError && e.action === GossipAction.REJECT) {
          chain.persistInvalidSszValue(ssz.altair.SignedContributionAndProof, contributionAndProof, "gossip_reject");
        }
        throw e;
      });

      // Handler
      metrics?.registerGossipSyncContributionAndProof(contributionAndProof.message, syncCommitteeParticipantIndices);

      try {
        chain.syncContributionAndProofPool.add(contributionAndProof.message, syncCommitteeParticipantIndices.length);
      } catch (e) {
        logger.error("Error adding to contributionAndProof pool", {}, e as Error);
      }
    },

    [GossipType.sync_committee]: async (syncCommittee, {subnet}) => {
      let indexInSubcommittee = 0;
      try {
        indexInSubcommittee = (await validateGossipSyncCommittee(chain, syncCommittee, subnet)).indexInSubcommittee;
      } catch (e) {
        if (e instanceof SyncCommitteeError && e.action === GossipAction.REJECT) {
          chain.persistInvalidSszValue(ssz.altair.SyncCommitteeMessage, syncCommittee, "gossip_reject");
        }
        throw e;
      }

      // Handler

      try {
        chain.syncCommitteeMessagePool.add(subnet, syncCommittee, indexInSubcommittee);
      } catch (e) {
        logger.error("Error adding to syncCommittee pool", {subnet}, e as Error);
      }
    },

    [GossipType.light_client_finality_update]: async (lightClientFinalityUpdate) => {
      validateLightClientFinalityUpdate(config, chain, lightClientFinalityUpdate);
    },

    [GossipType.light_client_optimistic_update]: async (lightClientOptimisticUpdate) => {
      validateLightClientOptimisticUpdate(config, chain, lightClientOptimisticUpdate);
    },

    // blsToExecutionChange is to be generated and validated against GENESIS_FORK_VERSION
    [GossipType.bls_to_execution_change]: async (blsToExecutionChange, _topic) => {
      await validateBlsToExecutionChange(chain, blsToExecutionChange);

      // Handler
      try {
        chain.opPool.insertBlsToExecutionChange(blsToExecutionChange);
      } catch (e) {
        logger.error("Error adding blsToExecutionChange to pool", {}, e as Error);
      }
    },
  };
}

/**
 * If an attestation refers to a block root that's not known, it will wait for 1 slot max
 * See https://github.com/ChainSafe/lodestar/pull/3564 for reasoning and results
 * Waiting here requires minimal code and automatically affects attestation, and aggregate validation
 * both from gossip and the API. I also prevents having to catch and re-throw in multiple places.
 */
async function validateGossipAggregateAndProofRetryUnknownRoot(
  chain: IBeaconChain,
  signedAggregateAndProof: phase0.SignedAggregateAndProof
): Promise<ReturnType<typeof validateGossipAggregateAndProof>> {
  let unknownBlockRootRetries = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      return await validateGossipAggregateAndProof(chain, signedAggregateAndProof);
    } catch (e) {
      if (
        e instanceof AttestationError &&
        e.type.code === AttestationErrorCode.UNKNOWN_OR_PREFINALIZED_BEACON_BLOCK_ROOT
      ) {
        if (unknownBlockRootRetries++ < MAX_UNKNOWN_BLOCK_ROOT_RETRIES) {
          // Trigger unknown block root search here

          const attestation = signedAggregateAndProof.message.aggregate;
          const foundBlock = await chain.waitForBlockOfAttestation(
            attestation.data.slot,
            toHexString(attestation.data.beaconBlockRoot)
          );
          // Returns true if the block was found on time. In that case, try to get it from the fork-choice again.
          // Otherwise, throw the error below.
          if (foundBlock) {
            continue;
          }
        }
      }

      throw e;
    }
  }
}

/**
 * If an attestation refers to a block root that's not known, it will wait for 1 slot max
 * See https://github.com/ChainSafe/lodestar/pull/3564 for reasoning and results
 * Waiting here requires minimal code and automatically affects attestation, and aggregate validation
 * both from gossip and the API. I also prevents having to catch and re-throw in multiple places.
 */
async function validateGossipAttestationRetryUnknownRoot(
  chain: IBeaconChain,
  attestation: phase0.Attestation,
  subnet: number | null
): Promise<ReturnType<typeof validateGossipAttestation>> {
  let unknownBlockRootRetries = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      return await validateGossipAttestation(chain, attestation, subnet);
    } catch (e) {
      if (
        e instanceof AttestationError &&
        e.type.code === AttestationErrorCode.UNKNOWN_OR_PREFINALIZED_BEACON_BLOCK_ROOT
      ) {
        if (unknownBlockRootRetries++ < MAX_UNKNOWN_BLOCK_ROOT_RETRIES) {
          // Trigger unknown block root search here

          const foundBlock = await chain.waitForBlockOfAttestation(
            attestation.data.slot,
            toHexString(attestation.data.beaconBlockRoot)
          );
          // Returns true if the block was found on time. In that case, try to get it from the fork-choice again.
          // Otherwise, throw the error below.
          if (foundBlock) {
            continue;
          }
        }
      }

      throw e;
    }
  }
}
