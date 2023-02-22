import {ChainForkConfig} from "@lodestar/config";
import {deneb} from "@lodestar/types";
import {ckzg} from "./kzg.js";

// Cache empty KZG proof, compute once lazily if needed
let emptyKzgAggregatedProof: Uint8Array | null = null;
function getEmptyKzgAggregatedProof(): Uint8Array {
  if (!emptyKzgAggregatedProof) {
    emptyKzgAggregatedProof = ckzg.computeAggregateKzgProof([]);
  }
  return emptyKzgAggregatedProof;
}

/**
 * Construct a valid BlobSidecar for a SignedBeaconBlock that references 0 commitments
 */
export function getEmptyBlobSidecar(config: ChainForkConfig, block: deneb.SignedBeaconBlock): deneb.BlobSidecar {
  return {
    beaconBlockRoot: config.getForkTypes(block.message.slot).BeaconBlock.hashTreeRoot(block.message),
    beaconBlockSlot: block.message.slot,
    blobs: [],
    kzgAggregatedProof: getEmptyKzgAggregatedProof(),
  };
}
