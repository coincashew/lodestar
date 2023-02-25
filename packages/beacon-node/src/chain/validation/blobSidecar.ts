import bls from "@chainsafe/bls";
import {CoordType} from "@chainsafe/bls/types";
import {ChainForkConfig} from "@lodestar/config";
import {deneb, Root, ssz, Slot} from "@lodestar/types";
import {bytesToBigInt, toHex} from "@lodestar/utils";
import {BYTES_PER_FIELD_ELEMENT, FIELD_ELEMENTS_PER_BLOB} from "@lodestar/params";
import {verifyKzgCommitmentsAgainstTransactions} from "@lodestar/state-transition";
import {BlobSidecarError, BlobSidecarErrorCode} from "../errors/blobSidecarError.js";
import {GossipAction} from "../errors/gossipValidation.js";
import {byteArrayEquals} from "../../util/bytes.js";
import {ckzg} from "../../util/kzg.js";
import {IBeaconChain} from "../interface.js";

const BLS_MODULUS = BigInt("52435875175126190479447740508185965837690552500527637822603658699938581184513");

export function validateGossipBlobSidecar(
  config: ChainForkConfig,
  chain: IBeaconChain,
  blobSidecar: deneb.BlobSidecar,
  gossipIndex: number
): void {
  if (blobSidecar.index !== gossipIndex) {
    throw new BlobSidecarError(GossipAction.REJECT, {
      code: BlobSidecarErrorCode.INVALID_INDEX,
      blobIdx: blobSidecar.index,
      gossipIndex,
    });
  }
  // [REJECT] the sidecar.blobs are all well formatted, i.e. the BLSFieldElement in valid range (x < BLS_MODULUS).
  if (!blobIsValidRange(blobSidecar.blob)) {
    throw new BlobSidecarError(GossipAction.REJECT, {
      code: BlobSidecarErrorCode.INVALID_BLOB,
      blobIdx: blobSidecar.index,
    });
  }
  // [REJECT] The KZG proof is a correctly encoded compressed BLS G1 Point
  // -- i.e. blsKeyValidate(blobs_sidecar.kzg_aggregated_proof)
  if (!blsKeyValidate(blobSidecar.kzgProof)) {
    throw new BlobSidecarError(GossipAction.REJECT, {
      code: BlobSidecarErrorCode.INVALID_KZG_PROOF,
      blobIdx: blobSidecar.index,
    });
  }

  validateBlobsAndProofs([blobSidecar.kzgCommitment], [blobSidecar.blob], [blobSidecar.kzgProof]);
}

// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/beacon-chain.md#validate_blobs_sidecar
export function validateBlobSidecars(
  blockSlot: Slot,
  blockRoot: Root,
  expectedKzgCommitments: deneb.BlobKzgCommitments,
  blobSidecars: deneb.BlobSidecars
): void {
  // assert len(expected_kzg_commitments) == len(blobs)
  if (expectedKzgCommitments.length !== blobSidecars.length) {
    throw new Error(
      `blobSidecars length to commitments length mismatch. Blob length: ${blobSidecars.length}, Expected commitments length ${expectedKzgCommitments.length}`
    );
  }
  // No need to verify the aggregate proof of zero blobs. Also c-kzg throws.
  // https://github.com/dankrad/c-kzg/pull/12/files#r1025851956
  if (blobSidecars.length > 0) {
    // Verify the blob slot and root matches
    const blobs = [];
    const proofs = [];
    for (let index = 0; index < blobSidecars.length; index++) {
      const blobSidecar = blobSidecars[index];
      if (
        blobSidecar.slot !== blockSlot ||
        !byteArrayEquals(blobSidecar.blockRoot, blockRoot) ||
        blobSidecar.index !== index ||
        !byteArrayEquals(expectedKzgCommitments[index], blobSidecar.kzgCommitment)
      ) {
        throw new Error(
          `Invalid blob with slot=${blobSidecar.slot} blockRoot=${toHex(blockRoot)} index=${
            blobSidecar.index
          } for the block root=${toHex(blockRoot)} slot=${blockSlot} index=${index}`
        );
      }
      blobs.push(blobSidecar.blob);
      proofs.push(blobSidecar.kzgProof);
    }
    validateBlobsAndProofs(expectedKzgCommitments, blobs, proofs);
  }
}

function validateBlobsAndProofs(
  expectedKzgCommitments: deneb.BlobKzgCommitments,
  blobs: deneb.Blobs,
  proofs: deneb.KZGProofs
) {
  // assert verify_aggregate_kzg_proof(blobs, expected_kzg_commitments, kzg_aggregated_proof)
  let isProofValid: boolean;
  try {
    isProofValid = ckzg.verifyBlobKzgProofBatch(blobs, expectedKzgCommitments, proofs);
  } catch (e) {
    (e as Error).message = `Error on verifyAggregateKzgProof: ${(e as Error).message}`;
    throw e;
  }
  if (!isProofValid) {
    throw Error("Invalid AggregateKzgProof");
  }
}

/**
 * From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.5
 * KeyValidate = valid, non-identity point that is in the correct subgroup
 */
function blsKeyValidate(g1Point: Uint8Array): boolean {
  try {
    bls.PublicKey.fromBytes(g1Point, CoordType.jacobian, true);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * ```
 * Blob = new ByteVectorType(BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB);
 * ```
 * Check that each FIELD_ELEMENT as a uint256 < BLS_MODULUS
 */
function blobIsValidRange(blob: deneb.Blob): boolean {
  for (let i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
    const fieldElement = blob.subarray(i * BYTES_PER_FIELD_ELEMENT, (i + 1) * BYTES_PER_FIELD_ELEMENT);
    const fieldElementBN = bytesToBigInt(fieldElement, "be");
    if (fieldElementBN >= BLS_MODULUS) {
      return false;
    }
  }

  return true;
}
