import bls from "@chainsafe/bls";
import {CoordType} from "@chainsafe/bls/types";
import {ChainForkConfig} from "@lodestar/config";
import {deneb, Root, ssz} from "@lodestar/types";
import {bytesToBigInt} from "@lodestar/utils";
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
  index: number,
): void {
  const block = signedBlock.message;

  // [REJECT] the sidecar.blobs are all well formatted, i.e. the BLSFieldElement in valid range (x < BLS_MODULUS).
    if (!blobIsValidRange(blobSidecar.blob)) {
      throw new BlobSidecarError(GossipAction.REJECT, {code: BlobSidecarErrorCode.INVALID_BLOB, blobIdx: blobsSidecar.index});
    }

  // [REJECT] The KZG proof is a correctly encoded compressed BLS G1 Point
  // -- i.e. blsKeyValidate(blobs_sidecar.kzg_aggregated_proof)
  if (!blsKeyValidate(blobSidecar.kzgProof)) {
    throw new BlobSidecarError(GossipAction.REJECT, {code: BlobSidecarErrorCode.INVALID_KZG_PROOF,blobIdx: blobsSidecar.index});
  }

  // [REJECT] The KZG commitments in the block are valid against the provided blobs sidecar. -- i.e.
  // validate_blobs_sidecar(block.slot, hash_tree_root(block), block.body.blob_kzg_commitments, sidecar)
  validateBlobs(
    [blobSidecar.kzgCommitment],
    [blobSidecar.blob],
    [blobSidecar.kzgProof]
  );
}

// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/beacon-chain.md#validate_blobs_sidecar
export function validateBlobs(
  expectedKzgCommitments: deneb.KZGCommitment[],
  blobs: deneb.Blob[],
  proofs: deneb.KZGProof[],
): void {
  // assert len(expected_kzg_commitments) == len(blobs)
  if (expectedKzgCommitments.length !== blobs.length) {
    throw new Error(
      `blobs length to commitments length mismatch. Blob length: ${blobs.length}, Expected commitments length ${expectedKzgCommitments.length}`
    );
  }

  // No need to verify the aggregate proof of zero blobs. Also c-kzg throws.
  // https://github.com/dankrad/c-kzg/pull/12/files#r1025851956
  if (blobs.length > 0) {
    // assert verify_aggregate_kzg_proof(blobs, expected_kzg_commitments, kzg_aggregated_proof)
    let isProofValid: boolean;
    try {
      isProofValid = ckzg.verifyBlobKzgProofBatch(blobs, expectedKzgCommitments, proofs);
    } catch (e) {
      (e as Error).message = `Error on verifyAggregateKzgProof: ${(e as Error).message}`;
      throw e;
    }

    // TODO DENEB: TEMP Nov17: May always throw error -- we need to fix Geth's KZG to match C-KZG and the trusted setup used here
    if (!isProofValid) {
      throw Error("Invalid AggregateKzgProof");
    }
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
