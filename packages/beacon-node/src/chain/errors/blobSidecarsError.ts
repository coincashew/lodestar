import {Slot} from "@lodestar/types";
import {GossipActionError} from "./gossipValidation.js";

export enum BlobSidecarsErrorCode {
  /** !bls.KeyValidate(block.body.blob_kzg_commitments[i]) */
  INVALID_KZG = "BLOBS_SIDECAR_ERROR_INVALID_KZG",
  /** !verify_kzg_commitments_against_transactions(block.body.execution_payload.transactions, block.body.blob_kzg_commitments) */
  INVALID_KZG_TXS = "BLOBS_SIDECAR_ERROR_INVALID_KZG_TXS",
  /** sidecar.beacon_block_slot != block.slot */
  INCORRECT_SLOT = "BLOBS_SIDECAR_ERROR_INCORRECT_SLOT",
  /** BLSFieldElement in valid range (x < BLS_MODULUS) */
  INVALID_BLOB = "BLOBS_SIDECAR_ERROR_INVALID_BLOB",
  /** !bls.KeyValidate(blobs_sidecar.kzg_aggregated_proof) */
  INVALID_KZG_PROOF = "BLOBS_SIDECAR_ERROR_INVALID_KZG_PROOF",
}

export type BlobSidecarsErrorType =
  | {code: BlobSidecarsErrorCode.INVALID_KZG; kzgIdx: number}
  | {code: BlobSidecarsErrorCode.INVALID_KZG_TXS}
  | {code: BlobSidecarsErrorCode.INCORRECT_SLOT; blockSlot: Slot; blobSlot: Slot, blobIdx:number}
  | {code: BlobSidecarsErrorCode.INVALID_BLOB; blobIdx: number}
  | {code: BlobSidecarsErrorCode.INVALID_KZG_PROOF,blobIdx: number};

export class BlobSidecarsError extends GossipActionError<BlobSidecarsErrorType> {}
