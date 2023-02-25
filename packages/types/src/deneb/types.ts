import {ValueOf} from "@chainsafe/ssz";
import * as ssz from "./sszTypes.js";

export type KZGProof = ValueOf<typeof ssz.KZGProof>;
export type KZGCommitment = ValueOf<typeof ssz.KZGCommitment>;
export type Blob = ValueOf<typeof ssz.Blob>;
export type Blobs = ValueOf<typeof ssz.Blobs>;
export type BlobSidecar = ValueOf<typeof ssz.BlobSidecar>;
export type BlobSidecars = ValueOf<typeof ssz.BlobSidecars>;
export type SignedBlobSidecar = ValueOf<typeof ssz.SignedBlobSidecar>;
export type BlobIdentifier = ValueOf<typeof ssz.BlobIdentifier>;
export type BlobKzgCommitments = ValueOf<typeof ssz.BlobKzgCommitments>;
export type KZGProofs = ValueOf<typeof ssz.KZGProofs>;
export type Polynomial = ValueOf<typeof ssz.Polynomial>;
export type PolynomialAndCommitment = ValueOf<typeof ssz.PolynomialAndCommitment>;
export type BLSFieldElement = ValueOf<typeof ssz.BLSFieldElement>;

export type BlobSidecarsByRangeRequest = ValueOf<typeof ssz.BlobSidecarsByRangeRequest>;
export type BlobSidecarsByRootRequest = ValueOf<typeof ssz.BlobSidecarsByRootRequest>;

export type ExecutionPayload = ValueOf<typeof ssz.ExecutionPayload>;
export type ExecutionPayloadHeader = ValueOf<typeof ssz.ExecutionPayloadHeader>;

export type BeaconBlockBody = ValueOf<typeof ssz.BeaconBlockBody>;
export type BeaconBlock = ValueOf<typeof ssz.BeaconBlock>;
export type SignedBeaconBlock = ValueOf<typeof ssz.SignedBeaconBlock>;
export type SignedBeaconBlockAndBlobSidecars = ValueOf<typeof ssz.SignedBeaconBlockAndBlobSidecars>;

export type BeaconState = ValueOf<typeof ssz.BeaconState>;

export type BlindedBeaconBlockBody = ValueOf<typeof ssz.BlindedBeaconBlockBody>;
export type BlindedBeaconBlock = ValueOf<typeof ssz.BlindedBeaconBlock>;
export type SignedBlindedBeaconBlock = ValueOf<typeof ssz.SignedBlindedBeaconBlock>;

export type FullOrBlindedExecutionPayload = ExecutionPayload | ExecutionPayloadHeader;

export type BuilderBid = ValueOf<typeof ssz.BuilderBid>;
export type SignedBuilderBid = ValueOf<typeof ssz.SignedBuilderBid>;

export type LightClientHeader = ValueOf<typeof ssz.LightClientHeader>;
export type LightClientBootstrap = ValueOf<typeof ssz.LightClientBootstrap>;
export type LightClientUpdate = ValueOf<typeof ssz.LightClientUpdate>;
export type LightClientFinalityUpdate = ValueOf<typeof ssz.LightClientFinalityUpdate>;
export type LightClientOptimisticUpdate = ValueOf<typeof ssz.LightClientOptimisticUpdate>;
export type LightClientStore = ValueOf<typeof ssz.LightClientStore>;
