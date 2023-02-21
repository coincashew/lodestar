import {PeerId} from "@libp2p/interface-peer-id";
import {BeaconConfig} from "@lodestar/config";
import {RequestError, RequestErrorCode} from "@lodestar/reqresp";
import {Epoch, phase0, Root, Slot} from "@lodestar/types";
import {toHex} from "@lodestar/utils";
import {ForkSeq} from "@lodestar/params";
import {BlockInput, getBlockInput} from "../../chain/blocks/types.js";
import {wrapError} from "../../util/wrapError.js";
import {IReqRespBeaconNode} from "./interface.js";

export async function beaconBlocksMaybeBlobsByRoot(
  config: BeaconConfig,
  reqResp: IReqRespBeaconNode,
  peerId: PeerId,
  request: deneb.BeaconBlockByRootRequest,
  currentSlot: Epoch,
  finalizedSlot: Slot
): Promise<deneb.BlobSideCar[]> {
  // Assume all requests are post Deneb
  // TODO: make this multiblock
  const [blockRoot] = request;
  const resBlocks = await reqResp.beaconBlocksByRoot(peerId, request);
  if (resBlocks.length < 1) {
    throw Error(`beaconBlocksByRoot return empty for block root ${toHex(blockRoot)}`);
  }
  const blobKzgCommitmentsLen = (block.message.body as deneb.BeaconBlockBody).blobKzgCommitments.length??0;

  const blobsSidecars = await Promise.all(Array.from({length: blobKzgCommitmentsLen}),(_v,index)=>{
    const blobRequest = [{blockRoot,index}]
    return reqResp.blobSidecarsByRootRequest(peerId,blobRequest)
  })
}
