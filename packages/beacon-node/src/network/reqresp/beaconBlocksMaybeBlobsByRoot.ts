import {PeerId} from "@libp2p/interface-peer-id";
import {BeaconConfig} from "@lodestar/config";
import {RequestError, RequestErrorCode} from "@lodestar/reqresp";
import {Epoch, phase0, Root, Slot, deneb} from "@lodestar/types";
import {toHex} from "@lodestar/utils";
import {ForkSeq} from "@lodestar/params";
import {BlockInput, getBlockInput} from "../../chain/blocks/types.js";
import {wrapError} from "../../util/wrapError.js";
import {IReqRespBeaconNode} from "./interface.js";

export async function beaconBlocksMaybeBlobsByRoot(
  config: BeaconConfig,
  reqResp: IReqRespBeaconNode,
  peerId: PeerId,
  request: phase0.BeaconBlocksByRootRequest,
  currentSlot: Epoch,
  finalizedSlot: Slot
): Promise<BlockInput[]> {
  // Assume all requests are post Deneb
  // TODO: make this multiblock
  const [blockRoot] = request;
  const resBlocks = await reqResp.beaconBlocksByRoot(peerId, request);
  if (resBlocks.length < 1) {
    throw Error(`beaconBlocksByRoot return empty for block root ${toHex(blockRoot)}`);
  }
  const blockInputs = [];
  for (const block of resBlocks) {
    const blobKzgCommitmentsLen = (block.message.body as deneb.BeaconBlockBody).blobKzgCommitments.length ?? 0;

    // TODO: freetheblobs
    const blobSidecars = await Promise.all(
      Array.from({length: blobKzgCommitmentsLen}, (_v, index) => {
        const blobRequest = [{blockRoot, index}];
        return reqResp.blobSidecarsByRoot(peerId, blobRequest).then((response) => response[0]);
      })
    );
    blockInputs.push(getBlockInput.postDeneb(config, block, blobSidecars));
  }
  return blockInputs;
}
