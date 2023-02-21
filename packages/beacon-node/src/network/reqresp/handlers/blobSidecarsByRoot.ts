import {ContextBytesType, EncodedPayload, EncodedPayloadType} from "@lodestar/reqresp";
import {deneb} from "@lodestar/types";
import {toHex} from "@lodestar/utils";
import {IBeaconChain} from "../../../chain/index.js";
import {IBeaconDb} from "../../../db/index.js";
import {getSlotFromBytes} from "../../../util/multifork.js";

export async function* onBlobSidecarsByRoot(
  requestBody: deneb.BlobSidecarsByRootRequest,
  chain: IBeaconChain,
  db: IBeaconDb
): AsyncIterable<EncodedPayload<deneb.BlobSidecar>> {
  const finalizedSlot = chain.forkChoice.getFinalizedBlock().slot;

  for (const blobIdentifier of requestBody) {
    const {blockRoot} = blobIdentifier;
    const blockRootHex = toHex(blockRoot);
    const summary = chain.forkChoice.getBlockHex(blockRootHex);

    // NOTE: Only support non-finalized blocks.
    // SPEC: Clients MUST support requesting blocks and sidecars since the latest finalized epoch.
    // https://github.com/ethereum/consensus-specs/blob/11a037fd9227e29ee809c9397b09f8cc3383a8c0/specs/eip4844/p2p-interface.md#beaconblockandblobssidecarbyroot-v1
    if (!summary || summary.slot <= finalizedSlot) {
      // TODO: Should accept the finalized block? Is the finalized block in the archive DB or hot DB?
      continue;
    }

    const blobSidecarBytes = await db.blobsSidecar.getBinary(blobIdentifier);
    if (!blobSidecarBytes) {
      throw Error(`Inconsistent state, blobsSidecar known to fork-choice not in db ${blockRootHex}`);
    }

    yield {
      type: EncodedPayloadType.bytes,
      bytes: blobSidecarBytes,
      contextBytes: {
        type: ContextBytesType.ForkDigest,
        forkSlot: getSlotFromBytes(blockBytes),
      },
    };
  }
}
