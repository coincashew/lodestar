import {deneb} from "@lodestar/types";
import {EncodedPayloadBytes} from "@lodestar/reqresp";
import {IBeaconChain} from "../../../chain/index.js";
import {IBeaconDb} from "../../../db/index.js";
import {onBlocksOrBlobSidecarsByRange} from "./beaconBlocksByRange.js";

// TODO DENEB: Unit test

export function onBlobSidecarsByRange(
  request: deneb.BlobSidecarsByRangeRequest,
  chain: IBeaconChain,
  db: IBeaconDb
): AsyncIterable<EncodedPayloadBytes> {
  return onBlocksOrBlobSidecarsByRange(request, chain, {
    finalized: db.blobSidecarsArchive,
    unfinalized: db.blobSidecars,
  });
}
