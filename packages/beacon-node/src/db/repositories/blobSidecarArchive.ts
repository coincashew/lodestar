import {ChainForkConfig} from "@lodestar/config";
import {Db, Repository, KeyValue, FilterOptions, Bucket} from "@lodestar/db";
import {Slot, Root, ssz, deneb} from "@lodestar/types";
import {bytesToInt} from "@lodestar/utils";

export interface BlockFilterOptions extends FilterOptions<Slot> {
  step?: number;
}

export type BlockArchiveBatchPutBinaryItem = KeyValue<Slot, Uint8Array> & {
  slot: Slot;
  blockRoot: Root;
  parentRoot: Root;
};

/**
 * Stores finalized blocks. Block slot is identifier.
 */
export class BlobSidecarArchiveRepository extends Repository<Slot, deneb.BlobSidecar> {
  constructor(config: ChainForkConfig, db: Db) {
    super(config, db, Bucket.allForks_blobsSidecarArchive, ssz.deneb.BlobSidecar);
  }

  // TODO: deneb involve slot to store the blob?

  getId(value: deneb.BlobSidecar): Uint8Array {
    const {blockRoot,index} = value;
    return ssz.deneb.BlobIdentifier.serialize({blockRoot,index});
  }

  decodeKey(data: Uint8Array): deneb.BlobIdentifier {
    return ssz.deneb.BlobIdentifier.serialize(data);
  }
}
