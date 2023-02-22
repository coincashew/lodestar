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
export class BlobSidecarsArchiveRepository extends Repository<Slot, deneb.BlobSidecars> {
  constructor(config: ChainForkConfig, db: Db) {
    super(config, db, Bucket.allForks_blobSidecarArchive, ssz.deneb.BlobSidecars);
  }

  // TODO: deneb involve slot to store the blob?

  getId(value: deneb.BlobSidecars): Uint8Array {
    const {slot} = value[0]
    return slot;
  }

  decodeKey(data: Uint8Array): number {
    return bytesToInt((super.decodeKey(data) as unknown) as Uint8Array, "be");
  }
}
