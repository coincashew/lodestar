import {ChainForkConfig} from "@lodestar/config";
import {Bucket, Db, Repository} from "@lodestar/db";
import {deneb, ssz} from "@lodestar/types";

/**
 * BlobSidecar by block root (= hash_tree_root(SignedBeaconBlockAndBlobsSidecar.beacon_block.message))
 *
 * Used to store unfinalized BlobsSidecar
 */
export class BlobSidecarsRepository extends Repository<Uint8Array, deneb.BlobSidecars> {
  constructor(config: ChainForkConfig, db: Db) {
    super(config, db, Bucket.allForks_blobSidecar, ssz.deneb.BlobSidecars);
  }

  /**
   * Id is hashTreeRoot of unsigned BeaconBlock
   */
  getId(value: deneb.BlobSidecars): Uint8Array {
    const {blockRoot} = value[0];
    return blockRoot;
  }
}
