import {ChainForkConfig} from "@lodestar/config";
import {Bucket, Db, Repository} from "@lodestar/db";
import {deneb, ssz} from "@lodestar/types";

/**
 * BlobsSidecar by block root (= hash_tree_root(SignedBeaconBlockAndBlobsSidecar.beacon_block.message))
 *
 * Used to store unfinalized BlobsSidecar
 */
export class BlobSidecarRepository extends Repository<Uint8Array, deneb.BlobSidecar> {
  constructor(config: ChainForkConfig, db: Db) {
    super(config, db, Bucket.allForks_blobsSidecar, ssz.deneb.BlobSidecar);
  }

  /**
   * Id is hashTreeRoot of unsigned BeaconBlock
   */
  getId(value: deneb.BlobSidecar): Uint8Array {
    const {blockRoot,index} = value;
    return ssz.deneb.BlobIdentifier.serialize({blockRoot,index});
  }

  decodeKey(data: Uint8Array): deneb.BlobIdentifier {
    return ssz.deneb.BlobIdentifier.serialize(data);
  }
}
