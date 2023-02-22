import {expect} from "chai";
import {deneb, ssz} from "@lodestar/types";
import {toHex} from "@lodestar/utils";
import {signedBeaconBlockAndBlobsSidecarFromBytes} from "../../../src/network/reqresp/handlers/beaconBlockAndBlobsSidecarByRoot.js";

describe("signedBeaconBlockAndBlobsSidecarFromBytes", () => {
  it("signedBeaconBlockAndBlobsSidecarFromBytes", () => {
    const beaconBlock = ssz.deneb.SignedBeaconBlock.defaultValue();
    const blobSidecar = ssz.deneb.BlobSidecar.defaultValue();

    const signedBeaconBlockAndBlobsSidecarBytes = signedBeaconBlockAndBlobsSidecarFromBytes(
      ssz.deneb.SignedBeaconBlock.serialize(beaconBlock),
      ssz.deneb.BlobSidecar.serialize(blobsSidecar)
    );

    const signedBeaconBlockAndBlobSidecars: deneb.SignedBeaconBlockAndBlobSidecars = {
      beaconBlock,
      blobsSidecar,
    };

    expect(toHex(signedBeaconBlockAndBlobSidecarsBytes)).equals(
      toHex(ssz.deneb.SignedBeaconBlockAndBlobSidecar.serialize(signedBeaconBlockAndBlobSidecars)),
      "Wrong signedBeaconBlockAndBlobsSidecarBytes"
    );

    // Ensure deserialize does not throw
    ssz.deneb.SignedBeaconBlockAndBlobSidecar.deserialize(signedBeaconBlockAndBlobsSidecarBytes);
  });
});
