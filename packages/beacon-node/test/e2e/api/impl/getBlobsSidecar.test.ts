import {expect} from "chai";
import {config} from "@lodestar/config/default";
import {ssz} from "@lodestar/types";
import {GENESIS_SLOT} from "@lodestar/params";

import {setupApiImplTestServer, ApiImplTestModules} from "../../../unit/api/impl/index.test.js";

describe("getBlobSideCar", function () {
  let server: ApiImplTestModules;

  before(function () {
    server = setupApiImplTestServer();
  });

  it("getBlobSideCar", async () => {
    const block = config.getForkTypes(GENESIS_SLOT).SignedBeaconBlock.defaultValue();
    const blobSidecar = ssz.deneb.BlobSidecar.defaultValue();
    block.message.slot = GENESIS_SLOT;

    server.dbStub.blockArchive.get.resolves(block);
    blobSidecar.blockRoot = config.getForkTypes(GENESIS_SLOT).BeaconBlock.hashTreeRoot(block.message);

    server.dbStub.blobSidecar.get.resolves(blobSidecar);
    //server.dbStub.blobsSidecarArchive.get.resolves(blobsSidecar);

    const returnedBlobSideCar = await server.blockApi.getBlobsSidecar("genesis");

    expect(returnedBlobSideCar.data).to.equal(blobsSidecar);
  });
});
