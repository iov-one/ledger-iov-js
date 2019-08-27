import TransportNodeHid from "@ledgerhq/hw-transport-node-hid";
import { expect, test } from "jest";
import { Ed25519, Sha512 } from "@iov/crypto";
import { Encoding } from "@iov/encoding";
import LedgerApp from "..";

const { fromHex } = Encoding;

function harden(index) {
  // Don't use bitwise operations, which result in signed int32 in JavaScript.
  // Addition works well for small numbers.
  return 0x80000000 + index;
}

describe("Integration tests", () => {
  let transport;

  beforeAll(async () => {
    transport = await TransportNodeHid.create(1000);
  });

  test("get version", async () => {
    const app = new LedgerApp(transport);
    const version = await app.getVersion();
    expect(version).toEqual(
      expect.objectContaining({
        major: 0,
        minor: 8,
        patch: 0,
        device_locked: false,
        error_message: "No errors",
      }),
    );
  });

  test("get address", async () => {
    const app = new LedgerApp(transport);
    const version = await app.getVersion();

    const pathIndex = harden(5);
    const response = await app.getAddress(pathIndex);

    expect(response.pubKey).toEqual("05173bf18e8bc4203176be82c89ca9519100fe2cf340cbad239750bd3e3ff668");

    // Depending on the app version, we can get mainnet or testnet addresses
    if (version.test_mode) {
      expect(response.address).toEqual("tiov1k9rxcg8htk6wcq546p86ksgqhq8fza7hykl8mp");
    } else {
      expect(response.address).toEqual("iov1k9rxcg8htk6wcq546p86ksgqhq8fza7h2rkrms");
    }
  });

  test("get multiple addresses", async () => {
    const app = new LedgerApp(transport);
    const version = await app.getVersion();

    const response0 = await app.getAddress(harden(0));
    const response1 = await app.getAddress(harden(1));
    const response2 = await app.getAddress(harden(2));
    const response3 = await app.getAddress(harden(3));
    const response4 = await app.getAddress(harden(4));

    // Calculated using Token Finder tool with mnemonic
    // equip will roof matter pink blind book anxiety banner elbow sun young
    expect(response0.pubKey).toEqual("5fe68efa9e7e6373a51f6e519b4ffc7d6330c6cd011d00f6a9663ca82c361bff");
    expect(response1.pubKey).toEqual("385fe5a946e46727297cf7ad0bff7efa637e1c7516ea2fd9f6dc717404494455");
    expect(response2.pubKey).toEqual("c8dca85dd7f1c4f231e46d579199b310975379c37445c664d1be824f088dbe07");
    expect(response3.pubKey).toEqual("5ad1501134fb4ba2f5b1d7c8ca539152d7c31f07a301f6192bb757b3dab52a88");
    expect(response4.pubKey).toEqual("f10ea4323ac84582370321208c71ca77700c85a099991aefc153bc5284c9c025");

    if (version.test_mode) {
      expect(response0.address).toEqual("tiov1l678408y7a64cj66s8j64fevmspyfxdmv38cxw");
      expect(response1.address).toEqual("tiov1u42wk6lk009ex9t87gt54sn24m2psl4axfrd28");
      expect(response2.address).toEqual("tiov1lxry06n8l760mkthg7sgda48cne4t26llzwntz");
      expect(response3.address).toEqual("tiov10ur3vxhy00el95g5fqthe889z6lzqgr0f63tnl");
      expect(response4.address).toEqual("tiov12evzw2nds3qzfdrlnka5hx25azaarh3qypr6uv");
    } else {
      expect(response0.address).toEqual("iov1l678408y7a64cj66s8j64fevmspyfxdmzywuxl");
      expect(response1.address).toEqual("iov1u42wk6lk009ex9t87gt54sn24m2psl4agu2f2k");
      expect(response2.address).toEqual("iov1lxry06n8l760mkthg7sgda48cne4t26l3h8htn");
      expect(response3.address).toEqual("iov10ur3vxhy00el95g5fqthe889z6lzqgr080c0nw");
      expect(response4.address).toEqual("iov12evzw2nds3qzfdrlnka5hx25azaarh3q2527ua");
    }
  });

  test("show address", async () => {
    jest.setTimeout(60000);

    const app = new LedgerApp(transport);
    const version = await app.getVersion();

    const pathIndex = harden(10);
    const response = await app.getAddress(pathIndex, true);

    expect(response.pubKey).toEqual("54fb71bc543e9424d8f9df6de1701dd459456e0d1431c1a29f8b5d4e717424af");

    // Depending on the app version, we can get mainnet or testnet addresses
    if (version.test_mode) {
      expect(response.address).toEqual("tiov1w7n28wf9q297z3mw8lsxvurk6ydnndxrkn3k9x");
    } else {
      expect(response.address).toEqual("iov1w7n28wf9q297z3mw8lsxvurk6ydnndxrcxcj9h");
    }
  });

  test("sign_and_verify_testnet", async () => {
    jest.setTimeout(60000);

    const txBlobStr =
      "00cafe000b696f762d6c6f76656e657400000000000000009a03380a020801121473" +
      "f16e71d0878f6ad26531e174452aec9161e8d41a1400000000000000000000000000000000000000" +
      "0022061a0443415348";

    const txBlob = Buffer.from(txBlobStr, "hex");

    const app = new LedgerApp(transport);
    const version = await app.getVersion();

    const pathIndex = harden(0);

    const responseAddr = await app.getAddress(pathIndex);
    const pubkey = fromHex(responseAddr.pubKey);
    const responseSign = await app.sign(pathIndex, txBlob);

    if (version.test_mode) {
      // Check signature is valid
      const prehash = new Sha512(txBlob).digest();
      const signature = new Uint8Array([...responseSign.signature]);
      const valid = await Ed25519.verifySignature(signature, prehash, pubkey);
      expect(valid).toEqual(true);
    } else {
      expect(responseSign.return_code).toEqual(27012);
      expect(responseSign.error_message).toEqual("Data is invalid");
    }
  });

  test("sign_and_verify_mainnet", async () => {
    jest.setTimeout(60000);

    const txBlobStr =
      "00cafe000b696f762d6d61696e6e6574001fffffffffffff0a231214bad055e2cb" +
      "cffc633e7dc76dc1148d6e9a2debfd1a0b1080c2d72f1a04434153489a03560a0208011214bad0" +
      "55e2cbcffc633e7dc76dc1148d6e9a2debfd1a14020daec62066ec82a5a1b40378d87457ed88e4fc" +
      "220d0807108088debe011a03494f562a1574657874207769746820656d6f6a693a20f09f908e";

    const txBlob = Buffer.from(txBlobStr, "hex");

    const app = new LedgerApp(transport);
    const version = await app.getVersion();

    const pathIndex = harden(0);

    const responseAddr = await app.getAddress(pathIndex);
    const pubkey = fromHex(responseAddr.pubKey);

    const responseSign = await app.sign(pathIndex, txBlob);

    if (version.test_mode) {
      expect(responseSign.return_code).toEqual(27012);
      expect(responseSign.error_message).toEqual("Data is invalid");
    } else {
      // Check signature is valid
      const prehash = new Sha512(txBlob).digest();
      const signature = new Uint8Array([...responseSign.signature]);
      const valid = await Ed25519.verifySignature(signature, prehash, pubkey);
      expect(valid).toEqual(true);
    }
  });
});
