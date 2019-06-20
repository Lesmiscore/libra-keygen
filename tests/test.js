// https://github.com/libra/libra/blob/master/types/src/unit_tests/address_test.rs

const KeyPair = require("../src/keypair");
const assert = require("assert");

describe("Address test", function() {
  it("encodes a valid Bech32", function() {
    const data = Buffer.from(
      "269bdde7f42c25476707821eb44d5ce3c6c9e50a774f43ddebc5494a42870aa6",
      "hex"
    );
    const b32 = KeyPair.withBech32Body(null, data);
    assert.strictEqual(
      b32,
      "lb1y6damel59sj5wec8sg0tgn2uu0rvneg2wa858h0tc4y55s58p2nqjyd2lr"
    );
  });
  it("is reproducible", function() {
    const data = Buffer.from(
      "ca843279e3427144cead5e4d5999a3d0ccf92b8e124793820837625638742903",
      "hex"
    );
    const kp = KeyPair.fromPublicKey(data);
    const addr = kp.getYBuffer();
    assert.deepEqual(addr, data);
  });
});
