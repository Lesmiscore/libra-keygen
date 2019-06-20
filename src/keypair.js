// https://github.com/libra/libra/blob/master/types/src/account_address.rs
// https://github.com/libra/libra/blob/master/crypto/legacy_crypto/src/signing.rs

const EC = require("elliptic").ec;
const ed25519 = new EC("ed25519");
const BN = require("bn.js");
const rand = require("randombytes");
const bech32 = require("bech32");
const keccak = require("js-sha3").sha3_256.arrayBuffer;

const nBuf = Buffer.from(
  "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
  "hex"
);
const nSize = nBuf.length;
const nScalar = new BN(nBuf).sub(new BN(2));
const msb = new BN("2").pow(new BN("255"));
const mostBits = msb.sub(new BN(1));

const saltBuffer = Buffer.from("AccountAddress");

const KP = (module.exports = class KeyPair {
  constructor(pkSk, isSk) {
    pkSk = Buffer.from(pkSk);
    let elKp;
    if (isSk) {
      elKp = ed25519.keyFromPrivate(pkSk);
    } else {
      if (pkSk.length == 32) {
        // Y only
        const pkScalar = new BN(pkSk);
        const oddFlag = !!(pkScalar.and(msb).cmp(new BN(0)) == 1);
        elKp = ed25519.keyFromPublic(
          ed25519.curve.pointFromY(pkScalar.and(mostBits), oddFlag)
        );
      } else {
        // whole pubkey
        elKp = ed25519.keyFromPublic(pkSk);
      }
    }
    this.pub = elKp.getPublic();
    this.priv = elKp.getPrivate();
  }
  getPrivateKey() {
    return this.priv;
  }
  getPrivateKeyBuffer() {
    return this.priv.toBuffer();
  }
  getPublicKey() {
    return this.pub;
  }
  getPublicKeyBuffer() {
    return this.pub.encode("buffer", false);
  }
  getYBuffer() {
    const x = this.pub.getX();
    let y = this.pub.getY().and(mostBits);
    if (!x.isNeg()) {
      y = y.or(msb);
    }
    //console.log(...[x,y].map(a=>a.toString(16)))
    return y.toBuffer(null, 32);
  }

  addressHash() {
    return Buffer.from(keccak(this.getYBuffer()));
  }
  hash() {
    return Buffer.from(keccak(Buffer.concat([saltBuffer, this.addressHash()])));
  }
  toBech32Address(prefix) {
    const hashed = this.addressHash();
    return KP.withBody(prefix, hashed);
  }
  toAddress() {
    return this.addressHash().toString("hex");
  }
});

KP.fromPrivateKey = function(sk) {
  return new KP(sk, true);
};

KP.fromPublicKey = function(pk) {
  return new KP(pk, false);
};

KP.random = function() {
  while (true) {
    const sk = rand(nSize);
    if (nScalar.cmp(sk) < 0) continue;
    return KP.fromPrivateKey(sk);
  }
};

KP.withBech32Body = function(prefix, body) {
  const words = bech32.toWords(body);
  return bech32.encode(prefix || "lb", words);
};
