// HPKE (RFC 9180, base mode, single-shot) plus the one-stage SHAKE256 key
// schedule of draft-ietf-hpke-hpke for the post-quantum suites. Every
// primitive is from the noble libraries; this file only composes them.
//
// Public keys are in HPKE serialized form: X25519 raw, NIST curves
// uncompressed (0x04 || x || y), X-Wing / ML-KEM raw.

import { ml_kem1024, ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js'
import { p256, p384, p521 } from '@noble/curves/nist.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js'
import { shake256 } from '@noble/hashes/sha3.js'
import { expand, extract } from '@noble/hashes/hkdf.js'
import { gcm } from '@noble/ciphers/aes.js'
import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { concat, i2osp, utf8 } from './bytes.js'

const V1 = utf8('HPKE-v1')
const EMPTY = new Uint8Array()

function labeledExtract(hash, suite, salt, label, ikm) {
  return extract(hash, concat(V1, suite, utf8(label), ikm), salt)
}

function labeledExpand(hash, suite, prk, label, info, L) {
  return expand(hash, prk, concat(i2osp(L, 2), V1, suite, utf8(label), info), L)
}

// --- KEMs: encap(pkR) -> { enc, ss }, decap(enc, skR) -> ss ---

function dhkem(id, curve, hash, Nsecret, nist) {
  const suite = concat(utf8('KEM'), i2osp(id, 2))
  const pub = (sk) => (nist ? curve.getPublicKey(sk, false) : curve.getPublicKey(sk))
  const dh = (sk, pk) => (nist ? curve.getSharedSecret(sk, pk).slice(1) : curve.getSharedSecret(sk, pk))
  const derive = (dhv, enc, pkRm) => {
    const prk = labeledExtract(hash, suite, EMPTY, 'eae_prk', dhv)
    return labeledExpand(hash, suite, prk, 'shared_secret', concat(enc, pkRm), Nsecret)
  }
  return {
    id,
    publicKey: pub,
    generate: () => curve.utils.randomSecretKey(),
    encap(pkR) {
      const skE = curve.utils.randomSecretKey()
      const enc = pub(skE)
      return { enc, ss: derive(dh(skE, pkR), enc, pkR) }
    },
    decap(enc, skR) {
      return derive(dh(skR, enc), enc, pub(skR))
    }
  }
}

function pqkem(id, kem) {
  const cache = new WeakMap()
  const secret = (seed) => {
    let sk = cache.get(seed)
    if (!sk) {
      sk = kem.keygen(seed).secretKey
      cache.set(seed, sk)
    }
    return sk
  }
  return {
    id,
    publicKey: (seed) => kem.keygen(seed).publicKey,
    encap(pkR) {
      const { cipherText, sharedSecret } = kem.encapsulate(pkR)
      return { enc: cipherText, ss: sharedSecret }
    },
    decap(enc, seed) {
      return kem.decapsulate(enc, secret(seed))
    }
  }
}

export const KEM = {
  P256: dhkem(0x0010, p256, sha256, 32, true),
  P384: dhkem(0x0011, p384, sha384, 48, true),
  P521: dhkem(0x0012, p521, sha512, 64, true),
  X25519: dhkem(0x0020, x25519, sha256, 32, false),
  MLKEM768: pqkem(0x0041, ml_kem768),
  MLKEM1024: pqkem(0x0042, ml_kem1024),
  MLKEM768_X25519: pqkem(0x647a, ml_kem768_x25519)
}

export const KDF = {
  HKDF_SHA256: { id: 0x0001, hash: sha256, Nh: 32 },
  HKDF_SHA384: { id: 0x0002, hash: sha384, Nh: 48 },
  HKDF_SHA512: { id: 0x0003, hash: sha512, Nh: 64 },
  SHAKE256: { id: 0x0011, oneStage: true, Nh: 64 }
}

export const AEAD = {
  AES_128_GCM: { id: 0x0001, Nk: 16, cipher: gcm },
  AES_256_GCM: { id: 0x0002, Nk: 32, cipher: gcm },
  CHACHA20_POLY1305: { id: 0x0003, Nk: 32, cipher: chacha20poly1305 }
}

const Nn = 12

function keySchedule(kem, kdf, aead, ss, info) {
  const suite = concat(utf8('HPKE'), i2osp(kem.id, 2), i2osp(kdf.id, 2), i2osp(aead.id, 2))
  const Nk = aead.Nk
  if (kdf.oneStage) {
    const lp = (x) => concat(i2osp(x.length, 2), x)
    const secrets = concat(lp(EMPTY), lp(ss))
    const context = concat(new Uint8Array([0]), lp(EMPTY), lp(info))
    const L = Nk + Nn + kdf.Nh
    const ikm = concat(secrets, V1, suite, lp(utf8('secret')), i2osp(L, 2), context)
    const out = shake256(ikm, { dkLen: L })
    return { key: out.slice(0, Nk), nonce: out.slice(Nk, Nk + Nn) }
  }
  const h = kdf.hash
  const pskIdHash = labeledExtract(h, suite, EMPTY, 'psk_id_hash', EMPTY)
  const infoHash = labeledExtract(h, suite, EMPTY, 'info_hash', info)
  const ctx = concat(new Uint8Array([0]), pskIdHash, infoHash)
  const secret = labeledExtract(h, suite, ss, 'secret', EMPTY)
  return {
    key: labeledExpand(h, suite, secret, 'key', ctx, Nk),
    nonce: labeledExpand(h, suite, secret, 'base_nonce', ctx, Nn)
  }
}

export class Suite {
  constructor(kem, kdf, aead) {
    this.kem = kem
    this.kdf = kdf
    this.aead = aead
  }

  seal(pkR, plaintext, info = EMPTY, aad = EMPTY) {
    const { enc, ss } = this.kem.encap(pkR)
    const { key, nonce } = keySchedule(this.kem, this.kdf, this.aead, ss, info)
    return { enc, ct: this.aead.cipher(key, nonce, aad).encrypt(plaintext) }
  }

  open(skR, enc, ct, info = EMPTY, aad = EMPTY) {
    const ss = this.kem.decap(enc, skR)
    const { key, nonce } = keySchedule(this.kem, this.kdf, this.aead, ss, info)
    return this.aead.cipher(key, nonce, aad).decrypt(ct)
  }
}
