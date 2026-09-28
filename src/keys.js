// COSE algorithms and keys (RFC 9052/9053, RFC 9864, draft-ietf-cose-dilithium,
// draft-ietf-cose-hpke). Maps COSE algorithm ids onto noble primitives and
// (de)serializes COSE_Key maps.

import { ed25519 } from '@noble/curves/ed25519.js'
import { p256, p384, p521 } from '@noble/curves/nist.js'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { gcm } from '@noble/ciphers/aes.js'
import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { concat, equal, isBytes, randomBytes } from './bytes.js'
import { get } from './cbor.js'
import { AEAD, KDF, KEM, Suite } from './hpke.js'

export class CoseError extends Error {
  constructor(message) {
    super(message)
    this.name = 'CoseError'
  }
}

// COSE key types
export const KTY_OKP = 1
export const KTY_EC2 = 2
export const KTY_SYMMETRIC = 4
export const KTY_AKP = 7

// COSE_Key labels
export const KEY_KTY = 1
export const KEY_KID = 2
export const KEY_ALG = 3

// COSE curves
export const CRV_P256 = 1
export const CRV_P384 = 2
export const CRV_P521 = 3
export const CRV_X25519 = 4
export const CRV_ED25519 = 6

const EC = {
  [CRV_P256]: { curve: p256, size: 32 },
  [CRV_P384]: { curve: p384, size: 48 },
  [CRV_P521]: { curve: p521, size: 66 }
}

const EMPTY = new Uint8Array()

// A COSE key. `pub` is the raw public key (AKP "pub", OKP "x", EC2 x||y);
// `priv` the raw private key (AKP seed, OKP/EC2 "d", symmetric "k").
export class Key {
  constructor(alg, pub = EMPTY, priv = null, kid = null) {
    this.alg = alg
    this.pub = pub
    this.priv = priv
    this.kid = kid
    Object.defineProperty(this, '_cache', { value: {}, enumerable: false, writable: true })
  }

  get algorithm() {
    return getAlg(this.alg)
  }

  get hasPrivate() {
    return this.priv != null
  }

  public() {
    if (this.algorithm.kty === KTY_SYMMETRIC) throw new CoseError('symmetric keys have no public half')
    return new Key(this.alg, this.pub, null, this.kid)
  }

  toCose(priv = false) {
    return this.algorithm.encodeKey(this, priv)
  }

  static fromCose(m) {
    if (!(m instanceof Map)) throw new CoseError('COSE_Key must be a map')
    if (!m.has(KEY_ALG)) throw new CoseError('COSE_Key without alg is not supported')
    return getAlg(m.get(KEY_ALG)).decodeKey(m)
  }

  static generate(alg, kid = null) {
    const k = getAlg(alg).generate()
    k.kid = kid
    return k
  }

  // a full key from its private bytes (seed / d / k): the public half is derived
  static fromPrivate(alg, priv, kid = null) {
    return new Key(alg, getAlg(alg).publicFromPrivate(priv), priv, kid)
  }
}

function bytesField(m, label, name) {
  const v = m.get(label)
  if (!isBytes(v)) throw new CoseError(`COSE_Key ${name} must be a byte string`)
  return v
}

function optBytes(m, label) {
  const v = m.get(label)
  if (v === undefined) return null
  if (!isBytes(v)) throw new CoseError('COSE_Key private part must be a byte string')
  return v
}

class Alg {
  constructor(id, name) {
    this.id = id
    this.name = name
  }

  encodeKey(key) {
    const m = new Map([
      [KEY_KTY, this.kty],
      [KEY_ALG, this.id]
    ])
    if (key.kid != null) m.set(KEY_KID, key.kid)
    return m
  }

  decodeKey(m) {
    if (m.get(KEY_KTY) !== this.kty) throw new CoseError(`${this.name} requires kty ${this.kty}`)
    const kid = m.get(KEY_KID)
    if (kid !== undefined && !isBytes(kid)) throw new CoseError('COSE_Key kid must be a byte string')
    return new Key(this.id, EMPTY, null, kid ?? null)
  }

  publicFromPrivate() {
    throw new CoseError(`${this.name} cannot derive a public key`)
  }
}

// --- key shapes ---

const akp = (Base) =>
  class extends Base {
    get kty() {
      return KTY_AKP
    }

    encodeKey(key, priv) {
      const m = super.encodeKey(key, priv)
      m.set(-1, key.pub)
      if (priv && key.priv != null) m.set(-2, key.priv)
      return m
    }

    decodeKey(m) {
      const k = super.decodeKey(m)
      k.pub = bytesField(m, -1, 'pub')
      k.priv = optBytes(m, -2)
      return k
    }
  }

const okp = (Base, crv) =>
  class extends Base {
    get kty() {
      return KTY_OKP
    }

    encodeKey(key, priv) {
      const m = super.encodeKey(key, priv)
      m.set(-1, crv)
      m.set(-2, key.pub)
      if (priv && key.priv != null) m.set(-4, key.priv)
      return m
    }

    decodeKey(m) {
      if (m.get(-1) !== crv) throw new CoseError(`${this.name} requires crv ${crv}`)
      const k = super.decodeKey(m)
      k.pub = bytesField(m, -2, 'x')
      k.priv = optBytes(m, -4)
      return k
    }
  }

const ec2 = (Base) =>
  class extends Base {
    get kty() {
      return KTY_EC2
    }

    encodeKey(key, priv) {
      const m = super.encodeKey(key, priv)
      const n = EC[this.crv].size
      m.set(-1, this.crv)
      m.set(-2, key.pub.slice(0, n))
      m.set(-3, key.pub.slice(n))
      if (priv && key.priv != null) m.set(-4, key.priv)
      return m
    }

    decodeKey(m) {
      if (m.get(-1) !== this.crv) throw new CoseError(`${this.name} requires crv ${this.crv}`)
      const k = super.decodeKey(m)
      const n = EC[this.crv].size
      const x = bytesField(m, -2, 'x')
      const y = bytesField(m, -3, 'y')
      if (x.length !== n || y.length !== n) throw new CoseError(`${this.name} coordinates must be ${n} bytes`)
      k.pub = concat(x, y)
      k.priv = optBytes(m, -4)
      return k
    }

    generate() {
      const { curve } = EC[this.crv]
      const sk = curve.utils.randomSecretKey()
      return new Key(this.id, this.publicFromPrivate(sk), sk)
    }

    publicFromPrivate(priv) {
      return EC[this.crv].curve.getPublicKey(priv, false).slice(1)
    }
  }

// --- signatures ---

export class SignAlg extends Alg {}

class Ed25519Alg extends okp(SignAlg, CRV_ED25519) {
  generate() {
    const sk = ed25519.utils.randomSecretKey()
    return new Key(this.id, ed25519.getPublicKey(sk), sk)
  }

  publicFromPrivate(priv) {
    return ed25519.getPublicKey(priv)
  }

  sign(key, data) {
    return ed25519.sign(data, key.priv)
  }

  verify(key, sig, data) {
    try {
      return ed25519.verify(sig, data, key.pub, { zip215: false })
    } catch {
      return false
    }
  }
}

class EcdsaAlg extends ec2(SignAlg) {
  constructor(id, name, crv) {
    super(id, name)
    this.crv = crv
  }

  sign(key, data) {
    return EC[this.crv].curve.sign(data, key.priv, { lowS: false })
  }

  verify(key, sig, data) {
    const { curve, size } = EC[this.crv]
    if (sig.length !== size * 2) return false
    try {
      return curve.verify(sig, data, concat(new Uint8Array([4]), key.pub), { lowS: false })
    } catch {
      return false
    }
  }
}

// ML-DSA (FIPS 204), pure mode, empty context. priv is the 32-byte seed.
class MlDsaAlg extends akp(SignAlg) {
  constructor(id, name, dsa) {
    super(id, name)
    this.dsa = dsa
  }

  generate() {
    const seed = randomBytes(32)
    return new Key(this.id, this.dsa.keygen(seed).publicKey, seed)
  }

  publicFromPrivate(priv) {
    return this.dsa.keygen(priv).publicKey
  }

  sign(key, data) {
    if (!key._cache.sk) key._cache.sk = this.dsa.keygen(key.priv).secretKey
    return this.dsa.sign(data, key._cache.sk)
  }

  verify(key, sig, data) {
    try {
      return this.dsa.verify(sig, data, key.pub)
    } catch {
      return false
    }
  }
}

// --- HPKE (COSE_Encrypt0 integrated mode, COSE_Recipient key encryption) ---

export class HpkeAlg extends Alg {
  constructor(id, name, suite, integrated, sibling) {
    super(id, name)
    this.suite = suite
    this.integrated = integrated
    this.sibling = sibling
  }

  // HPKE serialized public key
  hpkePub(key) {
    return key.pub
  }

  seal(key, plaintext, info, aad) {
    return this.suite.seal(this.hpkePub(key), plaintext, info, aad)
  }

  open(key, enc, ct, info, aad) {
    if (key.priv == null) throw new CoseError('need the private key to decrypt')
    return this.suite.open(key.priv, enc, ct, info, aad)
  }

  generate() {
    const priv = this.suite.kem.generate ? this.suite.kem.generate() : randomBytes(this.seedSize)
    return new Key(this.id, this.publicFromPrivate(priv), priv)
  }
}

class HpkeOkpAlg extends okp(HpkeAlg, CRV_X25519) {
  publicFromPrivate(priv) {
    return this.suite.kem.publicKey(priv)
  }
}

class HpkeEc2Alg extends ec2(HpkeAlg) {
  constructor(crv, ...args) {
    super(...args)
    this.crv = crv
  }

  hpkePub(key) {
    return concat(new Uint8Array([4]), key.pub)
  }
}

// X-Wing (priv = 32-byte seed) and ML-KEM (priv = 64-byte d || z seed)
class HpkeAkpAlg extends akp(HpkeAlg) {
  constructor(seedSize, ...args) {
    super(...args)
    this.seedSize = seedSize
  }

  publicFromPrivate(priv) {
    if (!isBytes(priv) || priv.length !== this.seedSize) throw new CoseError(`${this.name} seed must be ${this.seedSize} bytes`)
    return this.suite.kem.publicKey(priv)
  }
}

// --- symmetric: content encryption and MAC ---

const sym = (Base) =>
  class extends Base {
    get kty() {
      return KTY_SYMMETRIC
    }

    encodeKey(key, priv) {
      const m = super.encodeKey(key, priv)
      m.set(-1, key.priv)
      return m
    }

    decodeKey(m) {
      const k = super.decodeKey(m)
      k.priv = bytesField(m, -1, 'k')
      return k
    }

    generate() {
      return new Key(this.id, EMPTY, randomBytes(this.keySize))
    }

    publicFromPrivate() {
      return EMPTY
    }
  }

export class AeadAlg extends sym(Alg) {
  constructor(id, name, cipher, keySize) {
    super(id, name)
    this.cipher = cipher
    this.keySize = keySize
    this.ivSize = 12
  }

  encrypt(k, iv, plaintext, aad) {
    return this.cipher(k, iv, aad).encrypt(plaintext)
  }

  decrypt(k, iv, ciphertext, aad) {
    if (!isBytes(iv) || iv.length !== this.ivSize) throw new CoseError('bad IV')
    return this.cipher(k, iv, aad).decrypt(ciphertext)
  }
}

export class HmacAlg extends sym(Alg) {
  constructor(id, name, hash, keySize, tagSize) {
    super(id, name)
    this.hash = hash
    this.keySize = keySize
    this.tagSize = tagSize
  }

  tag(k, data) {
    return hmac(this.hash, k, data).slice(0, this.tagSize)
  }

  verify(k, tag, data) {
    return equal(this.tag(k, data), tag)
  }
}

// --- registry ---

// signatures
export const ESP256 = -9
export const ES256 = -7
export const ED25519 = -19
export const EDDSA = -8
export const ML_DSA_44 = -48
export const ML_DSA_65 = -49
export const ML_DSA_87 = -50

// content encryption
export const A128GCM = 1
export const A192GCM = 2
export const A256GCM = 3
export const CHACHA20_POLY1305 = 24

// MAC
export const HMAC_256_64 = 4
export const HMAC_256_256 = 5
export const HMAC_384_384 = 6
export const HMAC_512_512 = 7

// HPKE integrated / key-encryption pairs
export const HPKE_0 = 35
export const HPKE_0_KE = 46
export const HPKE_1 = 37
export const HPKE_1_KE = 47
export const HPKE_2 = 39
export const HPKE_2_KE = 48
export const HPKE_3 = 41
export const HPKE_3_KE = 49
export const HPKE_4 = 42
export const HPKE_4_KE = 50
export const HPKE_7 = 45
export const HPKE_7_KE = 53
export const HPKE_9 = 56
export const HPKE_9_KE = 57
export const HPKE_12 = 62
export const HPKE_12_KE = 63
export const HPKE_13 = 64
export const HPKE_13_KE = 65

export const ALGS = new Map()

function reg(a) {
  ALGS.set(a.id, a)
}

reg(new Ed25519Alg(ED25519, 'Ed25519'))
reg(new Ed25519Alg(EDDSA, 'EdDSA'))
reg(new EcdsaAlg(ESP256, 'ESP256', CRV_P256))
reg(new EcdsaAlg(ES256, 'ES256', CRV_P256))
reg(new MlDsaAlg(ML_DSA_44, 'ML-DSA-44', ml_dsa44))
reg(new MlDsaAlg(ML_DSA_65, 'ML-DSA-65', ml_dsa65))
reg(new MlDsaAlg(ML_DSA_87, 'ML-DSA-87', ml_dsa87))

reg(new AeadAlg(A128GCM, 'A128GCM', gcm, 16))
reg(new AeadAlg(A192GCM, 'A192GCM', gcm, 24))
reg(new AeadAlg(A256GCM, 'A256GCM', gcm, 32))
reg(new AeadAlg(CHACHA20_POLY1305, 'ChaCha20/Poly1305', chacha20poly1305, 32))

reg(new HmacAlg(HMAC_256_64, 'HMAC 256/64', sha256, 32, 8))
reg(new HmacAlg(HMAC_256_256, 'HMAC 256/256', sha256, 32, 32))
reg(new HmacAlg(HMAC_384_384, 'HMAC 384/384', sha384, 48, 48))
reg(new HmacAlg(HMAC_512_512, 'HMAC 512/512', sha512, 64, 64))

for (const [i, ke, n, crv, kem, kdf, aead] of [
  [HPKE_0, HPKE_0_KE, 'HPKE-0', CRV_P256, KEM.P256, KDF.HKDF_SHA256, AEAD.AES_128_GCM],
  [HPKE_1, HPKE_1_KE, 'HPKE-1', CRV_P384, KEM.P384, KDF.HKDF_SHA384, AEAD.AES_256_GCM],
  [HPKE_2, HPKE_2_KE, 'HPKE-2', CRV_P521, KEM.P521, KDF.HKDF_SHA512, AEAD.AES_256_GCM],
  [HPKE_7, HPKE_7_KE, 'HPKE-7', CRV_P256, KEM.P256, KDF.HKDF_SHA256, AEAD.AES_256_GCM]
]) {
  const s = new Suite(kem, kdf, aead)
  reg(new HpkeEc2Alg(crv, i, n, s, true, ke))
  reg(new HpkeEc2Alg(crv, ke, n + '-KE', s, false, i))
}

for (const [i, ke, n, aead] of [
  [HPKE_3, HPKE_3_KE, 'HPKE-3', AEAD.AES_128_GCM],
  [HPKE_4, HPKE_4_KE, 'HPKE-4', AEAD.CHACHA20_POLY1305]
]) {
  const s = new Suite(KEM.X25519, KDF.HKDF_SHA256, aead)
  reg(new HpkeOkpAlg(i, n, s, true, ke))
  reg(new HpkeOkpAlg(ke, n + '-KE', s, false, i))
}

for (const [i, ke, n, kem, seed] of [
  [HPKE_9, HPKE_9_KE, 'HPKE-9', KEM.MLKEM768_X25519, 32],
  [HPKE_12, HPKE_12_KE, 'HPKE-12', KEM.MLKEM768, 64],
  [HPKE_13, HPKE_13_KE, 'HPKE-13', KEM.MLKEM1024, 64]
]) {
  const s = new Suite(kem, KDF.SHAKE256, AEAD.AES_256_GCM)
  reg(new HpkeAkpAlg(seed, i, n, s, true, ke))
  reg(new HpkeAkpAlg(seed, ke, n + '-KE', s, false, i))
}

// algorithms that stay secure against a quantum attacker
export const QUANTUM_SAFE_SIGN = new Set([ML_DSA_44, ML_DSA_65, ML_DSA_87])
export const QUANTUM_SAFE_KEM = new Set([HPKE_9, HPKE_9_KE, HPKE_12, HPKE_12_KE, HPKE_13, HPKE_13_KE])

export function getAlg(id) {
  const a = ALGS.get(id)
  if (!a) throw new CoseError(`unsupported COSE algorithm ${id}`)
  return a
}

// the HPKE suite to use with `key` for integrated or key-encryption mode
export function hpkeVariant(key, integrated) {
  const a = key.algorithm
  if (!(a instanceof HpkeAlg)) throw new CoseError(`${a.name} is not an HPKE algorithm`)
  return a.integrated === integrated ? a : getAlg(a.sibling)
}
