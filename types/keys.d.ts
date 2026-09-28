import type { Bytes } from './bytes.js'
import type { Suite } from './hpke.js'

export class CoseError extends Error {}

export type CoseKeyMap = Map<number, unknown>

export const KTY_OKP: 1
export const KTY_EC2: 2
export const KTY_SYMMETRIC: 4
export const KTY_AKP: 7
export const KEY_KTY: 1
export const KEY_KID: 2
export const KEY_ALG: 3
export const CRV_P256: 1
export const CRV_P384: 2
export const CRV_P521: 3
export const CRV_X25519: 4
export const CRV_ED25519: 6

/** A COSE key. `pub`: raw public key; `priv`: AKP seed, OKP/EC2 d, or symmetric k. */
export class Key {
  constructor(alg: number, pub?: Bytes, priv?: Bytes | null, kid?: Bytes | null)
  alg: number
  pub: Bytes
  priv: Bytes | null
  kid: Bytes | null
  readonly algorithm: Alg
  readonly hasPrivate: boolean
  public(): Key
  toCose(priv?: boolean): CoseKeyMap
  static fromCose(m: CoseKeyMap): Key
  static generate(alg: number, kid?: Bytes | null): Key
  /** A full key from its private bytes (the public half is derived). */
  static fromPrivate(alg: number, priv: Bytes, kid?: Bytes | null): Key
}

/** Base of the algorithm classes (type only: not exported at runtime). */
declare class Alg {
  readonly id: number
  readonly name: string
  readonly kty: number
}
export type { Alg }
export class SignAlg extends Alg {
  sign(key: Key, data: Bytes): Bytes
  verify(key: Key, sig: Bytes, data: Bytes): boolean
}
export class HpkeAlg extends Alg {
  readonly suite: Suite
  readonly integrated: boolean
  readonly sibling: number
}
export class AeadAlg extends Alg {
  readonly keySize: number
  readonly ivSize: number
  encrypt(k: Bytes, iv: Bytes, plaintext: Bytes, aad: Bytes): Bytes
  decrypt(k: Bytes, iv: Bytes, ciphertext: Bytes, aad: Bytes): Bytes
}
export class HmacAlg extends Alg {
  readonly keySize: number
  readonly tagSize: number
  tag(k: Bytes, data: Bytes): Bytes
  verify(k: Bytes, tag: Bytes, data: Bytes): boolean
}

export const ESP256: -9
export const ES256: -7
export const ED25519: -19
export const EDDSA: -8
export const ML_DSA_44: -48
export const ML_DSA_65: -49
export const ML_DSA_87: -50
export const A128GCM: 1
export const A192GCM: 2
export const A256GCM: 3
export const CHACHA20_POLY1305: 24
export const HMAC_256_64: 4
export const HMAC_256_256: 5
export const HMAC_384_384: 6
export const HMAC_512_512: 7
export const HPKE_0: 35
export const HPKE_0_KE: 46
export const HPKE_1: 37
export const HPKE_1_KE: 47
export const HPKE_2: 39
export const HPKE_2_KE: 48
export const HPKE_3: 41
export const HPKE_3_KE: 49
export const HPKE_4: 42
export const HPKE_4_KE: 50
export const HPKE_7: 45
export const HPKE_7_KE: 53
export const HPKE_9: 56
export const HPKE_9_KE: 57
export const HPKE_12: 62
export const HPKE_12_KE: 63
export const HPKE_13: 64
export const HPKE_13_KE: 65

export const ALGS: Map<number, Alg>
export const QUANTUM_SAFE_SIGN: Set<number>
export const QUANTUM_SAFE_KEM: Set<number>
export function getAlg(id: number): Alg
export function hpkeVariant(key: Key, integrated: boolean): HpkeAlg
