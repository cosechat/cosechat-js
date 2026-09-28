import type { Bytes } from './bytes.js'

export interface Kem {
  id: number
  publicKey(priv: Bytes): Bytes
  encap(pkR: Bytes): { enc: Bytes; ss: Bytes }
  decap(enc: Bytes, skR: Bytes): Bytes
}
export interface Kdf {
  id: number
  Nh: number
  oneStage?: boolean
}
export interface Aead {
  id: number
  Nk: number
}

export const KEM: Record<'P256' | 'P384' | 'P521' | 'X25519' | 'MLKEM768' | 'MLKEM1024' | 'MLKEM768_X25519', Kem>
export const KDF: Record<'HKDF_SHA256' | 'HKDF_SHA384' | 'HKDF_SHA512' | 'SHAKE256', Kdf>
export const AEAD: Record<'AES_128_GCM' | 'AES_256_GCM' | 'CHACHA20_POLY1305', Aead>

/** HPKE base mode, single shot (RFC 9180; one-stage SHAKE256 schedule for PQ KEMs). */
export class Suite {
  constructor(kem: Kem, kdf: Kdf, aead: Aead)
  seal(pkR: Bytes, plaintext: Bytes, info?: Bytes, aad?: Bytes): { enc: Bytes; ct: Bytes }
  open(skR: Bytes, enc: Bytes, ct: Bytes, info?: Bytes, aad?: Bytes): Bytes
}
