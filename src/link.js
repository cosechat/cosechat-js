// Links: sessions between two identities, like Reticulum's Links.
//
//   request (A -> B), sealed like a message:
//     COSE_Encrypt0 to B's ratchet of
//       A.sign(CBOR {1: A's ephemeral KEM public COSE_Key, 2: part_a (32 random bytes), 3: B's address})
//   accept (B -> A):
//     link id (16) || COSE_Encrypt0, HPKE to A's ephemeral key, of CBOR {1: part_b}
//     external_aad = SHA-256(request)
//   link id = SHA-256(request)[0:16]
//   keys    = HKDF-SHA-256(part_a || part_b, salt = link id, info = "cosechat link", 64)
//             A->B = keys[0:32], B->A = keys[32:64] (ChaCha20/Poly1305)
//   link message = link id || COSE_Encrypt0(direction key, external_aad = link id) of a message body without `to`

import { sha256 } from '@noble/hashes/sha2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { concat, equal, isBytes, randomBytes, utf8 } from './bytes.js'
import { decode, encode } from './cbor.js'
import * as cose from './cose.js'
import { signerOf } from './identity.js'
import { CHACHA20_POLY1305, CoseError, HpkeAlg, Key, QUANTUM_SAFE_KEM } from './keys.js'
import * as msg from './message.js'

export const LINK_ID_SIZE = 16
export const PART_SIZE = 32

export const L_EPHEMERAL = 1
export const L_PART = 2
export const L_PEER = 3

// extra body field in link messages: the sender is closing the link
export const M_CLOSE = 7

export class LinkKeys {
  constructor(linkId, peer, initiator, sendKey, recvKey) {
    this.linkId = linkId
    this.peer = peer // the other side's address
    this.initiator = initiator
    this.sendKey = sendKey
    this.recvKey = recvKey
  }
}

// initiator state between request and accept; holds the ephemeral private key
export class PendingLink {
  constructor(linkId, peer, request, ephemeral, partA) {
    this.linkId = linkId
    this.peer = peer
    this.request = request
    this.ephemeral = ephemeral
    this.partA = partA
  }
}

export function deriveKeys(linkId, partA, partB, peer, initiator) {
  const okm = hkdf(sha256, concat(partA, partB), linkId, utf8('cosechat link'), 64)
  const aToB = new Key(CHACHA20_POLY1305, new Uint8Array(), okm.slice(0, 32), linkId)
  const bToA = new Key(CHACHA20_POLY1305, new Uint8Array(), okm.slice(32), linkId)
  return initiator ? new LinkKeys(linkId, peer, true, aToB, bToA) : new LinkKeys(linkId, peer, false, bToA, aToB)
}

export function linkId(request) {
  return sha256(request).slice(0, LINK_ID_SIZE)
}

// start a link to `peer`; send .request as a LINK_REQUEST packet to peer.address
export function makeRequest(me, peer, peerRatchet) {
  const eph = Key.generate(me.kemAlg)
  const partA = randomBytes(PART_SIZE)
  const body = encode(
    new Map([
      [L_EPHEMERAL, eph.public().toCose()],
      [L_PART, partA],
      [L_PEER, peer.address]
    ])
  )
  const request = msg.envelope(me.sign(body), peerRatchet)
  return new PendingLink(linkId(request), peer.address, request, eph, partA)
}

// open and verify a request: { sender, ephemeral, partA }
export function readRequest(me, request, resolve, ratchets = null, quantumSafeOnly = true) {
  const { signed } = msg.open(cose.decode(request), ratchets)
  const sm = cose.decode(signed)
  const senderAddr = signerOf(sm)
  let sender = senderAddr ? resolve(senderAddr) : null
  if (!sender) sender = msg.attachedIdentity(signed)
  if (!sender && senderAddr) throw new msg.SenderUnknown(senderAddr) // the caller may fetch the keyset and retry
  if (!sender || !equal(sender.address, senderAddr)) throw new CoseError('link request from an unknown identity')
  const body = decode(sender.verify(sm))
  if (!(body instanceof Map) || !equal(body.get(L_PEER), me.address)) throw new CoseError('link request is for someone else')
  const partA = body.get(L_PART)
  if (!isBytes(partA) || partA.length !== PART_SIZE) throw new CoseError('bad link request')
  const eph = Key.fromCose(body.get(L_EPHEMERAL))
  if (!(eph.algorithm instanceof HpkeAlg) || eph.hasPrivate) throw new CoseError('bad ephemeral key in link request')
  if (quantumSafeOnly && !QUANTUM_SAFE_KEM.has(eph.alg)) throw new CoseError('link request uses a key that is not quantum-safe')
  return { sender, ephemeral: eph, partA }
}

// B's side: { sender, accept (payload to send back), keys }
export function acceptRequest(me, request, resolve, ratchets = null, quantumSafeOnly = true) {
  const { sender, ephemeral, partA } = readRequest(me, request, resolve, ratchets, quantumSafeOnly)
  const lid = linkId(request)
  const partB = randomBytes(PART_SIZE)
  const accept = concat(lid, cose.encrypt0(encode(new Map([[L_PART, partB]])), ephemeral, { externalAad: sha256(request) }))
  return { sender, accept, keys: deriveKeys(lid, partA, partB, sender.address, false) }
}

// A's side: check the accept and derive the link keys; drops the ephemeral key
export function finish(pending, accept) {
  if (!equal(accept.slice(0, LINK_ID_SIZE), pending.linkId)) throw new CoseError('accept is for another link')
  const body = decode(cose.decrypt0(accept.slice(LINK_ID_SIZE), pending.ephemeral, sha256(pending.request)))
  const partB = body instanceof Map ? body.get(L_PART) : null
  if (!isBytes(partB) || partB.length !== PART_SIZE) throw new CoseError('bad link accept')
  const keys = deriveKeys(pending.linkId, pending.partA, partB, pending.peer, true)
  pending.ephemeral = null // forward secrecy: nobody can recompute part_b now
  pending.partA = new Uint8Array()
  return keys
}

// link id || COSE_Encrypt0 of a message body (fresh IV every call)
export function seal(keys, body) {
  return concat(keys.linkId, cose.encrypt0(body, keys.sendKey, { externalAad: keys.linkId }))
}

export function unseal(keys, payload) {
  if (!equal(payload.slice(0, LINK_ID_SIZE), keys.linkId)) throw new CoseError('not a message on this link')
  return cose.decrypt0(payload.slice(LINK_ID_SIZE), keys.recvKey, keys.linkId)
}

// no `to`: the link keys already bind the two parties and the direction
export function messageBody({ content = '', title = '', fields = null, receiptSecret = null, close = false, timestamp = null } = {}) {
  const b = msg.messageBody({ timestamp, title, content, fields, receiptSecret })
  if (close) b.set(M_CLOSE, true)
  return encode(b)
}

// parse an opened link body into { message, close } (sender = the link peer)
export function readMessage(keys, me, bodyBytes) {
  const b = decode(bodyBytes)
  if (!(b instanceof Map)) throw new CoseError('bad link message')
  const message = new msg.Message({
    sender: keys.peer,
    recipients: [me],
    timestamp: b.get(msg.M_TIME) ?? 0,
    title: b.get(msg.M_TITLE) ?? '',
    content: b.get(msg.M_CONTENT) ?? '',
    fields: b.get(msg.M_FIELDS) ?? new Map(),
    id: sha256(concat(keys.linkId, bodyBytes)),
    receiptSecret: msg.receiptSecretOf(b.get(msg.M_RECEIPT)),
    linkId: keys.linkId
  })
  return { message, close: b.get(M_CLOSE) === true }
}
