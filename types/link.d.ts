import type { Bytes } from './bytes.js'
import type { Key } from './keys.js'
import type { Identity } from './identity.js'
import type { Fields, Message, Ratchets, Resolve } from './message.js'

export const LINK_ID_SIZE: 16
export const PART_SIZE: 32
export const L_EPHEMERAL: 1
export const L_PART: 2
export const L_PEER: 3
export const M_CLOSE: 7

export class LinkKeys {
  constructor(linkId: Bytes, peer: Bytes, initiator: boolean, sendKey: Key, recvKey: Key)
  linkId: Bytes
  peer: Bytes
  initiator: boolean
  sendKey: Key
  recvKey: Key
}

export class PendingLink {
  constructor(linkId: Bytes, peer: Bytes, request: Bytes, ephemeral: Key | null, partA: Bytes)
  linkId: Bytes
  peer: Bytes
  request: Bytes
  ephemeral: Key | null
  partA: Bytes
}

export function deriveKeys(linkId: Bytes, partA: Bytes, partB: Bytes, peer: Bytes, initiator: boolean): LinkKeys
export function linkId(request: Bytes): Bytes
export function makeRequest(me: Identity, peer: Identity, peerRatchet: Key): PendingLink
export function readRequest(me: Identity, request: Bytes, resolve: Resolve, ratchets?: Ratchets, quantumSafeOnly?: boolean): { sender: Identity; ephemeral: Key; partA: Bytes }
export function acceptRequest(me: Identity, request: Bytes, resolve: Resolve, ratchets?: Ratchets, quantumSafeOnly?: boolean): { sender: Identity; accept: Bytes; keys: LinkKeys }
export function finish(pending: PendingLink, accept: Bytes): LinkKeys
export function seal(keys: LinkKeys, body: Bytes): Bytes
export function unseal(keys: LinkKeys, payload: Bytes): Bytes
export function messageBody(opts?: { content?: unknown; title?: string; fields?: Fields | null; receiptSecret?: Bytes | null; close?: boolean; timestamp?: number | null }): Bytes
export function readMessage(keys: LinkKeys, me: Bytes, bodyBytes: Bytes): { message: Message; close: boolean }
