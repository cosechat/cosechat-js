import type { Bytes } from './bytes.js'
import type { CoseError, Key } from './keys.js'
import type { Message as CoseMessage } from './cose.js'
import type { Identity } from './identity.js'
import type { RatchetProvider } from './ratchet.js'

export const M_TO: 1
export const M_TIME: 2
export const M_TITLE: 3
export const M_CONTENT: 4
export const M_FIELDS: 5
export const M_RECEIPT: 6
export const RECEIPT_SECRET_SIZE: 16
export const RECEIPT_TAG_SIZE: 16
export const A_IDENTITY: 1
export const A_SEQUENCE: 2
export const A_APP_DATA: 4
export const A_RATCHET: 5
export const A_SERVICES: 7
export const H_IDENTITY: -65537
export const MAX_TRIAL_RATCHETS: 16

export type Fields = Map<unknown, unknown> | Record<string, unknown>
export type Ratchets = RatchetProvider | Iterable<Key> | null
/** Recipient address -> announced ratchet: a function or a BytesMap. */
export type RatchetLookup = ((address: Bytes) => Key | null | undefined) | { get(address: Bytes): Key | undefined }
export type Resolve = (address: Bytes) => Identity | null | undefined

export function nowMs(): number

export class Message {
  constructor(fields: Partial<Message> & { sender: Bytes; recipients: Bytes[]; timestamp: number })
  sender: Bytes
  recipients: Bytes[]
  /** the sender's claim (ms); nothing acts on it */
  timestamp: number
  title: string
  content: any
  fields: Map<unknown, unknown>
  id: Bytes
  signed: Bytes
  /** id of our ratchet it was sealed to */
  ratchetId: Bytes | null
  receiptSecret: Bytes | null
  /** set when it came over a link */
  linkId: Bytes | null
  readonly time: Date
}

export class SenderUnknown extends CoseError {
  address: Bytes
}
export class KeysetNeeded extends CoseError {
  address: Bytes
}

export function messageId(signed: Bytes): Bytes
export function receiptTag(secret: Bytes, recipient: Bytes): Bytes
export function receiptSecretOf(v: unknown): Bytes | null

export interface MessageOptions {
  content?: unknown
  title?: string
  fields?: Fields | null
  timestamp?: number | null
  attachIdentity?: boolean
  receiptSecret?: Bytes | null
}

export function messageBody(o: { to?: Bytes[]; timestamp?: number | null; title?: string; content?: unknown; fields?: Fields | null; receiptSecret?: Bytes | null }): Map<number, unknown>
export function signMessage(sender: Identity, recipients: Identity[], opts?: MessageOptions): Message
export function envelope(signed: Bytes, ratchet: Key): Bytes
export function seal(sender: Identity, recipients: Identity[], opts?: MessageOptions & { ratchets?: RatchetLookup; integrated?: boolean }): { sealed: Bytes; message: Message }
export function sealEach(sender: Identity, recipients: Identity[], opts?: MessageOptions & { ratchets?: RatchetLookup }): { sealed: [Bytes, Bytes][]; message: Message }
export function open(env: CoseMessage, ratchets: Ratchets): { signed: Bytes; rid: Bytes }
export function unseal(me: Identity, sealed: Bytes, resolve: Resolve, ratchets?: Ratchets): Message
export function attachedIdentity(signed: Bytes): Identity | null

export class Announce {
  constructor(identity: Identity, sequence: number | bigint, ratchet: Key, appData?: unknown, full?: boolean, services?: number)
  identity: Identity
  sequence: number | bigint
  ratchet: Key
  appData: any
  /** carried its keyset */
  full: boolean
  services: number
  readonly address: Bytes
}

export function makeAnnounce(identity: Identity, ratchet: Key, opts?: { appData?: unknown; sequence?: number | null; full?: boolean; services?: number }): Bytes
export function announceAddress(data: Bytes): Bytes | null
export function verifyAnnounce(data: Bytes, address?: Bytes | null, known?: Resolve | null): Announce
