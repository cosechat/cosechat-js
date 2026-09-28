import type { Bytes } from './bytes.js'
import type { Key } from './keys.js'
import type { Identity } from './identity.js'
import type { Announce, Fields, Message } from './message.js'
import type { RatchetProvider } from './ratchet.js'
import type { LinkKeys } from './link.js'
import type { Resource } from './resource.js'
import type { RoadAuth } from './packet.js'
import type { Store } from './store.js'
import type { Road } from './roads/road.js'

export const SEEN_CACHE: number
export const DELIVERED_CACHE: number
export const DELIVERY_RESULTS: number
export const ACCEPT_CACHE: number
export const WAITING_PER_SENDER: number
export const WAITING_SENDERS: number
export const FRAGMENT_CACHE_SETS: number
export const FRAGMENT_CACHE_TIME: number
export const NACK_BASE_DELAY: number
export const RESOURCE_STALLS: number
export const ANNOUNCE_QUEUE: number
export const TIMER_TABLE: number
export const KEYSET_WAITS: number
export const INGRESS: Record<'announce' | 'link' | 'message' | 'request', [number, number]>

/** An Identity, an address, or its hex. */
export type AddressLike = Identity | Bytes | string
export function toAddress(t: AddressLike): Bytes

export class LookupError extends Error {}
export class PermissionError extends Error {}
export class TimeoutError extends Error {}

export class Path {
  readonly lane: unknown
  via: Bytes | null
  hops: number
  sequence: number | bigint
  /** local monotonic clock (s) */
  expires: number
  readonly road: Road
}

/** All durations in seconds. */
export interface NodeOptions {
  identity?: Identity | null
  transport?: boolean
  propagate?: boolean
  appData?: unknown
  maxHops?: number
  rebroadcastDelay?: number
  announceInterval?: number | null
  /** default true: refuse peers a quantum attacker could break */
  quantumSafeOnly?: boolean
  ratchets?: RatchetProvider | null
  retryAfter?: number
  retryMax?: number
  maxAttempts?: number
  acceptLinks?: boolean
  linkAttempts?: number
  linkIdle?: number
  nackAttempts?: number
  store?: Store | null
  maxLinks?: number
  pathTtl?: number
  maxPeers?: number
  maxResource?: number
  propagationNode?: AddressLike | null
  autoPropagate?: boolean
  ingress?: Partial<typeof INGRESS> | null
  announceCap?: number
  announceQueueAge?: number
  rebroadcastMinInterval?: number
  name?: string | null
  log?: ((...args: unknown[]) => void) | null
}

export interface SendOptions {
  title?: string
  fields?: Fields | null
  attachIdentity?: boolean
  timeout?: number
  receipt?: boolean
  propagate?: boolean
}

type Unsubscribe = () => void

export class Node {
  constructor(opts?: NodeOptions)
  readonly identity: Identity
  readonly address: Bytes
  readonly ratchets: RatchetProvider
  readonly store: Store
  appData: unknown
  transport: boolean
  propagate: boolean
  quantumSafeOnly: boolean
  name: string
  log: (...args: unknown[]) => void
  /** keyed by hex address */
  readonly identities: Map<string, Identity>
  readonly announces: Map<string, [Bytes, Announce]>
  readonly paths: Map<string, Path>
  readonly peerRatchets: Map<string, Key>
  readonly propagationNodes: Map<string, true>
  readonly links: Map<string, LinkKeys>

  addRoad<R extends Road>(road: R, auth?: RoadAuth | null): R
  start(): Promise<void>
  stop(): Promise<void>

  onMessage(cb: (m: Message) => unknown): Unsubscribe
  onAnnounce(cb: (a: Announce, path: Path) => unknown): Unsubscribe
  onReceipt(cb: (m: Message, recipient: Bytes) => unknown): Unsubscribe
  onResource(cb: (r: Resource) => unknown): Unsubscribe

  known(address: Bytes): Identity | null
  path(dest: Bytes): Path | null
  peerRatchet(address: Bytes): Key | null
  announce(opts?: { appData?: unknown; full?: boolean | null }): Promise<void>
  contactCard(): Bytes
  addContact(card: Bytes): Announce
  rotateRatchet(announce?: boolean): Promise<Key>
  requestPath(address: Bytes, opts?: { timeout?: number; fresh?: boolean }): Promise<Identity | null>
  send(to: AddressLike | AddressLike[], content?: unknown, opts?: SendOptions): Promise<Message>
  /** true once every recipient sent a receipt; false if any gave up (or on timeout) */
  delivered(m: Message, timeout?: number | null): Promise<boolean>
  linkTo(address: Bytes): LinkKeys | null
  openLink(to: AddressLike, timeout?: number): Promise<LinkKeys>
  closeLink(address: Bytes): Promise<void>
  fetch(opts?: { timeout?: number; node?: AddressLike | null }): Promise<number>
  sendResource(to: AddressLike, data: Bytes, opts?: { meta?: unknown; timeout?: number }): Promise<boolean>
}
