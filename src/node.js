// Node: identity + roads + routing. The road-agnostic transport, like
// Reticulum's Transport, reduced to its core ideas (see SPEC §17 of the
// Python reference; this is a port of cosechat/node.py):
//
//   * Announces flood the mesh; each node records a path (road, `via`, hops).
//   * DATA carries only the destination; transport nodes named in `via` forward it.
//   * PATH_REQUEST asks for a path; KEYSET_REQUEST fetches a keyset for a short announce.
//   * Propagation nodes hold sealed messages for offline peers.
//   * Delivery: each message carries a receipt secret; the sender resends
//     (re-sealed) with backoff until a RECEIPT comes back.
//
// All durations are in seconds, all timing is the local clock only.

import { concat, equal, fromHex, isBytes, randomBytes, toHex } from './bytes.js'
import { decode as cborDecode, encode } from './cbor.js'
import * as cose from './cose.js'
import { Identity, addressOf, signerOf } from './identity.js'
import { QUANTUM_SAFE_KEM } from './keys.js'
import * as L from './link.js'
import * as msg from './message.js'
import * as PR from './propagation.js'
import * as R from './resource.js'
import { ANNOUNCE, DATA, FRAGMENT_ID_SIZE, FRAGMENT_OVERHEAD, Fragment, KEYSET, KEYSET_REQUEST, LINK_ACCEPT, LINK_DATA, LINK_REQUEST, Nack, PATH_REQUEST, Packet, PacketError, RECEIPT, RECEIPT_NONCE_SIZE, REQUEST_TAG_SIZE, ROUTED, Reassembler, decode, fragment, nack } from './packet.js'
import { MemoryRatchets } from './ratchet.js'
import { MemoryStore } from './store.js'

// bounds on in-memory state (local policy, not protocol)
export const SEEN_CACHE = 50000
export const DELIVERED_CACHE = 10000
export const DELIVERY_RESULTS = 1000
export const ACCEPT_CACHE = 256
export const WAITING_PER_SENDER = 16
export const WAITING_SENDERS = 256
export const FRAGMENT_CACHE_SETS = 32
export const FRAGMENT_CACHE_TIME = 60
export const NACK_BASE_DELAY = 0.2
export const RESOURCE_STALLS = 8
export const ANNOUNCE_QUEUE = 256
export const TIMER_TABLE = 4096
export const KEYSET_WAITS = 256

// ingress: per road, [per second, burst] for work that costs CPU or airtime
export const INGRESS = {
  announce: [5, 20],
  link: [2, 10],
  message: [50, 200],
  request: [10, 30]
}

const monotonic = () => performance.now() / 1000
const hex = toHex
const TIMEOUT = Symbol('timeout')

function deferred() {
  let resolve
  const p = new Promise((r) => (resolve = r))
  p.done = false
  p.resolve = (v) => {
    if (p.done) return
    p.done = true
    resolve(v)
  }
  return p
}

// an address from an Identity, bytes, or hex text
export function toAddress(t) {
  if (t instanceof Identity) return t.address
  if (isBytes(t)) return t
  if (typeof t === 'string') return fromHex(t.replace(/[-\s]/g, ''))
  throw new TypeError('not an address')
}

// LRU helpers on insertion-ordered Maps
const touch = (m, k, v) => {
  m.delete(k)
  m.set(k, v)
}
const trim = (m, n) => {
  while (m.size > n) m.delete(m.keys().next().value)
}

export class Path {
  constructor(lane, via, hops, sequence, expires) {
    this.lane = lane
    this.via = via
    this.hops = hops
    this.sequence = sequence // the announce's sequence (ordering only)
    this.expires = expires // local monotonic clock
  }

  get road() {
    return this.lane.road
  }
}

let laneIds = 0

// A road attached to a node, plus its auth wrapper and announce budget. On a
// road with a bitrate, announces use at most `cap` of it (Reticulum's 2%);
// waiting announces go fewest-hops first, newest per destination kept.
class Lane {
  constructor(node, road, auth) {
    this.id = ++laneIds
    this.node = node
    this.road = road
    this.auth = auth
    this._sent = new Map() // fid hex -> [frames, expires]
    this._buckets = new Map()
    this.queue = new Map() // dest hex -> { hops, at, packet }
    this._readyAt = 0
    this._pumping = false
  }

  // token bucket per road and kind of incoming work
  allow(kind) {
    const [rate, burst] = this.node.ingress[kind]
    const now = monotonic()
    let b = this._buckets.get(kind)
    if (!b) this._buckets.set(kind, (b = [burst, now]))
    b[0] = Math.min(burst, b[0] + (now - b[1]) * rate)
    b[1] = now
    if (b[0] < 1) return false
    b[0] -= 1
    return true
  }

  get maxFrame() {
    return this.road.mtu - (this.auth ? this.auth.overhead : 0)
  }

  get budgeted() {
    return Boolean(this.road.bitrate && this.node.announceCap)
  }

  // seconds to put one full frame on this road (0 if it is fast)
  get frameTime() {
    return this.road.bitrate ? (this.road.mtu * 8) / this.road.bitrate : 0
  }

  async send(packet) {
    const frame = packet.encode()
    let frames = [frame]
    if (frame.length > this.maxFrame) {
      const fid = randomBytes(FRAGMENT_ID_SIZE)
      frames = fragment(frame, this.maxFrame - FRAGMENT_OVERHEAD, fid)
      this._sent.set(hex(fid), [frames, monotonic() + FRAGMENT_CACHE_TIME])
      trim(this._sent, FRAGMENT_CACHE_SETS)
    }
    let total = 0
    for (const f of frames) total += await this.sendFrame(f)
    return total
  }

  async sendFrame(frame) {
    const wire = this.auth ? this.auth.wrap(frame) : frame
    await this.road.send(wire)
    return wire.length
  }

  async resend(n) {
    const entry = this._sent.get(hex(n.fid))
    if (!entry || monotonic() > entry[1]) return
    for (const i of new Set(n.missing)) if (i < entry[0].length) await this.sendFrame(entry[0][i])
  }

  async announce(packet) {
    if (!this.budgeted) {
      await this.send(packet)
      return
    }
    const k = hex(packet.dest)
    if (!this.queue.has(k) && this.queue.size >= ANNOUNCE_QUEUE) {
      let worst = null
      for (const [d, e] of this.queue) if (!worst || e.hops > worst[1].hops || (e.hops === worst[1].hops && e.at < worst[1].at)) worst = [d, e]
      if (worst[1].hops <= packet.hops) return
      this.queue.delete(worst[0])
    }
    this.queue.set(k, { hops: packet.hops, at: monotonic(), packet })
    this._pump()
  }

  _pump() {
    if (this._pumping || !this.queue.size) return
    this._pumping = true
    this.node._after(Math.max(0, this._readyAt - monotonic()), async () => {
      try {
        const now = monotonic()
        for (const [d, e] of this.queue) if (now - e.at > this.node.announceQueueAge) this.queue.delete(d)
        let best = null
        for (const [d, e] of this.queue) if (!best || e.hops < best[1].hops || (e.hops === best[1].hops && e.at < best[1].at)) best = [d, e]
        if (best) {
          this.queue.delete(best[0])
          const size = await this.send(best[1].packet)
          this._readyAt = monotonic() + (size * 8) / (this.road.bitrate * this.node.announceCap)
        }
      } finally {
        this._pumping = false
        this._pump()
      }
    })
  }
}

export class Node {
  constructor({ identity = null, transport = false, propagate = false, appData = null, maxHops = 16, rebroadcastDelay = 0.25, announceInterval = null, quantumSafeOnly = true, ratchets = null, retryAfter = 30, retryMax = 600, maxAttempts = 4, acceptLinks = true, linkAttempts = 3, linkIdle = 3600, nackAttempts = 3, store = null, maxLinks = 256, pathTtl = 7 * 86400, maxPeers = 10000, maxResource = R.MAX_RESOURCE, propagationNode = null, autoPropagate = true, ingress = null, announceCap = 0.02, announceQueueAge = 3600, rebroadcastMinInterval = 60, name = null, log = null } = {}) {
    this.identity = identity || Identity.generate()
    if (!this.identity.hasPrivate) throw new Error('node identity needs private keys')
    this.transport = transport || propagate
    this.propagate = propagate
    this.appData = appData
    this.maxHops = maxHops
    this.rebroadcastDelay = rebroadcastDelay
    this.announceInterval = announceInterval
    this.announceCap = announceCap
    this.announceQueueAge = announceQueueAge
    this.rebroadcastMinInterval = rebroadcastMinInterval
    // On by default: refuse peers whose keys a quantum attacker could break.
    // Pre-quantum peers need an explicit quantumSafeOnly: false.
    this.quantumSafeOnly = quantumSafeOnly
    if (quantumSafeOnly && !this.identity.quantumSafe) throw new Error('identity is not quantum-safe; use the pq or hybrid suite, or pass quantumSafeOnly: false to accept pre-quantum crypto')
    // where our ratchets live; when to rotate or discard them is the application's policy
    this.ratchets = ratchets || new MemoryRatchets(this.identity.kemAlg)
    this.retryAfter = retryAfter
    this.retryMax = retryMax
    this.maxAttempts = maxAttempts
    this.acceptLinks = acceptLinks
    this.linkAttempts = linkAttempts
    this.linkIdle = linkIdle
    this.nackAttempts = nackAttempts
    this.maxLinks = maxLinks
    this.pathTtl = pathTtl
    this.maxPeers = maxPeers
    this.maxResource = maxResource
    this.propagationNode = propagationNode
    this.autoPropagate = autoPropagate
    this.ingress = { ...INGRESS, ...(ingress || {}) }
    this.store = store || new MemoryStore()
    this.name = name || hex(this.identity.address).slice(0, 8)
    this.log = log || (() => {})

    // tables keyed by hex address / id
    this.identities = new Map([[hex(this.address), this.identity.public()]])
    this.announces = new Map() // addr -> [payload, Announce]
    this.paths = new Map()
    this.peerRatchets = new Map()
    this.propagationNodes = new Map()
    this.links = new Map() // link id -> LinkKeys, LRU order
    this._linkTo = new Map() // peer -> link id
    this._linkUsed = new Map()
    this._pendingLinks = new Map() // link id -> [PendingLink, deferred]
    this._accepts = new Map() // link id -> [peer, accept]
    this._needKeyset = new Map() // addr -> [lane, packet]
    this._waitingMessages = new Map() // sender -> [packet, lane]
    this._keysetAsked = new Map() // addr -> Set(lane)
    this._keysetRequestedAt = new Map()
    this._rebroadcastAt = new Map()
    this._rediscoverAt = new Map()
    this._outbox = new Map() // receipt tag -> outgoing
    this._deliveries = new Map() // message id -> [deferred]
    this._delivered = new Map() // message ids handed over
    this._nackTimers = new Map()
    this._batches = new Map()
    this._fetching = new Map()
    this._resOut = new Map()
    this._resIn = new Map()
    this._resDone = new Map()
    this._peers = new Map()
    this._waiters = new Map() // addr -> [deferred]
    this._seen = new Map()
    this._reassembler = new Reassembler()
    this._handlers = { message: [], announce: [], receipt: [], resource: [] }
    this._timers = new Set()
    this._announced = false
    this._sequence = 0 // our announce sequence: Unix ms, but never going backwards
    this._running = false
    this.lanes = []
  }

  get address() {
    return this.identity.address
  }

  toString() {
    return `<Node ${this.name} ${hex(this.address)}>`
  }

  // --- timers & tasks ---

  _after(seconds, fn) {
    const t = setTimeout(() => {
      this._timers.delete(t)
      this._spawn(fn())
    }, seconds * 1000)
    this._timers.add(t)
    return t
  }

  _cancel(t) {
    clearTimeout(t)
    this._timers.delete(t)
  }

  _sleep(seconds) {
    return new Promise((resolve) => this._after(seconds, resolve))
  }

  // resolves to the promise's value, or TIMEOUT
  _waitFor(p, seconds) {
    if (seconds == null) return p
    return new Promise((resolve) => {
      const t = this._after(seconds, () => resolve(TIMEOUT))
      p.then((v) => {
        this._cancel(t)
        resolve(v)
      })
    })
  }

  _spawn(p) {
    if (p && typeof p.then === 'function') p.catch((e) => this.log('task failed', e))
    return p
  }

  // --- lifecycle ---

  addRoad(road, auth = null) {
    const lane = new Lane(this, road, auth)
    road.onFrame = (frame) => this._onFrame(lane, frame)
    this.lanes.push(lane)
    if (this._running) this._spawn(road.start())
    return road
  }

  async start() {
    this._running = true
    for (const lane of this.lanes) await lane.road.start()
    if (this.announceInterval) this._announceLoop()
  }

  async stop() {
    this._running = false
    for (const t of this._timers) clearTimeout(t)
    this._timers.clear()
    for (const e of this._nackTimers.values()) clearTimeout(e[0])
    this._nackTimers.clear()
    for (const lane of this.lanes) await lane.road.stop()
  }

  _announceLoop() {
    if (!this._running) return
    this._spawn(this.announce())
    this._after(this.announceInterval, () => this._announceLoop())
  }

  // --- public API ---

  // cb(message); returns a function that removes the handler
  onMessage(cb) {
    return this._on('message', cb)
  }

  // cb(announce, path)
  onAnnounce(cb) {
    return this._on('announce', cb)
  }

  // cb(message, recipient address) when a recipient confirms it opened a message
  onReceipt(cb) {
    return this._on('receipt', cb)
  }

  // cb(resource) when a large transfer from a peer has arrived whole
  onResource(cb) {
    return this._on('resource', cb)
  }

  _on(kind, cb) {
    this._handlers[kind].push(cb)
    return () => {
      const i = this._handlers[kind].indexOf(cb)
      if (i >= 0) this._handlers[kind].splice(i, 1)
    }
  }

  _emit(kind, ...args) {
    for (const cb of this._handlers[kind]) {
      try {
        this._spawn(cb(...args))
      } catch (e) {
        this.log('handler failed', e)
      }
    }
  }

  known(address) {
    return this.identities.get(hex(address)) || null
  }

  // the current path to `dest`, or null (unknown, or expired: then it is forgotten)
  path(dest) {
    const k = hex(dest)
    const p = this.paths.get(k)
    if (p && monotonic() >= p.expires) {
      this.paths.delete(k)
      return null
    }
    return p || null
  }

  // the ratchet in the newest announce we accepted from `address`
  peerRatchet(address) {
    return this.peerRatchets.get(hex(address)) || null
  }

  _nextSequence() {
    this._sequence = Math.max(msg.nowMs(), this._sequence + 1)
    return this._sequence
  }

  // Signed announce with our current ratchet. full: include our keyset
  // (default: only the first time, and when answering a path request for us).
  async announce({ appData = null, full = null } = {}) {
    if (full == null) full = !this._announced
    this._announced = true
    const data = msg.makeAnnounce(this.identity, this.ratchets.current(), { appData: appData ?? this.appData, sequence: this._nextSequence(), full, services: this.propagate ? PR.SERVICE_PROPAGATION : 0 })
    const p = new Packet(ANNOUNCE, 0, this.address, null, data)
    this._markSeen(p.hash)
    await this._broadcast(p)
  }

  // a signed full announce to share out of band (see contact.js for a URI form)
  contactCard() {
    return msg.makeAnnounce(this.identity, this.ratchets.current(), { appData: this.appData, sequence: this._nextSequence(), services: this.propagate ? PR.SERVICE_PROPAGATION : 0 })
  }

  // take someone's contact card: their keyset and ratchet become known
  addContact(card) {
    const ann = msg.verifyAnnounce(card)
    const k = hex(ann.address)
    const known = this.identities.get(k)
    if (known && !equal(known.publicBytes, ann.identity.publicBytes)) throw new Error('a different keyset is already pinned to that address')
    if (this.quantumSafeOnly && !(ann.identity.quantumSafe && QUANTUM_SAFE_KEM.has(ann.ratchet.alg))) throw new Error('contact is not quantum-safe')
    const prev = this.announces.get(k)
    if (!prev || ann.sequence >= prev[1].sequence) {
      this.identities.set(k, ann.identity)
      this.announces.set(k, [card, ann])
      this.peerRatchets.set(k, ann.ratchet)
      this._heard(k)
    }
    return ann
  }

  // start using a new ratchet (the provider decides what happens to old ones)
  async rotateRatchet(announce = true) {
    const k = this.ratchets.rotate()
    if (announce) await this.announce()
    return k
  }

  // ask the mesh for `address`; resolves once its announce arrives (a new one if fresh)
  async requestPath(address, { timeout = 10, fresh = false } = {}) {
    const k = hex(address)
    if (!fresh && this.path(address) && this.identities.has(k)) return this.identities.get(k)
    const fut = deferred()
    if (!this._waiters.has(k)) this._waiters.set(k, [])
    this._waiters.get(k).push(fut)
    const p = new Packet(PATH_REQUEST, 0, address, null, randomBytes(REQUEST_TAG_SIZE))
    this._markSeen(p.hash)
    await this._broadcast(p)
    try {
      const r = await this._waitFor(fut, timeout)
      return r === TIMEOUT ? this.identities.get(k) || null : r
    } finally {
      const ws = this._waiters.get(k) || []
      const i = ws.indexOf(fut)
      if (i >= 0) ws.splice(i, 1)
      if (!ws.length) this._waiters.delete(k)
    }
  }

  // Seal a message for one or more recipients (Identities, addresses or hex)
  // and send it. With receipt (default) it is resent until each recipient
  // confirms; await node.delivered(message). propagate hands it to a
  // propagation node instead; with autoPropagate that also happens when direct
  // delivery gives up.
  async send(to, content = '', { title = '', fields = null, attachIdentity = false, timeout = 10, receipt = true, propagate = false } = {}) {
    const targets = Array.isArray(to) ? to : [to]
    if (targets.length === 1 && !propagate) {
      const addr = toAddress(targets[0])
      if (this._linkTo.has(hex(addr))) return this._sendOnLink(addr, { content, title, fields }, receipt)
    }
    const recipients = []
    for (const t of targets) recipients.push(await this._resolve(t, timeout, !propagate))
    const m = msg.signMessage(this.identity, recipients, { content, title, fields, attachIdentity, receiptSecret: receipt ? randomBytes(msg.RECEIPT_SECRET_SIZE) : null })
    for (const r of recipients) {
      // every (re)send is a fresh envelope around the same signed message
      const reseal = () => [msg.envelope(m.signed, this.peerRatchet(r.address)), DATA]
      if (propagate) {
        const dm = await this._deposit(m, r, receipt)
        if (receipt) this._addDeliveries(m.id, this._deliveries.get(hex(dm.id)) || [])
        continue
      }
      const fallback = async () => {
        // direct delivery gave up: leave it with a propagation node
        this.paths.delete(hex(r.address))
        if (!this.autoPropagate || !this._propagationNode(r.address)) return false
        const dm = await this._deposit(m, r, true)
        return Boolean(dm) && (await this.delivered(dm))
      }
      await this._dispatch(m, r.address, reseal, receipt, { fallback })
    }
    return m
  }

  // true once every recipient sent a receipt; false if any gave up (or timeout)
  async delivered(m, timeout = null) {
    const futs = this._deliveries.get(hex(m.id))
    if (!futs || !futs.length) throw new Error('not a message this node sent with receipts')
    const r = await this._waitFor(Promise.all(futs), timeout)
    return r !== TIMEOUT && r.every(Boolean)
  }

  _addDeliveries(id, futs) {
    const k = hex(id)
    if (!this._deliveries.has(k)) this._deliveries.set(k, [])
    this._deliveries.get(k).push(...futs)
    trim(this._deliveries, DELIVERY_RESULTS)
  }

  // the configured propagation node, or the nearest one we know a path to
  _propagationNode(exclude = null) {
    if (this.propagationNode) return toAddress(this.propagationNode)
    let best = null
    for (const k of this.propagationNodes.keys()) {
      const a = fromHex(k)
      if (exclude && equal(a, exclude)) continue
      const p = this.path(a)
      if (p && (!best || p.hops < best[1])) best = [a, p.hops]
    }
    return best ? best[0] : null
  }

  // hand `m` (sealed to r's ratchet) to a propagation node, over a link to it
  async _deposit(m, r, receipt) {
    const nodeAddr = this._propagationNode(r.address)
    if (!nodeAddr) throw new Error('no propagation node known')
    const keys = this.linkTo(nodeAddr) || (await this.openLink(nodeAddr))
    const lid = keys.linkId
    const secret = randomBytes(msg.RECEIPT_SECRET_SIZE)
    const dm = new msg.Message({ sender: this.address, recipients: [r.address], timestamp: m.timestamp, id: concat(m.id, new Uint8Array([0x64])), receiptSecret: secret })
    const reseal = () => {
      const live = this.linkTo(nodeAddr)
      if (!live || !equal(live.linkId, lid)) throw new LookupError('link closed')
      const body = new Map([[PR.P_DEPOSIT, [r.address, DATA, msg.envelope(m.signed, this.peerRatchet(r.address))]]])
      if (receipt) body.set(msg.M_RECEIPT, secret)
      return [L.seal(live, encode(body)), LINK_DATA]
    }
    await this._dispatch(dm, nodeAddr, reseal, receipt, { secret })
    return dm
  }

  // a recipient we may send to: known identity, quantum-safe, with a ratchet
  async _resolve(t, timeout, needPath = true) {
    if (t instanceof Identity) {
      if (!this.identities.has(hex(t.address))) this.identities.set(hex(t.address), t.public())
    }
    const addr = toAddress(t)
    const k = hex(addr)
    // no route yet: ask the mesh; without one we still flood to neighbours
    if (needPath && !this.path(addr)) await this.requestPath(addr, { timeout })
    const ident = this.identities.get(k)
    if (!ident) throw new LookupError(`no identity known for ${k}`)
    if (this.quantumSafeOnly && !ident.quantumSafe) throw new PermissionError(`${k} is not quantum-safe; refusing to send`)
    if (!this.peerRatchet(addr) && needPath) await this.requestPath(addr, { timeout, fresh: true })
    const rk = this.peerRatchet(addr)
    if (!rk) throw new LookupError(`no ratchet for ${k}: it must announce first`)
    if (this.quantumSafeOnly && !QUANTUM_SAFE_KEM.has(rk.alg)) throw new PermissionError(`${k} announced a ratchet that is not quantum-safe`)
    return ident
  }

  async _dispatch(m, addr, reseal, receipt, { attempts = null, fallback = null, secret = null } = {}) {
    const [payload, kind] = reseal()
    await this._sendData(addr, payload, kind)
    if (!receipt) return
    const o = { message: m, address: addr, future: deferred(), reseal, attempts: attempts || this.maxAttempts, fallback, secret: secret || m.receiptSecret }
    this._outbox.set(hex(msg.receiptTag(o.secret, addr)), o)
    this._addDeliveries(m.id, [o.future])
    this._spawn(this._retry(o))
  }

  async _retry(o) {
    const tag = hex(msg.receiptTag(o.secret, o.address))
    let wait = this.retryAfter
    try {
      for (let attempt = 1; attempt <= o.attempts; attempt++) {
        if ((await this._waitFor(o.future, wait)) !== TIMEOUT) return
        if (attempt === o.attempts) break
        this.log(`${this}: resending ${hex(o.message.id).slice(0, 8)} to ${hex(o.address)}`)
        // twice unanswered: the path may be dead; ask the mesh again meanwhile
        if (attempt === 2) this._rediscover(o.address)
        let payload, kind
        try {
          ;[payload, kind] = o.reseal()
        } catch (e) {
          if (e instanceof LookupError) break
          throw e
        }
        await this._sendData(o.address, payload, kind)
        wait = Math.min(wait * 2, this.retryMax)
      }
      this._outbox.delete(tag)
      if (!o.fallback) this.paths.delete(hex(o.address)) // find a new one next time
      let result = false
      if (o.fallback) {
        try {
          result = await o.fallback()
        } catch (e) {
          this.log('fallback failed', e)
        }
      }
      o.future.resolve(result)
    } finally {
      this._outbox.delete(tag)
    }
  }

  // --- links ---

  linkTo(address) {
    this._expireLinks()
    const lid = this._linkTo.get(hex(address))
    return lid ? this.links.get(lid) || null : null
  }

  _expireLinks() {
    const cutoff = monotonic() - this.linkIdle
    for (const lid of [...this.links.keys()]) {
      if ((this._linkUsed.get(lid) ?? 0) < cutoff) this._dropLink(lid)
    }
  }

  // Set up a session with a peer (one PQ handshake); after it, send() to that
  // peer costs tens of bytes per message. Either side's send() uses it.
  async openLink(to, timeout = 30) {
    const peer = await this._resolve(to, timeout)
    const deadline = monotonic() + timeout
    let wait = this.retryAfter
    while (true) {
      // a fresh request per attempt (each has its own link id and packet hash)
      const pending = L.makeRequest(this.identity, peer, this.peerRatchet(peer.address))
      const fut = deferred()
      const lid = hex(pending.linkId)
      this._pendingLinks.set(lid, [pending, fut])
      await this._sendData(peer.address, pending.request, LINK_REQUEST)
      const left = deadline - monotonic()
      const r = await this._waitFor(fut, Math.max(0, Math.min(wait, left)))
      if (r !== TIMEOUT) return r
      this._pendingLinks.delete(lid)
      if (monotonic() >= deadline) throw new TimeoutError(`no link accept from ${hex(peer.address)}`)
      wait = Math.min(wait * 2, this.retryMax)
    }
  }

  async closeLink(address) {
    const keys = this.linkTo(address)
    if (!keys) return
    await this._sendData(address, L.seal(keys, L.messageBody({ close: true })), LINK_DATA)
    this._dropLink(hex(keys.linkId))
  }

  _dropLink(lid) {
    this._linkUsed.delete(lid)
    const keys = this.links.get(lid)
    this.links.delete(lid)
    if (keys && this._linkTo.get(hex(keys.peer)) === lid) this._linkTo.delete(hex(keys.peer))
  }

  _addLink(keys) {
    const lid = hex(keys.linkId)
    const peer = hex(keys.peer)
    const old = this._linkTo.get(peer)
    if (old && old !== lid) this.links.delete(old)
    touch(this.links, lid, keys)
    this._linkTo.set(peer, lid)
    this._linkUsed.set(lid, monotonic())
    while (this.links.size > this.maxLinks) this._dropLink(this.links.keys().next().value) // least recently used
  }

  _usedLink(lid) {
    const keys = this.links.get(lid)
    if (!keys) return
    touch(this.links, lid, keys)
    this._linkUsed.set(lid, monotonic())
  }

  async _sendOnLink(addr, { content, title, fields }, receipt) {
    const keys = this.linkTo(addr)
    const secret = receipt ? randomBytes(msg.RECEIPT_SECRET_SIZE) : null
    const body = L.messageBody({ content, title, fields, receiptSecret: secret })
    const { message: m } = L.readMessage(keys, addr, body)
    m.sender = this.address
    m.recipients = [addr]
    const lid = hex(keys.linkId)
    const reseal = () => {
      const live = this.linkTo(addr)
      if (!live || hex(live.linkId) !== lid) throw new LookupError('link closed')
      this._usedLink(lid)
      return [L.seal(live, body), LINK_DATA] // fresh IV each time
    }
    const fallback = async () => {
      // the peer did not answer on the link: it has probably lost it
      this.log(`${this}: link to ${hex(addr)} seems dead, sending sealed`)
      this._dropLink(lid)
      let sealed
      try {
        sealed = await this.send(addr, content, { title, fields })
      } catch (e) {
        if (e instanceof LookupError || e instanceof PermissionError) return false
        throw e
      }
      return this.delivered(sealed)
    }
    await this._dispatch(m, addr, reseal, receipt, { attempts: this.linkAttempts, fallback })
    return m
  }

  // --- sending ---

  async _broadcast(p, exclude = null) {
    for (const lane of this.lanes) {
      if (lane === exclude || !lane.road.online) continue
      if (p.type === ANNOUNCE) await lane.announce(p)
      else await lane.send(p)
    }
  }

  async _sendAll(p) {
    for (const lane of this.lanes) if (lane.road.online) await lane.send(p)
  }

  async _sendData(dest, payload, type = DATA) {
    const path = this.path(dest)
    const p = new Packet(type, 0, dest, path ? path.via : null, payload)
    this._markSeen(p.hash)
    if (path) await path.lane.send(p)
    else await this._broadcast(p)
  }

  async _delayed(fn) {
    if (this.rebroadcastDelay) await this._sleep(Math.random() * this.rebroadcastDelay)
    await fn()
  }

  // --- receiving ---

  // record a packet hash; true if it was new
  _markSeen(h) {
    const k = hex(h)
    if (this._seen.has(k)) return false
    this._seen.set(k, true)
    trim(this._seen, SEEN_CACHE)
    return true
  }

  _onFrame(lane, frame) {
    let item
    try {
      if (lane.auth) frame = lane.auth.unwrap(frame)
      item = decode(frame)
      if (item instanceof Nack) {
        this._spawn(lane.resend(item))
        return
      }
      if (item instanceof Fragment) {
        const whole = this._reassembler.add(lane.id, item)
        this._watchFragments(lane, item.fid, whole !== null)
        if (whole === null) return
        item = decode(whole)
        if (!(item instanceof Packet)) throw new PacketError('nested fragment')
      }
    } catch (e) {
      if (!(e instanceof PacketError)) throw e
      this.log(`${this}: dropped frame on ${lane.road}: ${e.message}`)
      return
    }
    if (!this._markSeen(item.hash)) {
      if (item.type === ANNOUNCE) this._seenAnnounceAgain(lane, item)
      return
    }
    if (item.type === ANNOUNCE) this._handleAnnounce(lane, item)
    else if (ROUTED.has(item.type)) this._handleData(lane, item)
    else if (item.type === PATH_REQUEST) this._handlePathRequest(lane, item)
    else if (item.type === KEYSET_REQUEST) this._handleKeysetRequest(lane, item)
    else if (item.type === KEYSET) this._handleKeyset(lane, item)
  }

  // cheap checks before the (costly) signature verification
  _precheckAnnounce(p) {
    try {
      const sm = cose.decode(p.payload)
      if (!equal(signerOf(sm), p.dest)) return false
      const body = cborDecode(sm.content)
      const pub = body.get(msg.A_IDENTITY)
      let known = this.identities.get(hex(p.dest))
      if (pub !== undefined) {
        if (!equal(addressOf(pub), p.dest) || (known && !equal(known.publicBytes, pub))) return false // pinned to another keyset
        known = Identity.fromBytes(pub)
      }
      if (this.quantumSafeOnly) {
        if (known && !known.quantumSafe) return false
        const r = body.get(msg.A_RATCHET)
        if (!(r instanceof Map) || !QUANTUM_SAFE_KEM.has(r.get(3))) return false
      }
      return true
    } catch {
      return false
    }
  }

  // a gap of about two frame-times means fragments went missing
  _nackDelay(lane) {
    return 2 * lane.frameTime + NACK_BASE_DELAY
  }

  _watchFragments(lane, fid, complete) {
    const key = `${lane.id}/${hex(fid)}`
    const entry = this._nackTimers.get(key)
    if (entry) clearTimeout(entry[0])
    this._nackTimers.delete(key)
    if (complete || !this._running) return
    const delay = this._nackDelay(lane)
    const timer = setTimeout(() => this._stalled(lane, fid), delay * 1000)
    this._nackTimers.set(key, [timer, entry ? entry[1] : 0, delay])
  }

  _stalled(lane, fid) {
    const key = `${lane.id}/${hex(fid)}`
    const entry = this._nackTimers.get(key)
    this._nackTimers.delete(key)
    const missing = this._reassembler.missing(lane.id, fid)
    if (!entry || !missing || !missing.length || entry[1] >= this.nackAttempts || !this._running) return
    this._spawn(lane.sendFrame(nack(fid, missing)))
    const delay = entry[2] * 2 + lane.frameTime * missing.length
    const timer = setTimeout(() => this._stalled(lane, fid), delay * 1000)
    this._nackTimers.set(key, [timer, entry[1] + 1, delay])
  }

  _handleAnnounce(lane, p) {
    if (equal(p.dest, this.address) || !this._precheckAnnounce(p)) return
    if (!lane.allow('announce')) {
      this.log(`${this}: announce rate limit on ${lane.road}`)
      return
    }
    const k = hex(p.dest)
    let ann
    try {
      ann = msg.verifyAnnounce(p.payload, p.dest, (a) => this.identities.get(hex(a)) || null)
    } catch (e) {
      if (e instanceof msg.KeysetNeeded) {
        // a short announce from someone we have not met: fetch the keyset, then look again
        if (this._needKeyset.has(k) || this._needKeyset.size < KEYSET_WAITS) {
          this._needKeyset.set(k, [lane, p])
          this._requestKeyset(p.dest)
        }
      } else {
        this.log(`${this}: invalid announce: ${e.message}`)
      }
      return
    }
    // an identity's sequence only goes up: a replayed announce must not bring
    // back an old path or ratchet (the peer is compared with itself, never our clock)
    const prev = this.announces.get(k)
    if (prev && ann.sequence < prev[1].sequence) return
    this.identities.set(k, ann.identity)
    this.announces.set(k, [p.payload, ann])
    this.peerRatchets.set(k, ann.ratchet)
    this._heard(k)
    if (ann.services & PR.SERVICE_PROPAGATION) this.propagationNodes.set(k, true)
    else this.propagationNodes.delete(k)
    const path = this._updatePath(lane, p, ann.sequence)
    this._emit('announce', ann, path)
    this._rebroadcast(p)
  }

  // note activity from a peer; forget the least recent ones beyond maxPeers
  _heard(k) {
    touch(this._peers, k, true)
    while (this._peers.size > this.maxPeers) {
      const old = this._peers.keys().next().value
      this._peers.delete(old)
      if (old === hex(this.address)) continue
      for (const t of [this.identities, this.announces, this.paths, this.peerRatchets]) t.delete(old)
    }
  }

  // keep a per-address timer table bounded: drop entries whose time has passed
  _prune(table) {
    if (table.size <= TIMER_TABLE) return
    const now = monotonic()
    for (const [k, t] of table) if (t <= now) table.delete(k)
    trim(table, TIMER_TABLE)
  }

  // a copy of an announce we already accepted: take it if it came over fewer
  // hops, or if we asked for this path
  _seenAnnounceAgain(lane, p) {
    const k = hex(p.dest)
    const cached = this.announces.get(k)
    if (!cached || !equal(cached[0], p.payload)) return
    const path = this.path(p.dest)
    if (!path || this._waiters.has(k) || p.hops + 1 < path.hops) this._updatePath(lane, p, cached[1].sequence)
  }

  _updatePath(lane, p, sequence) {
    const k = hex(p.dest)
    const path = new Path(lane, p.via, p.hops + 1, sequence, monotonic() + this.pathTtl)
    this.paths.set(k, path)
    for (const fut of this._waiters.get(k) || []) fut.resolve(this.identities.get(k) || null)
    this._waiters.delete(k)
    this._spawn(
      Promise.resolve(this.store.take(p.dest)).then(async (held) => {
        for (const [kind, payload] of held || []) await path.lane.send(new Packet(kind, 0, p.dest, path.via, payload))
      })
    )
    return path
  }

  // transport nodes pass announces on, at most once per interval per identity
  _rebroadcast(p) {
    if (!this.transport || p.hops + 1 >= this.maxHops) return
    const k = hex(p.dest)
    const now = monotonic()
    if (now < (this._rebroadcastAt.get(k) ?? 0)) return
    this._rebroadcastAt.set(k, now + this.rebroadcastMinInterval)
    this._prune(this._rebroadcastAt)
    const fwd = new Packet(ANNOUNCE, p.hops + 1, p.dest, this.address, p.payload)
    this._spawn(this._delayed(() => this._broadcast(fwd)))
  }

  _requestKeyset(address) {
    const k = hex(address)
    const now = monotonic()
    if (now < (this._keysetRequestedAt.get(k) ?? 0)) return
    this._keysetRequestedAt.set(k, now + this.retryAfter)
    this._prune(this._keysetRequestedAt)
    const p = new Packet(KEYSET_REQUEST, 0, address, null, randomBytes(REQUEST_TAG_SIZE))
    this._markSeen(p.hash)
    this._spawn(this._sendAll(p))
  }

  _handleKeysetRequest(lane, p) {
    if (!lane.allow('request')) return
    const k = hex(p.dest)
    const ident = this.identities.get(k)
    if (ident) {
      // we are it, or we know it: the keyset proves itself by hashing to the address
      const resp = new Packet(KEYSET, 0, p.dest, null, ident.publicBytes)
      this._spawn(this._delayed(() => lane.send(resp)))
      return
    }
    if (this.transport && p.hops + 1 < this.maxHops) {
      if (!this._keysetAsked.has(k) && this._keysetAsked.size >= KEYSET_WAITS) return
      if (!this._keysetAsked.has(k)) this._keysetAsked.set(k, new Set())
      this._keysetAsked.get(k).add(lane)
      const fwd = new Packet(KEYSET_REQUEST, p.hops + 1, p.dest, null, p.payload)
      this._spawn(this._delayed(() => this._sendAll(fwd)))
    }
  }

  _handleKeyset(lane, p) {
    const k = hex(p.dest)
    const asked = this._keysetAsked.get(k) || new Set()
    const waiting = this._needKeyset.get(k)
    const messages = this._waitingMessages.get(k) || []
    this._keysetAsked.delete(k)
    this._needKeyset.delete(k)
    this._waitingMessages.delete(k)
    if (!asked.size && !waiting && !messages.length) return // nobody here asked for it
    if (!equal(addressOf(p.payload), p.dest)) return
    const known = this.identities.get(k)
    if (known && !equal(known.publicBytes, p.payload)) return
    let ident
    try {
      ident = Identity.fromBytes(p.payload)
    } catch {
      return
    }
    if (this.quantumSafeOnly && !ident.quantumSafe) return
    if (!this.identities.has(k)) this.identities.set(k, ident)
    for (const other of asked) if (other !== lane) this._spawn(other.send(p))
    if (waiting) this._handleAnnounce(...waiting)
    for (const m of messages) {
      if (m.type === LINK_REQUEST) this._handleLinkRequest(m)
      else this._deliver(m)
    }
  }

  // DATA and friends: take it if it is ours, else forward like any payload
  _handleData(lane, p) {
    if (equal(p.dest, this.address)) {
      if (p.type === DATA) this._deliver(p, lane)
      else if (p.type === RECEIPT) this._handleReceipt(p)
      else if (p.type === LINK_REQUEST) this._handleLinkRequest(p, lane)
      else if (p.type === LINK_ACCEPT) this._handleLinkAccept(p)
      else if (p.type === LINK_DATA) this._handleLinkData(p)
      return
    }
    if (!this.transport) return
    if (p.via && equal(p.via, this.address)) this._forward(p)
    else if (p.via === null && this.propagate) {
      const path = this.path(p.dest)
      if (path && path.lane === lane && path.via === null) return // a neighbour on this road already heard it
      this._forward(p)
    }
  }

  _forward(p) {
    const path = this.path(p.dest)
    if (!path) {
      if (this.propagate) this._spawn(Promise.resolve(this.store.put(p.dest, p.type, p.payload)))
      return
    }
    if (p.hops + 1 >= this.maxHops) return
    this._spawn(path.lane.send(new Packet(p.type, p.hops + 1, p.dest, path.via, p.payload)))
  }

  _handlePathRequest(lane, p) {
    if (!lane.allow('request')) return
    if (equal(p.dest, this.address)) {
      // whoever asks may not know us yet: include the keyset
      this._spawn(this._delayed(() => this.announce({ full: true })))
      return
    }
    if (!this.transport) return
    const cached = this.announces.get(hex(p.dest))
    const path = this.path(p.dest)
    if (cached && path) {
      const resp = new Packet(ANNOUNCE, path.hops, p.dest, this.address, cached[0])
      this._spawn(this._delayed(() => lane.announce(resp)))
    } else if (p.hops + 1 < this.maxHops) {
      const fwd = new Packet(PATH_REQUEST, p.hops + 1, p.dest, null, p.payload)
      this._spawn(this._delayed(() => this._broadcast(fwd)))
    }
  }

  _deliver(p, lane = null) {
    if (lane && !lane.allow('message')) return
    let m
    try {
      m = msg.unseal(this.identity, p.payload, (a) => this.identities.get(hex(a)) || null, this.ratchets)
    } catch (e) {
      // e.g. we restarted and forgot them: fetch their keyset, then try again
      if (e instanceof msg.SenderUnknown) this._waitForKeyset(e.address, p)
      else this.log(`${this}: could not open message: ${e.message}`)
      return
    }
    const sk = hex(m.sender)
    const sender = this.identities.get(sk) || msg.attachedIdentity(m.signed)
    if (this.quantumSafeOnly && !(sender && sender.quantumSafe)) {
      this.log(`${this}: dropped message from non-quantum-safe ${sk}`)
      return
    }
    if (!this.identities.has(sk)) this.identities.set(sk, sender)
    // a one-to-one sealed message means the peer has no link to us any more
    if (m.recipients.length === 1 && equal(m.recipients[0], this.address) && this._linkTo.has(sk)) this._dropLink(this._linkTo.get(sk))
    this._acceptMessage(m)
  }

  // receipt (always), then hand to the application once per message id
  _acceptMessage(m) {
    if (m.receiptSecret) {
      // always answer, even for a repeat: our last receipt may have been lost
      const tag = msg.receiptTag(m.receiptSecret, this.address)
      this._spawn(this._sendData(m.sender, concat(tag, randomBytes(RECEIPT_NONCE_SIZE)), RECEIPT))
    }
    const id = hex(m.id)
    if (this._delivered.has(id)) {
      // a repeat means our receipt did not arrive: the way back may be dead
      this._rediscover(m.sender)
      return
    }
    this._delivered.set(id, true)
    trim(this._delivered, DELIVERED_CACHE)
    this._emit('message', m)
  }

  // hold a message or link request from an unknown sender; fetch its keyset
  _waitForKeyset(address, p) {
    const k = hex(address)
    if (!this._waitingMessages.has(k)) this._waitingMessages.set(k, [])
    const q = this._waitingMessages.get(k)
    if (q.length < WAITING_PER_SENDER && this._waitingMessages.size <= WAITING_SENDERS) q.push(p)
    this._requestKeyset(address)
  }

  // ask for a fresh path to `address`, at most once per retryAfter
  _rediscover(address) {
    const k = hex(address)
    const now = monotonic()
    if (now < (this._rediscoverAt.get(k) ?? 0)) return
    this._rediscoverAt.set(k, now + this.retryAfter)
    this._prune(this._rediscoverAt)
    this._spawn(this.requestPath(address, { timeout: this.retryAfter, fresh: true }))
  }

  // --- propagation nodes ---

  // collect what a propagation node holds for us (over a link); returns how
  // many items came; they are handled as if they had just arrived
  async fetch({ timeout = 30, node = null } = {}) {
    node = node ? toAddress(node) : this._propagationNode()
    if (!node) throw new Error('no propagation node known')
    const keys = this.linkTo(node) || (await this.openLink(node, timeout))
    const deadline = monotonic() + timeout
    const fut = deferred()
    const k = hex(node)
    this._fetching.set(k, [new Map(), fut])
    try {
      while (true) {
        await this._sendData(node, L.seal(keys, encode(new Map([[PR.P_FETCH, true]]))), LINK_DATA)
        const left = deadline - monotonic()
        if (left <= 0) throw new TimeoutError('propagation node did not answer')
        const r = await this._waitFor(fut, Math.min(this.retryAfter, left))
        if (r !== TIMEOUT) return r // else ask again: the node resends the same batch
      }
    } finally {
      this._fetching.delete(k)
    }
  }

  async _handlePropagation(keys, body) {
    const peer = hex(keys.peer)
    const send = (f, v) => this._resourceSend(keys, f, v)
    if (body.has(PR.P_DEPOSIT) && this.propagate) {
      const item = body.get(PR.P_DEPOSIT)
      if (!Array.isArray(item) || item.length !== 3) return
      const [dest, kind, payload] = item
      if ((kind !== DATA && kind !== RECEIPT) || !isBytes(payload) || !isBytes(dest)) return
      if (await this.store.put(dest, kind, payload)) {
        const secret = body.get(msg.M_RECEIPT)
        if (isBytes(secret) && secret.length === msg.RECEIPT_SECRET_SIZE) {
          const tag = msg.receiptTag(secret, this.address)
          this._spawn(this._sendData(keys.peer, concat(tag, randomBytes(RECEIPT_NONCE_SIZE)), RECEIPT))
        }
      }
    } else if (body.has(PR.P_FETCH) && this.propagate) {
      // the link authenticated the peer: hand over what we hold for it
      let batch = this._batches.get(peer)
      if (!batch) {
        batch = ((await this.store.take(keys.peer)) || []).slice(0, PR.BATCH)
        this._batches.set(peer, batch)
      }
      batch.forEach(([kind, payload], i) => send(PR.P_ITEM, [i, kind, payload]))
      send(PR.P_END, batch.length)
    } else if (body.has(PR.P_ACK)) {
      const batch = this._batches.get(peer)
      if (batch && body.get(PR.P_ACK) === batch.length) this._batches.delete(peer)
    } else if (body.has(PR.P_ITEM)) {
      const entry = this._fetching.get(peer)
      const item = body.get(PR.P_ITEM)
      if (entry && Array.isArray(item) && item.length === 3) entry[0].set(item[0], [item[1], item[2]])
    } else if (body.has(PR.P_END)) {
      const entry = this._fetching.get(peer)
      const n = body.get(PR.P_END)
      if (!entry || entry[1].done || !Number.isInteger(n)) return
      const [items, fut] = entry
      for (let i = 0; i < n; i++) if (!items.has(i)) return // lost: fetch() asks again
      send(PR.P_ACK, n)
      for (let i = 0; i < n; i++) {
        const [kind, payload] = items.get(i)
        const p = new Packet(kind, 0, this.address, null, payload)
        if (kind === DATA) this._deliver(p)
        else if (kind === RECEIPT) this._handleReceipt(p)
      }
      fut.resolve(n)
    }
  }

  // --- resources ---

  // Send `data` (any size up to the peer's limit) over a link, opening one if
  // needed. True once the peer confirms it has all of it, intact.
  async sendResource(to, data, { meta = null, timeout = 600 } = {}) {
    const addr = toAddress(to)
    const keys = this.linkTo(addr) || (await this.openLink(to, timeout))
    const out = R.Outgoing.of(addr, data, meta)
    const fut = deferred()
    const rid = hex(out.id)
    this._resOut.set(rid, [out, fut])
    const deadline = monotonic() + timeout
    try {
      let quiet = this.retryAfter // silence before we advertise again (backs off)
      while (true) {
        // (re)advertise when the receiver has not been heard from for a while
        if (monotonic() - out.active >= quiet) {
          const live = this.linkTo(addr)
          if (!live || !equal(live.linkId, keys.linkId)) return false
          await this._sendData(addr, L.seal(live, R.encode(R.R_ADVERTISE, out.advertisement())), LINK_DATA)
          if (out.active !== -Infinity) quiet = Math.min(quiet * 2, this.retryMax)
          out.active = monotonic()
        }
        const left = deadline - monotonic()
        if (left <= 0) return false
        const r = await this._waitFor(fut, Math.min(this.retryAfter, left))
        if (r !== TIMEOUT) return r
      }
    } finally {
      this._resOut.delete(rid)
    }
  }

  _resourceSend(keys, fieldId, value) {
    this._spawn(this._sendData(keys.peer, L.seal(keys, R.encode(fieldId, value)), LINK_DATA))
  }

  _handleResource(keys, body) {
    const peer = hex(keys.peer)
    if (body.has(R.R_ADVERTISE)) {
      const ad = body.get(R.R_ADVERTISE)
      const rid = ad instanceof Map ? ad.get(1) : null
      if (!isBytes(rid)) return
      const k = `${peer}/${hex(rid)}`
      if (this._resDone.has(k)) {
        this._resourceSend(keys, R.R_DONE, rid) // our done was lost
        return
      }
      if (!this._resIn.has(k)) {
        let inc
        try {
          inc = R.Incoming.fromAdvertisement(keys.peer, ad, this.maxResource)
        } catch (e) {
          this.log(`${this}: refused resource: ${e.message}`)
          return
        }
        this._resIn.set(k, { inc, timer: null, stalls: 0, asked: [] })
      }
      this._resourceAsk(keys, rid)
    } else if (body.has(R.R_REQUEST)) {
      const [rid, want] = body.get(R.R_REQUEST)
      const entry = isBytes(rid) ? this._resOut.get(hex(rid)) : null
      if (!entry || !equal(entry[0].peer, keys.peer) || !Array.isArray(want)) return
      const out = entry[0]
      out.active = monotonic()
      for (const i of [...new Set(want)].slice(0, 2 * R.WINDOW)) {
        if (Number.isInteger(i) && i >= 0 && i < out.parts.length) this._resourceSend(keys, R.R_PART, [rid, i, out.parts[i]])
      }
    } else if (body.has(R.R_PART)) {
      const [rid, index, data] = body.get(R.R_PART)
      if (!isBytes(rid)) return
      const entry = this._resIn.get(`${peer}/${hex(rid)}`)
      if (!entry) return
      entry.inc.add(index, data)
      entry.stalls = 0 // progress: reset the stall count
      if (entry.inc.complete) this._resourceFinish(keys, entry)
      else if (entry.asked.every((i) => entry.inc.parts.has(i))) this._resourceAsk(keys, rid) // window in: next
    } else if (body.has(R.R_DONE)) {
      const rid = body.get(R.R_DONE)
      const entry = isBytes(rid) ? this._resOut.get(hex(rid)) : null
      if (entry && equal(entry[0].peer, keys.peer)) entry[1].resolve(true)
    }
  }

  _resourceAsk(keys, rid) {
    const entry = this._resIn.get(`${hex(keys.peer)}/${hex(rid)}`)
    if (!entry) return
    const want = entry.inc.missing(R.WINDOW)
    entry.asked = want
    this._resourceSend(keys, R.R_REQUEST, [rid, want])
    if (entry.timer) this._cancel(entry.timer)
    const path = this.path(keys.peer)
    const delay = Math.max(0.3, 2 * R.WINDOW * (path ? path.lane.frameTime : 0))
    entry.timer = this._after(delay, () => this._resourceStalled(keys, rid))
  }

  _resourceStalled(keys, rid) {
    const k = `${hex(keys.peer)}/${hex(rid)}`
    const entry = this._resIn.get(k)
    if (!entry) return
    if (++entry.stalls > RESOURCE_STALLS) {
      this.log(`${this}: giving up on resource ${hex(rid)}`)
      this._resIn.delete(k)
      return
    }
    this._resourceAsk(keys, rid)
  }

  _resourceFinish(keys, entry) {
    const inc = entry.inc
    if (entry.timer) this._cancel(entry.timer)
    const k = `${hex(keys.peer)}/${hex(inc.id)}`
    this._resIn.delete(k)
    let data
    try {
      data = inc.assemble()
    } catch (e) {
      this.log(`${this}: resource failed its hash: ${e.message}`)
      return
    }
    this._resDone.set(k, true)
    trim(this._resDone, DELIVERED_CACHE)
    this._resourceSend(keys, R.R_DONE, inc.id)
    this._emit('resource', new R.Resource(keys.peer, inc.id, data, inc.meta))
  }

  _handleReceipt(p) {
    const tag = hex(p.payload.slice(0, msg.RECEIPT_TAG_SIZE))
    const o = this._outbox.get(tag)
    this._outbox.delete(tag)
    if (!o || o.future.done) return
    o.future.resolve(true)
    this._emit('receipt', o.message, o.address)
  }

  _handleLinkRequest(p, lane = null) {
    if (!this.acceptLinks) return
    const lid = hex(L.linkId(p.payload))
    if (this._accepts.has(lid)) {
      // a repeat: our accept may have been lost
      const [peer, accept] = this._accepts.get(lid)
      this._spawn(this._sendData(peer, accept, LINK_ACCEPT))
      return
    }
    if (lane && !lane.allow('link')) return
    let r
    try {
      r = L.acceptRequest(this.identity, p.payload, (a) => this.identities.get(hex(a)) || null, this.ratchets, this.quantumSafeOnly)
    } catch (e) {
      if (e instanceof msg.SenderUnknown) this._waitForKeyset(e.address, p)
      else this.log(`${this}: bad link request: ${e.message}`)
      return
    }
    const { sender: peer, accept, keys } = r
    if (this.quantumSafeOnly && !peer.quantumSafe) return
    const pk = hex(peer.address)
    if (!this.identities.has(pk)) this.identities.set(pk, peer)
    this._addLink(keys)
    this._accepts.set(lid, [peer.address, accept])
    trim(this._accepts, ACCEPT_CACHE)
    this._spawn(this._sendData(peer.address, accept, LINK_ACCEPT))
  }

  _handleLinkAccept(p) {
    const lid = hex(p.payload.slice(0, L.LINK_ID_SIZE))
    const entry = this._pendingLinks.get(lid)
    this._pendingLinks.delete(lid)
    if (!entry) return
    const [pending, fut] = entry
    let keys
    try {
      keys = L.finish(pending, p.payload)
    } catch (e) {
      this.log(`${this}: bad link accept: ${e.message}`)
      return
    }
    this._addLink(keys)
    fut.resolve(keys)
  }

  _handleLinkData(p) {
    this._expireLinks()
    const lid = hex(p.payload.slice(0, L.LINK_ID_SIZE))
    const keys = this.links.get(lid)
    if (!keys) return
    let m, close
    try {
      const plain = L.unseal(keys, p.payload)
      const body = cborDecode(plain)
      if (body instanceof Map && [R.R_ADVERTISE, R.R_REQUEST, R.R_PART, R.R_DONE].some((f) => body.has(f))) {
        this._usedLink(lid)
        this._handleResource(keys, body)
        return
      }
      if (body instanceof Map && [...PR.FIELDS].some((f) => body.has(f))) {
        this._usedLink(lid)
        this._spawn(this._handlePropagation(keys, body))
        return
      }
      ;({ message: m, close } = L.readMessage(keys, this.address, plain))
    } catch (e) {
      this.log(`${this}: bad link message: ${e.message}`)
      return
    }
    if (close) {
      this._dropLink(lid)
      return
    }
    this._usedLink(lid)
    this._acceptMessage(m)
  }
}

export class LookupError extends Error {
  constructor(message) {
    super(message)
    this.name = 'LookupError'
  }
}

export class PermissionError extends Error {
  constructor(message) {
    super(message)
    this.name = 'PermissionError'
  }
}

export class TimeoutError extends Error {
  constructor(message) {
    super(message)
    this.name = 'TimeoutError'
  }
}
