// cosechat in the browser: the happy path. The page joins a room on a
// broadcast WebSocket worker (https://github.com/konsumer/signal-worker),
// where every frame reaches everyone in the room, announces itself, and
// chats with whoever else is there, with delivery receipts.

import { Identity, Key, MemoryRatchets, Node } from 'cosechat/index.js'
import { WebSocketClientRoad } from 'cosechat/roads/websocket.js'
import { fromHex, toHex } from 'cosechat/bytes.js'
import { decode, encode } from 'cosechat/cbor.js'
import { KeyStore } from './keystore.js'

const ROOM = 'wss://signal.konsumer.workers.dev/ws/cosechat'
const REANNOUNCE = 30 * 60 // seconds; paths last a week, peers can also find you by address
const RATCHETS_KEPT = 8

const $ = (id) => document.getElementById(id)
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])

const state = {
  identity: null,
  node: null,
  connected: false,
  peers: new Map(), // hex address -> { address, name, seen, unread }
  chats: new Map(), // hex address -> [{ dir, text, time, status }]
  selected: null
}

function log(...args) {
  const el = $('log')
  el.textContent += `${new Date().toLocaleTimeString()} ${args.map((a) => (a instanceof Error ? a.message : String(a))).join(' ')}\n`
  el.scrollTop = el.scrollHeight
}

function toast(text, kind = 'info') {
  const el = document.createElement('div')
  el.className = `alert alert-${kind} text-sm`
  el.textContent = text
  $('toasts').append(el)
  setTimeout(() => el.remove(), 4000)
}

// --- keys: the identity and its newest ratchets survive reloads (IndexedDB) ---

let keystore = null

class StoredRatchets extends MemoryRatchets {
  constructor(identity, keys) {
    super(identity.kemAlg, keys, RATCHETS_KEPT)
  }

  rotate() {
    const k = super.rotate()
    keystore.set('ratchets', encode(this.keys().map((r) => r.toCose(true)))).catch((e) => log('could not save ratchets:', e))
    return k
  }
}

async function loadKeys() {
  keystore = await KeyStore.open()
  let raw = await keystore.get('identity')
  let identity
  try {
    identity = raw && Identity.fromBytes(raw)
  } catch (e) {
    log('stored identity is unreadable, making a new one:', e)
  }
  if (!identity) return newIdentity()
  let ratchets = []
  try {
    raw = await keystore.get('ratchets')
    if (raw) ratchets = decode(raw).map((m) => Key.fromCose(m))
  } catch (e) {
    log('stored ratchets are unreadable, starting fresh:', e)
  }
  return { identity, ratchets: new StoredRatchets(identity, ratchets) }
}

// a fresh identity replaces the stored one; its old ratchets go with it
async function newIdentity() {
  const identity = Identity.generate('pq')
  await keystore.set('identity', identity.toBytes(true))
  await keystore.set('ratchets', undefined)
  return { identity, ratchets: new StoredRatchets(identity, []) }
}

// --- peers ---

const hex = (b) => toHex(b)

function upsertPeer(address, patch = {}) {
  const k = hex(address)
  const p = state.peers.get(k) || { address, name: null, seen: 0, unread: 0 }
  Object.assign(p, patch)
  state.peers.set(k, p)
  renderPeers()
  if (state.selected === k) renderHeader()
  return p
}

const label = (p) => p.name || hex(p.address).slice(0, 8)

function renderPeers() {
  const items = [...state.peers.entries()].sort((a, b) => b[1].seen - a[1].seen)
  $('peers').innerHTML = items.length
    ? items
        .map(
          ([k, p]) => `
      <li><a data-peer="${k}" class="${state.selected === k ? 'menu-active' : ''} flex items-center gap-2">
        <span class="font-semibold truncate">${esc(label(p))}</span>
        ${p.unread ? `<span class="badge badge-primary badge-sm">${p.unread}</span>` : ''}
        <span class="mono text-xs opacity-60 ml-auto">${k.slice(0, 8)}</span>
      </a></li>`
        )
        .join('')
    : '<li class="p-4 text-sm opacity-60">Nobody here yet. Peers show up when they announce; open this page in another browser (or a private window) to chat with yourself.</li>'
}

// --- chat ---

function chatOf(k) {
  if (!state.chats.has(k)) state.chats.set(k, [])
  return state.chats.get(k)
}

function select(k) {
  state.selected = k
  const p = state.peers.get(k)
  if (p) p.unread = 0
  renderPeers()
  renderHeader()
  renderMessages()
  updateComposer()
  $('text').focus()
}

function renderHeader() {
  const p = state.selected && state.peers.get(state.selected)
  $('chat-header').innerHTML = p ? `<div class="min-w-0"><div class="font-semibold truncate">${esc(label(p))}</div><div class="mono text-xs opacity-60 truncate">${hex(p.address)}</div></div>` : '<span class="opacity-60">No conversation selected</span>'
}

const STATUS = {
  sending: '<span class="loading loading-dots loading-xs"></span>',
  sent: '<span title="sent, waiting for a receipt">✓</span>',
  delivered: '<span class="text-success" title="receipt: they opened it">✓✓</span>',
  failed: '<span class="text-error" title="no receipt">✕</span>'
}

function renderMessages() {
  const el = $('messages')
  if (!state.selected) {
    el.innerHTML = '<div class="hero h-full"><div class="hero-content text-center"><div><h2 class="text-2xl font-bold">Hello</h2><p class="opacity-70">Pick someone on the left to chat with.</p></div></div></div>'
    return
  }
  const list = chatOf(state.selected)
  el.innerHTML = list.length
    ? list
        .map(
          (m) => `
      <div class="chat ${m.dir === 'out' ? 'chat-end' : 'chat-start'}">
        <div class="chat-header text-xs opacity-60">${new Date(m.time).toLocaleTimeString()}</div>
        <div class="chat-bubble ${m.dir === 'out' ? 'chat-bubble-primary' : ''} whitespace-pre-wrap break-words">${esc(m.text)}</div>
        ${m.dir === 'out' ? `<div class="chat-footer opacity-70">${STATUS[m.status]}</div>` : ''}
      </div>`
        )
        .join('')
    : '<p class="text-center opacity-60 p-8">No messages yet.</p>'
  el.scrollTop = el.scrollHeight
}

function updateComposer() {
  const ready = state.connected && state.selected
  $('text').disabled = $('send').disabled = !ready
  $('text').placeholder = ready ? 'message' : state.connected ? 'pick a peer, then type a message' : 'connecting…'
}

function renderStatus() {
  $('status').className = `badge ${state.connected ? 'badge-success' : 'badge-warning'}`
  $('status').textContent = state.connected ? 'online' : 'connecting…'
  $('announce').disabled = !state.connected
}

async function send(e) {
  e.preventDefault()
  const k = state.selected
  const text = $('text').value
  if (!k || !text) return
  $('text').value = ''
  const entry = { dir: 'out', text, time: Date.now(), status: 'sending' }
  chatOf(k).push(entry)
  renderMessages()
  try {
    const m = await state.node.send(fromHex(k), text)
    entry.status = 'sent'
    renderMessages()
    entry.status = (await state.node.delivered(m)) ? 'delivered' : 'failed'
  } catch (err) {
    entry.status = 'failed'
    toast(err.message, 'error')
    log('send failed:', err)
  }
  renderMessages()
}

async function find() {
  const v = $('find').value.trim().replace(/\s/g, '')
  if (!/^[0-9a-f]{32}$/i.test(v)) {
    toast('an address is 32 hex characters', 'warning')
    return
  }
  const address = fromHex(v)
  upsertPeer(address)
  select(hex(address))
  $('find').value = ''
  log(`asking the room for ${v}`)
  const found = await state.node.requestPath(address, { timeout: 10, fresh: true })
  toast(found ? 'found them' : 'no answer yet', found ? 'success' : 'warning')
}

// --- start ---

const defaultName = (identity) => `web-${hex(identity.address).slice(0, 4)}`
const appData = () => new Map([['name', $('name').value.trim() || 'web']])

// on joining the room, every REANNOUNCE seconds, on a name change, and on demand
async function announce() {
  if (!state.node || !state.connected) return false
  state.node.appData = appData()
  await state.node.announce({ full: true })
  log('announced')
  return true
}

// a node for this identity, on the room
async function startNode({ identity, ratchets }) {
  state.identity = identity
  $('address').textContent = hex(identity.address)
  const node = new Node({ identity, ratchets, appData: appData(), retryAfter: 10 })
  state.node = node
  const road = new WebSocketClientRoad(ROOM)
  road.onStatus = async (up) => {
    if (state.node !== node) return // an old node, stopped by regenerate()
    state.connected = up
    renderStatus()
    updateComposer()
    log(up ? `joined ${ROOM}` : 'lost the room (retrying)')
    if (up) await announce()
  }
  node.addRoad(road)

  node.onAnnounce((ann) => {
    const name = ann.appData instanceof Map ? ann.appData.get('name') : null
    upsertPeer(ann.address, { name, seen: Date.now() })
    log(`announce from ${name || hex(ann.address)}`)
  })
  node.onMessage((m) => {
    const k = hex(m.sender)
    const p = upsertPeer(m.sender, { seen: Date.now() })
    // they announced before we joined: ask for their announce (it has their name)
    if (!p.name) node.requestPath(m.sender, { timeout: 10, fresh: true }).catch(() => {})
    chatOf(k).push({ dir: 'in', text: typeof m.content === 'string' ? m.content : JSON.stringify(m.content), time: Date.now() })
    if (state.selected === k) renderMessages()
    else {
      p.unread++
      renderPeers()
    }
  })

  log(`you are ${hex(identity.address)}`)
  await node.start()
}

async function regenerate() {
  if (!confirm('Make a new identity? This address and its keys are gone for good, and so are these chats.')) return
  const old = state.identity
  const node = state.node
  state.node = null
  state.connected = false
  renderStatus()
  updateComposer()
  await node.stop()
  state.peers.clear()
  state.chats.clear()
  state.selected = null
  const keys = await newIdentity()
  // a name still derived from the old address follows the new one
  if (!$('name').value.trim() || $('name').value.trim() === defaultName(old)) {
    $('name').value = defaultName(keys.identity)
    localStorage.removeItem('cosechat:name')
  }
  renderPeers()
  renderHeader()
  renderMessages()
  await startNode(keys)
  toast('new identity', 'success')
}

async function main() {
  const keys = await loadKeys()
  $('name').value = localStorage.getItem('cosechat:name') || defaultName(keys.identity)
  renderPeers()
  renderHeader()
  renderMessages()

  $('name').onchange = () => {
    localStorage.setItem('cosechat:name', $('name').value.trim())
    announce()
  }
  $('copy-address').onclick = async () => {
    await navigator.clipboard.writeText(hex(state.identity.address))
    toast('address copied', 'success')
  }
  $('announce').onclick = async () => {
    if (await announce()) toast('announced', 'success')
  }
  $('regenerate').onclick = () => regenerate().catch((e) => toast(e.message, 'error'))
  $('composer').onsubmit = send
  $('find-go').onclick = find
  $('find').onkeydown = (e) => {
    if (e.key === 'Enter') find()
  }
  $('peers').onclick = (e) => {
    const a = e.target.closest('[data-peer]')
    if (a) select(a.dataset.peer)
  }

  await startNode(keys)
  setInterval(announce, REANNOUNCE * 1000)
}

main().catch((e) => {
  log('could not start:', e)
  toast(e.message, 'error')
})
// for poking at from devtools: cosechat.node, cosechat.peers, ...
window.cosechat = state
