// cosechat in the browser: a node on a WebSocket road to a relay (a transport
// node: examples/web/serve.js --relay, or the Python examples/chat.py
// --ws-server 4243 --transport). Everything here uses the public API.

import { Identity, Key, MemoryRatchets, Node, RoadAuth, contact } from 'cosechat/index.js'
import { WebSocketClientRoad } from 'cosechat/roads/websocket.js'
import { fromHex, toHex } from 'cosechat/bytes.js'
import { decode, encode } from 'cosechat/cbor.js'
import { getAlg } from 'cosechat/keys.js'

const $ = (id) => document.getElementById(id)
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])

// --- persisted settings (per-browser conveniences) ---

const store = {
  get(k, d) {
    try {
      const v = localStorage.getItem('cosechat:' + k)
      return v === null ? d : JSON.parse(v)
    } catch {
      return d
    }
  },
  set(k, v) {
    try {
      localStorage.setItem('cosechat:' + k, JSON.stringify(v))
    } catch {}
  }
}

const state = {
  identity: null,
  node: null,
  road: null,
  ratchets: null,
  connected: false,
  peers: new Map(), // hex -> { address, name, hops, quantumSafe, kem, propagation, seen, unread }
  chats: new Map(), // hex -> [entry]
  selected: null,
  announceTimer: null
}

// --- log & toasts ---

function log(...args) {
  const line = `${new Date().toLocaleTimeString()} ${args.map((a) => (a instanceof Error ? a.message : typeof a === 'string' ? a : JSON.stringify(a))).join(' ')}`
  const el = $('log')
  el.textContent += line + '\n'
  el.scrollTop = el.scrollHeight
}

function toast(text, kind = 'info') {
  const el = document.createElement('div')
  el.className = `alert alert-${kind} text-sm`
  el.textContent = text
  $('toasts').append(el)
  setTimeout(() => el.remove(), 4000)
}

// --- ratchets ---

// Ratchet storage is the application's policy. This page keeps the newest
// RATCHETS_KEPT in localStorage (per identity), so messages sealed to a
// ratchet we announced still open after a reconnect or reload (e.g. ones a
// propagation node held for us). Older ones are gone: forward secrecy.
// Like the identity, they are stored unencrypted: fine for playing only.
const RATCHETS_KEPT = 8

class LocalRatchets extends MemoryRatchets {
  constructor(identity) {
    const slot = 'ratchets:' + toHex(identity.address)
    let keys = []
    try {
      keys = (store.get(slot, []) || []).map((h) => Key.fromCose(decode(fromHex(h))))
    } catch (e) {
      log('stored ratchets are unreadable, starting fresh:', e)
    }
    super(identity.kemAlg, keys, RATCHETS_KEPT)
    this.slot = slot
  }

  rotate() {
    const k = super.rotate()
    store.set(
      this.slot,
      this.keys().map((r) => toHex(encode(r.toCose(true))))
    )
    return k
  }
}

// --- identity ---

function loadIdentity() {
  const saved = store.get('identity')
  if (saved) {
    try {
      return Identity.fromBytes(fromHex(saved))
    } catch (e) {
      log('saved identity is unreadable, making a new one:', e)
    }
  }
  return newIdentity(store.get('suite', 'pq'))
}

function newIdentity(suite) {
  const ident = Identity.generate(suite)
  store.set('identity', toHex(ident.toBytes(true)))
  store.set('suite', suite)
  return ident
}

function suiteOf(ident) {
  const algs = ident.signKeys.map((k) => k.alg)
  if (algs.length > 1) return 'hybrid'
  return ident.quantumSafe ? 'pq' : 'prequantum'
}

function renderIdentity() {
  const i = state.identity
  const qs = i.quantumSafe
  $('identity').innerHTML = `
    <div class="flex items-center gap-2 mb-1">
      <span class="badge ${qs ? 'badge-success' : 'badge-warning'}">${qs ? 'quantum-safe' : 'pre-quantum'}</span>
      <span class="badge badge-ghost">${esc(suiteOf(i))}</span>
      <span class="badge badge-ghost">${esc(i.signKeys.map((k) => k.algorithm.name).join(' + '))}</span>
    </div>
    <div class="text-xs opacity-60">address</div>
    <div class="mono text-sm break-all">${esc(toHex(i.address))}</div>
    <div class="text-xs opacity-60 mt-1">address text (read it aloud)</div>
    <div class="mono text-sm">${esc(contact.addressText(i.address))}</div>`
  $('suite').value = suiteOf(i)
  if (!qs) $('qso').checked = false
}

// --- peers ---

const nameOf = (appData) => (appData instanceof Map ? appData.get('name') : typeof appData === 'string' ? appData : null)

function upsertPeer(address, patch = {}) {
  const k = toHex(address)
  const p = state.peers.get(k) || { address, name: null, hops: null, quantumSafe: null, kem: null, propagation: false, seen: null, unread: 0 }
  Object.assign(p, patch)
  state.peers.set(k, p)
  renderPeers()
  if (state.selected === k) renderHeader()
  return p
}

function peerLabel(p) {
  return p.name || contact.addressText(p.address).slice(0, 11)
}

function renderPeers() {
  $('peer-count').textContent = state.peers.size
  const items = [...state.peers.entries()].sort((a, b) => (b[1].seen || 0) - (a[1].seen || 0))
  $('peers').innerHTML = items.length
    ? items
        .map(
          ([k, p]) => `
      <li><a data-peer="${k}" class="${state.selected === k ? 'menu-active' : ''} flex flex-col items-start gap-1">
        <span class="flex w-full items-center gap-2">
          <span class="font-semibold truncate">${esc(peerLabel(p))}</span>
          ${p.unread ? `<span class="badge badge-primary badge-sm">${p.unread}</span>` : ''}
          <span class="ml-auto flex gap-1">
            ${p.propagation ? '<span class="badge badge-info badge-xs">propagation</span>' : ''}
            ${p.quantumSafe === true ? '<span class="badge badge-success badge-xs">PQ</span>' : p.quantumSafe === false ? '<span class="badge badge-warning badge-xs">pre-PQ</span>' : ''}
            ${state.node?.linkTo(p.address) ? '<span class="badge badge-accent badge-xs">link</span>' : ''}
          </span>
        </span>
        <span class="mono text-xs opacity-60">${k.slice(0, 16)}… ${p.hops != null ? `· ${p.hops} hop${p.hops === 1 ? '' : 's'}` : ''}</span>
      </a></li>`
        )
        .join('')
    : '<li class="p-4 text-sm opacity-60">No announces yet. Connect, and wait for peers to announce (or find one by address).</li>'
  renderPropNodes()
}

function renderPropNodes() {
  const nodes = [...state.peers.values()].filter((p) => p.propagation)
  $('prop-nodes').innerHTML = nodes.length ? nodes.map((p) => `<div>• ${esc(peerLabel(p))} <span class="mono opacity-60">${toHex(p.address).slice(0, 12)}</span></div>`).join('') : '<span class="opacity-60">none known yet (run the relay with --propagate)</span>'
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
  const k = state.selected
  const p = k && state.peers.get(k)
  if (!p) {
    $('chat-header').innerHTML = '<span class="opacity-60">No conversation selected</span>'
    return
  }
  const link = state.node?.linkTo(p.address)
  const ratchet = state.node?.peerRatchet(p.address)
  $('chat-header').innerHTML = `
    <div class="min-w-0 flex-1">
      <div class="font-semibold truncate">${esc(peerLabel(p))}</div>
      <div class="mono text-xs opacity-60 truncate">${esc(contact.addressText(p.address))} · ${ratchet ? esc(getAlg(ratchet.alg).name) + ' ratchet' : 'no ratchet yet'}</div>
    </div>
    ${link ? '<span class="badge badge-accent">link up</span>' : ''}
    <button class="btn btn-sm" data-action="path">Request path</button>
    ${link ? '<button class="btn btn-sm" data-action="close-link">Close link</button>' : '<button class="btn btn-sm" data-action="open-link">Open link</button>'}`
}

const STATUS = {
  sending: '<span class="loading loading-dots loading-xs"></span>',
  sent: '<span title="sent, waiting for a receipt">✓</span>',
  delivered: '<span class="text-success" title="receipt: they opened it">✓✓</span>',
  failed: '<span class="text-error" title="no receipt">✕</span>'
}

function contentText(c) {
  if (typeof c === 'string') return c
  if (c instanceof Uint8Array) return `<${c.length} bytes>`
  try {
    return JSON.stringify(c, (_, v) => (v instanceof Map ? Object.fromEntries(v) : v instanceof Uint8Array ? toHex(v) : typeof v === 'bigint' ? String(v) : v))
  } catch {
    return String(c)
  }
}

function renderMessages() {
  const k = state.selected
  const el = $('messages')
  if (!k) {
    el.innerHTML = '<div class="hero h-full"><div class="hero-content text-center"><div><h2 class="text-2xl font-bold">Hello</h2><p class="opacity-70">Connect to a relay, announce yourself, and pick a peer.</p></div></div></div>'
    return
  }
  const list = chatOf(k)
  el.innerHTML = list.length
    ? list
        .map((m) => {
          const out = m.dir === 'out'
          const body = m.file ? `📄 <a class="link" href="${m.file.url}" download="${esc(m.file.name)}">${esc(m.file.name)}</a> <span class="opacity-60">(${m.file.size} bytes)</span>` : esc(contentText(m.content))
          return `
        <div class="chat ${out ? 'chat-end' : 'chat-start'}">
          <div class="chat-header text-xs opacity-60">${m.title ? `<b>${esc(m.title)}</b> · ` : ''}${new Date(m.time).toLocaleTimeString()}${m.via ? ` · ${esc(m.via)}` : ''}</div>
          <div class="chat-bubble ${out ? 'chat-bubble-primary' : ''} whitespace-pre-wrap break-words">${body}</div>
          ${out ? `<div class="chat-footer opacity-70">${STATUS[m.status] || ''}</div>` : ''}
        </div>`
        })
        .join('')
    : '<p class="text-center opacity-60 p-8">No messages yet.</p>'
  el.scrollTop = el.scrollHeight
}

function updateComposer() {
  const ready = state.connected && state.selected
  $('text').disabled = $('send').disabled = !ready
  $('text').placeholder = ready ? 'message' : 'pick a peer, then type a message'
}

// --- node ---

function viaOf(m) {
  return m.linkId ? 'link' : 'sealed'
}

async function connect() {
  if (state.node) {
    await disconnect()
    return
  }
  const url = $('url').value.trim()
  store.set('url', url)
  const quantumSafeOnly = $('qso').checked
  if (quantumSafeOnly && !state.identity.quantumSafe) {
    toast('This identity is pre-quantum: turn off "quantum-safe peers only" or make a pq identity', 'warning')
    return
  }
  const node = new Node({
    identity: state.identity,
    appData: new Map([['name', $('name').value.trim() || 'web']]),
    quantumSafeOnly,
    ratchets: state.ratchets,
    retryAfter: 10,
    log: (...a) => $('verbose').checked && log(...a)
  })
  const pass = $('passphrase').value
  const auth = pass ? RoadAuth.fromPassphrase(pass, $('mode').value) : null
  const road = new WebSocketClientRoad(url)
  road.onStatus = async (up) => {
    state.connected = up
    renderStatus()
    updateComposer()
    log(up ? `connected to ${url}` : state.road === road ? 'disconnected (retrying)' : 'disconnected')
    if (up) await announce(true)
  }
  node.addRoad(road, auth)

  node.onAnnounce((ann, path) => {
    const p = upsertPeer(ann.address, { name: nameOf(ann.appData), hops: path.hops, quantumSafe: ann.identity.quantumSafe, kem: getAlg(ann.ratchet.alg).name, propagation: Boolean(ann.services & 1), seen: Date.now() })
    log(`announce from ${peerLabel(p)} (${path.hops} hop(s), ${ann.full ? 'full' : 'short'})`)
  })

  node.onMessage((m) => {
    const k = toHex(m.sender)
    const known = node.known(m.sender)
    const p = upsertPeer(m.sender, { seen: Date.now(), quantumSafe: known ? known.quantumSafe : null })
    chatOf(k).push({ dir: 'in', content: m.content, title: m.title, time: Date.now(), via: viaOf(m) })
    if (state.selected !== k) {
      p.unread++
      renderPeers()
      toast(`${peerLabel(p)}: ${contentText(m.content).slice(0, 60)}`)
    } else renderMessages()
  })

  node.onResource((r) => {
    const k = toHex(r.peer)
    const meta = r.meta instanceof Map ? r.meta : new Map()
    const name = meta.get('name') || 'file.bin'
    const url = URL.createObjectURL(new Blob([r.data], { type: meta.get('type') || 'application/octet-stream' }))
    const p = upsertPeer(r.peer, { seen: Date.now() })
    chatOf(k).push({ dir: 'in', file: { name, size: r.data.length, url }, time: Date.now(), via: 'resource' })
    log(`resource from ${peerLabel(p)}: ${name} (${r.data.length} bytes)`)
    if (state.selected === k) renderMessages()
    else {
      p.unread++
      renderPeers()
    }
  })

  state.node = node
  state.road = road
  await node.start()
  $('connect').textContent = 'Disconnect'
  $('connect').classList.replace('btn-primary', 'btn-outline')
  for (const id of ['announce', 'find-go', 'copy-card', 'rotate', 'fetch']) $(id).disabled = false
  renderRatchet()
  if ($('auto-announce').checked) state.announceTimer = setInterval(() => announce(false), 300e3)
}

async function disconnect() {
  clearInterval(state.announceTimer)
  await state.node.stop()
  state.node = null
  state.road = null
  state.connected = false
  $('connect').textContent = 'Connect'
  $('connect').classList.replace('btn-outline', 'btn-primary')
  for (const id of ['announce', 'find-go', 'copy-card', 'rotate', 'fetch']) $(id).disabled = true
  renderStatus()
  updateComposer()
  log('stopped')
}

function renderStatus() {
  const el = $('status')
  el.className = `badge ${state.connected ? 'badge-success' : state.node ? 'badge-warning' : 'badge-neutral'}`
  el.textContent = state.connected ? 'online' : state.node ? 'connecting…' : 'offline'
}

function renderRatchet() {
  const r = state.node?.ratchets.current()
  $('ratchet').innerHTML = r ? `current: ${esc(getAlg(r.alg).name)} <b>${toHex(r.kid)}</b><br>held: ${state.node.ratchets.size}` : ''
  $('card').value = state.node ? contact.cardUri(state.node.contactCard()) : ''
}

async function announce(full = null) {
  if (!state.node) return
  state.node.appData = new Map([['name', $('name').value.trim() || 'web']])
  await state.node.announce({ full })
  log(`announced (${full ? 'full' : full === false ? 'short' : 'auto'})`)
}

async function sendText(e) {
  e.preventDefault()
  const k = state.selected
  const text = $('text').value
  if (!k || !text || !state.node) return
  $('text').value = ''
  const title = $('title').value.trim()
  const propagate = $('via-prop').checked
  const entry = { dir: 'out', content: text, title, time: Date.now(), status: 'sending', via: propagate ? 'propagation' : state.node.linkTo(fromHex(k)) ? 'link' : 'sealed' }
  chatOf(k).push(entry)
  renderMessages()
  try {
    const m = await state.node.send(fromHex(k), text, { title, propagate })
    entry.status = 'sent'
    renderMessages()
    entry.status = (await state.node.delivered(m)) ? 'delivered' : 'failed'
  } catch (err) {
    entry.status = 'failed'
    toast(err.message, 'error')
    log('send failed:', err)
  }
  renderMessages()
  renderPeers()
}

async function sendFile(file) {
  const k = state.selected
  if (!k || !file || !state.node) return
  const data = new Uint8Array(await file.arrayBuffer())
  const entry = { dir: 'out', file: { name: file.name, size: data.length, url: URL.createObjectURL(file) }, time: Date.now(), status: 'sending', via: 'resource' }
  chatOf(k).push(entry)
  renderMessages()
  try {
    const ok = await state.node.sendResource(fromHex(k), data, {
      meta: new Map([
        ['name', file.name],
        ['type', file.type || 'application/octet-stream']
      ]),
      timeout: 120
    })
    entry.status = ok ? 'delivered' : 'failed'
  } catch (err) {
    entry.status = 'failed'
    toast(err.message, 'error')
  }
  renderMessages()
  renderHeader()
  renderPeers()
}

async function find() {
  const v = $('find').value.trim()
  if (!v || !state.node) return
  try {
    if (v.startsWith(contact.URI_PREFIX)) {
      const ann = state.node.addContact(contact.cardFromUri(v))
      upsertPeer(ann.address, { name: nameOf(ann.appData), quantumSafe: ann.identity.quantumSafe, propagation: Boolean(ann.services & 1), seen: Date.now() })
      select(toHex(ann.address))
      toast('contact added', 'success')
      await state.node.requestPath(ann.address, { timeout: 5 })
    } else {
      const address = contact.parseAddress(v)
      upsertPeer(address)
      select(toHex(address))
      log(`asking the mesh for ${toHex(address)}`)
      const ident = await state.node.requestPath(address, { timeout: 10, fresh: true })
      toast(ident ? 'found them' : 'no answer yet', ident ? 'success' : 'warning')
    }
    $('find').value = ''
  } catch (e) {
    toast(e.message, 'error')
  }
}

async function headerAction(action) {
  const k = state.selected
  if (!k || !state.node) return
  const addr = fromHex(k)
  try {
    if (action === 'path') {
      const ident = await state.node.requestPath(addr, { timeout: 10, fresh: true })
      toast(ident ? `path: ${state.node.path(addr)?.hops ?? '?'} hop(s)` : 'no answer', ident ? 'success' : 'warning')
    } else if (action === 'open-link') {
      toast('opening link…')
      await state.node.openLink(addr, 30)
      toast('link up: messages now cost tens of bytes', 'success')
    } else if (action === 'close-link') {
      await state.node.closeLink(addr)
      toast('link closed')
    }
  } catch (e) {
    toast(e.message, 'error')
  }
  renderHeader()
  renderPeers()
}

// --- wiring ---

function setTab(name) {
  for (const t of document.querySelectorAll('[data-tab]')) t.classList.toggle('tab-active', t.dataset.tab === name)
  for (const p of document.querySelectorAll('[data-panel]')) {
    p.classList.toggle('hidden', p.dataset.panel !== name)
    p.classList.toggle('flex', p.dataset.panel === name)
  }
}

function init() {
  state.identity = loadIdentity()
  state.ratchets = new LocalRatchets(state.identity)
  const theme = store.get('theme', 'dim')
  document.documentElement.dataset.theme = theme
  $('theme').value = theme
  $('theme').onchange = () => {
    document.documentElement.dataset.theme = $('theme').value
    store.set('theme', $('theme').value)
  }
  $('url').value = store.get('url', `ws://${location.hostname || 'localhost'}:4243`)
  $('name').value = store.get('name', `web-${toHex(state.identity.address).slice(0, 4)}`)
  $('name').onchange = () => store.set('name', $('name').value.trim())
  renderIdentity()
  renderPeers()
  renderHeader()
  renderMessages()

  for (const t of document.querySelectorAll('[data-tab]')) t.onclick = () => setTab(t.dataset.tab)
  $('connect').onclick = () => connect().catch((e) => toast(e.message, 'error'))
  $('announce').onclick = () => announce(true)
  $('composer').onsubmit = sendText
  $('file').onchange = (e) => {
    sendFile(e.target.files[0])
    e.target.value = ''
  }
  $('find-go').onclick = find
  $('find').onkeydown = (e) => {
    if (e.key === 'Enter') find()
  }
  $('peers').onclick = (e) => {
    const a = e.target.closest('[data-peer]')
    if (a) select(a.dataset.peer)
  }
  $('chat-header').onclick = (e) => {
    const b = e.target.closest('[data-action]')
    if (b) headerAction(b.dataset.action)
  }
  $('copy-card').onclick = async () => {
    await navigator.clipboard.writeText($('card').value)
    toast('card copied', 'success')
  }
  $('rotate').onclick = async () => {
    await state.node.rotateRatchet()
    renderRatchet()
    toast('ratchet rotated and announced', 'success')
  }
  $('fetch').onclick = async () => {
    try {
      const n = await state.node.fetch({ timeout: 20 })
      toast(`${n} item(s) from the propagation node`, 'success')
    } catch (e) {
      toast(e.message, 'error')
    }
  }
  $('new-identity').onclick = () => $('confirm').showModal()
  $('confirm').onclose = async () => {
    if ($('confirm').returnValue !== 'yes') return
    if (state.node) await disconnect()
    state.identity = newIdentity($('suite').value)
    state.ratchets = new LocalRatchets(state.identity)
    state.peers.clear()
    state.chats.clear()
    state.selected = null
    if (state.identity.quantumSafe) $('qso').checked = true
    renderIdentity()
    renderPeers()
    renderHeader()
    renderMessages()
    toast(`new ${$('suite').value} identity`, 'success')
  }
  $('export').onclick = () => {
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([state.identity.toBytes(true)]))
    a.download = `cosechat-${toHex(state.identity.address).slice(0, 8)}.keyset`
    a.click()
  }
  $('import').onchange = async (e) => {
    const f = e.target.files[0]
    e.target.value = ''
    if (!f) return
    try {
      const ident = Identity.fromBytes(new Uint8Array(await f.arrayBuffer()))
      if (!ident.hasPrivate) throw new Error('that keyset has no private keys')
      if (state.node) await disconnect()
      state.identity = ident
      state.ratchets = new LocalRatchets(ident)
      store.set('identity', toHex(ident.toBytes(true)))
      renderIdentity()
      toast('identity imported', 'success')
    } catch (err) {
      toast(`import failed: ${err.message}`, 'error')
    }
  }
  $('clear-log').onclick = () => ($('log').textContent = '')
  log(`identity ${toHex(state.identity.address)} (${suiteOf(state.identity)})`)
}

init()
// for poking at from devtools: cosechat.node, cosechat.peers, ...
window.cosechat = state
