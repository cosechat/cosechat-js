// Interop vectors, as in the Python reference (cosechat/vectors.py):
//   generate()  fresh vectors from this implementation (must-accept, must-reject
//               and byte-exact cases), for other implementations to check
//   check(v)    verify a vector file from any implementation; returns failures
//   exact()     the byte-exact cases, rebuilt from their inputs

import { BytesMap, concat, equal, fromHex, toHex, utf8 } from './bytes.js'
import { decode, encode } from './cbor.js'
import * as cose from './cose.js'
import { Identity, SUITES } from './identity.js'
import * as K from './keys.js'
import { A256GCM, ED25519, HMAC_256_256, HPKE_0, Key } from './keys.js'
import * as L from './link.js'
import * as M from './message.js'
import * as P from './packet.js'
import { newRatchet, ratchetId } from './ratchet.js'

const h = fromHex
const key = (hex) => Key.fromCose(decode(h(hex)))
const byAddr = (list) => (a) => list.find((i) => equal(i.address, a)) || null

const OPS = {
  verify_sign1: (v, d, aad) => cose.verifySign1(d, key(v.key), aad),
  verify_sign: (v, d, aad) => cose.verifySign(d, v.keys.map(key), aad),
  verify_mac0: (v, d, aad) => cose.verifyMac0(d, key(v.key), aad),
  verify_mac: (v, d, aad) => cose.verifyMac(d, key(v.key), aad),
  decrypt0: (v, d, aad) => cose.decrypt0(d, key(v.key), aad),
  decrypt: (v, d, aad) => cose.decrypt(d, key(v.key), aad)
}

function seed(n, size = 32) {
  return Uint8Array.from({ length: size }, (_, i) => (n + i) % 256)
}

// the byte-exact cases, built the same way as the Python reference
export function exact() {
  const out = []
  const kase = (name, inputs, expect) => out.push({ name, inputs, expect })
  const sk = Key.fromPrivate(ED25519, seed(1))
  const alice = new Identity([sk])
  kase('identity (prequantum)', { ed25519_private: toHex(seed(1)) }, { keyset: toHex(alice.publicBytes), address: toHex(alice.address) })
  const rk = Key.fromPrivate(HPKE_0, seed(40))
  rk.kid = ratchetId(rk.pub)
  kase('ratchet (HPKE-0)', { p256_private: toHex(seed(40)) }, { cose_key: toHex(encode(rk.public().toCose())), ratchet_id: toHex(rk.kid) })
  kase('COSE_Sign1 Ed25519', { ed25519_private: toHex(seed(1)), payload: toHex(utf8('cosechat')), kid: toHex(utf8('k')) }, { data: toHex(cose.sign1(utf8('cosechat'), new Key(ED25519, sk.pub, sk.priv, utf8('k')), { kidProtected: true })) })
  kase('COSE_Mac0 HMAC 256/256', { key: toHex(seed(80)), payload: toHex(utf8('cosechat')) }, { data: toHex(cose.mac0(utf8('cosechat'), new Key(HMAC_256_256, undefined, seed(80)))) })
  kase('COSE_Encrypt0 A256GCM', { key: toHex(seed(120)), iv: toHex(seed(160, 12)), plaintext: toHex(utf8('cosechat')) }, { data: toHex(cose.encrypt0(utf8('cosechat'), new Key(A256GCM, undefined, seed(120)), { iv: seed(160, 12) })) })
  const appData = new Map([['name', 'alice']])
  for (const full of [true, false]) {
    const ann = M.makeAnnounce(alice, rk, { appData, sequence: 1700000000000, full })
    const pkt = new P.Packet(P.ANNOUNCE, 0, alice.address, null, ann)
    kase(`announce (${full ? 'full' : 'short'})`, { identity: 'identity (prequantum)', ratchet: 'ratchet (HPKE-0)', sequence: 1700000000000, app_data_cbor: toHex(encode(appData)) }, { announce: toHex(ann), packet: toHex(pkt.encode()), packet_hash: toHex(pkt.hash) })
  }
  const bob = new Identity([Key.fromPrivate(ED25519, seed(2))])
  const fields = new Map([[1, utf8('x')]])
  const m = M.signMessage(alice, [bob], { content: 'hi bob', title: 'hello', fields, timestamp: 1700000000001, receiptSecret: seed(200, 16) })
  kase('signed message layer', { sender: 'identity (prequantum)', recipient_ed25519_private: toHex(seed(2)), content: 'hi bob', title: 'hello', fields_cbor: toHex(encode(fields)), timestamp: 1700000000001, receipt_secret: toHex(seed(200, 16)) }, { signed: toHex(m.signed), message_id: toHex(m.id), receipt_tag: toHex(M.receiptTag(seed(200, 16), bob.address)) })
  const frame = new Uint8Array(768).map((_, i) => i % 256)
  kase('fragments', { frame: toHex(frame), chunk_size: 300, fragment_id: toHex(seed(9, 8)) }, { fragments: P.fragment(frame, 300, seed(9, 8)).map(toHex) })
  kase('nack', { fragment_id: toHex(seed(9, 8)), missing: [0, 2] }, { frame: toHex(P.nack(seed(9, 8), [0, 2])) })
  const keys = L.deriveKeys(seed(20, 16), seed(30), seed(60), new Uint8Array(16), true)
  kase('link keys', { link_id: toHex(seed(20, 16)), part_a: toHex(seed(30)), part_b: toHex(seed(60)) }, { a_to_b: toHex(keys.sendKey.priv), b_to_a: toHex(keys.recvKey.priv) })
  const road = P.RoadAuth.fromPassphrase('cosechat vectors', 'mac')
  const pr = new P.Packet(P.PATH_REQUEST, 0, seed(3, 16), null, seed(4, 8)).encode()
  kase('road auth (mac)', { passphrase: 'cosechat vectors', frame: toHex(pr) }, { key: toHex(road.key.priv), data: toHex(road.wrap(pr)) })
  return out
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)

export function check(vectors) {
  const fails = []
  const expect = (ok, what) => ok || fails.push(what)
  const attempt = (what, fn) => {
    try {
      fn()
    } catch (e) {
      fails.push(`${what}: ${e.message}`)
    }
  }

  ;(vectors.cose || []).forEach((v, i) => {
    const what = `cose[${i}] ${v.op} ${v.alg || ''}`
    attempt(what, () => expect(toHex(OPS[v.op](v, h(v.data), h(v.external_aad || ''))) === v.expect, what))
  })

  const ids = new Map()
  const rks = new Map()
  for (const v of vectors.identities || []) {
    const k = `${v.suite}/${v.name}`
    attempt(`identity ${k}`, () => {
      const i = Identity.fromBytes(h(v.private))
      ids.set(k, i)
      rks.set(k, (v.ratchets || []).map(key))
      const pub = Identity.fromBytes(h(v.public))
      expect(toHex(pub.address) === v.address && toHex(i.address) === v.address, `identity ${k}`)
    })
  }

  ;(vectors.messages || []).forEach((v, n) => {
    for (const who of v.to) {
      const what = `message[${n}] ${v.suite} ${v.kind} -> ${who}`
      attempt(what, () => {
        const sender = ids.get(`${v.suite}/${v.from}`).public()
        const me = ids.get(`${v.suite}/${who}`)
        const m = M.unseal(me, h(v.data), byAddr([sender]), rks.get(`${v.suite}/${who}`))
        const e = v.expect
        const tags = e.receipt_tags || {}
        if (who in tags) expect(m.receiptSecret && toHex(M.receiptTag(m.receiptSecret, me.address)) === tags[who], what + ' receipt tag')
        expect(m.ratchetId && toHex(m.id) === e.id && toHex(m.sender) === e.sender && same(m.recipients.map(toHex), e.recipients) && m.timestamp === e.timestamp && m.title === e.title && m.content === e.content && toHex(encode(m.fields)) === e.fields_cbor, what)
      })
    }
  })

  const pubs = [...ids.values()].map((i) => i.public())
  ;(vectors.announces || []).forEach((v, n) => {
    const what = `announce[${n}] ${v.suite}`
    attempt(what, () => {
      const e = v.expect
      const a = M.verifyAnnounce(h(v.data), h(e.address), byAddr(pubs))
      expect(a.sequence === e.sequence && a.full === (v.full ?? true) && toHex(a.ratchet.kid) === e.ratchet_id && toHex(encode(a.appData)) === e.app_data_cbor, what)
    })
  })

  ;(vectors.packets || []).forEach((v, n) => {
    const what = `packet[${n}] ${v.suite}`
    attempt(what, () => {
      const p = P.decode(h(v.data))
      expect(toHex(p.hash) === v.hash && P.TYPES[p.type] === v.type, what)
    })
  })

  ;(vectors.links || []).forEach((v, n) => {
    const what = `link[${n}] ${v.suite}`
    attempt(what, () => {
      const a = Identity.fromBytes(h(v.initiator))
      const b = Identity.fromBytes(h(v.responder))
      const request = h(v.request)
      const { sender, partA } = L.readRequest(b, request, byAddr([a.public()]), v.responder_ratchets.map(key), false)
      const pending = new L.PendingLink(L.linkId(request), b.address, request, key(v.initiator_ephemeral), partA)
      const ka = L.finish(pending, h(v.accept))
      const e = v.expect
      expect(equal(sender.address, a.address) && toHex(ka.linkId) === e.link_id && toHex(ka.sendKey.priv) === e.key_a_to_b && toHex(ka.recvKey.priv) === e.key_b_to_a, what + ' keys')
      const kb = new L.LinkKeys(ka.linkId, a.address, false, ka.recvKey, ka.sendKey)
      v.messages.forEach((lm, i) => {
        const [keys, me] = lm.from === 'initiator' ? [kb, b.address] : [ka, a.address]
        const { message } = L.readMessage(keys, me, L.unseal(keys, h(lm.data)))
        expect(message.content === lm.content, `${what} message[${i}]`)
      })
    })
  })

  ;(vectors.road_auth || []).forEach((v, n) => {
    const what = `road_auth[${n}] ${v.mode}`
    attempt(what, () => {
      const auth = P.RoadAuth.fromPassphrase(v.passphrase, v.mode)
      expect(toHex(encode(auth.key.toCose(true))) === v.key, what + ' key derivation')
      expect(toHex(auth.unwrap(h(v.data))) === v.expect, what)
    })
  })

  if (vectors.exact) {
    const mine = new Map(exact().map((c) => [c.name, c]))
    for (const c of vectors.exact) {
      const ours = mine.get(c.name)
      if (!ours) fails.push(`exact ${c.name}: unknown case`)
      else if (!same(ours.inputs, c.inputs) || !same(ours.expect, c.expect)) fails.push(`exact ${c.name}: bytes differ`)
    }
  }

  for (const v of vectors.reject || []) {
    if (accepted(v)) fails.push(`reject ${v.kind}: ${v.name} was accepted (${v.rule})`)
  }
  return fails
}

// true if the case gets through; every reject vector must not
function accepted(v) {
  const data = h(v.data)
  try {
    switch (v.kind) {
      case 'message':
      case 'link_request': {
        const me = Identity.fromBytes(h(v.me))
        const book = byAddr(v.known.map((x) => Identity.fromBytes(h(x))))
        const ratchets = v.ratchets.map(key)
        if (v.kind === 'link_request') {
          L.readRequest(me, data, book, ratchets, false)
          return true
        }
        const m = M.unseal(me, data, book, ratchets)
        const sender = book(m.sender) || M.attachedIdentity(m.signed)
        return !(v.quantum_safe_only && !sender.quantumSafe)
      }
      case 'announce': {
        const known = v.known ? Identity.fromBytes(h(v.known)) : null
        const a = M.verifyAnnounce(data, h(v.address), () => known)
        if (v.previous) return a.sequence >= M.verifyAnnounce(h(v.previous), h(v.address)).sequence
        return true
      }
      case 'packet':
        P.decode(data)
        return true
      case 'link_accept': {
        const request = h(v.request)
        L.finish(new L.PendingLink(L.linkId(request), new Uint8Array(), request, key(v.ephemeral), new Uint8Array(32)), data)
        return true
      }
      case 'road_auth':
        P.RoadAuth.fromPassphrase(v.passphrase, v.mode).unwrap(data)
        return true
    }
  } catch {
    return false
  }
  throw new Error(`unknown reject kind ${v.kind}`)
}

// --- generate ---

const hexKey = (k) => toHex(encode(k.toCose(true)))
const PAYLOAD = utf8('cosechat test payload')
const algName = (id) => K.getAlg(id).name

export function generate() {
  const out = { description: 'cosechat interop vectors: every entry must verify / decrypt to `expect`', generator: 'cosechat-js', cose: [], identities: [], messages: [], announces: [], packets: [] }
  const c = out.cose
  const entry = (op, alg, k, data, aad = new Uint8Array()) => ({ op, alg, key: hexKey(k), data: toHex(data), external_aad: toHex(aad), expect: toHex(PAYLOAD) })

  for (const alg of [K.ED25519, K.ESP256, K.ML_DSA_44, K.ML_DSA_65, K.ML_DSA_87]) {
    const k = Key.generate(alg, utf8('signer'))
    c.push(entry('verify_sign1', algName(alg), k, cose.sign1(PAYLOAD, k, { externalAad: utf8('aad') }), utf8('aad')))
  }
  const ks = [Key.generate(K.ED25519), Key.generate(K.ML_DSA_65)]
  c.push({ op: 'verify_sign', alg: 'Ed25519 + ML-DSA-65', keys: ks.map(hexKey), data: toHex(cose.sign(PAYLOAD, ks)), external_aad: '', expect: toHex(PAYLOAD) })
  for (const alg of [K.HMAC_256_64, K.HMAC_256_256, K.HMAC_384_384, K.HMAC_512_512]) {
    const k = Key.generate(alg)
    c.push(entry('verify_mac0', algName(alg), k, cose.mac0(PAYLOAD, k)))
  }
  for (const alg of [K.A128GCM, K.A256GCM, K.CHACHA20_POLY1305]) {
    const k = Key.generate(alg)
    c.push(entry('decrypt0', algName(alg), k, cose.encrypt0(PAYLOAD, k)))
  }
  for (const alg of [K.HPKE_0, K.HPKE_4, K.HPKE_9, K.HPKE_12]) {
    const k = Key.generate(alg)
    c.push(entry('decrypt0', algName(alg), k, cose.encrypt0(PAYLOAD, k.public())))
    const rs = [k, Key.generate(alg)]
    const enc = cose.encrypt(
      PAYLOAD,
      rs.map((r) => r.public())
    )
    const macd = cose.mac(
      PAYLOAD,
      rs.map((r) => r.public())
    )
    const ke = algName(K.getAlg(alg).sibling)
    for (const r of rs) {
      c.push(entry('decrypt', `A256GCM / ${ke}`, r, enc))
      c.push(entry('verify_mac', `HMAC 256/256 / ${ke}`, r, macd))
    }
  }

  const fields = new Map([
    [1, new Uint8Array([0, 1, 2])],
    ['k', 'v']
  ])
  const appData = new Map([['name', 'alice']])
  for (const suite of Object.keys(SUITES)) {
    const [alice, bob, carol] = [0, 1, 2].map(() => Identity.generate(suite))
    const ratchets = {}
    for (const [who, i] of [
      ['alice', alice],
      ['bob', bob],
      ['carol', carol]
    ]) {
      ratchets[who] = newRatchet(i.kemAlg)
      out.identities.push({ suite, name: who, private: toHex(i.toBytes(true)), public: toHex(i.publicBytes), address: toHex(i.address), ratchets: [hexKey(ratchets[who])] })
    }
    const rks = new BytesMap()
    rks.set(bob.address, ratchets.bob.public())
    rks.set(carol.address, ratchets.carol.public())
    const message = (kind, to, sealed, m, title = '', f = null) => ({
      suite,
      kind,
      from: 'alice',
      to,
      ratchet: true,
      data: toHex(sealed),
      expect: { id: toHex(m.id), sender: toHex(alice.address), recipients: [bob, carol].slice(0, to.length).map((r) => toHex(r.address)), timestamp: m.timestamp, title, content: m.content, fields_cbor: toHex(encode(f || new Map())) }
    })
    const secret = Uint8Array.from({ length: 16 }, (_, i) => i)
    let { sealed, message: m } = M.seal(alice, [bob.public()], { content: 'hi bob', title: 'one', fields, timestamp: 1700000000000, ratchets: rks, receiptSecret: secret })
    const v = message('Encrypt0', ['bob'], sealed, m, 'one', fields)
    v.expect.receipt_tags = { bob: toHex(M.receiptTag(secret, bob.address)) }
    out.messages.push(v)
    ;({ sealed, message: m } = M.seal(alice, [bob.public(), carol.public()], { content: 'hi all', timestamp: 1700000000002, ratchets: rks }))
    out.messages.push(message('Encrypt', ['bob', 'carol'], sealed, m))
    let ann
    for (const full of [true, false]) {
      ann = M.makeAnnounce(alice, ratchets.alice, { appData, sequence: 1700000000003, full })
      out.announces.push({ suite, from: 'alice', full, data: toHex(ann), expect: { address: toHex(alice.address), sequence: 1700000000003, app_data_cbor: toHex(encode(appData)), ratchet_id: toHex(ratchets.alice.kid) } })
    }
    const pkt = new P.Packet(P.ANNOUNCE, 0, alice.address, null, ann)
    out.packets.push({ suite, data: toHex(pkt.encode()), hash: toHex(pkt.hash), type: 'ANNOUNCE' })
  }

  out.links = []
  for (const suite of ['pq', 'prequantum']) {
    const [a, b] = [Identity.generate(suite), Identity.generate(suite)]
    const rb = newRatchet(b.kemAlg)
    const pending = L.makeRequest(a, b.public(), rb.public())
    const eph = pending.ephemeral
    const { accept, keys: kb } = L.acceptRequest(b, pending.request, byAddr([a.public()]), [rb], false)
    const ka = L.finish(pending, accept)
    out.links.push({
      suite,
      initiator: toHex(a.toBytes(true)),
      responder: toHex(b.toBytes(true)),
      responder_ratchets: [hexKey(rb)],
      // normally deleted right after the accept; here so accept can be checked
      initiator_ephemeral: hexKey(eph),
      request: toHex(pending.request),
      accept: toHex(accept),
      expect: { link_id: toHex(ka.linkId), key_a_to_b: toHex(ka.sendKey.priv), key_b_to_a: toHex(ka.recvKey.priv) },
      messages: [
        { from: 'initiator', data: toHex(L.seal(ka, L.messageBody({ content: 'hi over the link' }))), content: 'hi over the link' },
        { from: 'responder', data: toHex(L.seal(kb, L.messageBody({ content: 'and back' }))), content: 'and back' }
      ]
    })
  }

  const frame = new P.Packet(P.PATH_REQUEST, 0, new Uint8Array(16).fill(0x11), null, new Uint8Array(8).fill(0x22)).encode()
  out.road_auth = ['mac', 'encrypt'].map((mode) => {
    const auth = P.RoadAuth.fromPassphrase('cosechat vectors', mode)
    return { passphrase: 'cosechat vectors', mode, key: hexKey(auth.key), data: toHex(auth.wrap(frame)), expect: toHex(frame) }
  })
  out.reject = rejects()
  out.exact = exact()
  return out
}

function flip(b, pos = -3) {
  const x = b.slice()
  x[x.length + pos] ^= 1
  return x
}

// cases every implementation MUST refuse; each names the rule it tests
function rejects() {
  const out = []
  const [alice, bob, carol, mallory] = [0, 1, 2, 3].map(() => Identity.generate('prequantum'))
  const rb = newRatchet(bob.kemAlg)
  const rc = newRatchet(carol.kemAlg)
  const rks = new BytesMap()
  rks.set(bob.address, rb.public())
  const ident = (i) => toHex(i.toBytes(true))
  const message = (name, rule, data, { me = bob, known = [alice], ratchets = [rb], qso = false } = {}) => out.push({ kind: 'message', name, rule, me: ident(me), ratchets: ratchets.map(hexKey), known: known.map((k) => toHex(k.publicBytes)), quantum_safe_only: qso, data: toHex(data) })

  const { sealed: good } = M.seal(alice, [bob.public()], { content: 'hi', ratchets: rks })
  message('tampered', 'AEAD tag must verify', flip(good))
  const signed = cose.decrypt0(good, rb)
  message('forwarded to a third party', 'reject unless our address is in the signed `to`', M.envelope(signed, rc.public()), { me: carol, ratchets: [rc] })
  message('unknown sender', 'sender keyset must be known or attached', good, { known: [] })
  message('sealed to a ratchet we do not hold', 'the kid must name one of our ratchets', good, { ratchets: [newRatchet(bob.kemAlg)] })
  const body = encode(
    new Map([
      [M.M_TO, [bob.address]],
      [M.M_TIME, 1],
      [M.M_CONTENT, 'x']
    ])
  )
  const mk = mallory.signKeys[0]
  const forged = cose.sign1(body, new Key(mk.alg, mk.pub, mk.priv, alice.address), { kidProtected: true })
  message('signature kid names someone else', 'the signature must verify with the kid identity keys', M.envelope(forged, rb.public()))
  message('pre-quantum sender under the default policy', 'quantum_safe_only drops non-quantum-safe senders', good, { qso: true })

  const announce = (name, rule, data, address, { previous = null, known = null } = {}) => out.push({ kind: 'announce', name, rule, address: toHex(address), previous: previous ? toHex(previous) : null, known: known ? toHex(known.publicBytes) : null, data: toHex(data) })
  const ra = newRatchet(alice.kemAlg)
  const ann = M.makeAnnounce(alice, ra, { sequence: 10 })
  announce('tampered', 'signature must verify', flip(ann), alice.address)
  announce('for another address', 'keyset must hash to dest', ann, bob.address)
  announce('older sequence', 'ignore a lower sequence than the last accepted', M.makeAnnounce(alice, ra, { sequence: 9 }), alice.address, { previous: ann })
  const short = M.makeAnnounce(alice, ra, { sequence: 11, full: false })
  announce('short announce checked against another keyset', 'a short announce verifies only with the keyset that hashes to its address', short, alice.address, { known: mallory })
  announce('short announce, keyset unknown', 'fetch the keyset first', short, alice.address)
  const wrongKid = newRatchet(alice.kemAlg)
  wrongKid.kid = new Uint8Array(8)
  const notKem = Key.generate(K.ED25519)
  notKem.kid = newRatchet(alice.kemAlg).kid
  for (const [name, rk, asPrivate] of [
    ['ratchet with a wrong kid', wrongKid, false],
    ['ratchet that is not a KEM key', notKem, false],
    ['ratchet carrying its private key', newRatchet(alice.kemAlg), true]
  ]) {
    const b = new Map([
      [M.A_IDENTITY, alice.publicBytes],
      [M.A_SEQUENCE, 12],
      [M.A_RATCHET, rk.toCose(asPrivate)]
    ])
    announce(name, 'an announced ratchet is a public HPKE key carrying its own id', alice.sign(encode(b)), alice.address)
  }
  const noRatchet = new Map([
    [M.A_IDENTITY, alice.publicBytes],
    [M.A_SEQUENCE, 13]
  ])
  announce('announce without a ratchet', 'an announce must carry a ratchet', alice.sign(encode(noRatchet)), alice.address)

  const a16 = new Uint8Array(16).fill(1)
  for (const [name, frame] of [
    ['future protocol version', encode([1, P.DATA, 0, a16, null, new Uint8Array()])],
    ['unknown packet type', encode([P.VERSION, 99, 0, a16, null, new Uint8Array()])],
    ['short address', encode([P.VERSION, P.DATA, 0, new Uint8Array(8).fill(1), null, new Uint8Array()])]
  ]) {
    out.push({ kind: 'packet', name, rule: 'drop malformed frames', data: toHex(frame) })
  }

  const pending = L.makeRequest(alice, bob.public(), rb.public())
  out.push({ kind: 'link_request', name: 'link request for someone else', rule: 'a request must name us as the peer', me: ident(carol), ratchets: [hexKey(rc)], known: [toHex(alice.publicBytes)], data: toHex(M.envelope(cose.decrypt0(pending.request, rb), rc.public())) })
  const other = L.makeRequest(alice, bob.public(), rb.public())
  const { accept } = L.acceptRequest(bob, other.request, byAddr([alice.public()]), [rb], false)
  out.push({ kind: 'link_accept', name: 'accept for a different request', rule: 'the accept is bound to SHA-256(request)', request: toHex(pending.request), ephemeral: hexKey(pending.ephemeral), data: toHex(concat(pending.linkId, accept.slice(L.LINK_ID_SIZE))) })
  out.push({ kind: 'road_auth', name: 'frame under another road key', rule: 'drop frames that fail road auth', passphrase: 'right', mode: 'mac', data: toHex(P.RoadAuth.fromPassphrase('wrong', 'mac').wrap(new Uint8Array([0x80]))) })
  return out
}
