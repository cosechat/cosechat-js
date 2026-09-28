// Interop vectors: check() verifies a vector file (from the Python reference
// or any other implementation) and returns the failures; exact() rebuilds
// the byte-exact cases from their inputs.

import { equal, fromHex, toHex, utf8 } from './bytes.js'
import { decode, encode } from './cbor.js'
import * as cose from './cose.js'
import { Identity } from './identity.js'
import { A256GCM, ED25519, HMAC_256_256, HPKE_0, Key } from './keys.js'
import * as L from './link.js'
import * as M from './message.js'
import * as P from './packet.js'
import { ratchetId } from './ratchet.js'

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
