import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as cose from '../src/cose.js'
import { decode } from '../src/cbor.js'
import { Key, CoseError, ED25519, ESP256, ML_DSA_65, HMAC_256_256, A256GCM, HPKE_0, HPKE_4, HPKE_9, HPKE_12, HPKE_13, HPKE_1, HPKE_2, HPKE_3, HPKE_7, CHACHA20_POLY1305 } from '../src/keys.js'
import { toHex, utf8 } from '../src/bytes.js'
import { vectors, h } from './helpers.js'

const key = (hex) => Key.fromCose(decode(h(hex)))

for (const v of vectors.cose) {
  test(`python vector ${v.op} ${v.alg}`, () => {
    const aad = h(v.external_aad)
    let out
    if (v.op === 'verify_sign') out = cose.verifySign(h(v.data), v.keys.map(key), aad)
    else {
      const fn = { verify_sign1: cose.verifySign1, verify_mac0: cose.verifyMac0, decrypt0: cose.decrypt0, decrypt: cose.decrypt, verify_mac: cose.verifyMac }[v.op]
      out = fn(h(v.data), key(v.key), aad)
    }
    assert.equal(toHex(out), v.expect)
  })
}

const payload = utf8('cosechat payload')

test('sign1 round trip and tamper', () => {
  for (const alg of [ED25519, ESP256, ML_DSA_65]) {
    const k = Key.generate(alg, utf8('me'))
    const s = cose.sign1(payload, k, { externalAad: utf8('x') })
    assert.deepEqual(cose.verifySign1(s, k.public(), utf8('x')), payload)
    assert.throws(() => cose.verifySign1(s, k.public(), utf8('y')), CoseError)
  }
})

test('sign with several keys needs all', () => {
  const a = Key.generate(ED25519)
  const b = Key.generate(ML_DSA_65)
  const s = cose.sign(payload, [a, b])
  assert.deepEqual(cose.verifySign(s, [a.public(), b.public()]), payload)
  assert.throws(() => cose.verifySign(cose.sign(payload, [a]), [a, b]), CoseError)
})

test('mac0 and encrypt0 with shared keys', () => {
  const m = Key.generate(HMAC_256_256)
  assert.deepEqual(cose.verifyMac0(cose.mac0(payload, m), m), payload)
  for (const alg of [A256GCM, CHACHA20_POLY1305]) {
    const k = Key.generate(alg)
    assert.deepEqual(cose.decrypt0(cose.encrypt0(payload, k, { externalAad: utf8('a') }), k, utf8('a')), payload)
    assert.throws(() => cose.decrypt0(cose.encrypt0(payload, k), k, utf8('a')), CoseError)
  }
})

test('HPKE suites: encrypt0, encrypt, mac', () => {
  for (const alg of [HPKE_0, HPKE_1, HPKE_2, HPKE_3, HPKE_4, HPKE_7, HPKE_9, HPKE_12, HPKE_13]) {
    const k = Key.generate(alg)
    const pub = k.public()
    assert.deepEqual(cose.decrypt0(cose.encrypt0(payload, pub), k), payload)
    const other = Key.generate(alg)
    const e = cose.encrypt(payload, [other.public(), pub])
    assert.deepEqual(cose.decrypt(e, k), payload)
    assert.deepEqual(cose.decrypt(e, other), payload)
    assert.deepEqual(cose.verifyMac(cose.mac(payload, [pub]), k), payload)
    assert.throws(() => cose.decrypt0(cose.encrypt0(payload, other.public()), k), CoseError)
  }
})

test('public keys derive like python', () => {
  for (const v of vectors.cose.filter((v) => v.key)) {
    const k = key(v.key)
    if (k.priv && k.pub.length) assert.equal(toHex(Key.fromPrivate(k.alg, k.priv).pub), toHex(k.pub), v.alg)
  }
})
