import { test } from 'node:test'
import assert from 'node:assert/strict'
import { check } from '../src/vectors.js'
import { vectors } from './helpers.js'

test('python reference vectors all pass', () => {
  assert.deepEqual(check(vectors), [])
})

for (const section of ['identities', 'messages', 'announces', 'packets', 'links', 'road_auth', 'exact', 'reject']) {
  test(`vectors: ${section}`, () => {
    assert.deepEqual(check({ [section === 'messages' || section === 'announces' ? 'identities' : '_']: vectors.identities, [section]: vectors[section] }), [])
  })
}
