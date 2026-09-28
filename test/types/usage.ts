// Type-checked with `npm run types`: the declarations compile, and the
// documented usage type-checks against them.
import { Identity, MemoryRatchets, Node, RoadAuth, contact, type Announce, type Message } from 'cosechat'
import { WebSocketClientRoad } from 'cosechat/roads/websocket'
import { RNodeRoad } from 'cosechat/roads/rnode'
import { MemoryHub } from 'cosechat/roads/memory'
import * as cose from 'cosechat/cose'
import * as msg from 'cosechat/message'
import { Key, ED25519, HPKE_9 } from 'cosechat/keys'

async function main(address: Uint8Array) {
  const identity = Identity.generate('pq')
  const node = new Node({ identity, appData: new Map([['name', 'alice']]), ratchets: new MemoryRatchets(identity.kemAlg), retryAfter: 10 })
  const road = new WebSocketClientRoad('ws://localhost:4243')
  road.onStatus = (up: boolean) => {
    if (up) void node.announce({ full: true })
  }
  node.addRoad(road, RoadAuth.fromPassphrase('secret', 'mac'))
  node.addRoad(new MemoryHub().road({ mtu: 255 }))
  node.addRoad(new RNodeRoad('/dev/ttyUSB0', { frequency: 868e6, sf: 8 }))
  const off = node.onMessage((m: Message) => console.log(contact.addressText(m.sender), m.content, m.linkId !== null))
  node.onAnnounce((a: Announce, path) => console.log(a.appData, path.hops, a.identity.quantumSafe))
  node.onResource((r) => console.log(r.data.length, r.meta))
  await node.start()
  const m = await node.send(address, 'hello', { title: 'hi', fields: new Map([[1, new Uint8Array(3)]]) })
  const ok: boolean = await node.delivered(m, 30)
  const keys = await node.openLink(address)
  const sent: boolean = await node.sendResource(address, new Uint8Array(5000), { meta: 'blob' })
  const card: string = contact.cardUri(node.contactCard())
  node.addContact(contact.cardFromUri(card))
  const n: number = await node.fetch({ timeout: 20 })
  off()
  await node.stop()

  const k = Key.generate(ED25519)
  const payload: Uint8Array = cose.verifySign1(cose.sign1(new Uint8Array([1]), k), k.public())
  const r = Key.generate(HPKE_9)
  cose.decrypt0(cose.encrypt0(payload, r.public()), r)
  const { sealed } = msg.seal(identity, [identity.public()], { content: 'x', ratchets: () => r })
  return [ok, keys.linkId, sent, n, sealed]
}
void main
