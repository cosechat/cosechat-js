// Raw 802.11 management-frame road (JS).
//
// Each cosechat frame rides one vendor-specific action frame (category 127,
// OUI 0xCC-0C-05) addressed to broadcast.  No association, no auth.
//
// Bits on the wire: [mgmt-hdr 24][cat=127][OUI 3][payload <=252]
//   addr1 = ff:ff:ff:ff:ff:ff   addr2 = random local MAC   addr3 = broadcast
//
// Real transport is Linux AF_PACKET raw socket.  On other platforms the
// road is codec-only; use MemoryHub for tests/simulation.
//
//    import { MemoryHub } from 'cosechat/roads/memory'
//    const hub = new MemoryHub()
//    node.addRoad(hub.road({ mtu: WIFI_MTU }))

import { randomBytes } from 'node:crypto'
import { Road } from './road.js'

// 802.11 management frame constants
const HDR = 24
const ACTION = 4
const CATEGORY = 127
const OUI = new Uint8Array([0xcc, 0x0c, 0x05])
const FRAME_MAX = 280
export const WIFI_MTU = FRAME_MAX - HDR - ACTION // 252
const BROADCAST = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])

function randomMAC() {
  const mac = randomBytes(6)
  mac[0] = (mac[0] & 0xfc) | 0x02
  return mac
}

// Wrap payload in an 802.11 vendor-specific action frame.
export function encode(payload, src = null) {
  if (payload.byteLength > WIFI_MTU) throw new Error(`payload ${payload.byteLength} > WIFI_MTU ${WIFI_MTU}`)
  src = src || randomMAC()
  const frame = new Uint8Array(HDR + ACTION + payload.byteLength)
  frame[0] = 0xd0 // mgmt + action
  frame.set(BROADCAST, 4) // addr1 DA
  frame.set(src, 10) // addr2 SA
  frame.set(BROADCAST, 16) // addr3 BSSID
  frame[HDR] = CATEGORY
  frame[HDR + 1] = OUI[0]
  frame[HDR + 2] = OUI[1]
  frame[HDR + 3] = OUI[2]
  frame.set(payload, HDR + ACTION)
  return frame
}

// Extract payload from an 802.11 action frame, or null.
export function decode(frame) {
  if (frame.byteLength < HDR + ACTION) return null
  if ((frame[0] & 0xfc) !== 0xd0) return null
  for (let i = 0; i < 6; i++) if (frame[4 + i] !== 0xff) return null
  if (frame[HDR] !== CATEGORY) return null
  if (frame[HDR + 1] !== OUI[0] || frame[HDR + 2] !== OUI[1] || frame[HDR + 3] !== OUI[2]) return null
  const payload = frame.slice(HDR + ACTION)
  return payload.byteLength <= WIFI_MTU ? payload : null
}

// Road
export class RawWifiRoad extends Road {
  constructor({ interface: iface = null, channel = 1, name = null } = {}) {
    super({ name: name || 'wifi-raw', mtu: WIFI_MTU })
    this.interface = iface
    this.channel = channel
    this.src = randomMAC()
  }

  // Node has no AF_PACKET, so this road cannot reach the air from JavaScript.
  // The codec above is what a caller needs to build a real transport (a native
  // addon, a helper process, or an ESP32 on a serial port); until then, use
  // MemoryHub with the same MTU.
  async start() {
    throw new Error(`${this}: raw 802.11 needs AF_PACKET, which Node does not expose. ` + `Use MemoryHub for emulation, or the Python road (or a native helper) ` + `behind this codec.`)
  }
}
