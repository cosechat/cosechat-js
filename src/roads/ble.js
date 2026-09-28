// Anonymous BLE extended-advertising road (JS).
//
// Each cosechat frame rides one BLE 5 extended advertisement as
// manufacturer-specific data (company id 0xFFFF): non-connectable,
// non-scannable, no GATT, no bonding.  On the wire each advertisement carries
// at most 251 bytes of AD data; with the AD header (2) and company id (2) that
// leaves BLE_MTU (247) bytes for one road frame, so what a node transmits is
// exactly encode(frame) -- the same bytes the C reference (road_ble.cpp) puts
// on the air, so the two interoperate.
//
// Requirements: Linux + BlueZ + the pure-JS `dbus-next` package (`npm i
// dbus-next`).  Both directions go through BlueZ's D-Bus API:
//
//   TX  register an org.bluez.LEAdvertisement1 whose ManufacturerData is
//       { 0xFFFF: frame }, hold it, unregister.  BlueZ builds the AD
//       structure, so the air bytes match encode().
//   RX  ask BlueZ to discover, and read ManufacturerData off the Device1
//       objects it reports.
//
// Extended advertising needs a controller/kernel that supports it (BlueZ
// reports the ceiling as LEAdvertisingManager1.SupportedCapabilities.MaxAdvLen;
// we need 251).  Honest gap vs the ESP32 road: BlueZ always puts the adapter
// address in the advertisement, so a host node is not address-less the way
// road_ble.cpp's setAnonymous(true) makes the ESP32 one.  It is still
// non-connectable and carries nothing but the frame.
//
// For tests/simulation use MemoryHub with the right MTU.

import { Road } from './road.js'

export const COMPANY_ID = 0xffff
export const ADV_MAX = 251
export const BLE_MTU = ADV_MAX - 4 // 247
const AD_TYPE_MANUFACTURER = 0xff

const BLUEZ = 'org.bluez'
const ADV_IFACE = 'org.bluez.LEAdvertisement1'
const MGR_IFACE = 'org.bluez.LEAdvertisingManager1'
const ADAPTER_IFACE = 'org.bluez.Adapter1'
const DEVICE_IFACE = 'org.bluez.Device1'
const PROPS_IFACE = 'org.freedesktop.DBus.Properties'
const OM_IFACE = 'org.freedesktop.DBus.ObjectManager'

const isLinux = process.platform === 'linux'

// Wrap a road frame in a Manufacturer-Specific AD structure (what goes on air).
export function encode(frame) {
  if (frame.byteLength > BLE_MTU) throw new Error(`frame ${frame.byteLength} > BLE_MTU ${BLE_MTU}`)
  const ad = new Uint8Array(4 + frame.byteLength)
  ad[0] = 3 + frame.byteLength // length (type + company id + data)
  ad[1] = AD_TYPE_MANUFACTURER
  ad[2] = COMPANY_ID & 0xff
  ad[3] = (COMPANY_ID >>> 8) & 0xff
  ad.set(frame, 4)
  return ad
}

// Extract a road frame from a Manufacturer-Specific AD, or null.
export function decode(ad) {
  if (ad.byteLength < 5) return null
  const len = ad[0]
  if (len + 1 > ad.byteLength) return null
  if (ad[1] !== AD_TYPE_MANUFACTURER) return null
  if (len < 3) return null
  const cid = ad[2] | (ad[3] << 8)
  if (cid !== COMPANY_ID) return null
  const frame = ad.slice(4, len + 1)
  return frame.byteLength <= BLE_MTU ? frame : null
}

async function loadDbus() {
  try {
    return await import('dbus-next')
  } catch {
    throw new Error('the BLE road needs dbus-next: npm install dbus-next')
  }
}

export class BlueZ {
  // BlueZ over D-Bus: advertise one frame at a time, and scan for frames.
  constructor({ adapter = null, secondary = null, txPower = null, dbus = null } = {}) {
    this.adapter = adapter
    this.secondary = secondary
    this.txPower = txPower
    this._dbus = dbus
    this._bus = null
    this._path = null
    this._advPath = null
    this.maxAdvLen = null
    this._onFrame = null
    this._discovering = false
  }

  static get available() {
    return isLinux
  }

  async open() {
    if (!this.constructor.available) throw new Error('BLE needs Linux + BlueZ')
    const dbus = this._dbus || (await loadDbus())
    this._dbus = dbus
    this._bus = dbus.systemBus()
    this._path = await this._findAdapter()
    const caps = await this._getProperty(MGR_IFACE, 'SupportedCapabilities')
    this.maxAdvLen = caps ? caps.MaxAdvLen : null
    if (this.maxAdvLen != null && this.maxAdvLen < BLE_MTU + 4) throw new Error(`${this._path} advertises at most ${this.maxAdvLen} AD bytes; the road needs ${BLE_MTU + 4} (extended advertising)`)
    if (this.secondary == null) {
      const channels = (await this._getProperty(MGR_IFACE, 'SupportedSecondaryChannels')) || []
      // a secondary channel selects an extended advertising set, which is what a
      // 251-byte advertisement needs; prefer the most compatible PHY
      this.secondary = ['1M', '2M', 'Coded'].find((p) => channels.includes(p)) || null
    }
  }

  async _findAdapter() {
    if (this.adapter) return this.adapter.startsWith('/') ? this.adapter : `/org/bluez/${this.adapter}`
    for (let i = 0; i < 8; i++) {
      const path = `/org/bluez/hci${i}`
      try {
        const value = await this._getProperty(MGR_IFACE, 'SupportedInstances', path)
        if (value != null) return path
      } catch {
        // no adapter there
      }
    }
    throw new Error(`no BlueZ adapter with ${MGR_IFACE}`)
  }

  async _getProperty(iface, name, path = null) {
    const proxy = await this._bus.getProxyObject(BLUEZ, path || this._path)
    const props = proxy.getInterface(PROPS_IFACE)
    const variant = await props.Get(iface, name)
    return variant ? variant.value : null
  }

  // The advertisement object, implemented at the message level so there is no
  // decorator/Babel step: BlueZ reads it with org.freedesktop.DBus.Properties.
  _properties(frame) {
    const { Variant } = this._dbus
    return {
      Type: new Variant('s', 'broadcast'),
      ManufacturerData: new Variant('a{qv}', { [COMPANY_ID]: new Variant('ay', Buffer.from(frame)) }),
      SecondaryChannel: new Variant('s', this.secondary || '1M'),
      TxPower: new Variant('n', this.txPower != null ? this.txPower : 0)
    }
  }

  // Broadcast `frame` for `seconds` seconds.
  async advertise(frame, seconds) {
    if (!this._bus) throw new Error('advertiser is not open')
    if (frame.byteLength > BLE_MTU) throw new Error(`frame ${frame.byteLength} > BLE_MTU ${BLE_MTU}`)
    const { Message } = this._dbus
    const path = `/com/cosechat/ble/${process.hrtime.bigint().toString(36)}`
    const properties = this._properties(frame)
    this._advPath = path
    this._advProperties = properties
    const handler = (msg) => {
      if (msg.path !== path) return false
      if (msg.interface === PROPS_IFACE && msg.member === 'GetAll') {
        this._bus.send(Message.newMethodReturn(msg, 'a{sv}', [properties]))
        return true
      }
      if (msg.interface === PROPS_IFACE && msg.member === 'Get') {
        const want = properties[msg.body[1]]
        if (!want) return false
        this._bus.send(Message.newMethodReturn(msg, 'v', [want]))
        return true
      }
      if (msg.interface === ADV_IFACE && msg.member === 'Release') return true // [noreply]
      return false
    }
    const remove = this._bus.addMethodHandler ? this._bus.addMethodHandler(handler) : null
    try {
      const proxy = await this._bus.getProxyObject(BLUEZ, this._path)
      const mgr = proxy.getInterface(MGR_IFACE)
      await mgr.RegisterAdvertisement(path, {})
      await new Promise((resolve) => setTimeout(resolve, seconds * 1000))
      await mgr.UnregisterAdvertisement(path)
    } finally {
      this._advPath = null
      if (typeof remove === 'function') remove()
    }
  }

  // Scan for advertisements carrying our manufacturer id; call `onFrame` with
  // each road frame.
  async scan(onFrame) {
    this._onFrame = onFrame
    const proxy = await this._bus.getProxyObject(BLUEZ, '/')
    const objects = proxy.getInterface(OM_IFACE)
    objects.on('InterfacesAdded', (path, interfaces) => {
      const device = interfaces ? interfaces[DEVICE_IFACE] : null
      if (device) this._device(device)
    })
    const adapter = (await this._bus.getProxyObject(BLUEZ, this._path)).getInterface(ADAPTER_IFACE)
    const { Variant } = this._dbus
    try {
      // DuplicateData keeps repeated advertisements of the same fragment coming
      await adapter.SetDiscoveryFilter({ Transport: new Variant('s', 'le'), DuplicateData: new Variant('b', true) })
    } catch {
      // older BlueZ: no filter, we filter in _device
    }
    await adapter.StartDiscovery()
    this._discovering = true
    return () => this.stopScan()
  }

  async stopScan() {
    if (!this._discovering) return
    this._discovering = false
    try {
      const adapter = (await this._bus.getProxyObject(BLUEZ, this._path)).getInterface(ADAPTER_IFACE)
      await adapter.StopDiscovery()
    } catch {
      // already stopped
    }
  }

  _device(device) {
    const data = device.ManufacturerData
    if (!data || !this._onFrame) return
    const entry = data[COMPANY_ID]
    if (!entry) return
    const value = entry.value !== undefined ? entry.value : entry
    this._onFrame(new Uint8Array(Buffer.from(value)))
  }

  async close() {
    await this.stopScan()
    if (this._bus && typeof this._bus.disconnect === 'function') {
      try {
        this._bus.disconnect()
      } catch {
        // already gone
      }
    }
    this._bus = null
    this._path = null
  }
}

export class BLERoad extends Road {
  constructor({ adapter = null, advMs = 250, txPower = null, secondary = null, dbus = null, name = null } = {}) {
    super({ name: name || 'ble', mtu: BLE_MTU })
    this.bitrate = 1_000_000 // 1 Mbps BLE PHY
    this.advMs = advMs
    this.bluez = new BlueZ({ adapter, secondary, txPower, dbus })
    this.txReady = false
    this._stopScan = null
  }

  get adapter() {
    return this.bluez.adapter
  }

  async start() {
    if (BlueZ.available) {
      try {
        await this.bluez.open()
        this.txReady = true
        this._stopScan = await this.bluez.scan((frame) => this._deliver(frame))
      } catch (e) {
        console.warn(`${this}: BLE transport unavailable: ${e.message}`)
      }
    } else {
      console.warn(`${this}: BLE needs Linux + BlueZ; use MemoryHub for emulation`)
    }
    await super.start()
  }

  async stop() {
    await super.stop()
    await this.bluez.close()
    this.txReady = false
  }

  async send(frame) {
    if (!this.txReady) throw new Error(`${this}: no BLE advertiser (needs Linux, BlueZ, and an adapter that supports extended advertising). Use MemoryHub for emulation.`)
    await this.bluez.advertise(frame, this.advMs / 1000)
  }
}
