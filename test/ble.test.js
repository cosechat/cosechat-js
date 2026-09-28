// The BLE road's BlueZ path, against a fake D-Bus.
//
// No Bluetooth stack in CI, so the D-Bus boundary is faked: a bus object with
// the proxy/interface surface dbus-next exposes, plus Variant/Message.  What
// this pins is the part that would otherwise be untested -- that BlueZ is asked
// to register an advertisement whose ManufacturerData is our frame, that the
// advertisement object answers Properties.GetAll (no decorators/Babel), that
// discovery is started, and that a Device1 with our manufacturer id becomes a
// road frame.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { BLERoad, BlueZ, BLE_MTU, COMPANY_ID, encode, decode } from '../src/roads/ble.js'

const MGR = 'org.bluez.LEAdvertisingManager1'
const PROPS = 'org.freedesktop.DBus.Properties'
const ADAPTER = 'org.bluez.Adapter1'
const OM = 'org.freedesktop.DBus.ObjectManager'
const DEVICE = 'org.bluez.Device1'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

class Variant {
  constructor(signature, value) {
    this.signature = signature
    this.value = value
  }
}

const Message = {
  newMethodReturn: (msg, signature, body) => ({ replySerial: msg.serial, signature, body })
}

const FULL = { caps: { MaxAdvLen: 251 }, channels: ['1M', '2M'] }

function makeBus(adapters) {
  const state = { sent: [], handlers: [], signal: null, registered: [], unregistered: [], discovering: false }
  const info = (path) => {
    const a = adapters[path]
    if (!a) throw new Error(`no object at ${path}`)
    return a
  }
  const bus = {
    state,
    async getProxyObject(name, path) {
      return {
        getInterface(iface) {
          if (iface === PROPS) {
            return {
              Get: async (ifaceName, prop) => {
                const a = info(path)
                if (ifaceName !== MGR) throw new Error(`no ${ifaceName}`)
                if (prop === 'SupportedCapabilities') return new Variant('a{sv}', a.caps)
                if (prop === 'SupportedSecondaryChannels') return new Variant('as', a.channels)
                if (prop === 'SupportedInstances') return new Variant('y', 1)
                return null
              }
            }
          }
          if (iface === MGR) {
            info(path)
            return {
              RegisterAdvertisement: async (p, opts) => state.registered.push([p, opts]),
              UnregisterAdvertisement: async (p) => state.unregistered.push(p)
            }
          }
          if (iface === ADAPTER) {
            info(path)
            return {
              SetDiscoveryFilter: async () => {},
              StartDiscovery: async () => {
                state.discovering = true
              },
              StopDiscovery: async () => {
                state.discovering = false
              }
            }
          }
          if (iface === OM) return { on: (event, cb) => (state.signal = cb) }
          throw new Error(`no ${iface} at ${path}`)
        }
      }
    },
    send: (m) => state.sent.push(m),
    addMethodHandler: (fn) => {
      state.handlers.push(fn)
      return () => state.handlers.splice(state.handlers.indexOf(fn), 1)
    },
    disconnect: () => (state.disconnected = true)
  }
  return bus
}

const fakeDbus = (bus) => ({ systemBus: () => bus, Variant, Message })

// the transport is Linux-only by design; pretend for the test
const onLinux = () => Object.defineProperty(BlueZ, 'available', { value: true, configurable: true })

test('codec roundtrip and MTU', () => {
  const frame = new Uint8Array(BLE_MTU).fill(9)
  assert.equal(encode(frame).byteLength, 251)
  assert.deepEqual(decode(encode(frame)), frame)
  assert.throws(() => encode(new Uint8Array(BLE_MTU + 1)))
  assert.equal(decode(new Uint8Array(4)), null)
})

test('ble advertises the frame and reads frames off advertisements', async () => {
  const bus = makeBus({ '/org/bluez/hci0': FULL })
  const road = new BLERoad({ advMs: 200, dbus: fakeDbus(bus) })
  const got = []
  road.onFrame = (f) => got.push(f)
  onLinux()

  await road.start()
  assert.equal(road.txReady, true)
  assert.equal(bus.state.discovering, true)

  // while the advertisement is live, BlueZ reads its properties
  const frame = new Uint8Array([1, 2, 3, 4, 5])
  const sending = road.send(frame)
  await sleep(30)
  assert.equal(bus.state.registered.length, 1)
  const [advPath, options] = bus.state.registered[0]
  assert.match(advPath, /^\/com\/cosechat\/ble\//)
  assert.deepEqual(options, {})

  const handler = bus.state.handlers[0]
  assert.ok(handler, 'an advertisement object is exported')
  assert.equal(handler({ path: '/somewhere/else', interface: PROPS, member: 'GetAll' }), false)
  assert.ok(handler({ path: advPath, interface: PROPS, member: 'GetAll' }))
  const props = bus.state.sent.pop().body[0]
  assert.equal(props.Type.value, 'broadcast')
  assert.equal(props.SecondaryChannel.value, '1M')
  assert.deepEqual(Buffer.from(props.ManufacturerData.value[COMPANY_ID].value), Buffer.from(frame))
  // Single-property read, as BlueZ does after the first GetAll
  assert.ok(handler({ path: advPath, interface: PROPS, member: 'Get', body: [null, 'ManufacturerData'] }))
  assert.equal(bus.state.sent.pop().signature, 'v')

  await sending
  assert.deepEqual(bus.state.unregistered, [advPath])
  assert.equal(bus.state.handlers.length, 0, 'the advertisement object is gone')

  // and the bytes BlueZ builds are what the C road puts on air
  assert.deepEqual(decode(encode(frame)), frame)

  // a Device1 advertisement carrying our manufacturer id becomes a road frame
  const seen = new Uint8Array([9, 9, 9])
  bus.state.signal('/org/bluez/hci0/dev_AA', {
    [DEVICE]: { ManufacturerData: { [COMPANY_ID]: new Variant('ay', Buffer.from(seen)) } }
  })
  assert.equal(got.length, 1)
  assert.deepEqual(got[0], seen)

  await road.stop()
  assert.equal(bus.state.discovering, false)
  assert.equal(bus.state.disconnected, true)
})

test('ble refuses an adapter that cannot carry an extended advertisement', async () => {
  const bus = makeBus({ '/org/bluez/hci0': { caps: { MaxAdvLen: 31 }, channels: [] } })
  onLinux()
  await assert.rejects(() => new BlueZ({ dbus: fakeDbus(bus) }).open(), /251/)
})

test('ble picks the first adapter that advertises', async () => {
  const bus = makeBus({ '/org/bluez/hci2': FULL })
  onLinux()
  const bluez = new BlueZ({ dbus: fakeDbus(bus) })
  await bluez.open()
  assert.equal(bluez._path, '/org/bluez/hci2')
})

test('ble honours an explicit adapter', async () => {
  const bus = makeBus({ '/org/bluez/hci0': FULL, '/org/bluez/hci1': { caps: { MaxAdvLen: 251 }, channels: ['2M'] } })
  onLinux()
  const bluez = new BlueZ({ adapter: 'hci1', dbus: fakeDbus(bus) })
  await bluez.open()
  assert.equal(bluez._path, '/org/bluez/hci1')
  assert.equal(bluez.secondary, '2M')
})

test('ble send without a transport says so', async () => {
  const road = new BLERoad({ advMs: 1 })
  await assert.rejects(() => road.send(new Uint8Array([1])), /advertiser/)
})
