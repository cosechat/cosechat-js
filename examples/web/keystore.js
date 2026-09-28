// A tiny IndexedDB key-value store for the web example's keys (identity and
// ratchets). They are stored as they are: readable by anything running on
// this origin, and cleared with the site's data. Fine for a tester; a real app
// should encrypt them (see examples/storage.js for a passphrase lock).

export class KeyStore {
  constructor(db) {
    this.db = db
  }

  static open(name = 'cosechat') {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(name, 1)
      req.onupgradeneeded = () => req.result.createObjectStore('kv')
      req.onsuccess = () => resolve(new KeyStore(req.result))
      req.onerror = () => reject(req.error)
    })
  }

  _tx(mode, fn) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('kv', mode)
      const req = fn(tx.objectStore('kv'))
      tx.oncomplete = () => resolve(req.result)
      tx.onerror = () => reject(tx.error)
    })
  }

  async get(k) {
    const v = await this._tx('readonly', (s) => s.get(k))
    return v == null ? undefined : new Uint8Array(v)
  }

  set(k, v) {
    return this._tx('readwrite', (s) => (v === undefined ? s.delete(k) : s.put(v, k)))
  }
}
