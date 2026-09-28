// Propagation nodes (like LXMF's): hold messages for peers that are offline,
// and hand them over when those peers ask. Announced with services bit 1.
// Depositing and fetching happen over a link. Link body fields:
//   15  deposit  [recipient address, packet type, payload]   with 6: deposit receipt secret
//   12  fetch    true
//   13  item     [index, packet type, payload]
//   14  end      count
//   16  ack      count

export const SERVICE_PROPAGATION = 1

export const P_FETCH = 12
export const P_ITEM = 13
export const P_END = 14
export const P_DEPOSIT = 15
export const P_ACK = 16

export const FIELDS = new Set([P_FETCH, P_ITEM, P_END, P_DEPOSIT, P_ACK])
export const BATCH = 64 // items handed over per fetch
