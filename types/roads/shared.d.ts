import { Road } from './road.js'

/** One physical road, several nodes (identities) on this device. */
export class SharedRoad {
  constructor(road: Road)
  road: Road
  branches: Branch[]
  branch(name?: string | null): Branch
}
export class Branch extends Road {
  shared: SharedRoad
}
