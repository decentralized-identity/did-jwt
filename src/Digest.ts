import { hash } from '@stablelib/sha256'
import * as u8a from 'uint8arrays'
import { keccak_256 } from 'js-sha3' // eslint-disable-line

export function sha256(payload: string): Uint8Array {
  return hash(u8a.fromString(payload))
}

export function keccak(data: Uint8Array): Uint8Array {
  return new Uint8Array(keccak_256.arrayBuffer(data))
}

export function toEthereumAddress(hexPublicKey: string): string {
  const hashInput = u8a.fromString(hexPublicKey.slice(2), 'base16')
  return `0x${u8a.toString(keccak(hashInput).slice(-20), 'base16')}`
}
