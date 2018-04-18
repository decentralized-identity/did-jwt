import { sha256 as sha256js } from 'js-sha256'
import { keccak_256 } from 'js-sha3'
import { Buffer } from 'buffer'

export function sha256 (payload) {
  return Buffer.from(sha256js.arrayBuffer(payload))
}

export function keccak (data) {
  return Buffer.from(keccak_256.buffer(data))
}

export function toEthereumAddress (hexPublicKey) {
  return `0x${keccak(Buffer.from(hexPublicKey.slice(2), 'hex')).slice(-20).toString('hex')}`
}
