import hash from 'hash.js'
import { keccak_256 } from 'js-sha3' // eslint-disable-line
import { Buffer } from 'buffer'

export function sha256 (payload) {
  return Buffer.from(hash.sha256().update(payload).digest())
}

export function keccak (data) {
  return Buffer.from(keccak_256.buffer(data))
}

export function toEthereumAddress (hexPublicKey) {
  return `0x${keccak(Buffer.from(hexPublicKey.slice(2), 'hex')).slice(-20).toString('hex')}`
}
