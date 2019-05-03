import { sha256 as sha256js, Message } from 'js-sha256'
import { keccak_256 } from 'js-sha3' // eslint-disable-line
import { Buffer } from 'buffer'

export function sha256 (payload: Message): Buffer {
  return Buffer.from(sha256js.arrayBuffer(payload))
}

export function keccak (data: Message): Buffer {
  return Buffer.from(keccak_256.arrayBuffer(data))
}

export function toEthereumAddress (hexPublicKey: string): string {
  return `0x${keccak(Buffer.from(hexPublicKey.slice(2), 'hex')).slice(-20).toString('hex')}`
}
