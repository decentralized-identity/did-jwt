import { hash } from '@stablelib/sha256'
import * as u8a from 'uint8arrays'
import { keccak_256 } from 'js-sha3' // eslint-disable-line

export function sha256(payload: string | Uint8Array): Uint8Array {
  const data = typeof payload === 'string' ? u8a.fromString(payload) : payload
  return hash(data)
}

export function keccak(data: Uint8Array): Uint8Array {
  return new Uint8Array(keccak_256.arrayBuffer(data))
}

export function toEthereumAddress(hexPublicKey: string): string {
  const hashInput = u8a.fromString(hexPublicKey.slice(2), 'base16')
  return `0x${u8a.toString(keccak(hashInput).slice(-20), 'base16')}`
}

function writeUint32BE(value: number, array = new Uint8Array(4)): Uint8Array {
  const encoded = u8a.fromString(value.toString(), 'base10')
  array.set(encoded, 4 - encoded.length)
  return array
}

const lengthAndInput = (input: Uint8Array): Uint8Array => u8a.concat([writeUint32BE(input.length), input])

// This implementation of concatKDF was inspired by these two implementations:
// https://github.com/digitalbazaar/minimal-cipher/blob/master/algorithms/ecdhkdf.js
// https://github.com/panva/jose/blob/master/lib/jwa/ecdh/derive.js
export function concatKDF(
  secret: Uint8Array,
  keyLen: number,
  alg: string,
  producerInfo?: Uint8Array,
  consumerInfo?: Uint8Array
): Uint8Array {
  if (keyLen !== 256) throw new Error(`Unsupported key length: ${keyLen}`)
  const value = u8a.concat([
    lengthAndInput(u8a.fromString(alg)),
    lengthAndInput(typeof producerInfo === 'undefined' ? new Uint8Array(0) : producerInfo), // apu
    lengthAndInput(typeof consumerInfo === 'undefined' ? new Uint8Array(0) : consumerInfo), // apv
    writeUint32BE(keyLen),
  ])

  // since our key lenght is 256 we only have to do one round
  const roundNumber = 1
  return hash(u8a.concat([writeUint32BE(roundNumber), secret, value]))
}
