import { sha256 as sha256Hash } from '@noble/hashes/sha256'
export { ripemd160 } from '@noble/hashes/ripemd160'
import { keccak_256 } from '@noble/hashes/sha3'
import { fromString, toString, concat } from 'uint8arrays'

export function sha256(payload: string | Uint8Array): Uint8Array {
  const data = typeof payload === 'string' ? fromString(payload) : payload
  return sha256Hash(data)
}

export const keccak = keccak_256

export function toEthereumAddress(hexPublicKey: string): string {
  const hashInput = fromString(hexPublicKey.slice(2), 'base16')
  return `0x${toString(keccak(hashInput).slice(-20), 'base16')}`
}

function writeUint32BE(value: number, array = new Uint8Array(4)): Uint8Array {
  const encoded = fromString(value.toString(), 'base10')
  array.set(encoded, 4 - encoded.length)
  return array
}

const lengthAndInput = (input: Uint8Array): Uint8Array => concat([writeUint32BE(input.length), input])

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
  const value = concat([
    lengthAndInput(fromString(alg)),
    lengthAndInput(typeof producerInfo === 'undefined' ? new Uint8Array(0) : producerInfo), // apu
    lengthAndInput(typeof consumerInfo === 'undefined' ? new Uint8Array(0) : consumerInfo), // apv
    writeUint32BE(keyLen),
  ])

  // since our key lenght is 256 we only have to do one round
  const roundNumber = 1
  return sha256(concat([writeUint32BE(roundNumber), secret, value]))
}
