import { hash } from '@stablelib/sha256'
import { concat, fromString } from 'uint8arrays'
import sha3 from 'js-sha3'
import { bytesToHex, hexToBytes } from './util.js'
import { Ripemd160 } from './blockchains/utils/ripemd160.js'

export function sha256(payload: string | Uint8Array): Uint8Array {
  const data = typeof payload === 'string' ? fromString(payload, 'utf-8') : payload
  return hash(data)
}

export function keccak(data: Uint8Array): Uint8Array {
  return new Uint8Array(sha3.keccak_256.arrayBuffer(data))
}

export function toEthereumAddress(hexPublicKey: string): string {
  const hashInput = hexToBytes(hexPublicKey.slice(2))
  return `0x${bytesToHex(keccak(hashInput).slice(-20))}`
}

export function ripemd160(data: Uint8Array): Uint8Array {
  return new Ripemd160().update(data).digest()
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
    lengthAndInput(fromString(alg, 'utf-8')),
    lengthAndInput(typeof producerInfo === 'undefined' ? new Uint8Array(0) : producerInfo), // apu
    lengthAndInput(typeof consumerInfo === 'undefined' ? new Uint8Array(0) : consumerInfo), // apv
    writeUint32BE(keyLen),
  ])

  // since our key lenght is 256 we only have to do one round
  const roundNumber = 1
  return sha256(concat([writeUint32BE(roundNumber), secret, value]))
}
