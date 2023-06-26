import { concat, fromString, toString } from 'uint8arrays'
import { bases } from 'multiformats/basics'
import { x25519 } from '@noble/curves/ed25519'
import type { EphemeralKeyPair } from './encryption/types.js'

const u8a = { toString, fromString, concat }

/**
 * @deprecated Signers will be expected to return base64url `string` signatures.
 */
export interface EcdsaSignature {
  r: string
  s: string
  recoveryParam?: number
}

/**
 * @deprecated Signers will be expected to return base64url `string` signatures.
 */
export type ECDSASignature = {
  compact: Uint8Array
  recovery?: number
}

export type JsonWebKey = {
  crv: string
  kty: string
  x?: string
  y?: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any
}

export function bytesToBase64url(b: Uint8Array): string {
  return u8a.toString(b, 'base64url')
}

export function base64ToBytes(s: string): Uint8Array {
  const inputBase64Url = s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  return u8a.fromString(inputBase64Url, 'base64url')
}

export function bytesToBase64(b: Uint8Array): string {
  return u8a.toString(b, 'base64pad')
}

export function base58ToBytes(s: string): Uint8Array {
  return u8a.fromString(s, 'base58btc')
}

export function bytesToBase58(b: Uint8Array): string {
  return u8a.toString(b, 'base58btc')
}

export function bytesToMultibase(b: Uint8Array, base: keyof typeof bases): string {
  return bases[base].encode(b)
}

export function hexToBytes(s: string, minLength?: number): Uint8Array {
  let input = s.startsWith('0x') ? s.substring(2) : s

  if (input.length % 2 !== 0) {
    input = `0${input}`
  }

  if (minLength) {
    const paddedLength = Math.max(input.length, minLength * 2)
    input = input.padStart(paddedLength, '00')
  }

  return u8a.fromString(input.toLowerCase(), 'base16')
}

export function encodeBase64url(s: string): string {
  return bytesToBase64url(u8a.fromString(s))
}

export function decodeBase64url(s: string): string {
  return u8a.toString(base64ToBytes(s))
}

export function bytesToHex(b: Uint8Array): string {
  return u8a.toString(b, 'base16')
}

export function bytesToBigInt(b: Uint8Array): bigint {
  return BigInt(`0x` + u8a.toString(b, 'base16'))
}

export function bigintToBytes(n: bigint, minLength?: number): Uint8Array {
  return hexToBytes(n.toString(16), minLength)
}

export function stringToBytes(s: string): Uint8Array {
  return u8a.fromString(s)
}

export function toJose({ r, s, recoveryParam }: EcdsaSignature, recoverable?: boolean): string {
  const jose = new Uint8Array(recoverable ? 65 : 64)
  jose.set(u8a.fromString(r, 'base16'), 0)
  jose.set(u8a.fromString(s, 'base16'), 32)
  if (recoverable) {
    if (typeof recoveryParam === 'undefined') {
      throw new Error('Signer did not return a recoveryParam')
    }
    jose[64] = <number>recoveryParam
  }
  return bytesToBase64url(jose)
}

export function fromJose(signature: string): { r: string; s: string; recoveryParam?: number } {
  const signatureBytes: Uint8Array = base64ToBytes(signature)
  if (signatureBytes.length < 64 || signatureBytes.length > 65) {
    throw new TypeError(`Wrong size for signature. Expected 64 or 65 bytes, but got ${signatureBytes.length}`)
  }
  const r = bytesToHex(signatureBytes.slice(0, 32))
  const s = bytesToHex(signatureBytes.slice(32, 64))
  const recoveryParam = signatureBytes.length === 65 ? signatureBytes[64] : undefined
  return { r, s, recoveryParam }
}

export function toSealed(ciphertext: string, tag?: string): Uint8Array {
  return u8a.concat([base64ToBytes(ciphertext), tag ? base64ToBytes(tag) : new Uint8Array(0)])
}

export function leftpad(data: string, size = 64): string {
  if (data.length === size) return data
  return '0'.repeat(size - data.length) + data
}

/**
 * Generate random x25519 key pair.
 */
export function generateKeyPair(): { secretKey: Uint8Array; publicKey: Uint8Array } {
  const secretKey = x25519.utils.randomPrivateKey()
  const publicKey = x25519.getPublicKey(secretKey)
  return {
    secretKey: secretKey,
    publicKey: publicKey,
  }
}

/**
 * Generate private-public x25519 key pair from `seed`.
 */
export function generateKeyPairFromSeed(seed: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array } {
  if (seed.length !== 32) {
    throw new Error(`x25519: seed must be ${32} bytes`)
  }
  return {
    publicKey: x25519.getPublicKey(seed),
    secretKey: seed,
  }
}

export function genX25519EphemeralKeyPair(): EphemeralKeyPair {
  const epk = generateKeyPair()
  return {
    publicKeyJWK: { kty: 'OKP', crv: 'X25519', x: bytesToBase64url(epk.publicKey) },
    secretKey: epk.secretKey,
  }
}
