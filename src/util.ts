import * as u8a from 'uint8arrays'

export interface EcdsaSignature {
  r: string
  s: string
  recoveryParam?: number
}

export function bytesToBase64url(b: Uint8Array): string {
  return u8a.toString(b, 'base64url')
}

export function base64urlToBytes(s: string): Uint8Array {
  return u8a.fromString(s, 'base64url')
}

export function base64ToBytes(s: string): Uint8Array {
  return u8a.fromString(s, 'base64pad')
}

export function bytesToBase64(b: Uint8Array): string {
  return u8a.toString(b, 'base64pad')
}

export function base58ToBytes(s: string): Uint8Array {
  return u8a.fromString(s, 'base58btc')
}

export function encodeBase64url(s: string): string {
  return bytesToBase64url(u8a.fromString(s))
}

export function decodeBase64url(s: string): string {
  return u8a.toString(base64urlToBytes(s))
}

export function bytesToHex(b: Uint8Array): string {
  return u8a.toString(b, 'base16')
}

export function toJose({ r, s, recoveryParam }: EcdsaSignature, recoverable?: boolean): string {
  const jose = new Uint8Array(recoverable ? 65 : 64)
  jose.set(u8a.fromString(r, 'base16'), 0)
  jose.set(u8a.fromString(s, 'base16'), 32)
  if (recoverable) {
    if (recoveryParam === undefined) {
      throw new Error('Signer did not return a recoveryParam')
    }
    jose[64] = recoveryParam
  }
  return bytesToBase64url(jose)
}

export function toSealed(ciphertext: string, tag: string): Uint8Array {
  return u8a.concat([base64urlToBytes(ciphertext), base64urlToBytes(tag)])
}
