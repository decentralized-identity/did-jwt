import { EcdsaSignature } from './JWT'
import base64url from 'uport-base64url'

export function base64ToBytes(s: string): Uint8Array {
  return new Uint8Array(Array.prototype.slice.call(Buffer.from(s, 'base64'), 0))
}

export function bytesToBase64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64')
}

export function toJose({ r, s, recoveryParam }: EcdsaSignature, recoverable?: boolean): string {
  const jose: Buffer = Buffer.alloc(recoverable ? 65 : 64)
  Buffer.from(r, 'hex').copy(jose, 0)
  Buffer.from(s, 'hex').copy(jose, 32)
  if (recoverable) {
    if (recoveryParam === undefined) {
      throw new Error('Signer did not return a recoveryParam')
    }
    jose[64] = recoveryParam
  }
  return base64url.encode(jose)
}
