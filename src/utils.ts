import * as u8a from 'uint8arrays'
import { randomBytes } from '@stablelib/random'

import type { DagJWS } from './types'

const B64 = 'base64pad'
const B64_URL = 'base64url'

export function encodeBase64(bytes: Uint8Array): string {
  return u8a.toString(bytes, B64)
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return u8a.toString(bytes, B64_URL)
}

export function decodeBase64(s: string): Uint8Array {
  return u8a.fromString(s, B64)
}

export function base64urlToJSON(s: string): Record<string, any> {
  return JSON.parse(u8a.toString(u8a.fromString(s, B64_URL))) as Record<string, any>
}

export function randomString(): string {
  return u8a.toString(randomBytes(16), 'base64')
}

export function fromDagJWS(jws: DagJWS): string {
  if (jws.signatures.length > 1) throw new Error('Cant convert to compact jws')
  return `${jws.signatures[0].protected}.${jws.payload}.${jws.signatures[0].signature}`
}
