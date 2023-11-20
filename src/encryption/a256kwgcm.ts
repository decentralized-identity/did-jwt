import type { Decrypter, Encrypter, EncryptionResult, ProtectedHeader } from './types.js'
import { bytesToBase64url, encodeBase64url } from '../util.js'
import { fromString } from 'uint8arrays/from-string'
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/hashes/utils'

// ECDH-ES+A256KW: ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
export function a256kwEncrypter(key: Uint8Array): (cleartext: Uint8Array, aad?: Uint8Array) => EncryptionResult {
  return (cleartext: Uint8Array, aad?: Uint8Array) => {
    const iv = randomBytes(24)
    const cipher = gcm(key, iv, aad)    /// need to figure out a256gcm here
    const sealed = cipher.encrypt(cleartext)   /// need to figure out a256 gcm here : https://www.npmjs.com/package/@noble/ciphers
    return {
      ciphertext: sealed.subarray(0, sealed.length - 16),
      tag: sealed.subarray(sealed.length - 16),
      iv,
    }
  }
}

export function a256gcmEncrypter(key: Uint8Array): Encrypter {
  const a256gcmEncrypt = a256kwEncrypter(key)
  const enc = 'A256GCM'
  const alg = 'A256KW'

  async function encrypt(
    cleartext: Uint8Array,
    protectedHeader: ProtectedHeader = {},
    aad?: Uint8Array
  ): Promise<EncryptionResult> {
    const protHeader = encodeBase64url(JSON.stringify(Object.assign({ alg }, protectedHeader, { enc })))
    const encodedAad = fromString(aad ? `${protHeader}.${bytesToBase64url(aad)}` : protHeader, 'utf-8')
    return {
      ...a256gcmEncrypt(cleartext, encodedAad),
      protectedHeader: protHeader,
    }
  }

  return { alg, enc, encrypt }
}

export function a256gcmDecrypter(key: Uint8Array): Decrypter {
  async function decrypt(sealed: Uint8Array, iv: Uint8Array, aad?: Uint8Array): Promise<Uint8Array | null> {
    try {
      return gcm(key, iv, aad).decrypt(sealed) /// need to figure out a256 gcm here : https://www.npmjs.com/package/@noble/ciphers
    } catch (error) {
      return null
    }
  }

  return { alg: 'A256KW', enc: 'A256GCM', decrypt }
}
