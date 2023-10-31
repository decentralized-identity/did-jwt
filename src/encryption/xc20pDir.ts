import type { Decrypter, Encrypter, EncryptionResult, ProtectedHeader } from './types.js'
import { bytesToBase64url, encodeBase64url, stringToBytes } from '../util.js'
import { xchacha20poly1305 } from '@noble/ciphers/chacha'
import { randomBytes } from '@noble/hashes/utils'

export function xc20pEncrypter(key: Uint8Array): (cleartext: Uint8Array, aad?: Uint8Array) => EncryptionResult {
  return (cleartext: Uint8Array, aad?: Uint8Array) => {
    const iv = randomBytes(24)
    const cipher = xchacha20poly1305(key, iv, aad)
    const sealed = cipher.encrypt(cleartext)
    return {
      ciphertext: sealed.subarray(0, sealed.length - 16),
      tag: sealed.subarray(sealed.length - 16),
      iv,
    }
  }
}

export function xc20pDirEncrypter(key: Uint8Array): Encrypter {
  const xc20pEncrypt = xc20pEncrypter(key)
  const enc = 'XC20P'
  const alg = 'dir'

  async function encrypt(
    cleartext: Uint8Array,
    protectedHeader: ProtectedHeader = {},
    aad?: Uint8Array
  ): Promise<EncryptionResult> {
    const protHeader = encodeBase64url(JSON.stringify(Object.assign({ alg }, protectedHeader, { enc })))
    const encodedAad = stringToBytes(aad ? `${protHeader}.${bytesToBase64url(aad)}` : protHeader)
    return {
      ...xc20pEncrypt(cleartext, encodedAad),
      protectedHeader: protHeader,
    }
  }

  return { alg, enc, encrypt }
}

export function xc20pDirDecrypter(key: Uint8Array): Decrypter {
  async function decrypt(sealed: Uint8Array, iv: Uint8Array, aad?: Uint8Array): Promise<Uint8Array | null> {
    try {
      return xchacha20poly1305(key, iv, aad).decrypt(sealed)
    } catch (error) {
      return null
    }
  }

  return { alg: 'dir', enc: 'XC20P', decrypt }
}
