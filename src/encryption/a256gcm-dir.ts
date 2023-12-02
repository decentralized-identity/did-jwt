import type { Decrypter, Encrypter, EncryptionResult, ProtectedHeader } from './types.js'
import { bytesToBase64url, encodeBase64url } from '../util.js'
import { fromString } from 'uint8arrays/from-string'
import { AES } from '@stablelib/aes'
import { GCM } from '@stablelib/gcm'
import { createA256GCMEncrypter } from './a256gcm.js'

// copied from: https://github.com/decentralized-identity/veramo/blob/d89a4dd403942445e1262eabd34be88afa5f9685/packages/did-comm/src/encryption/a256gcm-dir.ts

export function a256gcmDirEncrypter(key: Uint8Array): Encrypter {
  const enc = 'A256GCM'
  const alg = 'dir'

  async function encrypt(
    cleartext: Uint8Array,
    protectedHeader: ProtectedHeader = {},
    aad?: Uint8Array,
  ): Promise<EncryptionResult> {
    const protHeader = encodeBase64url(JSON.stringify(Object.assign({ alg }, protectedHeader, { enc })))
    const encodedAad = fromString(aad ? `${protHeader}.${bytesToBase64url(aad)}` : protHeader, 'utf-8')
    return {
      ...createA256GCMEncrypter(key)(cleartext, encodedAad),
      protectedHeader: protHeader,
    }
  }

  return { alg, enc, encrypt }
}

export function a256gcmDirDecrypter(key: Uint8Array): Decrypter {
  const cipher = new GCM(new AES(key))

  async function decrypt(sealed: Uint8Array, iv: Uint8Array, aad?: Uint8Array): Promise<Uint8Array | null> {
    return cipher.open(iv, sealed, aad)
  }

  return { alg: 'dir', enc: 'A256GCM', decrypt }
}