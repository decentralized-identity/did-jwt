import type { Decrypter, Encrypter, EncryptionResult, ProtectedHeader } from './types.js'
import { bytesToBase64url, encodeBase64url } from '../util.js'
import { fromString } from 'uint8arrays/from-string'
// import { gcm } from '@noble/ciphers/aes';
import { AES } from '@stablelib/aes'
import { GCM } from '@stablelib/gcm'
import { randomBytes } from '@noble/hashes/utils'

// ECDH-ES+A256KW: ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
/*
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
*/

export function createA256GCMEncrypter(key: Uint8Array): (cleartext: Uint8Array, aad?: Uint8Array) => EncryptionResult {
  const blockcipher = new AES(key)
  const cipher = new GCM(blockcipher)
  return (cleartext: Uint8Array, aad?: Uint8Array) => {
    const iv = randomBytes(cipher.nonceLength)
    const sealed = cipher.seal(iv, cleartext, aad)
    return {
      ciphertext: sealed.subarray(0, sealed.length - cipher.tagLength),
      tag: sealed.subarray(sealed.length - cipher.tagLength),
      iv,
    }
  }
}


export function a256gcmEncrypter(key: Uint8Array): Encrypter {
  //const a256gcmEncrypt = a256kwEncrypter(key)
  const a256gcmEncrypt = createA256GCMEncrypter(key)
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

/*
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
*/

// export function a256gcmDirDecrypter(key: Uint8Array): Decrypter {
export function a256gcmDecrypter(key: Uint8Array): Decrypter {
  const cipher = new GCM(new AES(key))

  async function decrypt(sealed: Uint8Array, iv: Uint8Array, aad?: Uint8Array): Promise<Uint8Array | null> {
    try {
      return cipher.open(iv, sealed, aad)
    } catch(error) {
      return null
    }
  }

  return { alg: 'A256KW', enc: 'A256GCM', decrypt }
}
