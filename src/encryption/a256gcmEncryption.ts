import type { Resolvable, VerificationMethod } from 'did-resolver'
import type {
  AnonEncryptParams,
  AuthEncryptParams,
  Decrypter,
  ECDH,
  Encrypter,
  KeyWrapper,
  ProtectedHeader,
  Recipient,
  WrappingResult,
} from './types.js'
import { base64ToBytes } from '../util.js'
import { a256gcmDecrypter, a256gcmEncrypter } from './a256gcm.js'  // change 1st two
import { computeP256EcdhEsKek, createP256EcdhEsKek } from './P256-ECDH-ES.js' // change
import { extractPublicKeyBytes } from '../VerifierAlgorithm.js'
import { createFullEncrypter } from './createEncrypter.js'
import {a256KeyWrapper, a256KeyUnwrapper } from './a256kw.js'
import { a256gcmDirDecrypter, a256gcmDirEncrypter } from './a256gcm-dir.js'

export function validateHeader(header?: ProtectedHeader): Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>> {
  if (!(header && header.epk && header.iv && header.tag)) {
    throw new Error('bad_jwe: malformed header')
  }
  return header as Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>>
}

/**
 *  In general the following resources are useful:
 *  {@link hhttps://www.rfc-editor.org/rfc/rfc6090| ECDH } and
 *  {@link https://www.rfc-editor.org/rfc/rfc3394 | AES } and
 *  {@link https://www.rfc-editor.org/rfc/rfc5649 | AES with padding } and
 * NIST SP 800-38[A-G] for asking what is AES, AES-GCM, Key Wrapping,...
 * Recommendation for Block Cipher Modes of Operation: Methods and Techniques https://csrc.nist.gov/pubs/sp/800/38/a/final
 * Recommendation for Block Cipher Modes of Operation: the CMAC Mode for Authentication https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final
 * Recommendation for Block Cipher Modes of Operation: the CCM Mode for Authentication and Confidentiality https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final
 * Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC https://csrc.nist.gov/pubs/sp/800/38/d/final
 * Recommendation for Block Cipher Modes of Operation: the XTS-AES Mode for Confidentiality on Storage Devices https://csrc.nist.gov/pubs/sp/800/38/e/final
 * Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping https://csrc.nist.gov/pubs/sp/800/38/f/final
 * Recommendation for Block Cipher Modes of Operation: Methods for Format-Preserving Encryption https://csrc.nist.gov/pubs/sp/800/38/g/upd1/final
 *  {@link https://www.rfc-editor.org/rfc/rfc7517 | JWK } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7516 | JWE } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7518 | JWA } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7520 |  Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE) }
 *  Real-World Cryptography by David Wong for those who get lost in the previous https://www.manning.com/books/real-world-cryptography
 */

export function a256gcmAnonEncrypterP256WithA256KW(
  recipientPublicKey: Uint8Array,
  options: Partial<AnonEncryptParams> = {}
): Encrypter {
  return createFullEncrypter(
    recipientPublicKey,
    undefined,
    options,
    { createKek: createP256EcdhEsKek, alg: 'ECDH-ES' },
    a256KeyWrapper,
    { from: (cek: Uint8Array) => a256gcmEncrypter(cek), enc: 'A256GCM' },
  )
}

export function p256a256gcmEncrypter(publicKey: Uint8Array, kid?: string, apv?: string): Encrypter {
  return a256gcmAnonEncrypterP256WithA256KW(publicKey, { kid, apv })
}

// I am not sure how to write this code... & it would be nice if it also included dir encrypters from resolveP256a256gcmDirEncrypters
export async function resolveP256a256gcmEncrypters(dids: string[], resolver: Resolvable): Promise<Encrypter[]> {
  const encryptersForDID = async (did: string, resolved: string[] = []): Promise<Encrypter[]> => {
    const { didResolutionMetadata, didDocument } = await resolver.resolve(did)
    resolved.push(did)
    if (didResolutionMetadata?.error || didDocument == null) {
      throw new Error(
        `resolver_error: Could not resolve ${did}: ${didResolutionMetadata.error}, ${didResolutionMetadata.message}`
      )
    }
    let controllerEncrypters: Encrypter[] = []
    if (!didDocument.controller && !didDocument.keyAgreement) {
      throw new Error(`no_suitable_keys: Could not find p256 key for ${did}`)
    }
    if (didDocument.controller) {
      let controllers = Array.isArray(didDocument.controller) ? didDocument.controller : [didDocument.controller]
      controllers = controllers.filter((c) => !resolved.includes(c))
      const encrypterPromises = controllers.map((did) =>
        encryptersForDID(did, resolved).catch(() => {
          return []
        })
      )
      const encrypterArrays = await Promise.all(encrypterPromises)
      controllerEncrypters = ([] as Encrypter[]).concat(...encrypterArrays)
    }
    const agreementKeys: VerificationMethod[] = didDocument.keyAgreement
      ?.map((key) => {
        if (typeof key === 'string') {
          return [...(didDocument.publicKey || []), ...(didDocument.verificationMethod || [])].find(
            (pk) => pk.id === key
          )
        }
        return key
      })
      ?.filter((key) => typeof key !== 'undefined') as VerificationMethod[]
    const pks =
      agreementKeys?.filter((key) => {
        return key.type === 'P256KeyAgreementKey2023' || key.type === 'P256KeyAgreementKey2023'
      }) || []
    if (!pks.length && !controllerEncrypters.length)
      throw new Error(`no_suitable_keys: Could not find p256 key for ${did}`)
    return pks.map((pk) => p256a256gcmEncrypter(extractPublicKeyBytes(pk), pk.id)).concat(...controllerEncrypters)
  }

  const encrypterPromises = dids.map((did) => encryptersForDID(did))
  const encrypterArrays = await Promise.all(encrypterPromises)
  return ([] as Encrypter[]).concat(...encrypterArrays)
}

// modified from: https://github.com/decentralized-identity/veramo/blob/d89a4dd403942445e1262eabd34be88afa5f9685/packages/did-comm/src/encryption/a256kw-encrypters.ts
export function a256gcmAnonDecrypterEcdhESp256WithA256KW(receiverSecret: Uint8Array | ECDH): Decrypter {
  const alg = 'ECDH-ES+A256KW'
  const enc = 'A256GCM'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient,
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
    const kek = await computeP256EcdhEsKek(recipient, receiverSecret, alg)
    if (kek === null) return null

    const unwrapper = a256KeyUnwrapper(kek)
    const cek = await unwrapper.unwrap(base64ToBytes(recipient.encrypted_key))
    if (cek === null) return null

    return a256gcmDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
}


export function p256a256gcmDecrypter(receiverSecret: Uint8Array | ECDH): Decrypter {
  return a256gcmAnonDecrypterEcdhESp256WithA256KW(receiverSecret)
}

export function a256gcmAnonDirEncrypterP256WithA256KW(
  recipientPublicKey: Uint8Array,
  options: Partial<AnonEncryptParams> = {}
): Encrypter {
  return createFullEncrypter(
    recipientPublicKey,
    undefined,
    options,
    { createKek: createP256EcdhEsKek, alg: 'ECDH-ES' },
    a256KeyWrapper,
    { from: (cek: Uint8Array) => a256gcmDirEncrypter(cek), enc: 'A256GCM' },
  )
}

// modified from: https://github.com/decentralized-identity/veramo/blob/d89a4dd403942445e1262eabd34be88afa5f9685/packages/did-comm/src/encryption/a256kw-encrypters.ts
export function a256gcmAnonDirDecrypterEcdhESp256WithA256KW(receiverSecret: Uint8Array | ECDH): Decrypter {
  const alg = 'ECDH-ES+A256KW'
  const enc = 'A256GCM'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient,
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
    const kek = await computeP256EcdhEsKek(recipient, receiverSecret, alg)
    if (kek === null) return null
    const unwrapper = a256KeyUnwrapper(kek)
    const cek = await unwrapper.unwrap(base64ToBytes(recipient.encrypted_key)) 

    if (cek === null) return null

    return a256gcmDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
}


export function p256DirA256gcmDecrypter(receiverSecret: Uint8Array | ECDH): Decrypter {
  return a256gcmAnonDirDecrypterEcdhESp256WithA256KW(receiverSecret)
}


export function p256DirA256GCMEncrypter(publicKey: Uint8Array, kid?: string, apv?: string): Encrypter {
  return a256gcmAnonDirEncrypterP256WithA256KW(publicKey, { kid, apv })
}

export async function resolveP256a256gcmDirEncrypters(dids: string[], resolver: Resolvable): Promise<Encrypter[]> {
  const encryptersForDID = async (did: string, resolved: string[] = []): Promise<Encrypter[]> => {
    const { didResolutionMetadata, didDocument } = await resolver.resolve(did)
    resolved.push(did)
    if (didResolutionMetadata?.error || didDocument == null) {
      throw new Error(
        `resolver_error: Could not resolve ${did}: ${didResolutionMetadata.error}, ${didResolutionMetadata.message}`
      )
    }
    let controllerEncrypters: Encrypter[] = []
    if (!didDocument.controller && !didDocument.keyAgreement) {
      throw new Error(`no_suitable_keys: Could not find p256 key for ${did}`)
    }
    if (didDocument.controller) {
      let controllers = Array.isArray(didDocument.controller) ? didDocument.controller : [didDocument.controller]
      controllers = controllers.filter((c) => !resolved.includes(c))
      const encrypterPromises = controllers.map((did) =>
        encryptersForDID(did, resolved).catch(() => {
          return []
        })
      )
      const encrypterArrays = await Promise.all(encrypterPromises)
      controllerEncrypters = ([] as Encrypter[]).concat(...encrypterArrays)
    }
    const agreementKeys: VerificationMethod[] = didDocument.keyAgreement
      ?.map((key) => {
        if (typeof key === 'string') {
          return [...(didDocument.publicKey || []), ...(didDocument.verificationMethod || [])].find(
            (pk) => pk.id === key
          )
        }
        return key
      })
      ?.filter((key) => typeof key !== 'undefined') as VerificationMethod[]
    const pks =
      agreementKeys?.filter((key) => {
        return key.type === 'P256KeyAgreementKey2023' || key.type === 'P256KeyAgreementKey2023'
      }) || []
    if (!pks.length && !controllerEncrypters.length)
      throw new Error(`no_suitable_keys: Could not find p256 key for ${did}`)
    return pks.map((pk) => p256DirA256GCMEncrypter(extractPublicKeyBytes(pk), pk.id)).concat(...controllerEncrypters)
  }

  const encrypterPromises = dids.map((did) => encryptersForDID(did))
  const encrypterArrays = await Promise.all(encrypterPromises)
  return ([] as Encrypter[]).concat(...encrypterArrays)
}
