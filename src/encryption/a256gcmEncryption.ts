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
import { computeP256Ecdh1PUv3Kek, createP256Ecdh1PUv3Kek } from './P256-ECDH-1PU.js'
import { extractPublicKeyBytes } from '../VerifierAlgorithm.js'
import { createFullEncrypter } from './createEncrypter.js'
import {a256KeyWrapper, a256KeyUnwrapper } from './a256kw.js'
import { a256gcmDirDecrypter, a256gcmDirEncrypter } from './a256gcm-dir.js'

// I need to change the comments in this file

export function validateHeader(header?: ProtectedHeader): Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>> {
  if (!(header && header.epk && header.iv && header.tag)) {
    throw new Error('bad_jwe: malformed header')
  }
  return header as Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>>
}

// which one of the below do I need to select? (start here...)
/**
 *  Recommended encrypter for authenticated encryption (i.e. sender authentication and requires
 *  sender private key to encrypt the data).
 *  Uses {@link hhttps://www.rfc-editor.org/rfc/rfc6090| ECDH } and
 *  {@link https://www.rfc-editor.org/rfc/rfc3394 | AES } and
 *  {@link https://www.rfc-editor.org/rfc/rfc5649 | AES with padding } and
 *  {@link | NIST SP 800-38[A-G] | includes GCM } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7517 | JWK } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7516 | JWE } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7518 | JWA } 
 *  
 *
 *  @param recipientPublicKey - the byte array representing the recipient public key
 *  @param senderSecret - either a Uint8Array representing the sender secret key or
 *    an ECDH function that wraps the key and can promise a shared secret given a public key
 *  @param options - {@link AuthEncryptParams} used to specify extra header parameters
 *
 *  @returns an {@link Encrypter} instance usable with {@link createJWE}
 *
 *
 * Implements ECDH-ES+A256KW with A256GCM based on the following specs:
 */
export function a256gcmAuthEncrypterEcdhP256WithA256kw(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH,
  options: Partial<AuthEncryptParams> = {}
): Encrypter {
  return createFullEncrypter(
    recipientPublicKey,
    senderSecret,
    options,
    { createKek: createP256Ecdh1PUv3Kek, alg: 'ECDH-ES' },
    a256KeyWrapper,
    { from: (cek: Uint8Array) => a256gcmEncrypter(cek), enc: 'A256GCM' }
  )
}

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



/**
 * @deprecated Use {@link xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2 | xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2() }
 *   instead
 */
export function p256Encrypter(publicKey: Uint8Array, kid?: string, apv?: string): Encrypter {
  return a256gcmAnonEncrypterP256WithA256KW(publicKey, { kid, apv })
}

// I am not sure how to write this code...
export async function resolveP256Encrypters(dids: string[], resolver: Resolvable): Promise<Encrypter[]> {
//export async function resolveP256Encrypters(dids: string[], resolver: Resolvable, senderSecret: Uint8Array | ECDH, options: Partial<AuthEncryptParams> = {}): Promise<Encrypter[]> {
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
    return pks.map((pk) => p256Encrypter(extractPublicKeyBytes(pk), pk.id)).concat(...controllerEncrypters)
  }

  const encrypterPromises = dids.map((did) => encryptersForDID(did))
  const encrypterArrays = await Promise.all(encrypterPromises)
  return ([] as Encrypter[]).concat(...encrypterArrays)
}

/**
 *  Recommended encrypter for authenticated encryption (i.e. sender authentication and requires
 *  sender private key to encrypt the data).
 *  Uses {@link hhttps://www.rfc-editor.org/rfc/rfc6090| ECDH } and
 *  {@link https://www.rfc-editor.org/rfc/rfc3394 | AES } and
 *  {@link https://www.rfc-editor.org/rfc/rfc5649 | AES with padding } and
 *  {@link | NIST SP 800-38[A-G] | includes GCM } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7517 | JWK } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7516 | JWE } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7518 | JWA } 
 *  
 *
 * @param recipientSecret - either a Uint8Array representing the recipient secret key or
 *   an ECDH function that wraps the key and can promise a shared secret given a public key
 * @param senderPublicKey - the byte array representing the sender public key
 *
 * @returns a {@link Decrypter} instance usable with {@link decryptJWE}
 *
 * Implements ECDH-ES+A256KW with A256GCM based on the following specs:
 */
export function a256gcmAuthDecrypterEcdhP256WithA256kw(
  recipientSecret: Uint8Array | ECDH,
  senderPublicKey: Uint8Array
): Decrypter {
  const alg = 'ECDH-ES+A256KW'
  const enc = 'A256GCM'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient

    const kek = await computeP256Ecdh1PUv3Kek(recipient, recipientSecret, senderPublicKey, alg)

    if (!kek) return null
    // Content Encryption Key
    const unwrapper = a256KeyUnwrapper(kek)
    const cek = await unwrapper.unwrap(base64ToBytes(recipient.encrypted_key))
    if (cek === null) return null

    return a256gcmDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
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

/**
 * @deprecated Use {@link xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2 | xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2() }
 *   instead
 */
export function p256Decrypter(receiverSecret: Uint8Array | ECDH): Decrypter {
  return a256gcmAnonDecrypterEcdhESp256WithA256KW(receiverSecret)
}

/// modifiy to DIR

export function a256gcmAuthDirEncrypterEcdhP256WithA256kw(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH,
  options: Partial<AuthEncryptParams> = {}
): Encrypter {
  return createFullEncrypter(
    recipientPublicKey,
    senderSecret,
    options,
    { createKek: createP256Ecdh1PUv3Kek, alg: 'ECDH-ES' },
    a256KeyWrapper,
    { from: (cek: Uint8Array) => a256gcmDirEncrypter(cek), enc: 'A256GCM' }
  )
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

/**
 *  Recommended encrypter for authenticated encryption (i.e. sender authentication and requires
 *  sender private key to encrypt the data).
 *  Uses {@link hhttps://www.rfc-editor.org/rfc/rfc6090| ECDH } and
 *  {@link https://www.rfc-editor.org/rfc/rfc3394 | AES } and
 *  {@link https://www.rfc-editor.org/rfc/rfc5649 | AES with padding } and
 *  {@link | NIST SP 800-38[A-G] | includes GCM } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7517 | JWK } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7516 | JWE } and
 *  {@link https://www.rfc-editor.org/rfc/rfc7518 | JWA } 
 *  
 * @param recipientSecret - either a Uint8Array representing the recipient secret key or
 *   an ECDH function that wraps the key and can promise a shared secret given a public key
 * @param senderPublicKey - the byte array representing the sender public key
 *
 * @returns a {@link Decrypter} instance usable with {@link decryptJWE}
 *
 * Implements ECDH-ES+A256KW with A256GCM based on the following specs:
 */
export function a256gcmAuthDirDecrypterEcdhP256WithA256kw(
  recipientSecret: Uint8Array | ECDH,
  senderPublicKey: Uint8Array
): Decrypter {
  const alg = 'ECDH-ES+A256KW'
  const enc = 'A256GCM'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
 
    const kek = await computeP256Ecdh1PUv3Kek(recipient, recipientSecret, senderPublicKey, alg)

    if (!kek) return null
    const unwrapper = a256KeyUnwrapper(kek)
    const cek = await unwrapper.unwrap(base64ToBytes(recipient.encrypted_key)) 
   // const cek = base64ToBytes(recipient.encrypted_key) // It doesn't matter if I use this or the two lines above? If it is dir enc, it should?
    if (cek === null) return null

    return a256gcmDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
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
    const cek = await unwrapper.unwrap(base64ToBytes(recipient.encrypted_key)) // for some reason I have to use this even though dir does not use wrapping?
    //const cek = base64ToBytes(recipient.encrypted_key)
    if (cek === null) return null

    return a256gcmDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
}

/**
 * @deprecated Use {@link xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2 | xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2() }
 *   instead
 */
export function p256DirDecrypter(receiverSecret: Uint8Array | ECDH): Decrypter {
  return a256gcmAnonDirDecrypterEcdhESp256WithA256KW(receiverSecret)
}

/**
 * @deprecated Use {@link xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2 | xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2() }
 *   instead
 */
export function p256DirEncrypter(publicKey: Uint8Array, kid?: string, apv?: string): Encrypter {
  return a256gcmAnonDirEncrypterP256WithA256KW(publicKey, { kid, apv })
}

export async function resolveP256DirEncrypters(dids: string[], resolver: Resolvable): Promise<Encrypter[]> {
//export async function resolveP256DirEncrypters(dids: string[], resolver: Resolvable, senderSecret: Uint8Array | ECDH, options: Partial<AuthEncryptParams> = {}): Promise<Encrypter[]> {
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
    return pks.map((pk) => p256DirEncrypter(extractPublicKeyBytes(pk), pk.id)).concat(...controllerEncrypters)
  }

  const encrypterPromises = dids.map((did) => encryptersForDID(did))
  const encrypterArrays = await Promise.all(encrypterPromises)
  return ([] as Encrypter[]).concat(...encrypterArrays)
}
