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
import { base64ToBytes, extractPublicKeyBytes, isDefined, toSealed } from '../util.js'
import { xc20pDirDecrypter, xc20pDirEncrypter, xc20pEncrypter } from './xc20pDir.js'
import { computeX25519Ecdh1PUv3Kek, createX25519Ecdh1PUv3Kek } from './X25519-ECDH-1PU.js'
import { computeX25519EcdhEsKek, createX25519EcdhEsKek } from './X25519-ECDH-ES.js'
import { createFullEncrypter } from './createEncrypter.js'

/**
 * @deprecated Use
 *   {@link xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2 | xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2() } instead
 */
export function createAuthEncrypter(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH,
  options: Partial<AuthEncryptParams> = {}
): Encrypter {
  return xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(recipientPublicKey, senderSecret, options)
}

/**
 * @deprecated Use {@link xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2 | xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2() }
 *   instead
 */
export function createAnonEncrypter(publicKey: Uint8Array, options: Partial<AnonEncryptParams> = {}): Encrypter {
  return xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2(publicKey, options)
}

/**
 * @deprecated Use
 *   {@link xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2 | xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2() } instead
 */
export function createAuthDecrypter(recipientSecret: Uint8Array | ECDH, senderPublicKey: Uint8Array): Decrypter {
  return xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(recipientSecret, senderPublicKey)
}

/**
 * @deprecated Use {@link xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2 | xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2() }
 *   instead
 */
export function createAnonDecrypter(recipientSecret: Uint8Array | ECDH): Decrypter {
  return xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2(recipientSecret)
}

export function validateHeader(header?: ProtectedHeader): Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>> {
  if (!(header && header.epk && header.iv && header.tag)) {
    throw new Error('bad_jwe: malformed header')
  }
  return header as Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>>
}

export const xc20pKeyWrapper: KeyWrapper = {
  from: (wrappingKey: Uint8Array) => {
    const wrap = async (cek: Uint8Array): Promise<WrappingResult> => {
      return xc20pEncrypter(wrappingKey)(cek)
    }
    return { wrap }
  },

  alg: 'XC20PKW',
}

/**
 * @deprecated Use {@link xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2 | xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2() }
 *   instead
 */
export function x25519Encrypter(publicKey: Uint8Array, kid?: string, apv?: string): Encrypter {
  return xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2(publicKey, { kid, apv })
}

/**
 * Recommended encrypter for anonymous encryption (i.e. no sender authentication).
 * Uses {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | ECDH-ES+XC20PKW v2}.
 *
 * @param recipientPublicKey - the byte array representing the recipient public key
 * @param options - {@link AnonEncryptParams} used to specify the recipient key ID (`kid`)
 *
 * @returns an {@link Encrypter} instance usable with {@link createJWE}
 *
 * NOTE: ECDH-ES+XC20PKW is a proposed draft in IETF and not a standard yet and
 * is subject to change as new revisions or until the official CFRG specification is released.
 */
export function xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2(
  recipientPublicKey: Uint8Array,
  options: Partial<AnonEncryptParams> = {}
): Encrypter {
  return createFullEncrypter(
    recipientPublicKey,
    undefined,
    options,
    { createKek: createX25519EcdhEsKek, alg: 'ECDH-ES' },
    xc20pKeyWrapper,
    { from: (cek: Uint8Array) => xc20pDirEncrypter(cek), enc: 'XC20P' }
  )
}

/**
 *  Recommended encrypter for authenticated encryption (i.e. sender authentication and requires
 *  sender private key to encrypt the data).
 *  Uses {@link https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03 | ECDH-1PU v3 } and
 *  {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | XC20PKW v2 }.
 *
 *  @param recipientPublicKey - the byte array representing the recipient public key
 *  @param senderSecret - either a Uint8Array representing the sender secret key or
 *    an ECDH function that wraps the key and can promise a shared secret given a public key
 *  @param options - {@link AuthEncryptParams} used to specify extra header parameters
 *
 *  @returns an {@link Encrypter} instance usable with {@link createJWE}
 *
 *  NOTE: ECDH-1PU and XC20PKW are proposed drafts in IETF and not a standard yet and
 *  are subject to change as new revisions or until the official CFRG specification are released.
 *
 * Implements ECDH-1PU+XC20PKW with XChaCha20Poly1305 based on the following specs:
 *   - {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | XC20PKW}
 *   - {@link https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03 | ECDH-1PU}
 */
export function xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH,
  options: Partial<AuthEncryptParams> = {}
): Encrypter {
  return createFullEncrypter(
    recipientPublicKey,
    senderSecret,
    options,
    { createKek: createX25519Ecdh1PUv3Kek, alg: 'ECDH-1PU' },
    xc20pKeyWrapper,
    { from: (cek: Uint8Array) => xc20pDirEncrypter(cek), enc: 'XC20P' }
  )
}

export async function resolveX25519Encrypters(dids: string[], resolver: Resolvable): Promise<Encrypter[]> {
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
      throw new Error(`no_suitable_keys: Could not find x25519 key for ${did}`)
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
      agreementKeys?.filter((key) =>
        ['X25519KeyAgreementKey2019', 'X25519KeyAgreementKey2020', 'JsonWebKey2020', 'Multikey'].includes(key.type)
      ) ?? []
    if (!pks.length && !controllerEncrypters.length)
      throw new Error(`no_suitable_keys: Could not find X25519 key for ${did}`)
    return pks
      .map((pk) => {
        const { keyBytes, keyType } = extractPublicKeyBytes(pk)
        if (keyType === 'X25519') {
          return x25519Encrypter(keyBytes, pk.id)
        } else {
          return null
        }
      })
      .filter(isDefined)
      .concat(...controllerEncrypters)
  }

  const encrypterPromises = dids.map((did) => encryptersForDID(did))
  const encrypterArrays = await Promise.all(encrypterPromises)
  return ([] as Encrypter[]).concat(...encrypterArrays)
}

/**
 * @deprecated Use {@link xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2 | xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2() }
 *   instead
 */
export function x25519Decrypter(receiverSecret: Uint8Array | ECDH): Decrypter {
  return xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2(receiverSecret)
}

/**
 * Recommended decrypter for anonymous encryption (i.e. no sender authentication).
 * Uses {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | ECDH-ES+XC20PKW v2 }.
 *
 * @param recipientSecret - either a Uint8Array representing the recipient secret key or
 *   an ECDH function that wraps the key and can promise a shared secret given a public key
 *
 * @returns a {@link Decrypter} instance usable with {@link decryptJWE}
 *
 * NOTE: ECDH-ES+XC20PKW is a proposed draft in IETF and not a standard yet and
 * is subject to change as new revisions or until the official CFRG specification is released.
 *
 * @beta
 */
export function xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2(recipientSecret: Uint8Array | ECDH): Decrypter {
  const alg = 'ECDH-ES+XC20PKW'
  const enc = 'XC20P'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
    const header = validateHeader(recipient.header)

    const kek = await computeX25519EcdhEsKek(recipient, recipientSecret, alg)
    if (!kek) return null
    // Content Encryption Key
    const sealedCek = toSealed(recipient.encrypted_key, header.tag)
    const cek = await xc20pDirDecrypter(kek).decrypt(sealedCek, base64ToBytes(header.iv))
    if (cek === null) return null

    return xc20pDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
}

/**
 * Recommended decrypter for authenticated encryption (i.e. sender authentication and requires
 * sender public key to decrypt the data).
 * Uses {@link https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03 | ECDH-1PU v3 } and
 * {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | XC20PKW v2 }.
 *
 * @param recipientSecret - either a Uint8Array representing the recipient secret key or
 *   an ECDH function that wraps the key and can promise a shared secret given a public key
 * @param senderPublicKey - the byte array representing the sender public key
 *
 * @returns a {@link Decrypter} instance usable with {@link decryptJWE}
 *
 * NOTE: ECDH-1PU and XC20PKW are proposed drafts in IETF and not a standard yet and
 * are subject to change as new revisions or until the official CFRG specification are released.
 *
 * @beta
 *
 * Implements ECDH-1PU+XC20PKW with XChaCha20Poly1305 based on the following specs:
 *   - {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | XC20PKW}
 *   - {@link https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03 | ECDH-1PU}
 */
export function xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(
  recipientSecret: Uint8Array | ECDH,
  senderPublicKey: Uint8Array
): Decrypter {
  const alg = 'ECDH-1PU+XC20PKW'
  const enc = 'XC20P'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
    const header = validateHeader(recipient.header)
    const kek = await computeX25519Ecdh1PUv3Kek(recipient, recipientSecret, senderPublicKey, alg)
    if (!kek) return null
    // Content Encryption Key
    const sealedCek = toSealed(recipient.encrypted_key, header.tag)
    const cek = await xc20pDirDecrypter(kek).decrypt(sealedCek, base64ToBytes(header.iv))
    if (cek === null) return null

    return xc20pDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
}
