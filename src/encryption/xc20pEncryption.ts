import type { Resolvable, VerificationMethod } from 'did-resolver'
import { randomBytes } from '@noble/hashes/utils'
import { base64ToBytes, bytesToBase64url, toSealed, generateKeyPair } from '../util.js'
import { Decrypter, Encrypter, EncryptionResult, EphemeralKeyPair, ProtectedHeader, Recipient } from './JWE.js'
import { ECDH } from './ECDH.js'
import { xc20pDirDecrypter, xc20pDirEncrypter, xc20pEncrypter } from './xc20pDir.js'
import { computeX25519Ecdh1PUv3Kek, createX25519Ecdh1PUv3Kek } from './X25519-ECDH-1PU.js'
import { computeX25519EcdhEsKek, createX25519EcdhEsKek } from './X25519-ECDH-ES.js'
import { extractPublicKeyBytes } from '../VerifierAlgorithm.js'

/**
 * Extra parameters for JWE using authenticated encryption
 */
export type AuthEncryptParams = {
  /**
   * recipient key ID
   */
  kid?: string

  /**
   * See {@link https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.2}
   * base64url encoded
   */
  apu?: string

  /**
   * See {@link https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.3}
   * base64url encoded
   */
  apv?: string
}

/**
 * Extra parameters for JWE using anonymous encryption
 */
export type AnonEncryptParams = {
  /**
   * recipient key ID
   */
  kid?: string

  /**
   * See {@link https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.3}
   * base64url encoded
   */
  apv?: string
}

/**
 * Recommended encrypter for authenticated encryption (i.e. sender authentication and requires
 * sender private key to encrypt the data).
 * Uses {@link https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03 | ECDH-1PU v3 } and
 * {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | XC20PKW v2 }.
 *
 * @param recipientPublicKey the byte array representing the recipient public key
 * @param senderSecret either a Uint8Array representing the sender secret key or
 *   an ECDH function that wraps the key and can promise a shared secret given a public key
 * @param options {@link AuthEncryptParams} used to specify extra header parameters
 *
 * @returns an {@link Encrypter} instance usable with {@link createJWE}
 *
 * NOTE: ECDH-1PU and XC20PKW are proposed drafts in IETF and not a standard yet and
 * are subject to change as new revisions or until the official CFRG specification are released.
 *
 * @beta
 */
export function createAuthEncrypter(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH,
  options: Partial<AuthEncryptParams> = {}
): Encrypter {
  return xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(recipientPublicKey, senderSecret, options)
}

/**
 * Recommended encrypter for anonymous encryption (i.e. no sender authentication).
 * Uses {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | ECDH-ES+XC20PKW v2}.
 *
 * @param publicKey the byte array representing the recipient public key
 * @param options {@link AnonEncryptParams} used to specify the recipient key ID (`kid`)
 *
 * @returns an {@link Encrypter} instance usable with {@link createJWE}
 *
 * NOTE: ECDH-ES+XC20PKW is a proposed draft in IETF and not a standard yet and
 * is subject to change as new revisions or until the official CFRG specification is released.
 *
 * @beta
 */
export function createAnonEncrypter(publicKey: Uint8Array, options: Partial<AnonEncryptParams> = {}): Encrypter {
  return x25519Encrypter(publicKey, options?.kid, options?.apv)
}

/**
 * Recommended decrypter for authenticated encryption (i.e. sender authentication and requires
 * sender public key to decrypt the data).
 * Uses {@link https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03 | ECDH-1PU v3 } and
 * {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | XC20PKW v2 }.
 *
 * @param recipientSecret either a Uint8Array representing the recipient secret key or
 *   an ECDH function that wraps the key and can promise a shared secret given a public key
 * @param senderPublicKey the byte array representing the sender public key
 *
 * @returns a {@link Decrypter} instance usable with {@link decryptJWE}
 *
 * NOTE: ECDH-1PU and XC20PKW are proposed drafts in IETF and not a standard yet and
 * are subject to change as new revisions or until the official CFRG specification are released.
 *
 * @beta
 */
export function createAuthDecrypter(recipientSecret: Uint8Array | ECDH, senderPublicKey: Uint8Array): Decrypter {
  return xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(recipientSecret, senderPublicKey)
}

/**
 * Recommended decrypter for anonymous encryption (i.e. no sender authentication).
 * Uses {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | ECDH-ES+XC20PKW v2 }.
 *
 * @param recipientSecret either a Uint8Array representing the recipient secret key or
 *   an ECDH function that wraps the key and can promise a shared secret given a public key
 *
 * @returns a {@link Decrypter} instance usable with {@link decryptJWE}
 *
 * NOTE: ECDH-ES+XC20PKW is a proposed draft in IETF and not a standard yet and
 * is subject to change as new revisions or until the official CFRG specification is released.
 *
 * @beta
 */
export function createAnonDecrypter(recipientSecret: Uint8Array | ECDH): Decrypter {
  return x25519Decrypter(recipientSecret)
}

export function validateHeader(header?: ProtectedHeader): Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>> {
  if (!(header && header.epk && header.iv && header.tag)) {
    throw new Error('bad_jwe: malformed header')
  }
  return header as Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>>
}

export function x25519Encrypter(publicKey: Uint8Array, kid?: string, apv?: string): Encrypter {
  const alg = 'ECDH-ES+XC20PKW'
  const enc = 'XC20P'

  async function encryptCek(cek: Uint8Array, ephemeralKeyPair?: EphemeralKeyPair): Promise<Recipient> {
    const { epk, kek } = createX25519EcdhEsKek(ephemeralKeyPair, publicKey, apv, alg)
    const res = xc20pEncrypter(kek)(cek)
    const recipient: Recipient = {
      encrypted_key: bytesToBase64url(res.ciphertext),
      header: {},
    }
    if (res.iv) recipient.header.iv = bytesToBase64url(res.iv)
    if (res.tag) recipient.header.tag = bytesToBase64url(res.tag)
    if (kid) recipient.header.kid = kid
    if (apv) recipient.header.apv = apv
    if (!ephemeralKeyPair) {
      recipient.header.alg = alg
      recipient.header.epk = epk
    }
    return recipient
  }

  async function encrypt(
    cleartext: Uint8Array,
    protectedHeader: ProtectedHeader = {},
    aad?: Uint8Array,
    ephemeralKeyPair?: EphemeralKeyPair
  ): Promise<EncryptionResult> {
    // we won't want alg to be set to dir from xc20pDirEncrypter
    Object.assign(protectedHeader, { alg: undefined })
    // Content Encryption Key
    const cek = randomBytes(32)
    const recipient: Recipient = await encryptCek(cek, ephemeralKeyPair)
    if (ephemeralKeyPair) {
      protectedHeader.alg = alg
      protectedHeader.epk = ephemeralKeyPair.publicKeyJWK
    }
    return {
      ...(await xc20pDirEncrypter(cek).encrypt(cleartext, protectedHeader, aad)),
      recipient,
      cek,
    }
  }

  return { alg, enc, encrypt, encryptCek, genEpk: genX25519EphemeralKeyPair }
}

export function genX25519EphemeralKeyPair(): EphemeralKeyPair {
  const epk = generateKeyPair()
  return {
    publicKeyJWK: { kty: 'OKP', crv: 'X25519', x: bytesToBase64url(epk.publicKey) },
    secretKey: epk.secretKey,
  }
}

/**
 * Implements ECDH-1PU+XC20PKW with XChaCha20Poly1305 based on the following specs:
 *   - {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | XC20PKW}
 *   - {@link https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03 | ECDH-1PU}
 */
export function xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH,
  options: Partial<AuthEncryptParams> = {}
): Encrypter {
  const alg = 'ECDH-1PU+XC20PKW'
  const enc = 'XC20P'

  async function encryptCek(cek: Uint8Array, ephemeralKeyPair?: EphemeralKeyPair): Promise<Recipient> {
    const { epk, kek } = await createX25519Ecdh1PUv3Kek(
      ephemeralKeyPair,
      recipientPublicKey,
      senderSecret,
      options.apu,
      options.apv,
      alg
    )

    const res = xc20pEncrypter(kek)(cek)
    const recipient: Recipient = {
      encrypted_key: bytesToBase64url(res.ciphertext),
      header: {},
    }
    if (res.iv) recipient.header.iv = bytesToBase64url(res.iv)
    if (res.tag) recipient.header.tag = bytesToBase64url(res.tag)
    if (options.kid) recipient.header.kid = options.kid
    if (options.apu) recipient.header.apu = options.apu
    if (options.apv) recipient.header.apv = options.apv
    if (!ephemeralKeyPair) {
      recipient.header.alg = alg
      recipient.header.epk = epk
    }

    return recipient
  }

  async function encrypt(
    cleartext: Uint8Array,
    protectedHeader: ProtectedHeader = {},
    aad?: Uint8Array,
    ephemeralKeyPair?: EphemeralKeyPair
  ): Promise<EncryptionResult> {
    // we won't want alg to be set to dir from xc20pDirEncrypter
    Object.assign(protectedHeader, { alg: undefined })
    // Content Encryption Key
    const cek = randomBytes(32)
    const recipient: Recipient = await encryptCek(cek, ephemeralKeyPair)
    if (ephemeralKeyPair) {
      protectedHeader.alg = alg
      protectedHeader.epk = ephemeralKeyPair.publicKeyJWK
    }
    return {
      ...(await xc20pDirEncrypter(cek).encrypt(cleartext, protectedHeader, aad)),
      recipient,
      cek,
    }
  }

  return { alg, enc, encrypt, encryptCek, genEpk: genX25519EphemeralKeyPair }
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
      agreementKeys?.filter((key) => {
        return key.type === 'X25519KeyAgreementKey2019' || key.type === 'X25519KeyAgreementKey2020'
      }) || []
    if (!pks.length && !controllerEncrypters.length)
      throw new Error(`no_suitable_keys: Could not find x25519 key for ${did}`)
    return pks.map((pk) => x25519Encrypter(extractPublicKeyBytes(pk), pk.id)).concat(...controllerEncrypters)
  }

  const encrypterPromises = dids.map((did) => encryptersForDID(did))
  const encrypterArrays = await Promise.all(encrypterPromises)
  const flattenedArray = ([] as Encrypter[]).concat(...encrypterArrays)
  return flattenedArray
}

export function x25519Decrypter(receiverSecret: Uint8Array | ECDH): Decrypter {
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

    const kek = await computeX25519EcdhEsKek(recipient, receiverSecret, alg)
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
