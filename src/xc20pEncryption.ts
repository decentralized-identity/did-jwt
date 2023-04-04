import type { Resolvable, VerificationMethod } from 'did-resolver'
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305'
import { generateKeyPair, generateKeyPairFromSeed, KeyPair as X25519KeyPair, sharedKey } from '@stablelib/x25519'
import { randomBytes } from '@stablelib/random'
import { fromString } from 'uint8arrays'
import { concatKDF } from './Digest.js'
import { base58ToBytes, base64ToBytes, bytesToBase64url, encodeBase64url, toSealed } from './util.js'
import { Decrypter, Encrypter, EncryptionResult, EphemeralKeyPair, ProtectedHeader, Recipient } from './JWE.js'
import { ECDH } from './ECDH.js'

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

function xc20pEncrypter(key: Uint8Array): (cleartext: Uint8Array, aad?: Uint8Array) => EncryptionResult {
  const cipher = new XChaCha20Poly1305(key)
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
    const encodedAad = fromString(aad ? `${protHeader}.${bytesToBase64url(aad)}` : protHeader, 'utf-8')
    return {
      ...xc20pEncrypt(cleartext, encodedAad),
      protectedHeader: protHeader,
    }
  }

  return { alg, enc, encrypt }
}

export function xc20pDirDecrypter(key: Uint8Array): Decrypter {
  const cipher = new XChaCha20Poly1305(key)

  async function decrypt(sealed: Uint8Array, iv: Uint8Array, aad?: Uint8Array): Promise<Uint8Array | null> {
    return cipher.open(iv, sealed, aad)
  }

  return { alg: 'dir', enc: 'XC20P', decrypt }
}

export function x25519Encrypter(publicKey: Uint8Array, kid?: string, apv?: string): Encrypter {
  const alg = 'ECDH-ES+XC20PKW'
  const keyLen = 256
  const crv = 'X25519'

  let consumerInfo: Uint8Array | undefined
  if (apv !== undefined) consumerInfo = base64ToBytes(apv)

  async function encryptCek(cek: Uint8Array, ephemeralKeyPair?: EphemeralKeyPair): Promise<Recipient> {
    const ephemeral: X25519KeyPair = ephemeralKeyPair
      ? generateKeyPairFromSeed(ephemeralKeyPair.secretKey)
      : generateKeyPair()
    const epk = { kty: 'OKP', crv, x: bytesToBase64url(ephemeral.publicKey) }
    const sharedSecret = sharedKey(ephemeral.secretKey, publicKey)
    // Key Encryption Key
    const kek = concatKDF(sharedSecret, keyLen, alg, undefined, consumerInfo)
    const res = xc20pEncrypter(kek)(cek)
    const recipient: Recipient = {
      encrypted_key: bytesToBase64url(res.ciphertext),
      header: {
        iv: bytesToBase64url(res.iv),
        tag: bytesToBase64url(res.tag),
      },
    }
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
      protectedHeader.epk = ephemeralKeyPair.publicKey
    }
    return {
      ...(await xc20pDirEncrypter(cek).encrypt(cleartext, protectedHeader, aad)),
      recipient,
      cek,
    }
  }

  return { alg, enc: 'XC20P', encrypt, encryptCek, genEpk: genX25519EphemeralKeyPair }
}

export function genX25519EphemeralKeyPair(): EphemeralKeyPair {
  const epk = generateKeyPair()
  return {
    publicKey: { kty: 'OKP', crv: 'X25519', x: bytesToBase64url(epk.publicKey) },
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
  const keyLen = 256
  const crv = 'X25519'

  let partyUInfo: Uint8Array
  let partyVInfo: Uint8Array
  if (options.apu !== undefined) partyUInfo = base64ToBytes(options.apu)
  if (options.apv !== undefined) partyVInfo = base64ToBytes(options.apv)

  async function encryptCek(cek: Uint8Array, ephemeralKeyPair?: EphemeralKeyPair): Promise<Recipient> {
    const ephemeral: X25519KeyPair = ephemeralKeyPair
      ? generateKeyPairFromSeed(ephemeralKeyPair.secretKey)
      : generateKeyPair()
    const epk = { kty: 'OKP', crv, x: bytesToBase64url(ephemeral.publicKey) }
    const zE = sharedKey(ephemeral.secretKey, recipientPublicKey)

    // ECDH-1PU requires additional shared secret between
    // static key of sender and static key of recipient
    let zS
    if (senderSecret instanceof Uint8Array) {
      zS = sharedKey(senderSecret, recipientPublicKey)
    } else {
      zS = await senderSecret(recipientPublicKey)
    }

    const sharedSecret = new Uint8Array(zE.length + zS.length)
    sharedSecret.set(zE)
    sharedSecret.set(zS, zE.length)

    // Key Encryption Key
    const kek = concatKDF(sharedSecret, keyLen, alg, partyUInfo, partyVInfo)

    const res = xc20pEncrypter(kek)(cek)
    const recipient: Recipient = {
      encrypted_key: bytesToBase64url(res.ciphertext),
      header: {
        iv: bytesToBase64url(res.iv),
        tag: bytesToBase64url(res.tag),
      },
    }
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
      protectedHeader.epk = ephemeralKeyPair.publicKey
    }
    return {
      ...(await xc20pDirEncrypter(cek).encrypt(cleartext, protectedHeader, aad)),
      recipient,
      cek,
    }
  }

  return { alg, enc: 'XC20P', encrypt, encryptCek, genEpk: genX25519EphemeralKeyPair }
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
        // TODO: should be able to use non base58 keys too
        return key.type === 'X25519KeyAgreementKey2019' && Boolean(key.publicKeyBase58)
      }) || []
    if (!pks.length && !controllerEncrypters.length)
      throw new Error(`no_suitable_keys: Could not find x25519 key for ${did}`)
    return pks
      .map((pk) => x25519Encrypter(base58ToBytes(<string>pk.publicKeyBase58), pk.id))
      .concat(...controllerEncrypters)
  }

  const encrypterPromises = dids.map((did) => encryptersForDID(did))
  const encrypterArrays = await Promise.all(encrypterPromises)
  const flattenedArray = ([] as Encrypter[]).concat(...encrypterArrays)
  return flattenedArray
}

function validateHeader(header?: ProtectedHeader): Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>> {
  if (!(header && header.epk && header.iv && header.tag)) {
    throw new Error('bad_jwe: malformed header')
  }
  return header as Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>>
}

export function x25519Decrypter(receiverSecret: Uint8Array | ECDH): Decrypter {
  const alg = 'ECDH-ES+XC20PKW'
  const keyLen = 256
  const crv = 'X25519'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
    const header = validateHeader(recipient.header)
    if (header.epk?.crv !== crv || typeof header.epk.x == 'undefined') return null
    const publicKey = base64ToBytes(header.epk.x)
    let sharedSecret
    if (receiverSecret instanceof Uint8Array) {
      sharedSecret = sharedKey(receiverSecret, publicKey)
    } else {
      sharedSecret = await receiverSecret(publicKey)
    }

    // Key Encryption Key
    let producerInfo: Uint8Array | undefined = undefined
    let consumerInfo: Uint8Array | undefined = undefined
    if (recipient.header.apu) producerInfo = base64ToBytes(recipient.header.apu)
    if (recipient.header.apv) consumerInfo = base64ToBytes(recipient.header.apv)
    const kek = concatKDF(sharedSecret, keyLen, alg, producerInfo, consumerInfo)
    // Content Encryption Key
    const sealedCek = toSealed(recipient.encrypted_key, header.tag)
    const cek = await xc20pDirDecrypter(kek).decrypt(sealedCek, base64ToBytes(header.iv))
    if (cek === null) return null

    return xc20pDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc: 'XC20P', decrypt }
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
  const keyLen = 256
  const crv = 'X25519'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
    const header = validateHeader(recipient.header)
    if (header.epk?.crv !== crv || typeof header.epk.x == 'undefined') return null
    // ECDH-1PU requires additional shared secret between
    // static key of sender and static key of recipient
    const publicKey = base64ToBytes(header.epk.x)
    let zE: Uint8Array
    let zS: Uint8Array

    if (recipientSecret instanceof Uint8Array) {
      zE = sharedKey(recipientSecret, publicKey)
      zS = sharedKey(recipientSecret, senderPublicKey)
    } else {
      zE = await recipientSecret(publicKey)
      zS = await recipientSecret(senderPublicKey)
    }

    const sharedSecret = new Uint8Array(zE.length + zS.length)
    sharedSecret.set(zE)
    sharedSecret.set(zS, zE.length)

    // Key Encryption Key
    let producerInfo
    let consumerInfo
    if (recipient.header.apu) producerInfo = base64ToBytes(recipient.header.apu)
    if (recipient.header.apv) consumerInfo = base64ToBytes(recipient.header.apv)

    const kek = concatKDF(sharedSecret, keyLen, alg, producerInfo, consumerInfo)
    // Content Encryption Key
    const sealedCek = toSealed(recipient.encrypted_key, header.tag)
    const cek = await xc20pDirDecrypter(kek).decrypt(sealedCek, base64ToBytes(header.iv))
    if (cek === null) return null

    return xc20pDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc: 'XC20P', decrypt }
}
