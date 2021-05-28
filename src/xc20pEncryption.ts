import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305'
import { generateKeyPair, sharedKey } from '@stablelib/x25519'
import { randomBytes } from '@stablelib/random'
import { concatKDF } from './Digest'
import { bytesToBase64url, base58ToBytes, encodeBase64url, toSealed, base64ToBytes } from './util'
import { Recipient, EncryptionResult, Encrypter, Decrypter } from './JWE'
import type { VerificationMethod, Resolvable } from 'did-resolver'

// remove when targeting node 11+ or ES2019
const flatten = <T>(arrays: T[]) => [].concat.apply([], arrays)

export type AuthEncryptParams = {
  kid?: string
  skid?: string
  // base64url encoded
  apu?: string
  // base64url encoded
  apv?: string
}

export type AnonEncryptParams = {
  kid?: string
}

/**
 * Recommended encrypter for authenticated encryption (i.e. sender authentication and requires
 * sender private key to encrypt the data).
 * Uses ECDH-1PU [v3](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03) and
 * XC20PKW [v2](https://tools.ietf.org/html/draft-amringer-jose-chacha-02).
 *
 * NOTE: ECDH-1PU and XC20PKW are proposed drafts in IETF and not a standard yet and
 * are subject to change as new revisions or until the offical CFRG specification are released.
 */
export function createAuthEncrypter(
  recipientPublicKey: Uint8Array,
  senderSecretKey: Uint8Array,
  options: Partial<AuthEncryptParams> = {}
): Encrypter {
  return xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(recipientPublicKey, senderSecretKey, options)
}

/**
 * Recommended encrypter for anonymous encryption (i.e. no sender authentication).
 * Uses ECDH-ES+XC20PKW [v2](https://tools.ietf.org/html/draft-amringer-jose-chacha-02).
 *
 * NOTE: ECDH-ES+XC20PKW is a proposed draft in IETF and not a standard yet and
 * is subject to change as new revisions or until the offical CFRG specification is released.
 */
export function createAnonEncrypter(publicKey: Uint8Array, options: Partial<AnonEncryptParams> = {}): Encrypter {
  return options !== undefined ? x25519Encrypter(publicKey, options.kid) : x25519Encrypter(publicKey)
}

/**
 * Recommended decrypter for authenticated encryption (i.e. sender authentication and requires
 * sender public key to decrypt the data).
 * Uses ECDH-1PU [v3](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03) and
 * XC20PKW [v2](https://tools.ietf.org/html/draft-amringer-jose-chacha-02).
 *
 * NOTE: ECDH-1PU and XC20PKW are proposed drafts in IETF and not a standard yet and
 * are subject to change as new revisions or until the offical CFRG specification are released.
 */
export function createAuthDecrypter(recipientSecretKey: Uint8Array, senderPublicKey: Uint8Array): Decrypter {
  return xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(recipientSecretKey, senderPublicKey)
}

/**
 * Recommended decrypter for anonymous encryption (i.e. no sender authentication).
 * Uses ECDH-ES+XC20PKW [v2](https://tools.ietf.org/html/draft-amringer-jose-chacha-02).
 *
 * NOTE: ECDH-ES+XC20PKW is a proposed draft in IETF and not a standard yet and
 * is subject to change as new revisions or until the offical CFRG specification is released.
 */
export function createAnonDecrypter(secretKey: Uint8Array): Decrypter {
  return x25519Decrypter(secretKey)
}

function xc20pEncrypter(key: Uint8Array): (cleartext: Uint8Array, aad?: Uint8Array) => EncryptionResult {
  const cipher = new XChaCha20Poly1305(key)
  return (cleartext: Uint8Array, aad?: Uint8Array) => {
    const iv = randomBytes(cipher.nonceLength)
    const sealed = cipher.seal(iv, cleartext, aad)
    return {
      ciphertext: sealed.subarray(0, sealed.length - cipher.tagLength),
      tag: sealed.subarray(sealed.length - cipher.tagLength),
      iv
    }
  }
}

export function xc20pDirEncrypter(key: Uint8Array): Encrypter {
  const xc20pEncrypt = xc20pEncrypter(key)
  const enc = 'XC20P'
  const alg = 'dir'
  async function encrypt(cleartext, protectedHeader = {}, aad?): Promise<EncryptionResult> {
    const protHeader = encodeBase64url(JSON.stringify(Object.assign({ alg }, protectedHeader, { enc })))
    const encodedAad = new Uint8Array(Buffer.from(aad ? `${protHeader}.${bytesToBase64url(aad)}` : protHeader))
    return {
      ...xc20pEncrypt(cleartext, encodedAad),
      protectedHeader: protHeader
    }
  }
  return { alg, enc, encrypt }
}

export function xc20pDirDecrypter(key: Uint8Array): Decrypter {
  const cipher = new XChaCha20Poly1305(key)
  async function decrypt(sealed, iv, aad?): Promise<Uint8Array> {
    return cipher.open(iv, sealed, aad)
  }
  return { alg: 'dir', enc: 'XC20P', decrypt }
}

export function x25519Encrypter(publicKey: Uint8Array, kid?: string): Encrypter {
  const alg = 'ECDH-ES+XC20PKW'
  const keyLen = 256
  const crv = 'X25519'
  async function encryptCek(cek): Promise<Recipient> {
    const epk = generateKeyPair()
    const sharedSecret = sharedKey(epk.secretKey, publicKey)
    // Key Encryption Key
    const kek = concatKDF(sharedSecret, keyLen, alg)
    const res = xc20pEncrypter(kek)(cek)
    const recipient: Recipient = {
      encrypted_key: bytesToBase64url(res.ciphertext),
      header: {
        alg,
        iv: bytesToBase64url(res.iv),
        tag: bytesToBase64url(res.tag),
        epk: { kty: 'OKP', crv, x: bytesToBase64url(epk.publicKey) }
      }
    }
    if (kid) recipient.header.kid = kid
    return recipient
  }
  async function encrypt(cleartext, protectedHeader = {}, aad?): Promise<EncryptionResult> {
    // we won't want alg to be set to dir from xc20pDirEncrypter
    Object.assign(protectedHeader, { alg: undefined })
    // Content Encryption Key
    const cek = randomBytes(32)
    return {
      ...(await xc20pDirEncrypter(cek).encrypt(cleartext, protectedHeader, aad)),
      recipient: await encryptCek(cek),
      cek
    }
  }
  return { alg, enc: 'XC20P', encrypt, encryptCek }
}

/**
 * Implements ECDH-1PU+XC20PKW with XChaCha20Poly1305 based on the following specs:
 *   - [XC20PKW](https://tools.ietf.org/html/draft-amringer-jose-chacha-02)
 *   - [ECDH-1PU](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03)
 */
export function xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(
  recipientPublicKey: Uint8Array,
  senderSecretKey: Uint8Array,
  options: Partial<AuthEncryptParams> = {}
): Encrypter {
  const alg = 'ECDH-1PU+XC20PKW'
  const keyLen = 256
  const crv = 'X25519'

  let partyUInfo
  let partyVInfo
  if (options.apu !== undefined) partyUInfo = base64ToBytes(options.apu)
  if (options.apv !== undefined) partyVInfo = base64ToBytes(options.apv)

  async function encryptCek(cek): Promise<Recipient> {
    const epk = generateKeyPair()
    const zE = sharedKey(epk.secretKey, recipientPublicKey)

    // ECDH-1PU requires additional shared secret between
    // static key of sender and static key of recipient
    const zS = sharedKey(senderSecretKey, recipientPublicKey)

    const sharedSecret = new Uint8Array(zE.length + zS.length)
    sharedSecret.set(zE)
    sharedSecret.set(zS, zE.length)

    // Key Encryption Key
    const kek = concatKDF(sharedSecret, keyLen, alg, partyUInfo, partyVInfo)

    const res = xc20pEncrypter(kek)(cek)
    const recipient: Recipient = {
      encrypted_key: bytesToBase64url(res.ciphertext),
      header: {
        alg,
        iv: bytesToBase64url(res.iv),
        tag: bytesToBase64url(res.tag),
        epk: { kty: 'OKP', crv, x: bytesToBase64url(epk.publicKey) }
      }
    }
    if (options.kid) recipient.header.kid = options.kid
    if (options.apu) recipient.header.apu = options.apu
    if (options.apv) recipient.header.apv = options.apv

    return recipient
  }
  async function encrypt(cleartext, protectedHeader = {}, aad?): Promise<EncryptionResult> {
    // we won't want alg to be set to dir from xc20pDirEncrypter
    Object.assign(protectedHeader, { alg: undefined, skid: options.skid })
    // Content Encryption Key
    const cek = randomBytes(32)
    return {
      ...(await xc20pDirEncrypter(cek).encrypt(cleartext, protectedHeader, aad)),
      recipient: await encryptCek(cek),
      cek
    }
  }
  return { alg, enc: 'XC20P', encrypt, encryptCek }
}

export async function resolveX25519Encrypters(dids: string[], resolver: Resolvable): Promise<Encrypter[]> {
  const encryptersForDID = async (did): Promise<Encrypter[]> => {
    const { didResolutionMetadata, didDocument } = await resolver.resolve(did)
    if (didResolutionMetadata?.error) {
      throw new Error(
        `Could not find x25519 key for ${did}: ${didResolutionMetadata.error}, ${didResolutionMetadata.message}`
      )
    }
    if (!didDocument.keyAgreement) throw new Error(`Could not find x25519 key for ${did}`)
    const agreementKeys: VerificationMethod[] = didDocument.keyAgreement?.map((key) => {
      if (typeof key === 'string') {
        return [...(didDocument.publicKey || []), ...(didDocument.verificationMethod || [])].find((pk) => pk.id === key)
      }
      return key
    })
    const pks = agreementKeys.filter((key) => {
      return key.type === 'X25519KeyAgreementKey2019' && Boolean(key.publicKeyBase58)
    })
    if (!pks.length) throw new Error(`Could not find x25519 key for ${did}`)
    return pks.map((pk) => x25519Encrypter(base58ToBytes(pk.publicKeyBase58), pk.id))
  }

  const encrypterPromises = dids.map((did) => encryptersForDID(did))
  const encrypterArrays = await Promise.all(encrypterPromises)

  return flatten(encrypterArrays)
}

function validateHeader(header: Record<string, any>) {
  if (!(header.epk && header.iv && header.tag)) {
    throw new Error('Invalid JWE')
  }
}

export function x25519Decrypter(secretKey: Uint8Array): Decrypter {
  const alg = 'ECDH-ES+XC20PKW'
  const keyLen = 256
  const crv = 'X25519'
  async function decrypt(sealed, iv, aad, recipient): Promise<Uint8Array> {
    validateHeader(recipient.header)
    if (recipient.header.epk.crv !== crv) return null
    const publicKey = base64ToBytes(recipient.header.epk.x)
    const sharedSecret = sharedKey(secretKey, publicKey)

    // Key Encryption Key
    const kek = concatKDF(sharedSecret, keyLen, alg)
    // Content Encryption Key
    const sealedCek = toSealed(recipient.encrypted_key, recipient.header.tag)
    const cek = await xc20pDirDecrypter(kek).decrypt(sealedCek, base64ToBytes(recipient.header.iv))
    if (cek === null) return null

    return xc20pDirDecrypter(cek).decrypt(sealed, iv, aad)
  }
  return { alg, enc: 'XC20P', decrypt }
}

/**
 * Implements ECDH-1PU+XC20PKW with XChaCha20Poly1305 based on the following specs:
 *   - [XC20PKW](https://tools.ietf.org/html/draft-amringer-jose-chacha-02)
 *   - [ECDH-1PU](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03)
 */
export function xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(
  recipientSecretKey: Uint8Array,
  senderPublicKey: Uint8Array
): Decrypter {
  const alg = 'ECDH-1PU+XC20PKW'
  const keyLen = 256
  const crv = 'X25519'
  async function decrypt(sealed, iv, aad, recipient): Promise<Uint8Array> {
    validateHeader(recipient.header)
    if (recipient.header.epk.crv !== crv) return null
    // ECDH-1PU requires additional shared secret between
    // static key of sender and static key of recipient
    const publicKey = base64ToBytes(recipient.header.epk.x)
    const zE = sharedKey(recipientSecretKey, publicKey)
    const zS = sharedKey(recipientSecretKey, senderPublicKey)

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
    const sealedCek = toSealed(recipient.encrypted_key, recipient.header.tag)
    const cek = await xc20pDirDecrypter(kek).decrypt(sealedCek, base64ToBytes(recipient.header.iv))
    if (cek === null) return null

    return xc20pDirDecrypter(cek).decrypt(sealed, iv, aad)
  }
  return { alg, enc: 'XC20P', decrypt }
}
