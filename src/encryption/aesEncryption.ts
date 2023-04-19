import { Decrypter, Encrypter, EncryptionResult, EphemeralKeyPair, ProtectedHeader, Recipient } from './JWE.js'
import { base64ToBytes, bytesToBase64url, encodeBase64url } from '../util.js'
import { AuthEncryptParams, genX25519EphemeralKeyPair } from './xc20pEncryption.js'
import { ECDH } from './ECDH.js'
import { KeyUnwrapper, KeyWrapper } from './KW.js'
import { xc20pDirDecrypter, xc20pDirEncrypter } from './xc20pDir.js'
import { computeX25519EcdhEsKek, createX25519EcdhEsKek } from './X25519-ECDH-ES.js'
import { computeX25519Ecdh1PUv3Kek, createX25519Ecdh1PUv3Kek } from './X25519-ECDH-1PU.js'
import { randomBytes } from '@noble/hashes/utils'
import { AESKW } from '@stablelib/aes-kw'
import { AES } from '@stablelib/aes'
import { GCM } from '@stablelib/gcm'
import { fromString } from 'uint8arrays/from-string'

/**
 * Creates a wrapper using AES-KW
 * @param wrappingKey
 */
export function a256KeyWrapper(wrappingKey: Uint8Array): KeyWrapper {
  const wrap = async (cek: Uint8Array): Promise<EncryptionResult> => {
    return { ciphertext: new AESKW(wrappingKey).wrapKey(cek) }
  }
  return { wrap, alg: 'A256KW' }
}

export function a256KeyUnwrapper(wrappingKey: Uint8Array): KeyUnwrapper {
  const unwrap = async (wrappedCek: Uint8Array): Promise<Uint8Array | null> => {
    try {
      return new AESKW(wrappingKey).unwrapKey(wrappedCek)
    } catch (e) {
      return null
    }
  }
  return { unwrap, alg: 'A256KW' }
}

export function a256gcmEncrypter(key: Uint8Array): (cleartext: Uint8Array, aad?: Uint8Array) => EncryptionResult {
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

export function a256gcmDirEncrypter(key: Uint8Array): Encrypter {
  const xc20pEncrypt = a256gcmEncrypter(key)
  const enc = 'A256GCM'
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

export function a256gcmDirDecrypter(key: Uint8Array): Decrypter {
  const cipher = new GCM(new AES(key))

  async function decrypt(sealed: Uint8Array, iv: Uint8Array, aad?: Uint8Array): Promise<Uint8Array | null> {
    return cipher.open(iv, sealed, aad)
  }

  return { alg: 'dir', enc: 'A256GCM', decrypt }
}

export function a256gcmAnonEncrypterX25519WithA256KW(
  recipientPublicKey: Uint8Array,
  kid?: string,
  apv?: string
): Encrypter {
  const alg = 'ECDH-ES+A256KW'
  const enc = 'A256GCM'

  async function encryptCek(cek: Uint8Array, ephemeralKeyPair?: EphemeralKeyPair): Promise<Recipient> {
    const { epk, kek } = createX25519EcdhEsKek(ephemeralKeyPair, recipientPublicKey, apv, alg)
    const wrapper = a256KeyWrapper(kek)
    const res = await wrapper.wrap(cek)
    const recipient: Recipient = {
      encrypted_key: bytesToBase64url(res.ciphertext),
      header: {},
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
      protectedHeader.epk = ephemeralKeyPair.publicKeyJWK
    }
    return {
      ...(await a256gcmDirEncrypter(cek).encrypt(cleartext, protectedHeader, aad)),
      recipient,
      cek,
    }
  }

  return { alg, enc, encrypt, encryptCek, genEpk: genX25519EphemeralKeyPair }
}

export function xc20pAnonEncrypterX25519WithA256KW(
  recipientPublicKey: Uint8Array,
  kid?: string,
  apv?: string
): Encrypter {
  const alg = 'ECDH-ES+A256KW'
  const enc = 'XC20P'

  async function encryptCek(cek: Uint8Array, ephemeralKeyPair?: EphemeralKeyPair): Promise<Recipient> {
    const { epk, kek } = createX25519EcdhEsKek(ephemeralKeyPair, recipientPublicKey, apv, alg)
    const wrapper = a256KeyWrapper(kek)
    const res = await wrapper.wrap(cek)
    const recipient: Recipient = {
      encrypted_key: bytesToBase64url(res.ciphertext),
      header: {},
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

export function xc20pAnonDecrypterX25519WithA256KW(receiverSecret: Uint8Array | ECDH): Decrypter {
  const alg = 'ECDH-ES+A256KW'
  const enc = 'XC20P'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
    const kek = await computeX25519EcdhEsKek(recipient, receiverSecret, alg)
    if (kek === null) return null
    // Content Encryption Key
    const unwrapper = a256KeyUnwrapper(kek)
    const cek = await unwrapper.unwrap(base64ToBytes(recipient.encrypted_key))
    if (cek === null) return null

    return xc20pDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
}

export function a256gcmAnonDecrypterX25519WithA256KW(receiverSecret: Uint8Array | ECDH): Decrypter {
  const alg = 'ECDH-ES+A256KW'
  const enc = 'A256GCM'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
    const kek = await computeX25519EcdhEsKek(recipient, receiverSecret, alg)
    if (kek === null) return null
    // Content Encryption Key
    const unwrapper = a256KeyUnwrapper(kek)
    const cek = await unwrapper.unwrap(base64ToBytes(recipient.encrypted_key))
    if (cek === null) return null

    return a256gcmDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
}

export function xc20pAuthEncrypterEcdh1PuV3x25519WithA256KW(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH,
  options: Partial<AuthEncryptParams> = {}
): Encrypter {
  const alg = 'ECDH-1PU+A256KW'
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
    const wrapper = a256KeyWrapper(kek)
    const res = await wrapper.wrap(cek)
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

export function xc20pAuthDecrypterEcdh1PuV3x25519WithA256KW(
  recipientSecret: Uint8Array | ECDH,
  senderPublicKey: Uint8Array
): Decrypter {
  const alg = 'ECDH-1PU+A256KW'
  const enc = 'XC20P'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
    const kek = await computeX25519Ecdh1PUv3Kek(recipient, recipientSecret, senderPublicKey, alg)
    if (!kek) return null
    // Content Encryption Key
    const unwrapper = a256KeyUnwrapper(kek)
    const cek = await unwrapper.unwrap(base64ToBytes(recipient.encrypted_key))
    if (cek === null) return null

    return xc20pDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
}

export function a256gcmAuthEncrypterEcdh1PuV3x25519WithA256KW(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH,
  options: Partial<AuthEncryptParams> = {}
): Encrypter {
  const alg = 'ECDH-1PU+A256KW'
  const enc = 'A256GCM'

  async function encryptCek(cek: Uint8Array, ephemeralKeyPair?: EphemeralKeyPair): Promise<Recipient> {
    const { epk, kek } = await createX25519Ecdh1PUv3Kek(
      ephemeralKeyPair,
      recipientPublicKey,
      senderSecret,
      options.apu,
      options.apv,
      alg
    )
    const wrapper = a256KeyWrapper(kek)
    const res = await wrapper.wrap(cek)
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
      ...(await a256gcmDirEncrypter(cek).encrypt(cleartext, protectedHeader, aad)),
      recipient,
      cek,
    }
  }

  return { alg, enc, encrypt, encryptCek, genEpk: genX25519EphemeralKeyPair }
}

export function a256gcmAuthDecrypterEcdh1PuV3x25519WithA256KW(
  recipientSecret: Uint8Array | ECDH,
  senderPublicKey: Uint8Array
): Decrypter {
  const alg = 'ECDH-1PU+A256KW'
  const enc = 'A256GCM'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
    const kek = await computeX25519Ecdh1PUv3Kek(recipient, recipientSecret, senderPublicKey, alg)
    if (!kek) return null
    // Content Encryption Key
    const unwrapper = a256KeyUnwrapper(kek)
    const cek = await unwrapper.unwrap(base64ToBytes(recipient.encrypted_key))
    if (cek === null) return null

    return a256gcmDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
}
