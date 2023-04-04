import { randomBytes } from '@stablelib/random'
import { generateKeyPair, generateKeyPairFromSeed, KeyPair as X25519KeyPair, sharedKey } from '@stablelib/x25519'
import { Decrypter, Encrypter, EncryptionResult, EphemeralKeyPair, ProtectedHeader, Recipient } from './JWE.js'
import { concatKDF } from './Digest.js'
import { base64ToBytes, bytesToBase64url } from './util.js'
import { genX25519EphemeralKeyPair, xc20pDirDecrypter, xc20pDirEncrypter } from './xc20pEncryption.js'
import crypto from 'isomorphic-webcrypto'
import { ECDH } from './ECDH'

export async function a256KeyWrapper(wrappingKey: Uint8Array) {
  // TODO: check wrapping key size
  const cryptoWrappingKey = await crypto.subtle.importKey(
    'raw',
    wrappingKey,
    {
      name: 'AES-KW',
      length: 256,
    },
    false,
    ['wrapKey', 'unwrapKey']
  )

  return async (cek: Uint8Array): Promise<Uint8Array> => {
    // create a CryptoKey instance from the cek. The algorithm doesn't matter since we'll be working with raw keys
    const cryptoCek = await crypto.subtle.importKey('raw', cek, { hash: 'SHA-256', name: 'HMAC' }, true, ['sign'])
    return new Uint8Array(await crypto.subtle.wrapKey('raw', cryptoCek, cryptoWrappingKey, 'AES-KW'))
  }
}

export async function a256KeyUnwrapper(wrappingKey: Uint8Array) {
  // TODO: check wrapping key size
  const cryptoWrappingKey = await crypto.subtle.importKey(
    'raw',
    wrappingKey,
    {
      name: 'AES-KW',
      length: 256,
    },
    false,
    ['wrapKey', 'unwrapKey']
  )

  return async (wrappedCek: Uint8Array): Promise<Uint8Array> => {
    const cryptoKeyCek = await crypto.subtle.unwrapKey(
      'raw',
      wrappedCek,
      cryptoWrappingKey,
      'AES-KW',
      // algorithm doesn't matter since we'll be exporting as raw
      { hash: 'SHA-256', name: 'HMAC' },
      true,
      ['sign']
    )

    return new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKeyCek))
  }
}

export function x25519EncrypterWithA256KW(publicKey: Uint8Array, kid?: string): Encrypter {
  const alg = 'ECDH-ES+A256KW'
  const keyLen = 256
  const crv = 'X25519'

  async function encryptCek(cek: Uint8Array, ephemeralKeyPair?: EphemeralKeyPair): Promise<Recipient> {
    const ephemeral: X25519KeyPair = ephemeralKeyPair
      ? generateKeyPairFromSeed(ephemeralKeyPair.secretKey)
      : generateKeyPair()
    const epk = { kty: 'OKP', crv, x: bytesToBase64url(ephemeral.publicKey) }
    const sharedSecret = sharedKey(ephemeral.secretKey, publicKey)
    // Key Encryption Key
    const kek = concatKDF(sharedSecret, keyLen, alg)
    const wrapper = await a256KeyWrapper(kek)
    const res = await wrapper(cek)
    const recipient: Recipient = {
      encrypted_key: bytesToBase64url(res),
      header: {},
    }
    if (kid) recipient.header.kid = kid
    if (!ephemeralKeyPair) {
      recipient.header.epk = epk
      recipient.header.alg = alg
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
      delete recipient.header.alg
      delete recipient.header.epk
    }
    return {
      ...(await xc20pDirEncrypter(cek).encrypt(cleartext, protectedHeader, aad)),
      recipient,
      cek,
    }
  }

  return { alg, enc: 'XC20P', encrypt, encryptCek, genEpk: genX25519EphemeralKeyPair }
}

export function x25519DecrypterWithA256KW(receiverSecret: Uint8Array | ECDH): Decrypter {
  const alg = 'ECDH-ES+A256KW'
  const keyLen = 256
  const crv = 'X25519'

  async function decrypt(
    sealed: Uint8Array,
    iv: Uint8Array,
    aad?: Uint8Array,
    recipient?: Recipient
  ): Promise<Uint8Array | null> {
    recipient = <Recipient>recipient
    const header = recipient.header
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
    const unwrap = await a256KeyUnwrapper(kek)
    const cek = await unwrap(base64ToBytes(recipient.encrypted_key))
    if (cek === null) return null

    return xc20pDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc: 'XC20P', decrypt }
}
