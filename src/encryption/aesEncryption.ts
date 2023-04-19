import { randomBytes } from '@stablelib/random'
import crypto from 'isomorphic-webcrypto'
import { Decrypter, Encrypter, EncryptionResult, EphemeralKeyPair, ProtectedHeader, Recipient } from './JWE.js'
import { base64ToBytes, bytesToBase64url } from '../util.js'
import { genX25519EphemeralKeyPair } from './xc20pEncryption.js'
import { ECDH } from './ECDH.js'
import { KeyUnwrapper, KeyWrapper } from './KW.js'
import { xc20pDirDecrypter, xc20pDirEncrypter } from './xc20pDir.js'
import { computeX25519EcdhEsKek, createX25519EcdhEsKek } from './X25519-ECDH-ES.js'

/**
 * Creates a wrapper using AES-KW
 * @param wrappingKey
 */
export async function a256KeyWrapper(wrappingKey: Uint8Array): Promise<KeyWrapper> {
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

  const wrap = async (cek: Uint8Array): Promise<EncryptionResult> => {
    // create a CryptoKey instance from the cek. The algorithm doesn't matter since we'll be working with raw keys
    const cryptoCek = await crypto.subtle.importKey('raw', cek, { hash: 'SHA-256', name: 'HMAC' }, true, ['sign'])
    const ciphertext = new Uint8Array(await crypto.subtle.wrapKey('raw', cryptoCek, cryptoWrappingKey, 'AES-KW'))
    return { ciphertext }
  }
  return { wrap, alg: 'A256KW' }
}

export async function a256KeyUnwrapper(wrappingKey: Uint8Array): Promise<KeyUnwrapper> {
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

  const unwrap = async (wrappedCek: Uint8Array): Promise<Uint8Array> => {
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
  return { unwrap, alg: 'A256KW' }
}

export function x25519EncrypterWithA256KW(publicKey: Uint8Array, kid?: string, apv?: string): Encrypter {
  const alg = 'ECDH-ES+A256KW'
  const enc = 'XC20P'

  async function encryptCek(cek: Uint8Array, ephemeralKeyPair?: EphemeralKeyPair): Promise<Recipient> {
    const { epk, kek } = createX25519EcdhEsKek(ephemeralKeyPair, publicKey, apv, alg)
    const wrapper = await a256KeyWrapper(kek)
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

export function x25519DecrypterWithA256KW(receiverSecret: Uint8Array | ECDH): Decrypter {
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
    const unwrapper = await a256KeyUnwrapper(kek)
    const cek = await unwrapper.unwrap(base64ToBytes(recipient.encrypted_key))
    if (cek === null) return null

    return xc20pDirDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
}
