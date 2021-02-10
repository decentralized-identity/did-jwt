import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305'
import { generateKeyPair, sharedKey } from '@stablelib/x25519'
import { randomBytes } from '@stablelib/random'
import { concatKDF } from './Digest'
import { bytesToBase64url, base58ToBytes, encodeBase64url, toSealed, base64ToBytes } from './util'
import { Recipient, EncryptionResult, Encrypter, Decrypter } from './JWE'
import type { PublicKey, Resolver } from 'did-resolver'

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
      ...(xc20pEncrypt(cleartext, encodedAad)),
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

export async function resolveX25519Encrypters(dids: string[], resolver: Resolver): Promise<Encrypter[]> {
  return Promise.all(
    dids.map(async (did) => {
      const didDoc = await resolver.resolve(did)
      if (!didDoc.keyAgreement) throw new Error(`Could not find x25519 key for ${did}`)
      const agreementKeys: PublicKey[] = didDoc.keyAgreement?.map((key) => {
        if (typeof key === 'string') {
          return didDoc.publicKey.find((pk) => pk.id === key)
        }
        return key
      })
      const pk = agreementKeys.find((key) => {
        return key.type === 'X25519KeyAgreementKey2019' && Boolean(key.publicKeyBase58)
      })
      if (!pk) throw new Error(`Could not find x25519 key for ${did}`)
      return x25519Encrypter(base58ToBytes(pk.publicKeyBase58), pk.id)
    })
  )
}

function validateHeader(header: Record<string, any>) {
  if(!(
    header.epk &&
    header.iv &&
    header.tag
  )) {
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
