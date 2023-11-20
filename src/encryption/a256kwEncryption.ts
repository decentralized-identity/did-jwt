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
import { base64ToBytes, toSealed } from '../util.js'
import { a256gcmDecrypter, a256gcmEncrypter, a256kwEncrypter } from './a256kwgcm.js'  // change 1st two
import { computeP256EcdhEsKek, createP256EcdhEsKek } from './P256-ECDH-ES.js' // change
import { extractPublicKeyBytes } from '../VerifierAlgorithm.js'
import { createFullP256Encrypter } from './createEncrypter.js'

// I need to change the comments in this file

export function validateHeader(header?: ProtectedHeader): Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>> {
  if (!(header && header.epk && header.iv && header.tag)) {
    throw new Error('bad_jwe: malformed header')
  }
  return header as Required<Pick<ProtectedHeader, 'epk' | 'iv' | 'tag'>>
}

export const a256kwKeyWrapper: KeyWrapper = {
  from: (wrappingKey: Uint8Array) => {
    const wrap = async (cek: Uint8Array): Promise<WrappingResult> => { 
      return a256kwEncrypter(wrappingKey)(cek)     // ECDH-ES+A256KW: ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
    }
    return { wrap }
  },

  alg: 'A256KW',
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
 *
 * Implements ECDH-ES+A256KW with A256GCM based on the following specs:
 *   - {@link https://tools.ietf.org/html/draft-amringer-jose-chacha-02 | XC20PKW}
 *   - {@link https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03 | ECDH-1PU}
 */
export function a256gcmAuthEncrypterEcdhP256Witha256kw(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH,
  options: Partial<AuthEncryptParams> = {}
): Encrypter {
  return createFullP256Encrypter(
    recipientPublicKey,
    senderSecret,
    options,
    { createKek: createP256EcdhEsKek, alg: 'ECDH-ES' },
    a256kwKeyWrapper,
    { from: (cek: Uint8Array) => a256gcmEncrypter(cek), enc: 'A256GCM' }
  )
}

// I am not sure how to write this code...
export async function resolveP256Encrypters(dids: string[], resolver: Resolvable, senderSecret: Uint8Array | ECDH, options: Partial<AuthEncryptParams> = {}): Promise<Encrypter[]> {
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
        return key.type === 'P256KeyAgreementKey2019' || key.type === 'P256KeyAgreementKey2020'
      }) || []
    if (!pks.length && !controllerEncrypters.length)
      throw new Error(`no_suitable_keys: Could not find p256 key for ${did}`)
    return pks.map((pk) => a256gcmAuthEncrypterEcdhP256Witha256kw(extractPublicKeyBytes(pk),senderSecret,options)).concat(...controllerEncrypters)
  }

  const encrypterPromises = dids.map((did) => encryptersForDID(did))
  const encrypterArrays = await Promise.all(encrypterPromises)
  return ([] as Encrypter[]).concat(...encrypterArrays)
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
export function a256gcmAuthDecrypterEcdh1PuV3p256Witha256kw(
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
    const header = validateHeader(recipient.header)
    const kek = await computeP256EcdhEsKek(recipient, recipientSecret, alg)
    if (!kek) return null
    // Content Encryption Key
    const sealedCek = toSealed(recipient.encrypted_key, header.tag)
    const cek = await a256gcmDecrypter(kek).decrypt(sealedCek, base64ToBytes(header.iv))
    if (cek === null) return null

    return a256gcmDecrypter(cek).decrypt(sealed, iv, aad)
  }

  return { alg, enc, decrypt }
}
