import { JsonWebKey } from '../util.js'

/**
 * A wrapper around `mySecretKey` that can compute a shared secret using `theirPublicKey`.
 * The promise should resolve to a `Uint8Array` containing the raw shared secret.
 *
 * This method is meant to be used when direct access to a secret key is impossible or not desired.
 *
 * @param theirPublicKey `Uint8Array` the other party's public key
 * @returns a `Promise` that resolves to a `Uint8Array` representing the computed shared secret
 */
export type ECDH = (theirPublicKey: Uint8Array) => Promise<Uint8Array>

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ProtectedHeader = Record<string, any> & Partial<RecipientHeader>

/**
 * The JWK representation of an ephemeral public key.
 * See https://www.rfc-editor.org/rfc/rfc7518.html#section-6
 */
export interface EphemeralPublicKey {
  kty?: string
  //ECC
  crv?: string
  x?: string
  y?: string
  //RSA
  n?: string
  e?: string
}

/**
 * A pair of an ephemeral public key (JWK) and its corresponding secret key.
 * This is used to encrypt content encryption key (cek) for a recipient.
 *
 * @see {@link KekCreator}
 */
export interface EphemeralKeyPair {
  publicKeyJWK: EphemeralPublicKey
  secretKey: Uint8Array
}

export interface RecipientHeader {
  alg?: string
  iv?: string
  tag?: string
  epk?: EphemeralPublicKey
  kid?: string
  apv?: string
  apu?: string
}

export interface Recipient {
  header: RecipientHeader
  encrypted_key: string
}

export interface JWE {
  protected: string
  iv: string
  ciphertext: string
  tag: string
  aad?: string
  recipients?: Recipient[]
}

export interface EncryptionResult {
  ciphertext: Uint8Array
  tag?: Uint8Array
  iv?: Uint8Array
  protectedHeader?: string
  recipient?: Recipient
  cek?: Uint8Array
}

export interface WrappingResult {
  ciphertext: Uint8Array
  tag?: Uint8Array
  iv?: Uint8Array
}

/**
 * An object that can perform content encryption and optionally key wrapping and key generation.
 */
export interface Encrypter {
  // key agreement + key wrapping algorithms (e.g. ECDH-ES+A256KW)
  alg: string

  // content encryption algorithm (e.g. A256GCM)
  enc: string

  // The content encryption method.
  encrypt: (
    cleartext: Uint8Array,
    protectedHeader: ProtectedHeader,
    aad?: Uint8Array,
    ephemeralKeyPair?: EphemeralKeyPair
  ) => Promise<EncryptionResult>

  // The method to encrypt the content encryption key (cek) for a recipient.
  encryptCek?: (cek: Uint8Array, ephemeralKeyPair?: EphemeralKeyPair) => Promise<Recipient>

  // The method to generate an ephemeral key pair.
  genEpk?: () => EphemeralKeyPair
}

/**
 * An object that can perform decryption of a ciphertext.
 * It also describes the content encryption (enc) and key agreement + wrapping (alg) algorithms it supports.
 */
export interface Decrypter {
  alg: string
  enc: string
  decrypt: (sealed: Uint8Array, iv: Uint8Array, aad?: Uint8Array, recipient?: Recipient) => Promise<Uint8Array | null>
}

/**
 * An object that can perform key unwrapping.
 */
export type KeyWrapper = {
  /**
   * Create a key wrapper from a key encryption key (kek).
   * @param kek
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  from: (kek: Uint8Array) => { wrap: (cek: Uint8Array, options?: any) => Promise<WrappingResult> }
  // key wrapping algorithm (e.g. A256KW, XC20PKW)
  alg: 'A256KW' | 'XC20PKW' | string
}

export type KekCreator = {
  createKek(
    recipientPublicKey: Uint8Array,
    senderSecret: Uint8Array | ECDH | undefined,
    // key agreement + key wrapping algorithm. e.g. ECDH-ES+A256KW
    alg: string,
    apu: string | undefined,
    apv: string | undefined,
    ephemeralKeyPair: EphemeralKeyPair | undefined
  ): Promise<{ epk: JsonWebKey; kek: Uint8Array }>

  // key agreement algorithm
  alg: 'ECDH-ES' | 'ECDH-1PU' | string
}

export type ContentEncrypter = {
  /**
   * Create a content `Encrypter` from a content encryption key (cek).
   * @param cek
   */
  from(cek: Uint8Array): Encrypter
  // content encryption algorithm
  enc: 'XC20P' | 'A256GCM' | 'A256CBC-HS512' | string
}

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
