import { x25519 } from '@noble/curves/ed25519'
import { p256 } from '@noble/curves/p256'
import type { ECDH } from './types.js'

/**
 * Wraps an X25519 secret key into an ECDH method that can be used to compute a shared secret with a public key.
 * @param mySecretKey A `Uint8Array` of length 32 representing the bytes of my secret key
 * @returns an `ECDH` method with the signature `(theirPublicKey: Uint8Array) => Promise<Uint8Array>`
 *
 * @throws 'invalid_argument:...' if the secret key size is wrong
 */
export function createX25519ECDH(mySecretKey: Uint8Array): ECDH {
  if (mySecretKey.length !== 32) {
    throw new Error('invalid_argument: incorrect secret key length for X25519')
  }
  return async (theirPublicKey: Uint8Array): Promise<Uint8Array> => {
    if (theirPublicKey.length !== 32) {
      throw new Error('invalid_argument: incorrect publicKey key length for X25519')
    }
    return x25519.getSharedSecret(mySecretKey, theirPublicKey)
  }
}

/**
 * Wraps an P256 secret key into an ECDH method that can be used to compute a shared secret with a public key.
 * @param mySecretKey A `Uint8Array` of length 33 representing the bytes of my secret key in compressed form
 * @returns an `ECDH` method with the signature `(theirPublicKey: Uint8Array) => Promise<Uint8Array>`
 *
 * @throws 'invalid_argument:...' if the secret key size is wrong
 */
export function createP256ECDH(mySecretKey: Uint8Array): ECDH {
  if (mySecretKey.length !== 32) {
    throw new Error('invalid_argument: incorrect secret key length for P256')
  }
  return async (theirPublicKey: Uint8Array): Promise<Uint8Array> => {  // see https://www.rfc-editor.org/rfc/rfc6090#section-4.2 for comment about compact represntation
    if (theirPublicKey.length !== 33) {  // should this be the compressed public key??? ... if it is uncompressed it could be 64 or with prefix 65
      throw new Error('invalid_argument: incorrect publicKey key length for P256')
    }
    return p256.getSharedSecret(mySecretKey, theirPublicKey)
  }
}