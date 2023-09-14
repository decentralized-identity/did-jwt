import { x25519 } from '@noble/curves/ed25519'
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
