import { sharedKey } from '@stablelib/x25519'

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
    return sharedKey(mySecretKey, theirPublicKey)
  }
}
