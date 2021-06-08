import { sharedKey } from '@stablelib/x25519'

/**
 * A wrapper around `mySecretKey` that can compute a shared secret using `theirPublicKey`
 * The promise should resolve to a Uint8Array containing the raw shared secret.
 *
 */
export type ECDH = (theirPublicKey: Uint8Array) => Promise<Uint8Array>

/**
 * Wraps an X25519 secretKey into an ECDH method that can be used to compute a shared secret with a publicKey.
 * @param mySecretKey A `Uint8Array` representing the bytes of my secret key
 * @returns an `ECDH` method with the signature `(theirPublicKey: Uint8Array) => Promise<Uint8Array>`
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
