import { ed25519 } from '@noble/curves/ed25519'
import type { Signer } from '../JWT.js'
import { bytesToBase64url, stringToBytes } from '../util.js'

/**
 *  Creates a configured signer function for signing data using the EdDSA (Ed25519) algorithm.
 *
 *  The private key is expected to be a `Uint8Array` of 32 bytes, but for compatibility 64 bytes are also acceptable.
 * Users of `@stablelib/ed25519` or `tweetnacl` will be able to use the 64 byte secret keys that library generates.
 * These libraries precompute the public key and append it as the last 32 bytes of the secretKey, to speed up later
 * signing operations.
 *
 *  The signing function itself takes the data as a `Uint8Array` or utf8 `string` and returns a `base64Url`-encoded
 * signature
 *
 *  @example
 *  ```typescript
 *  const sign: Signer = EdDSASigner(process.env.PRIVATE_KEY)
 *  const signature: string = await sign(data)
 *  ```
 *
 *  @param    {String}    secretKey   a 32 or 64 byte secret key as `Uint8Array`
 *  @return   {Function}              a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export function EdDSASigner(secretKey: Uint8Array): Signer {
  const privateKeyBytes: Uint8Array = secretKey
  if (![32, 64].includes(privateKeyBytes.length)) {
    throw new Error(`bad_key: Invalid private key format. Expecting 32 or 64 bytes, but got ${privateKeyBytes.length}`)
  }
  return async (data: string | Uint8Array): Promise<string> => {
    const dataBytes: Uint8Array = typeof data === 'string' ? stringToBytes(data) : data
    const signature = ed25519.sign(dataBytes, privateKeyBytes.slice(0, 32))
    return bytesToBase64url(signature)
  }
}
