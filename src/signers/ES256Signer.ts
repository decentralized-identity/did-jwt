import { leftpad, toJose } from '../util.js'
import { Signer } from '../JWT.js'
import { sha256 } from '../Digest.js'
import { p256 } from '@noble/curves/p256'

/**
 *  Creates a configured signer function for signing data using the ES256 (secp256r1 + sha256) algorithm.
 *
 *  The signing function itself takes the data as a `Uint8Array` or `string` and returns a `base64Url`-encoded signature
 *
 *  @example
 *  ```typescript
 *  const sign: Signer = ES256Signer(process.env.PRIVATE_KEY)
 *  const signature: string = await sign(data)
 *  ```
 *
 *  @param    {String}    privateKey   a private key as `Uint8Array`
 *  @return   {Function}               a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export function ES256Signer(privateKey: Uint8Array): Signer {
  if (privateKey.length !== 32) {
    throw new Error(`bad_key: Invalid private key format. Expecting 32 bytes, but got ${privateKey.length}`)
  }
  return async (data: string | Uint8Array): Promise<string> => {
    const signature = p256.sign(sha256(data), privateKey)
    return toJose({
      r: leftpad(signature.r.toString(16)),
      s: leftpad(signature.s.toString(16)),
    })
  }
}
