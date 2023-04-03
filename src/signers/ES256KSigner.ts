import { leftpad, toJose } from '../util.js'
import { Signer } from '../JWT.js'
import { sha256 } from '../Digest.js'
import { secp256k1 } from '@noble/curves/secp256k1'

/**
 *  Creates a configured signer function for signing data using the ES256K (secp256k1 + sha256) algorithm.
 *
 *  The signing function itself takes the data as a `Uint8Array` or `string` and returns a `base64Url`-encoded signature
 *
 *  @example
 *  ```typescript
 *  const sign: Signer = ES256KSigner(process.env.PRIVATE_KEY)
 *  const signature: string = await sign(data)
 *  ```
 *
 *  @param    {String}    privateKey   a private key as `Uint8Array`
 *  @param    {Boolean}   recoverable  an optional flag to add the recovery param to the generated signatures
 *  @return   {Function}               a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export function ES256KSigner(privateKey: Uint8Array, recoverable = false): Signer {
  const privateKeyBytes: Uint8Array = privateKey
  if (privateKeyBytes.length !== 32) {
    throw new Error(`bad_key: Invalid private key format. Expecting 32 bytes, but got ${privateKeyBytes.length}`)
  }

  return async (data: string | Uint8Array): Promise<string> => {
    const signature = secp256k1.sign(sha256(data), privateKeyBytes)
    return toJose(
      {
        r: leftpad(signature.r.toString(16)),
        s: leftpad(signature.s.toString(16)),
        recoveryParam: signature.recovery,
      },
      recoverable
    )
  }
}
