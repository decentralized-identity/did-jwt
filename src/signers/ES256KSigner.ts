import { parseKey, leftpad } from '../util'
import { toJose } from '../util'
import { Signer } from '../JWT'
import { sha256 } from '../Digest'

import { ec as EC, ec } from 'elliptic'
const secp256k1: EC = new EC('secp256k1')

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
 *  @param    {String}    privateKey   a private key as `Uint8Array` or encoded as `base64`, `base58`, or `hex` string
 *  @param    {Boolean}   recoverable  an optional flag to add the recovery param to the generated signatures
 *  @return   {Function}               a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export function ES256KSigner(privateKey: string | Uint8Array, recoverable = false): Signer {
  const privateKeyBytes: Uint8Array = parseKey(privateKey)
  if (privateKeyBytes.length !== 32) {
    throw new Error(`bad_key: Invalid private key format. Expecting 32 bytes, but got ${privateKeyBytes.length}`)
  }
  const keyPair: ec.KeyPair = secp256k1.keyFromPrivate(privateKeyBytes)

  return async (data: string | Uint8Array): Promise<string> => {
    const { r, s, recoveryParam }: EC.Signature = keyPair.sign(sha256(data))
    return toJose(
      {
        r: leftpad(r.toString('hex')),
        s: leftpad(s.toString('hex')),
        recoveryParam,
      },
      recoverable
    )
  }
}
