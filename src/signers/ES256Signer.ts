import { leftpad } from '../util'
import { toJose } from '../util'
import { Signer } from '../JWT'
import { sha256 } from '../Digest'
import elliptic from 'elliptic'

const secp256r1 = new elliptic.ec('p256')

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
  const privateKeyBytes: Uint8Array = privateKey
  if (privateKeyBytes.length !== 32) {
    throw new Error(`bad_key: Invalid private key format. Expecting 32 bytes, but got ${privateKeyBytes.length}`)
  }
  const keyPair: elliptic.ec.KeyPair = secp256r1.keyFromPrivate(privateKeyBytes)

  return async (data: string | Uint8Array): Promise<string> => {
    const { r, s }: elliptic.ec.Signature = keyPair.sign(sha256(data))
    return toJose({
      r: leftpad(r.toString('hex')),
      s: leftpad(s.toString('hex')),
    })
  }
}
