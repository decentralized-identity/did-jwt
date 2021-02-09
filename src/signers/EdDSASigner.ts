import { sign } from '@stablelib/ed25519'
import { Signer } from '../JWT'
import { bytesToBase64url, parseKey, stringToBytes } from '../util'

/**
 *  Creates a configured signer function for signing data using the EdDSA (Ed25519) algorithm.
 *
 *  The signing function itself takes the data as a `Uint8Array` or `string` and returns a `base64Url`-encoded signature
 *
 *  @example
 *  ```typescript
 *  const sign: Signer = EdDSASigner(process.env.PRIVATE_KEY)
 *  const signature: string = await sign(data)
 *  ```
 *
 *  @param    {String}    secretKey   a 64 byte secret key as `Uint8Array` or encoded as `base64`, `base58`, or `hex` string
 *  @return   {Function}              a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export function EdDSASigner(secretKey: string | Uint8Array): Signer {
  const privateKeyBytes: Uint8Array = parseKey(secretKey)
  if (privateKeyBytes.length !== 64) {
    throw new Error(`Invalid private key format. Expecting 64 bytes, but got ${privateKeyBytes.length}`)
  }
  return async (data: string | Uint8Array): Promise<string> => {
    const dataBytes: Uint8Array = (typeof data === 'string') ? stringToBytes(data) : data
    const sig: Uint8Array = sign(privateKeyBytes, dataBytes)
    return bytesToBase64url(sig)
  }
}
