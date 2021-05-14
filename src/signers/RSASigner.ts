import * as rsa from 'node-rsa';
import { Signer } from '../JWT'
import { bytesToBase64url, parseKey, stringToBytes } from '../util'

/**
 *  Creates a configured signer function for signing data using the RSA algorithm.
 *
 *  The signing function itself takes the data as a `Uint8Array` or `string` and returns a `base64Url`-encoded signature
 *
 *  @example
 *  ```typescript
 *  const sign: Signer = RSASigner(process.env.PEM)
 *  const signature: string = await sign(data)
 *  ```
 *
 *  @param    {String}    pem         a PEM
 *  @return   {Function}              a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export function RSASigner(pem: string | Uint8Array): Signer {
  const privateKey = rsa.importKey(pem);

  return async (data: string | Uint8Array): Promise<string> => {
    const dataBytes: Uint8Array = typeof data === 'string' ? stringToBytes(data) : data
    const sig: Uint8Array = privateKey.sign(dataBytes)
    return bytesToBase64url(sig)
  }
}
