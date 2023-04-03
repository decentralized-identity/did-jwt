import type { Signer } from '../JWT.js'
import { hexToBytes } from '../util.js'
import { ES256KSigner } from './ES256KSigner.js'

/**
 * @deprecated Please use ES256KSigner
 *  The EllipticSigner returns a configured function for signing data.
 *
 *  @example
 *  ```typescript
 *  const signer = EllipticSigner(process.env.PRIVATE_KEY)
 *  signer(data).then( (signature: string) => {
 *    ...
 *  })
 *  ```
 *
 *  @param    {String}         hexPrivateKey    a hex encoded private key
 *  @return   {Function}                        a configured signer function
 */
function EllipticSigner(hexPrivateKey: string): Signer {
  return ES256KSigner(hexToBytes(hexPrivateKey))
}

export default EllipticSigner
