import { Signer } from '../JWT'
import { ES256KSigner } from './ES256KSigner'

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
  return ES256KSigner(hexPrivateKey)
}

export default EllipticSigner
