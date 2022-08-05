import { fromJose, hexToBytes } from '../util'
import { Signer } from '../JWT'
import { ES256KSigner } from './ES256KSigner'

/**
 * @deprecated Please use ES256KSigner
 *  The SimpleSigner returns a configured function for signing data.
 *
 *  @example
 *  const signer = SimpleSigner(process.env.PRIVATE_KEY)
 *  signer(data, (err, signature) => {
 *    ...
 *  })
 *
 *  @param    {String}         hexPrivateKey    a hex encoded private key
 *  @return   {Function}                     a configured signer function
 */
function SimpleSigner(hexPrivateKey: string): Signer {
  const signer = ES256KSigner(hexToBytes(hexPrivateKey), true)
  return async (data) => {
    const signature = (await signer(data)) as string
    return fromJose(signature)
  }
}

export default SimpleSigner
