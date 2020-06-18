import { EcdsaSignature } from './JWT'
import SimpleSigner from './SimpleSigner'
import { toJose } from './util'

type Signer = (data: string) => Promise<string>
// we know that we always get a EcdsaSignature from Simplesigner
const isEcdsaSig = (obj: any): obj is EcdsaSignature => true

/**
 *  The EllipticSigner returns a configured function for signing data. It also defines
 *  an interface that you can also implement yourself and use in our other modules.
 *
 *  @example
 *  const signer = EllipticSigner(process.env.PRIVATE_KEY)
 *  signer(data, (err, signature) => {
 *    ...
 *  })
 *
 *  @param    {String}         hexPrivateKey    a hex encoded private key
 *  @return   {Function}                        a configured signer function
 */
function EllipticSigner(hexPrivateKey: string): Signer {
  const signer = SimpleSigner(hexPrivateKey)
  return async data => {
    const signature: EcdsaSignature | string = await signer(data)
    if (isEcdsaSig(signature)) {
      return toJose(signature)
    }
  }
}

export default EllipticSigner
