import { EdDSASigner as EdDSASigner } from './EdDSASigner'
import { Signer } from '../JWT'
import { base64ToBytes } from '../util'

/**
 * @deprecated Please use EdDSASigner
 *
 *  The NaclSigner returns a configured function for signing data using the Ed25519 algorithm.
 *
 *  The signing function itself takes the data as a `string` or `Uint8Array` parameter and returns a `base64Url`-encoded signature.
 *
 *  @example
 *  const signer = NaclSigner(process.env.PRIVATE_KEY)
 *  const data: string = '...'
 *  signer(data).then( (signature: string) => {
 *    ...
 *  })
 *
 *  @param    {String}   base64PrivateKey    a 64 byte base64 encoded private key
 *  @return   {Function}                     a configured signer function
 */

function NaclSigner(base64PrivateKey: string): Signer {
  return EdDSASigner(base64ToBytes(base64PrivateKey))
}

export default NaclSigner
