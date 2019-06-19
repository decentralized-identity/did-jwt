import nacl from 'tweetnacl'
import { encode } from '@stablelib/utf8'
import { Buffer } from 'buffer'
import { Signer } from './JWT'
import { base64ToBytes } from './util'
import base64url from 'uport-base64url'

/**
 *  The NaclSigner returns a configured function for signing data using the Ed25519 algorithm. It also defines
 *  an interface that you can also implement yourself and use in our other modules.
 *
 *  The signing function itself takes the data as a string parameter and returls a base64Url encoded signature
 *
 *  @example
 *  const signer = NaclSigner(process.env.PRIVATE_KEY)
 *  signer(data, (err, signature) => {
 *    ...
 *  })
 *
 *  @param    {String}         base64PrivateKey    a 64 byte base64 encoded private key
 *  @return   {Function}                     a configured signer function
 */

function NaclSigner(base64PrivateKey: string): Signer {
  const privateKey: Uint8Array = base64ToBytes(base64PrivateKey)
  return async data => {
    const dataBytes: Uint8Array = encode(data)
    const sig: Uint8Array = nacl.sign.detached(dataBytes, privateKey)
    const b64UrlSig: string = base64url.encode(Buffer.from(sig))
    return b64UrlSig
  }
}

export default NaclSigner
