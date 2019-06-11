import nacl from 'tweetnacl'
import naclutil from 'tweetnacl-util'
import { Buffer } from 'buffer'
import { Signer } from './JWT';
import base64url from 'base64url'

// converts a Buffer to Uint8Array
function tou8(buf: Buffer): Uint8Array {
  const a = new Uint8Array(buf.length)
  for (let i = 0; i < buf.length; i++) a[i] = buf[i]
  return a
} 

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
  const privateKey: Uint8Array = tou8(Buffer.from(base64PrivateKey, 'base64'))
  return async data => {
    const encodedData: Uint8Array = tou8(Buffer.from(data))
    const signed: string = Buffer.from(nacl.sign.detached(encodedData, privateKey)).toString('utf-8')
    return base64url.encode(signed)
  }
}

export default NaclSigner
