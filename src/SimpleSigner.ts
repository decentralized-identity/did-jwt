import { ec as EC, ec } from 'elliptic'
import base64url from 'uport-base64url'
import { sha256 } from './Digest'
import { Signer, EcdsaSignature } from './JWT'

const secp256k1: EC = new EC('secp256k1')

function leftpad(data: string, size = 64): string {
  if (data.length === size) return data
  return '0'.repeat(size - data.length) + data
}

export function ecdsaSigToJose({ r, s, recoveryParam }: EcdsaSignature): string {
  const jose: Buffer = Buffer.alloc(65)
  Buffer.from(r, 'hex').copy(jose, 0)
  Buffer.from(s, 'hex').copy(jose, 32)
  jose[64] = recoveryParam
  return base64url.encode(jose)
}

/**
 *  The SimpleSigner returns a configured function for signing data. It also defines
 *  an interface that you can also implement yourself and use in our other modules.
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
  const privateKey: ec.KeyPair = secp256k1.keyFromPrivate(hexPrivateKey)
  return async data => {
    const { r, s, recoveryParam }: EC.Signature = privateKey.sign(sha256(data))
    const signatureObj: EcdsaSignature = {
      r: leftpad(r.toString('hex')),
      s: leftpad(s.toString('hex')),
      recoveryParam
    }
    return ecdsaSigToJose(signatureObj)
  }
}

export default SimpleSigner
