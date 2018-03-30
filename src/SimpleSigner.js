import { ec as EC } from 'elliptic'
import { sha256 } from './Digest'

const secp256k1 = new EC('secp256k1')

function leftpad (data, size = 64) {
  if (data.length === size) return data
  return '0'.repeat(size - data.length) + data
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

function SimpleSigner (hexPrivateKey) {
  const privateKey = secp256k1.keyFromPrivate(hexPrivateKey)
  return async (data) => {
    const {r, s, recoveryParam} = privateKey.sign(sha256(data))
    return {
      r: leftpad(r.toString('hex')),
      s: leftpad(s.toString('hex')),
      recoveryParam
    }
  }
}

module.exports = SimpleSigner
