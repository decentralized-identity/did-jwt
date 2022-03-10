import { ec as EC } from 'elliptic'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type publicKeyCompressionObj = { (publicKey: string): any }

function compressSecp256k1(publicKey: string): string {
  if (publicKey == null) {
    throw new TypeError('input cannot be null or undefined.')
  }
  const ec = new EC('secp256k1')
  const compressedPublicKey = ec.keyFromPublic(publicKey, 'hex').getPublic().encode('hex', true)
  return compressedPublicKey
}

function compressSecp256r1(publicKey: string): string {
  if (publicKey == null) {
    throw new TypeError('input cannot be null or undefined.')
  }
  const ec = new EC('p256')
  const compressedPublicKey = ec.keyFromPublic(publicKey, 'hex').getPublic().encode('hex', true)
  return compressedPublicKey
}

interface Algorithms {
  [name: string]: publicKeyCompressionObj
}

const algorithms: Algorithms = {
  'secp256k1-pub': compressSecp256k1,
  'p256-pub': compressSecp256r1,
}

export function compressionAlgorithm(alg = 'secp256k1-pub'): publicKeyCompressionObj {
  const impl: publicKeyCompressionObj = algorithms[alg]
  if (!impl) throw new Error(`not_supported: Unsupported algorithm ${alg}`)
  return impl
}
