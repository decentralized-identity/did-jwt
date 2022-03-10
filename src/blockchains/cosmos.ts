import { compressionAlgorithm } from './utils/curveCompression'
import { bech32 } from 'bech32'
import * as u8a from 'uint8arrays'
import { sha256 } from '../Digest'
import { Ripemd160 } from './utils/ripemd160'

export const publicKeyToAddress = (publicKey: string, prefix: string, alg = 'secp256k1-pub'): string => {
  const compressor = compressionAlgorithm(alg)
  const compressedPublicKey = compressor(publicKey)
  const publicKeyBuffer = u8a.fromString(compressedPublicKey, 'hex')
  const hash = new Ripemd160().update(sha256(publicKeyBuffer)).digest()
  const words = bech32.toWords(hash)
  return bech32.encode(prefix, words).replace(prefix, '')
}
