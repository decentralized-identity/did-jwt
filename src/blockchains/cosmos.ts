import elliptic from 'elliptic'
import { bech32 } from 'bech32'
import * as u8a from 'uint8arrays'
import { sha256, ripemd160 } from '../Digest'

const EC = elliptic.ec

export const publicKeyToAddress = (publicKey: string, prefix: string): string => {
  const ec = new EC('secp256k1')
  const compressedPublicKey = ec.keyFromPublic(publicKey, 'hex').getPublic().encode('hex', true)
  const publicKeyBuffer = u8a.fromString(compressedPublicKey, 'hex')
  const hash = ripemd160(sha256(publicKeyBuffer))
  const words = bech32.toWords(hash)
  return bech32.encode(prefix, words).replace(prefix, '')
}
