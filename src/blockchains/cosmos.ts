import { bech32 } from '@scure/base'
import { ripemd160, sha256 } from '../Digest.js'
import { hexToBytes } from '../util.js'

export function publicKeyToAddress(publicKey: string, prefix: string): string {
  const publicKeyBuffer = hexToBytes(publicKey)
  const hash = ripemd160(sha256(publicKeyBuffer))
  const words = bech32.toWords(hash)
  return bech32.encode(prefix, words).replace(prefix, '')
}
