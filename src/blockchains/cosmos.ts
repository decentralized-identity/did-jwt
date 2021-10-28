import SHA256 from 'crypto-js/sha256'
import RIPEMD160 from 'crypto-js/ripemd160'
import enc from 'crypto-js/enc-hex'
import { bech32 } from 'bech32'

export const publicKeyToAddress = (publicKeyBuffer: string, prefix: string): string => {
  const hash = RIPEMD160(SHA256(enc.parse(publicKeyBuffer)))
  const words = bech32.toWords(Buffer.from(hash.toString(), 'hex'))
  return bech32.encode(prefix, words).replace(prefix, '')
}
