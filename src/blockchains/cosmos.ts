import RIPEMD160 from 'ripemd160'
import { sha256 } from '../Digest'
import { bech32 } from 'bech32'

export const publicKeyToAddress = (publicKey: string, prefix: string): string => {
  const publicKeyBuffer = Uint8Array.from(Buffer.from(publicKey, 'hex'))
  const hash = new RIPEMD160().update(Buffer.from(sha256(publicKeyBuffer))).digest()
  const words = bech32.toWords(hash)
  return bech32.encode(prefix, words).replace(prefix, '')
}
