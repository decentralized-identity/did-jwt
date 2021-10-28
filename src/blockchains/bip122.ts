import SHA256 from 'crypto-js/sha256'
import RIPEMD160 from 'crypto-js/ripemd160'
import enc from 'crypto-js/enc-hex'
import { bytesToBase58 } from '../util'

export const publicKeyToAddress = (publicKeyBuffer: string): string => {
  const publicKeyHash = RIPEMD160(SHA256(enc.parse(publicKeyBuffer)))
  const step1 = Buffer.from('00' + publicKeyHash.toString(enc), 'hex')
  const step2 = SHA256(SHA256(enc.parse(step1.toString('hex'))))
  const checksum = step2.toString(enc).substring(0, 8)
  const step3 = step1.toString('hex') + checksum
  return bytesToBase58(Uint8Array.from(Buffer.from(step3, 'hex')))
}
