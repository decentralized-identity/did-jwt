import * as u8a from 'uint8arrays'
import { bytesToBase58 } from '../util'
import { sha256 } from '../Digest'
import { Ripemd160 } from './utils/ripemd160'

export const publicKeyToAddress = (publicKey: string): string => {
  const publicKeyBuffer = u8a.fromString(publicKey, 'hex')
  const publicKeyHash = new Ripemd160().update(sha256(publicKeyBuffer)).digest()
  const step1 = '00' + u8a.toString(publicKeyHash, 'hex')
  const step2 = sha256(u8a.fromString(step1, 'hex'))
  const step3 = sha256(step2)
  const checksum = u8a.toString(step3, 'hex').substring(0, 8)
  const step4 = step1 + checksum
  return bytesToBase58(u8a.fromString(step4, 'hex'))
}
