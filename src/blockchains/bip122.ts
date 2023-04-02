import * as u8a from 'uint8arrays'
import { bytesToBase58, base58ToBytes } from '../util'
import { sha256, ripemd160 } from '../Digest'

export const publicKeyToAddress = (publicKey: string, otherAddress: string): string => {
  // Use the same version/prefix byte as the given address.
  const version = u8a.toString(base58ToBytes(otherAddress).slice(0, 1), 'hex')
  const publicKeyBuffer = u8a.fromString(publicKey, 'hex')
  const publicKeyHash = ripemd160(sha256(publicKeyBuffer))
  const step1 = version + u8a.toString(publicKeyHash, 'hex')
  const step2 = sha256(u8a.fromString(step1, 'hex'))
  const step3 = sha256(step2)
  const checksum = u8a.toString(step3, 'hex').substring(0, 8)
  const step4 = step1 + checksum
  return bytesToBase58(u8a.fromString(step4, 'hex'))
}
