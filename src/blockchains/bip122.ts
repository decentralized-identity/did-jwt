import { fromString } from 'uint8arrays/from-string'
import { toString } from 'uint8arrays/to-string'
import { bytesToBase58, base58ToBytes } from '../util'
import { sha256, ripemd160 } from '../Digest'

export function publicKeyToAddress(publicKey: string, otherAddress: string): string {
  // Use the same version/prefix byte as the given address.
  const version = toString(base58ToBytes(otherAddress).slice(0, 1), 'hex')
  const publicKeyBuffer = fromString(publicKey, 'hex')
  const publicKeyHash = ripemd160(sha256(publicKeyBuffer))
  const step1 = version + toString(publicKeyHash, 'hex')
  const step2 = sha256(fromString(step1, 'hex'))
  const step3 = sha256(step2)
  const checksum = toString(step3, 'hex').substring(0, 8)
  const step4 = step1 + checksum
  return bytesToBase58(fromString(step4, 'hex'))
}
