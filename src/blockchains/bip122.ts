import { base58ToBytes, bytesToBase58, bytesToHex, hexToBytes } from '../util.js'
import { ripemd160, sha256 } from '../Digest.js'

export function publicKeyToAddress(publicKey: string, otherAddress: string): string {
  // Use the same version/prefix byte as the given address.
  const version = bytesToHex(base58ToBytes(otherAddress).slice(0, 1))
  const publicKeyBuffer = hexToBytes(publicKey)
  const publicKeyHash = ripemd160(sha256(publicKeyBuffer))
  const step1 = version + bytesToHex(publicKeyHash)
  const step2 = sha256(hexToBytes(step1))
  const step3 = sha256(step2)
  const checksum = bytesToHex(step3).substring(0, 8)
  const step4 = step1 + checksum
  return bytesToBase58(hexToBytes(step4))
}
