import RIPEMD160 from 'ripemd160'
import { bytesToBase58 } from '../util'
import { sha256 } from '../Digest'

export const publicKeyToAddress = (publicKey: string): string => {
  const publicKeyBuffer = Uint8Array.from(Buffer.from(publicKey, 'hex'))
  const hash = new RIPEMD160().update(Buffer.from(sha256(publicKeyBuffer))).digest()
  const step1 = Buffer.concat([Buffer.from('00', 'hex'), hash])
  const checksum = Buffer.from(sha256(sha256(step1)))
    .toString('hex')
    .substring(0, 8)
  const step2 = step1.toString('hex') + checksum
  return bytesToBase58(Uint8Array.from(Buffer.from(step2, 'hex')))
}
