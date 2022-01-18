import { ec as EC } from 'elliptic'
import type { VerificationMethod } from 'did-resolver'
import { bases } from 'multiformats/basics'
import { hexToBytes, base58ToBytes, base64ToBytes, bytesToHex, EcdsaSignature } from '../util'

const secp256k1 = new EC('secp256k1')

// converts a JOSE signature to it's components
export function toSignatureObject(signature: string, recoverable = false): EcdsaSignature {
  const rawSig: Uint8Array = base64ToBytes(signature)
  if (rawSig.length !== (recoverable ? 65 : 64)) {
    throw new Error('wrong signature length')
  }
  const r: string = bytesToHex(rawSig.slice(0, 32))
  const s: string = bytesToHex(rawSig.slice(32, 64))
  const sigObj: EcdsaSignature = { r, s }
  if (recoverable) {
    sigObj.recoveryParam = rawSig[64]
  }
  return sigObj
}

/*
interface LegacyVerificationMethod extends VerificationMethod {
  publicKeyBase64: string
}
*/

export function extractPublicKeyBytes(pk: VerificationMethod): Uint8Array {
  if (pk.publicKeyBase58) {
    return base58ToBytes(pk.publicKeyBase58)
  } else if ((<LegacyVerificationMethod>pk).publicKeyBase64) {
    return base64ToBytes((<LegacyVerificationMethod>pk).publicKeyBase64)
  } else if (pk.publicKeyHex) {
    return hexToBytes(pk.publicKeyHex)
  } else if (pk.publicKeyJwk && pk.publicKeyJwk.crv === 'secp256k1' && pk.publicKeyJwk.x && pk.publicKeyJwk.y) {
    return hexToBytes(
      secp256k1
        .keyFromPublic({
          x: bytesToHex(base64ToBytes(pk.publicKeyJwk.x)),
          y: bytesToHex(base64ToBytes(pk.publicKeyJwk.y)),
        })
        .getPublic('hex')
    )
  } else if (pk.publicKeyMultibase) {
    const { base16, base58btc, base64, base64url } = bases
    const baseDecoder = base16.decoder.or(base58btc.decoder.or(base64.decoder.or(base64url.decoder)))
    return baseDecoder.decode(pk.publicKeyMultibase)
  }
  return new Uint8Array()
}
