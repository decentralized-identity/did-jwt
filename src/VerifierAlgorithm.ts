import type { VerificationMethod } from 'did-resolver'
import { base64ToBytes, bytesToHex, EcdsaSignature } from './util'

import { verifyEd25519 } from './VerifierAlg/Ed25519VerifierAlg'

import { verifyES256K } from './VerifierAlg/ES256KVerifierAlg'
import { verifyRecoverableES256K } from './VerifierAlg/ES256KVerifierAlg'

import { verifyES256 } from './VerifierAlg/ES256VerifierAlg'
import { verifyRecoverableES256 } from './VerifierAlg/ES256VerifierAlg'

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

type Verifier = (data: string, signature: string, authenticators: VerificationMethod[]) => VerificationMethod
interface Algorithms {
  [name: string]: Verifier
}
const algorithms: Algorithms = {
  ES256: verifyES256,
  'ES256-R': verifyRecoverableES256,
  ES256K: verifyES256K,
  // This is a non-standard algorithm but retained for backwards compatibility
  // see https://github.com/decentralized-identity/did-jwt/issues/146
  'ES256K-R': verifyRecoverableES256K,
  // This is actually incorrect but retained for backwards compatibility
  // see https://github.com/decentralized-identity/did-jwt/issues/130
  Ed25519: verifyEd25519,
  EdDSA: verifyEd25519,
}

function VerifierAlgorithm(alg: string): Verifier {
  const impl: Verifier = algorithms[alg]
  if (!impl) throw new Error(`not_supported: Unsupported algorithm ${alg}`)
  return impl
}

VerifierAlgorithm.toSignatureObject = toSignatureObject

export default VerifierAlgorithm
