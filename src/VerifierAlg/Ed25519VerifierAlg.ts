import { verify } from '@stablelib/ed25519'
import type { VerificationMethod } from 'did-resolver'
import { base64ToBytes, stringToBytes } from '../util'

import * as common_VerifierAlg from './common_VerifierAlg'

export function verifyEd25519(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  const clear: Uint8Array = stringToBytes(data)
  const sig: Uint8Array = base64ToBytes(signature)
  const signer = authenticators.find((pk: VerificationMethod) => {
    return verify(common_VerifierAlg.extractPublicKeyBytes(pk), clear, sig)
  })
  if (!signer) throw new Error('invalid_signature: Signature invalid for JWT')
  return signer
}
