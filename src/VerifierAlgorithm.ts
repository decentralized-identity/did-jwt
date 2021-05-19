const nodersa = require('node-rsa')
import * as jwt from 'jsonwebtoken'
import type { VerificationMethod } from 'did-resolver'
import { hexToBytes, base58ToBytes, base64ToBytes, bytesToHex, EcdsaSignature, stringToBytes } from './util'

interface LegacyVerificationMethod extends VerificationMethod {
  publicKeyBase64: string
}


export function verifyRS256(data: string, signature: string, authenticators: VerificationMethod[]): VerificationMethod {
  const signer: VerificationMethod = authenticators.find((pk: VerificationMethod) => {
  return jwt.verify(`${data}.${signature}`, pk.publicKeyPem, {
      algorithms: ['RS256']
    })
  })
  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

type Verifier = (data: string, signature: string, authenticators: VerificationMethod[]) => VerificationMethod
interface Algorithms {
  [name: string]: Verifier
}
const algorithms: Algorithms = {
  RS256: verifyRS256
}

function VerifierAlgorithm(alg: string): Verifier {
  const impl: Verifier = algorithms[alg]
  if (!impl) throw new Error(`Unsupported algorithm ${alg}`)
  return impl
}

export default VerifierAlgorithm
