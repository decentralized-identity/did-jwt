import type { VerificationMethod } from 'did-resolver'
import { hexToBytes, base58ToBytes, base64ToBytes, bytesToHex, EcdsaSignature, stringToBytes } from './util'

const rs = require('jsrsasign');
const rsu = require('jsrsasign-util');
const path = require('path');
const JWS = rs.jws.JWS;


interface LegacyVerificationMethod extends VerificationMethod {
  publicKeyPem?: string;
  publicKeyBase64?: string;
}


export function verifyRS256(data: string, signature: string, authenticators: LegacyVerificationMethod[]): LegacyVerificationMethod {
  const signer: any = authenticators.find((pk: any) => {
    const pubKeyObj = rs.KEYUTIL.getKey(pk.publicKeyPem);
    const acceptField = { alg: [] }
    acceptField.alg = ['RS256', 'RS384', 'RS512',
                     'PS256', 'PS384', 'PS512',
                     'ES256', 'ES384', 'ES512'];
    const isValid = rs.jws.JWS.verifyJWT(`${data}.${signature}`, pubKeyObj, acceptField);

    return isValid
  })
  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

type Verifier = (data: string, signature: string, authenticators: LegacyVerificationMethod[]) => LegacyVerificationMethod
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
