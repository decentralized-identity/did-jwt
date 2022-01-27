import { Signer, SignerAlgorithm } from '../JWT'
import { EcdsaSignature } from '../util'
import * as common_SignerAlg from './common_SignerAlg'

export function Ed25519SignerAlg(): SignerAlgorithm {
  return async function sign(payload: string, signer: Signer): Promise<string> {
    const signature: EcdsaSignature | string = await signer(payload)
    if (!common_SignerAlg.instanceOfEcdsaSignature(signature)) {
      return signature
    } else {
      throw new Error('invalid_config: expected a signer function that returns a string instead of signature object')
    }
  }
}
