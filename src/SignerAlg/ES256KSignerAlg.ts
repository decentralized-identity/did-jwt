import { Signer, SignerAlgorithm } from '../JWT'
import { EcdsaSignature, fromJose, toJose } from '../util'
import * as common from './common'

export function ES256KSignerAlg(recoverable?: boolean): SignerAlgorithm {
  return async function sign(payload: string, signer: Signer): Promise<string> {
    const signature: EcdsaSignature | string = await signer(payload)
    if (common.instanceOfEcdsaSignature(signature)) {
      return toJose(signature, recoverable)
    } else {
      if (recoverable && typeof fromJose(signature).recoveryParam === 'undefined') {
        throw new Error(`not_supported: ES256K-R not supported when signer doesn't provide a recovery param`)
      }
      return signature
    }
  }
}
