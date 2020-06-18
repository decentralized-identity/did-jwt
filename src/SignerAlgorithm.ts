import { Buffer } from 'buffer'
import { Signer, EcdsaSignature, SignerAlgorithm } from './JWT'
import { toJose } from './util'

function instanceOfEcdsaSignature(object: any): object is EcdsaSignature {
  return typeof object === 'object' && 'r' in object && 's' in object
}

export function ES256KSigner(recoverable?: boolean): SignerAlgorithm {
  return async function sign(payload: string, signer: Signer): Promise<string> {
    const signature: EcdsaSignature | string = await signer(payload)
    if (instanceOfEcdsaSignature(signature)) {
      return toJose(signature, recoverable)
    } else {
      if (recoverable) throw new Error('ES256K-R not supported when signer function returns string')
      return signature
    }
  }
}

export function Ed25519Signer(): SignerAlgorithm {
  return async function sign(payload: string, signer: Signer): Promise<string> {
    const signature: EcdsaSignature | string = await signer(payload)
    if (!instanceOfEcdsaSignature(signature)) {
      return signature
    } else {
      throw new Error('expected a signer function that returns a string instead of signature object')
    }
  }
}

interface SignerAlgorithms {
  [alg: string]: SignerAlgorithm
}

const algorithms: SignerAlgorithms = {
  ES256K: ES256KSigner(),
  'ES256K-R': ES256KSigner(true),
  Ed25519: Ed25519Signer()
}

function SignerAlgorithm(alg: string): SignerAlgorithm {
  const impl: SignerAlgorithm = algorithms[alg]
  if (!impl) throw new Error(`Unsupported algorithm ${alg}`)
  return impl
}

export default SignerAlgorithm
