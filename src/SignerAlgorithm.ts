import base64url from 'uport-base64url'
import { Buffer } from 'buffer'
import { Signer, EcdsaSignature, SignerAlgorithm } from './JWT'

function instanceOfEcdsaSignature(object: any): object is EcdsaSignature {
  return typeof object === 'object' && 'r' in object && 's' in object
}

export function ES256KSigner(recoverable?: boolean): SignerAlgorithm {
  function toJose({ r, s, recoveryParam }: EcdsaSignature): string {
    const jose: Buffer = Buffer.alloc(recoverable ? 65 : 64)
    Buffer.from(r, 'hex').copy(jose, 0)
    Buffer.from(s, 'hex').copy(jose, 32)
    if (recoverable) {
      if (recoveryParam === undefined) {
        throw new Error('Signer did not return a recoveryParam')
      }
      jose[64] = recoveryParam
    }
    return base64url.encode(jose)
  }

  return async function sign(payload: string, signer: Signer): Promise<string> {
    const signature: EcdsaSignature | string = await signer(payload)
    if (instanceOfEcdsaSignature(signature)) {
      return toJose(signature)
    } else {
      throw new Error(
        'expected a signer function that returns a signature object instead of string'
      )
    }
  }
}

export function Ed25519Signer(): SignerAlgorithm {
  return async function sign(payload: string, signer: Signer): Promise<string> {
    const signature: EcdsaSignature | string = await signer(payload)
    if (!instanceOfEcdsaSignature(signature)) {
      return signature
    } else {
      throw new Error(
        'expected a signer function that returns a string instead of signature object'
      )
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
