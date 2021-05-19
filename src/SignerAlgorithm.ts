import { Signer, SignerAlgorithm } from './JWT'

/**
 * RSA Signer
 * @returns A SignerAlgorithm instance
 */
export function RSASignerAlg(): SignerAlgorithm {
  return async function sign(payload: string, signer: Signer): Promise<string> {
    let signature
    try {
      signature = await signer(payload)
    } catch (e) {
      console.log(e)
    }
    if (signature) {
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
  RS256: RSASignerAlg()
}

function SignerAlg(alg: string): SignerAlgorithm {
  const impl: SignerAlgorithm = algorithms[alg]
  if (!impl) throw new Error(`Unsupported algorithm ${alg}`)
  return impl
}

export default SignerAlg
