import type { VerificationMethod } from 'did-resolver'
import { EcdsaSignature } from './util'
import { JWT_ERROR } from './Errors'
import { JWTDecoded, JWTVerifyOptions, resolveAuthenticator, verifyJWT, verifyJWTDecoded } from './JWT'

export type Signer = (data: string | Uint8Array) => Promise<EcdsaSignature | string>
export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>

export const CONDITIONAL_PROOF_2022 = 'ConditionalProof2022'

export async function verifyProof(
  jwt: string,
  { header, payload, signature, data }: JWTDecoded,
  authenticator: VerificationMethod,
  options: JWTVerifyOptions
): Promise<VerificationMethod> {
  if (authenticator.type === CONDITIONAL_PROOF_2022) {
    return await verifyConditionalProof(jwt, { payload, header, signature, data }, authenticator, options)
  } else {
    return await verifyJWTDecoded({ header, payload, data, signature }, [authenticator])
  }
}

export async function verifyConditionalProof(
  jwt: string,
  { header, payload, signature, data }: JWTDecoded,
  authenticator: VerificationMethod,
  options: JWTVerifyOptions
): Promise<VerificationMethod> {
  // Validate the condition according to it's condition property
  if (authenticator.conditionWeightedThreshold) {
    return await verifyConditionWeightedThreshold(jwt, { header, payload, data, signature }, authenticator, options)
  } else if (authenticator.conditionDelegated) {
    return await verifyConditionDelegated(jwt, { header, payload, data, signature }, authenticator, options)
  }
  // TODO other conditions

  throw new Error(
    `${JWT_ERROR.INVALID_JWT}: conditional proof type did not find condition for authenticator ${authenticator.id}.`
  )
}

async function verifyConditionWeightedThreshold(
  jwt: string,
  { header, payload, data, signature }: JWTDecoded,
  authenticator: VerificationMethod,
  options: JWTVerifyOptions
): Promise<VerificationMethod> {
  if (!authenticator.conditionWeightedThreshold || !authenticator.threshold) {
    throw new Error('Expected conditionWeightedThreshold and threshold')
  }

  const issuers: string[] = []
  const threshold = authenticator.threshold
  let weightCount = 0

  for (const weightedCondition of authenticator.conditionWeightedThreshold) {
    const currentCondition = weightedCondition.condition
    let foundSigner: VerificationMethod | undefined

    try {
      if (currentCondition.type === CONDITIONAL_PROOF_2022) {
        if (!options.didAuthenticator) {
          throw new Error('Expected didAuthenticator')
        }

        const newOptions = {
          ...options,
          ...{
            didAuthenticator: {
              didResolutionResult: options.didAuthenticator?.didResolutionResult,
              authenticators: [currentCondition],
              issuer: currentCondition.id,
            },
          },
        }
        const { verified } = await verifyJWT(jwt, newOptions as JWTVerifyOptions)
        if (verified) {
          foundSigner = currentCondition
        }
      } else {
        foundSigner = await verifyJWTDecoded({ header, payload, data, signature }, currentCondition)
      }
    } catch (e) {
      if (!(e as Error).message.startsWith(JWT_ERROR.INVALID_SIGNATURE)) throw e
    }

    if (foundSigner && !issuers.includes(foundSigner.id)) {
      issuers.push(foundSigner.id)
      weightCount += weightedCondition.weight

      if (weightCount >= threshold) {
        return authenticator
      }
    }
  }
  throw new Error(`${JWT_ERROR.INVALID_SIGNATURE}: condition for authenticator ${authenticator.id} is not met.`)
}

async function verifyConditionDelegated(
  jwt: string,
  { header, payload, data, signature }: JWTDecoded,
  authenticator: VerificationMethod,
  options: JWTVerifyOptions
): Promise<VerificationMethod> {
  if (!authenticator.conditionDelegated) {
    throw new Error('Expected conditionDelegated')
  }
  if (!options.resolver) {
    throw new Error('Expected resolver')
  }

  let foundSigner: VerificationMethod | undefined

  const issuer = authenticator.conditionDelegated
  const didAuthenticator = await resolveAuthenticator(options.resolver, header.alg, issuer, options.proofPurpose)
  const didResolutionResult = didAuthenticator.didResolutionResult

  if (!didResolutionResult?.didDocument) {
    throw new Error(`${JWT_ERROR.RESOLVER_ERROR}: Could not resolve delegated DID ${issuer}.`)
  }

  const delegatedAuthenticator = didAuthenticator.authenticators.find((authenticator) => authenticator.id === issuer)
  if (!delegatedAuthenticator) {
    throw new Error(
      `${JWT_ERROR.NO_SUITABLE_KEYS}: Could not find delegated authenticator ${issuer} in it's DID Document`
    )
  }

  if (delegatedAuthenticator.type === CONDITIONAL_PROOF_2022) {
    const { verified } = await verifyJWT(jwt, {
      ...options,
      ...{
        didAuthenticator: {
          didResolutionResult,
          authenticators: [delegatedAuthenticator],
          issuer: delegatedAuthenticator.id,
        },
      },
    })
    if (verified) {
      foundSigner = delegatedAuthenticator
    }
  } else {
    try {
      foundSigner = await verifyJWTDecoded({ header, payload, data, signature }, delegatedAuthenticator)
    } catch (e) {
      if (!(e as Error).message.startsWith('invalid_signature:')) throw e
    }
  }

  if (foundSigner) {
    return authenticator
  }

  throw new Error(`${JWT_ERROR.INVALID_SIGNATURE}: condition for authenticator ${authenticator.id} is not met.`)
}
