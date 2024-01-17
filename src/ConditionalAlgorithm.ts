import type { VerificationMethod } from 'did-resolver'
import { JWT_ERROR } from './Errors.js'
import { type JWTDecoded, type JWTVerifyOptions, resolveAuthenticator, verifyJWT, verifyJWTDecoded } from './JWT.js'

export const CONDITIONAL_PROOF_2022 = 'ConditionalProof2022'

export async function verifyProof(
  jwt: string,
  { header, payload, signature, data }: JWTDecoded,
  authenticator: VerificationMethod,
  options: JWTVerifyOptions
): Promise<VerificationMethod> {
  if (authenticator.type === CONDITIONAL_PROOF_2022) {
    return verifyConditionalProof(jwt, { payload, header, signature, data }, authenticator, options)
  } else {
    return verifyJWTDecoded({ header, payload, data, signature }, [authenticator])
  }
}

export async function verifyConditionalProof(
  jwt: string,
  { header, payload, signature, data }: JWTDecoded,
  authenticator: VerificationMethod,
  options: JWTVerifyOptions
): Promise<VerificationMethod> {
  // Validate the condition according to its condition property
  if (authenticator.conditionWeightedThreshold) {
    return verifyConditionWeightedThreshold(jwt, { header, payload, data, signature }, authenticator, options)
  } else if (authenticator.conditionDelegated) {
    return verifyConditionDelegated(jwt, { header, payload, data, signature }, authenticator, options)
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

        const newOptions: JWTVerifyOptions = {
          ...options,
          didAuthenticator: {
            didResolutionResult: options.didAuthenticator?.didResolutionResult,
            authenticators: [currentCondition],
            issuer: currentCondition.id,
          },
        }
        const { verified } = await verifyJWT(jwt, newOptions)
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
      foundSigner = verifyJWTDecoded({ header, payload, data, signature }, delegatedAuthenticator)
    } catch (e) {
      if (!(e as Error).message.startsWith('invalid_signature:')) throw e
    }
  }

  if (foundSigner) {
    return authenticator
  }

  throw new Error(`${JWT_ERROR.INVALID_SIGNATURE}: condition for authenticator ${authenticator.id} is not met.`)
}
