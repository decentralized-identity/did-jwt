import type { VerificationMethod } from 'did-resolver'
import { EcdsaSignature } from './util'
import { JWT_ERROR } from './Errors'
import { decodeJWT, JWSDecoded, JWTDecoded, JWTVerifyOptions, resolveAuthenticator, verifyJWSDecoded, verifyJWT } from './JWT'

export type Signer = (data: string | Uint8Array) => Promise<EcdsaSignature | string>
export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>

export const CONDITIONAL_PROOF_2022 = 'ConditionalProof2022'

type ConditionData = {
  jwtNestedLevel: number
  conditionSatisfied: boolean
  signers: string[]
  threshold: number
  weightCount: number
}

export async function verifyProof(
  jwt: string,
  { payload, header, signature, data }: JWTDecoded,
  authenticator: VerificationMethod,
  options: JWTVerifyOptions
): Promise<VerificationMethod> {
  if (authenticator.type === CONDITIONAL_PROOF_2022) {
    return await verifyConditionalProof(jwt, { payload, header, signature, data } as JWTDecoded, authenticator, options)
  } else {
    return await verifyJWSDecoded({ header, data, signature } as JWSDecoded, [authenticator])
  }
}

export async function verifyConditionalProof(
  jwt: string,
  { payload, header, signature, data }: JWTDecoded,
  authenticator: VerificationMethod,
  options: JWTVerifyOptions
): Promise<VerificationMethod> {
  // This object (reference) is used to track the state of the condition during execution of
  // recursive calls and nested function calls to sub-conditions
  const condition: ConditionData = {
    jwtNestedLevel: 1,
    conditionSatisfied: false,
    signers: [], // string of DID URLs to the verification method or submethod
    threshold: authenticator.threshold ?? 0,
    weightCount: 0,
  }

  // Iterate through each nested JWT
  let recurse = true
  do {
    console.log(`verifyConditionalProof(): checking JWT at level ${condition.jwtNestedLevel}`)

    if (!condition.conditionSatisfied) {
      try {
        // Validate the condition according to it's condition property
        if (authenticator.conditionWeightedThreshold) {
          // TODO, changing these reference objects may change them in the calling function. Check this does not cause bugs
          // perhaps use Object.assign() to create a new object copy
          await verifyConditionWeightedThreshold(
            jwt,
            { header, data, signature } as JWSDecoded,
            authenticator,
            condition,
            options
          )
        } else if (authenticator.conditionDelegated) {
          await verifyConditionDelegated(
            jwt,
            { header, data, signature } as JWSDecoded,
            authenticator,
            condition,
            options
          )
        }
        // TODO other conditions
      } catch (e) {
        // Do nothing
      }
    }

    // Check if we are at the root JWT with the VC inside, if not then decode and iterate the JWT next nested level
    condition.jwtNestedLevel++
    if (header.cty === 'JWT') {
      console.log(`verifyConditionalProof(): must go another level deeper to level ${condition.jwtNestedLevel}`)
      ;({ payload, header, signature, data } = decodeJWT(payload.jwt, false))
    } else {
      console.log(`verifyConditionalProof(): bottom jwt = ${JSON.stringify(payload, null, 2)}`)
      recurse = false
    }

    if (condition.conditionSatisfied) {
      recurse = false
    }
  } while (recurse)

  if (!condition.conditionSatisfied) {
    throw new Error(
      `${JWT_ERROR.INVALID_SIGNATURE}: JWT not valid. issuer ${authenticator.id} does not have a verificationMethod that matches the signature.`
    )
  }

  return authenticator
}

async function verifyConditionWeightedThreshold(
  jwt: string,
  { header, data, signature }: JWSDecoded,
  authenticator: VerificationMethod,
  condition: ConditionData,
  options: JWTVerifyOptions
): Promise<boolean> {
  if (!authenticator.conditionWeightedThreshold || !authenticator.threshold) {
    throw new Error('Expected conditionWeightedThreshold and threshold')
  }

  const newSigners: string[] = []

  for (const weightedCondition of authenticator.conditionWeightedThreshold) {
    const currentCondition = weightedCondition.condition
    let foundSigner: VerificationMethod | undefined

    if (currentCondition.type === CONDITIONAL_PROOF_2022) {
      console.log(`verifyConditionWeightedThreshold(): nested condition found in ${currentCondition.id}`)
      const newOptions = {
        ...options,
        ...{
          didAuthenticator: {
            // @ts-ignore
            didResolutionResult: options.didAuthenticator.didResolutionResult,
            authenticators: [currentCondition],
            issuer: currentCondition.id,
          },
        },
      }
      const { verified } = await verifyJWT(jwt, newOptions)
      if (verified) {
        foundSigner = currentCondition
      }
    } else {
      try {
        console.log(`verifyConditionWeightedThreshold(): testing to see if ${currentCondition.id} matches`)
        foundSigner = await verifyJWSDecoded({ header, data, signature } as JWSDecoded, currentCondition)
      } catch (e) {
        if (!(e as Error).message.startsWith('invalid_signature:')) throw e
      }
    }

    if (foundSigner && !condition.signers.includes(foundSigner.id)) {
      console.log(`verifyConditionWeightedThreshold(): signature valid and is unique for ${foundSigner.id}`)
      condition.signers.push(foundSigner.id)
      newSigners.push(foundSigner.id)
      condition.weightCount += weightedCondition.weight

      console.log(
        `verifyConditionWeightedThreshold(): signaturesThresholdCount ${condition.weightCount} >= threshold ${condition.threshold}`
      )
      if (condition.weightCount >= condition.threshold) {
        console.log(`verifyConditionWeightedThreshold(): condition valid: ${authenticator.id}`)
        condition.conditionSatisfied = true
        return true
      }
    }
  }
  return newSigners.length > 0
}

async function verifyConditionDelegated(
  jwt: string,
  { header, data, signature }: JWSDecoded,
  authenticator: VerificationMethod,
  condition: ConditionData,
  options: JWTVerifyOptions
): Promise<boolean> {
  if (!authenticator.conditionDelegated) {
    throw new Error('Expected conditionDelegated')
  }
  if (!options.resolver) {
    throw new Error('Expected resolver')
  }

  const newSigners: string[] = []
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
    console.log(`verifyConditionDelegated(): nested condition found in ${delegatedAuthenticator.id}`)
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
      console.log(`verifyConditionDelegated(): testing to see if ${authenticator.id} matches`)
      foundSigner = await verifyJWSDecoded({ header, data, signature } as JWSDecoded, delegatedAuthenticator)
    } catch (e) {
      if (!(e as Error).message.startsWith('invalid_signature:')) throw e
    }
  }

  if (foundSigner && !condition.signers.includes(foundSigner.id)) {
    console.log(`verifyConditionDelegated(): signature valid and is unique for ${foundSigner.id}`)
    condition.signers.push(foundSigner.id)
    condition.signers.push(authenticator.conditionDelegated)
    newSigners.push(foundSigner.id)

    console.log(`verifyConditionDelegated(): condition valid: ${authenticator.id}`)
    condition.conditionSatisfied = true
    return true
  }
  return false
}
