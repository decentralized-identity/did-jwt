import type { VerificationMethod } from 'did-resolver'
import { EcdsaSignature } from './util'
import { JWT_ERROR } from './Errors'
import { decodeJWT, JWSDecoded, JWTDecoded, JWTVerifyOptions, verifyJWSDecoded } from './JWT'

export type Signer = (data: string | Uint8Array) => Promise<EcdsaSignature | string>
export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>

type ConditionData = {
  jwtNestedLevel: number
  conditionSatisfied: boolean
  signers: string[]
  threshold: number
  weightCount: number
}
// TODO return VerificationMethod???
export async function verifyConditionalProof(
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
    threshold: authenticator.threshold ? authenticator.threshold : 0,
    weightCount: 0,
  }

  // Iterate through each nested JWT
  // validate that nested signatures are valid so that we know that each level is indirectly signing the VC
  let recurse = true
  do {
    console.log(`verifyConditionalProof(): checking JWT at level ${condition.jwtNestedLevel}`)
    let newSigners: string[] = []

    // Iterate through the condition
    if (authenticator.conditionWeightedThreshold) {
      // TODO, changing these reference objects may change them in the calling function. Check this does not cause bugs
      // perhaps use Object.assign() to create a new object copy
      ;({ newSigners } = await verifyConditionWeightedThreshold(
        { header, data, signature } as JWSDecoded,
        authenticator,
        condition
      ))
    } else if (authenticator.conditionDelegated) {
      ;({ newSigners } = await verifyConditionDelegated(
        { header, data, signature } as JWSDecoded,
        authenticator,
        condition,
        options
      ))
    }
    // TODO other conditions

    // Each (nested) JWT must be signed by at least one valid signature from the issuer all the way to the bottom
    if (newSigners.length === 0) {
      throw new Error(
        `${JWT_ERROR.RESOLVER_ERROR}: Invalid signature at nested level ${condition.jwtNestedLevel} with signer ${authenticator.id}`
      )
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
  } while (recurse)

  if (!condition.conditionSatisfied) {
    throw new Error(
      `${JWT_ERROR.INVALID_SIGNATURE}: JWT not valid. issuer ${authenticator.id} does not have a verificationMethod that matches the signature.`
    )
  }

  return authenticator
}

type VerifyConditionResponse = {
  newSigners: string[]
}

async function verifyConditionWeightedThreshold(
  { header, data, signature }: JWSDecoded,
  authenticator: VerificationMethod,
  condition: ConditionData
): Promise<VerifyConditionResponse> {
  if (!authenticator.conditionWeightedThreshold || !authenticator.threshold) {
    throw new Error('Expected conditionWeightedThreshold and threshold')
  }

  const newSigners: string[] = []

  for (const weightedCondition of authenticator.conditionWeightedThreshold) {
    let foundSigner: VerificationMethod | undefined

    try {
      console.log(`verifyConditionWeightedThreshold(): testing to see if ${weightedCondition.condition.id} matches`)
      // TODO this should probably call verifyJWT() instead recursively
      foundSigner = await verifyJWSDecoded({ header, data, signature } as JWSDecoded, weightedCondition.condition)
    } catch (e) {
      if (!((e as Error).message.startsWith('invalid_signature:'))) throw e
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
      }
    }
  }
  return { newSigners }
}

async function verifyConditionDelegated(
  { header, data, signature }: JWSDecoded,
  authenticator: VerificationMethod,
  condition: ConditionData,
  options: JWTVerifyOptions
): Promise<VerifyConditionResponse> {
  if (!authenticator.conditionDelegated) {
    throw new Error('Expected conditionDelegated')
  }
  if (!options.resolver) {
    throw new Error('Expected resolver')
  }

  const newSigners: string[] = []
  let foundSigner: VerificationMethod | undefined

  const delegatedDidDoc = await options.resolver.resolve(authenticator.conditionDelegated)
  if (!delegatedDidDoc || !delegatedDidDoc.didDocument || !delegatedDidDoc.didDocument.verificationMethod) {
    throw new Error(`${JWT_ERROR.RESOLVER_ERROR}: Could not resolve delegated DID ${authenticator.conditionDelegated}.`)
  }

  const delegatedAuthenticator = delegatedDidDoc.didDocument.verificationMethod.find(
    (authenticator) => authenticator.id === authenticator.conditionDelegated
  )
  if (!delegatedAuthenticator) {
    throw new Error(
      `${JWT_ERROR.NO_SUITABLE_KEYS}: Could not find delegated authenticator for ${authenticator.conditionDelegated}`
    )
  }

  try {
    console.log(`verifyConditionDelegated(): testing to see if ${authenticator.id} matches`)
    // TODO this should probably call verifyJWT() instead recursively
    foundSigner = await verifyJWSDecoded({ header, data, signature } as JWSDecoded, delegatedAuthenticator)
  } catch (e) {
    if (!((e as Error).message.startsWith('invalid_signature:'))) throw e
  }

  if (foundSigner && !condition.signers.includes(foundSigner.id)) {
    console.log(`verifyConditionDelegated(): signature valid and is unique for ${foundSigner.id}`)
    condition.signers.push(foundSigner.id)
    condition.signers.push(authenticator.conditionDelegated)
    newSigners.push(foundSigner.id)

    console.log(`verifyConditionDelegated(): condition valid: ${authenticator.id}`)
    condition.conditionSatisfied = true
  }

  return { newSigners }
}
