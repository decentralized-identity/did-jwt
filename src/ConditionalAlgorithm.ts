import type { VerificationMethod } from 'did-resolver'
import { EcdsaSignature } from './util'
import { JWT_ERROR } from './Errors'
import { decodeJWT, JWSDecoded, verifyJWSDecoded } from './JWT'

export type Signer = (data: string | Uint8Array) => Promise<EcdsaSignature | string>
export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>

// TODO return VerificationMethod???
export async function verifyConditionalProof(
  jwt: string,
  authenticator: VerificationMethod
): Promise<VerificationMethod> {
  // validate that nested signatures are valid so that we know that each level is indirectly signing the VC
  // TODO JWT has already been deceded, so better use the already decoded version
  let decoded = decodeJWT(jwt, false)

  let jwtNestedLevelCount = 1

  let signers: string[] = [] // string of DID URLs to the verification method or submethod

  let conditionSatisfied = false

  // Iterate through each nested JWT
  let recurse = true
  do {
    console.log(`verifyConitionalProof(): checking JWT at level ${jwtNestedLevelCount}`)
    const { header, data, payload, signature } = decoded
    let newSigners: string[] = []

    // Iterate through the condition
    if (authenticator.conditionWeightedThreshold) {
      ({ conditionSatisfied, newSigners, signers } = await verifyConditionWeightedThreshold(
        { header, data, signature } as JWSDecoded,
        authenticator,
        signers
      ))
    } else if (authenticator.conditionDelegated) {
      // TODO
    }

    // Each (nested) JWT must be signed by at least one valid signature from the issuer all the way to the bottom
    if (newSigners.length === 0) {
      throw new Error(
        `${JWT_ERROR.RESOLVER_ERROR}: Invalid signature at nested level ${jwtNestedLevelCount} with signer ${signature}`
      )
    }

    // Check if we are at the root JWT with the VC inside, if not then decode and iterate the JWT next nested level
    jwtNestedLevelCount++
    if (decoded.header.cty === 'JWT') {
      console.log(`verifyConitionalProof(): must go another level deeper to level ${jwtNestedLevelCount}`)
      decoded = decodeJWT(payload.jwt, false)
    } else {
      console.log(`verifyConitionalProof(): bottom jwt = ${JSON.stringify(decoded.payload, null, 2)}`)
      recurse = false
    }
  } while (recurse)

  if (!conditionSatisfied) {
    throw new Error(
      `${JWT_ERROR.INVALID_SIGNATURE}: JWT not valid. issuer ${authenticator.id} does not have a verificationMethod that matches the signature.`
    )
  }

  return authenticator
}

type VerifyConditionResponse = {
  signers: string[]
  newSigners: string[]
  conditionSatisfied: boolean
}

async function verifyConditionWeightedThreshold(
  { header, data, signature }: JWSDecoded,
  authenticator: VerificationMethod,
  signers: string[]
): Promise<VerifyConditionResponse> {
  if (!authenticator.conditionWeightedThreshold || !authenticator.threshold) {
    throw new Error('Expected conditionWeightedThreshold and threshold')
  }

  const newSigners: string[] = []
  let conditionSatisfied = false

  const threshold = authenticator.threshold
  let signaturesThresholdCount = 0

  for (const condition of authenticator.conditionWeightedThreshold) {
    let foundSigner: VerificationMethod | undefined

    try {
      console.log(`testing to see if ${condition.condition.id} matches`)
      // TODO this should probably call verifyJWT() instead recursively
      foundSigner = await verifyJWSDecoded({ header, data, signature } as JWSDecoded, condition.condition)
    } catch (e) {
      if (!((e as Error).message.startsWith('invalid_signature:'))) throw e
    }

    if (foundSigner && !signers.includes(foundSigner.id)) {
      console.log(`verifyConditionalProof(): signature valid and is unique for ${foundSigner.id}`)
      signers.push(foundSigner.id)
      signaturesThresholdCount += condition.weight
      newSigners.push(foundSigner.id)

      console.log(
        `verifyConditionalProof(): signaturesThresholdCount ${signaturesThresholdCount} >= threshold ${threshold}`
      )
      if (signaturesThresholdCount >= threshold) {
        console.log(`verifyConditionalProof(): condition valid: ${authenticator.id}`)
        conditionSatisfied = true
      }
    }
  }
  return { signers, newSigners, conditionSatisfied }
}
