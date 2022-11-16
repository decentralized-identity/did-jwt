import type { VerificationMethod } from 'did-resolver'
import { EcdsaSignature } from './util'
import { JWT_ERROR } from './Errors'
import { decodeJWT, JWSDecoded, verifyJWSDecoded } from './JWT'

export type Signer = (data: string | Uint8Array) => Promise<EcdsaSignature | string>
export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>

// TODO return VerificationMethod???
export async function verifyConditionalProof(jwt: string, signer: VerificationMethod): Promise<boolean> {
  // validate that nested signatures are valid so that we know that each level is indirectly signing the VC
  let decoded = decodeJWT(jwt, false)

  const threshold = signer.threshold as number
  let signaturesThresholdCount = 0

  let jwtNestedLevelCount = 1

  const signers: string[] = [] // string of DID URLs to the verification method or submethod

  let conditionSatisfied = false

  let recurse = true
  // Iterate through each nested JWT
  do {
    console.log(`verifyConitionalProof(): checking JWT at level ${jwtNestedLevelCount}`)
    const { header, data, payload, signature } = decoded
    let validSignatureFound = false

    // Iterate through the condition
    if (signer.conditionWeightedThreshold) {
      for (const condition of signer.conditionWeightedThreshold) {
        // TODO this should call verifyJWT() instead recursively
        let foundSigner: VerificationMethod | undefined
        try {
          console.log(`testing to see if ${condition.condition.id} matches`)
          foundSigner = await verifyJWSDecoded({ header, data, signature } as JWSDecoded, condition.condition)
        } catch (e) {
          if (!((e as Error).message.startsWith('invalid_signature:'))) throw e
        }

        if (foundSigner && !signers.includes(foundSigner.id)) {
          console.log(`verifyConditionalProof(): signature valid and is unique for ${foundSigner.id}`)
          signers.push(foundSigner.id)
          signaturesThresholdCount += condition.weight
          validSignatureFound = true

          console.log(
            `verifyConditionalProof(): signaturesThresholdCount ${signaturesThresholdCount} >= threshold ${threshold}`
          )
          if (signaturesThresholdCount >= threshold) {
            console.log(`verifyConditionalProof(): condition valid: ${signer.id}`)
            // NOTE: we still need to go through each (nested) JWT level and check there is a valid signature
            // so we don't `return true` here
            conditionSatisfied = true
          }
        }
      }
    }

    // Each (nested) JWT must be signed by at least one valid signature from the issuer all the way to the bottom
    if (!validSignatureFound) {
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

  return conditionSatisfied
}
