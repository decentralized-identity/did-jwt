import { ec as EC } from 'elliptic'
import { sha256, toEthereumAddress } from './Digest'
import { verify } from '@stablelib/ed25519'
import type { VerificationMethod } from 'did-resolver'
import { hexToBytes, base58ToBytes, base64ToBytes, bytesToHex, EcdsaSignature, stringToBytes } from './util'

const secp256k1 = new EC('secp256k1')

// converts a JOSE signature to it's components
export function toSignatureObject(signature: string, recoverable = false): EcdsaSignature {
  const rawsig: Uint8Array = base64ToBytes(signature)
  if (rawsig.length !== (recoverable ? 65 : 64)) {
    throw new Error('wrong signature length')
  }
  const r: string = bytesToHex(rawsig.slice(0, 32))
  const s: string = bytesToHex(rawsig.slice(32, 64))
  const sigObj: EcdsaSignature = { r, s }
  if (recoverable) {
    sigObj.recoveryParam = rawsig[64]
  }
  return sigObj
}

interface LegacyVerificationMethod extends VerificationMethod {
  publicKeyBase64: string
}

function extractPublicKeyBytes(pk: VerificationMethod): Uint8Array {
  if (pk.publicKeyBase58) {
    return base58ToBytes(pk.publicKeyBase58)
  } else if ((<LegacyVerificationMethod>pk).publicKeyBase64) {
    return base64ToBytes((<LegacyVerificationMethod>pk).publicKeyBase64)
  } else if (pk.publicKeyHex) {
    return hexToBytes(pk.publicKeyHex)
  }
  return new Uint8Array()
}

export function verifyES256K(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  const hash: Uint8Array = sha256(data)
  const sigObj: EcdsaSignature = toSignatureObject(signature)
  const fullPublicKeys = authenticators.filter(({ ethereumAddress, blockchainAccountId }) => {
    return typeof ethereumAddress === 'undefined' && typeof blockchainAccountId === 'undefined'
  })
  const ethAddressKeys = authenticators.filter(({ ethereumAddress, blockchainAccountId }) => {
    return typeof ethereumAddress !== 'undefined' || typeof blockchainAccountId !== undefined
  })

  let signer: VerificationMethod = fullPublicKeys.find((pk: VerificationMethod) => {
    try {
      const pubBytes = extractPublicKeyBytes(pk)
      return secp256k1.keyFromPublic(pubBytes).verify(hash, sigObj)
    } catch (err) {
      return false
    }
  })

  if (!signer && ethAddressKeys.length > 0) {
    signer = verifyRecoverableES256K(data, signature, ethAddressKeys)
  }

  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

export function verifyRecoverableES256K(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  let signatures: EcdsaSignature[]
  if (signature.length > 86) {
    signatures = [toSignatureObject(signature, true)]
  } else {
    const so = toSignatureObject(signature, false)
    signatures = [
      { ...so, recoveryParam: 0 },
      { ...so, recoveryParam: 1 }
    ]
  }

  const checkSignatureAgainstSigner = (sigObj: EcdsaSignature): VerificationMethod => {
    const hash: Uint8Array = sha256(data)
    const recoveredKey: any = secp256k1.recoverPubKey(hash, sigObj, sigObj.recoveryParam)
    const recoveredPublicKeyHex: string = recoveredKey.encode('hex')
    const recoveredCompressedPublicKeyHex: string = recoveredKey.encode('hex', true)
    const recoveredAddress: string = toEthereumAddress(recoveredPublicKeyHex)

    const signer: VerificationMethod = authenticators.find((pk: VerificationMethod) => {
      const keyHex = bytesToHex(extractPublicKeyBytes(pk))
      return (
        keyHex === recoveredPublicKeyHex ||
        keyHex === recoveredCompressedPublicKeyHex ||
        pk.ethereumAddress?.toLowerCase() === recoveredAddress ||
        pk.blockchainAccountId?.split('@eip155')?.[0].toLowerCase() === recoveredAddress
      )
    })

    return signer
  }

  const signer: VerificationMethod[] = signatures.map(checkSignatureAgainstSigner).filter((key) => key != null)

  if (signer.length === 0) throw new Error('Signature invalid for JWT')
  return signer[0]
}

export function verifyEd25519(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  const clear: Uint8Array = stringToBytes(data)
  const sig: Uint8Array = base64ToBytes(signature)
  const signer: VerificationMethod = authenticators.find((pk: VerificationMethod) => {
    return verify(extractPublicKeyBytes(pk), clear, sig)
  })
  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

type Verifier = (data: string, signature: string, authenticators: VerificationMethod[]) => VerificationMethod
interface Algorithms {
  [name: string]: Verifier
}
const algorithms: Algorithms = {
  ES256K: verifyES256K,
  // This is a non-standard algorithm but retained for backwards compatibility
  // see https://github.com/decentralized-identity/did-jwt/issues/146
  'ES256K-R': verifyRecoverableES256K,
  // This is actually incorrect but retained for backwards compatibility
  // see https://github.com/decentralized-identity/did-jwt/issues/130
  Ed25519: verifyEd25519,
  EdDSA: verifyEd25519
}

function VerifierAlgorithm(alg: string): Verifier {
  const impl: Verifier = algorithms[alg]
  if (!impl) throw new Error(`Unsupported algorithm ${alg}`)
  return impl
}

VerifierAlgorithm.toSignatureObject = toSignatureObject

export default VerifierAlgorithm
