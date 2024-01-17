import { sha256, toEthereumAddress } from './Digest.js'
import type { VerificationMethod } from 'did-resolver'
import {
  base64ToBytes,
  bytesToHex,
  EcdsaSignature,
  ECDSASignature,
  extractPublicKeyBytes,
  KNOWN_JWA,
  stringToBytes,
} from './util.js'
import { verifyBlockchainAccountId } from './blockchains/index.js'
import { secp256k1 } from '@noble/curves/secp256k1'
import { p256 } from '@noble/curves/p256'
import { ed25519 } from '@noble/curves/ed25519'

// converts a JOSE signature to it's components
export function toSignatureObject(signature: string, recoverable = false): EcdsaSignature {
  const rawSig: Uint8Array = base64ToBytes(signature)
  if (rawSig.length !== (recoverable ? 65 : 64)) {
    throw new Error('wrong signature length')
  }
  const r: string = bytesToHex(rawSig.slice(0, 32))
  const s: string = bytesToHex(rawSig.slice(32, 64))
  const sigObj: EcdsaSignature = { r, s }
  if (recoverable) {
    sigObj.recoveryParam = rawSig[64]
  }
  return sigObj
}

export function toSignatureObject2(signature: string, recoverable = false): ECDSASignature {
  const bytes = base64ToBytes(signature)
  if (bytes.length !== (recoverable ? 65 : 64)) {
    throw new Error('wrong signature length')
  }
  return {
    compact: bytes.slice(0, 64),
    recovery: bytes[64],
  }
}

export function verifyES256(data: string, signature: string, authenticators: VerificationMethod[]): VerificationMethod {
  const hash = sha256(data)
  const sig = p256.Signature.fromCompact(toSignatureObject2(signature).compact)
  const fullPublicKeys = authenticators.filter((a: VerificationMethod) => !a.ethereumAddress && !a.blockchainAccountId)

  const signer: VerificationMethod | undefined = fullPublicKeys.find((pk: VerificationMethod) => {
    try {
      const { keyBytes } = extractPublicKeyBytes(pk)
      return p256.verify(sig, hash, keyBytes)
    } catch (err) {
      return false
    }
  })

  if (!signer) throw new Error('invalid_signature: Signature invalid for JWT')
  return signer
}

export function verifyES256K(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  const hash = sha256(data)
  const signatureNormalized = secp256k1.Signature.fromCompact(base64ToBytes(signature)).normalizeS()
  const fullPublicKeys = authenticators.filter((a: VerificationMethod) => {
    return !a.ethereumAddress && !a.blockchainAccountId
  })
  const blockchainAddressKeys = authenticators.filter((a: VerificationMethod) => {
    return a.ethereumAddress || a.blockchainAccountId
  })

  let signer: VerificationMethod | undefined = fullPublicKeys.find((pk: VerificationMethod) => {
    try {
      const { keyBytes } = extractPublicKeyBytes(pk)
      return secp256k1.verify(signatureNormalized, hash, keyBytes)
    } catch (err) {
      return false
    }
  })

  if (!signer && blockchainAddressKeys.length > 0) {
    signer = verifyRecoverableES256K(data, signature, blockchainAddressKeys)
  }

  if (!signer) throw new Error('invalid_signature: Signature invalid for JWT')
  return signer
}

export function verifyRecoverableES256K(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  const signatures: ECDSASignature[] = []
  if (signature.length > 86) {
    signatures.push(toSignatureObject2(signature, true))
  } else {
    const so = toSignatureObject2(signature, false)
    signatures.push({ ...so, recovery: 0 })
    signatures.push({ ...so, recovery: 1 })
  }
  const hash = sha256(data)

  const checkSignatureAgainstSigner = (sigObj: ECDSASignature): VerificationMethod | undefined => {
    const signature = secp256k1.Signature.fromCompact(sigObj.compact).addRecoveryBit(sigObj.recovery || 0)
    const recoveredPublicKey = signature.recoverPublicKey(hash)
    const recoveredAddress = toEthereumAddress(recoveredPublicKey.toHex(false)).toLowerCase()
    const recoveredPublicKeyHex = recoveredPublicKey.toHex(false)
    const recoveredCompressedPublicKeyHex = recoveredPublicKey.toHex(true)

    return authenticators.find((a: VerificationMethod) => {
      const { keyBytes } = extractPublicKeyBytes(a)
      const keyHex = bytesToHex(keyBytes)
      return (
        keyHex === recoveredPublicKeyHex ||
        keyHex === recoveredCompressedPublicKeyHex ||
        a.ethereumAddress?.toLowerCase() === recoveredAddress ||
        a.blockchainAccountId?.split('@eip155')?.[0].toLowerCase() === recoveredAddress || // CAIP-2
        verifyBlockchainAccountId(recoveredPublicKeyHex, a.blockchainAccountId) // CAIP-10
      )
    })
  }

  // Find first verification method
  for (const signature of signatures) {
    const verificationMethod = checkSignatureAgainstSigner(signature)
    if (verificationMethod) return verificationMethod
  }
  // If no one found matching
  throw new Error('invalid_signature: Signature invalid for JWT')
}

export function verifyEd25519(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  const clear = stringToBytes(data)
  const signatureBytes = base64ToBytes(signature)
  const signer = authenticators.find((a: VerificationMethod) => {
    const { keyBytes, keyType } = extractPublicKeyBytes(a)
    if (keyType === 'Ed25519') {
      return ed25519.verify(signatureBytes, clear, keyBytes)
    } else {
      return false
    }
  })
  if (!signer) throw new Error('invalid_signature: Signature invalid for JWT')
  return signer
}

type Verifier = (data: string, signature: string, authenticators: VerificationMethod[]) => VerificationMethod

type Algorithms = Record<KNOWN_JWA, Verifier>

const algorithms: Algorithms = {
  ES256: verifyES256,
  ES256K: verifyES256K,
  // This is a non-standard algorithm but retained for backwards compatibility
  // see https://github.com/decentralized-identity/did-jwt/issues/146
  'ES256K-R': verifyRecoverableES256K,
  // This is actually incorrect but retained for backwards compatibility
  // see https://github.com/decentralized-identity/did-jwt/issues/130
  Ed25519: verifyEd25519,
  EdDSA: verifyEd25519,
}

function VerifierAlgorithm(alg: string): Verifier {
  const impl: Verifier = algorithms[alg as KNOWN_JWA]
  if (!impl) throw new Error(`not_supported: Unsupported algorithm ${alg}`)
  return impl
}

VerifierAlgorithm.toSignatureObject = toSignatureObject

export default VerifierAlgorithm
