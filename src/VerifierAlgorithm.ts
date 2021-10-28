import { ec as EC, SignatureInput } from 'elliptic'
import { sha256, toEthereumAddress } from './Digest'
import { verify } from '@stablelib/ed25519'
import type { VerificationMethod } from 'did-resolver'
import { bases } from 'multiformats/basics'
import { hexToBytes, base58ToBytes, base64ToBytes, bytesToHex, EcdsaSignature, stringToBytes } from './util'
import { verifyBlockchainAccountId } from './blockchains'

const secp256k1 = new EC('secp256k1')

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
  } else if (pk.publicKeyJwk && pk.publicKeyJwk.crv === 'secp256k1' && pk.publicKeyJwk.x && pk.publicKeyJwk.y) {
    return hexToBytes(
      secp256k1
        .keyFromPublic({
          x: bytesToHex(base64ToBytes(pk.publicKeyJwk.x)),
          y: bytesToHex(base64ToBytes(pk.publicKeyJwk.y)),
        })
        .getPublic('hex')
    )
  } else if (pk.publicKeyMultibase) {
    const { base16, base58btc, base64, base64url } = bases
    const baseDecoder = base16.decoder.or(base58btc.decoder.or(base64.decoder.or(base64url.decoder)))
    return baseDecoder.decode(pk.publicKeyMultibase)
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
  const blockchainAddressKeys = authenticators.filter(({ ethereumAddress, blockchainAccountId }) => {
    return typeof ethereumAddress !== 'undefined' || typeof blockchainAccountId !== undefined
  })

  let signer: VerificationMethod | undefined = fullPublicKeys.find((pk: VerificationMethod) => {
    try {
      const pubBytes = extractPublicKeyBytes(pk)
      return secp256k1.keyFromPublic(pubBytes).verify(hash, <SignatureInput>sigObj)
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
  let signatures: EcdsaSignature[]
  if (signature.length > 86) {
    signatures = [toSignatureObject(signature, true)]
  } else {
    const so = toSignatureObject(signature, false)
    signatures = [
      { ...so, recoveryParam: 0 },
      { ...so, recoveryParam: 1 },
    ]
  }

  const checkSignatureAgainstSigner = (sigObj: EcdsaSignature): VerificationMethod | undefined => {
    const hash: Uint8Array = sha256(data)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const recoveredKey: any = secp256k1.recoverPubKey(hash, <SignatureInput>sigObj, <number>sigObj.recoveryParam)
    const recoveredPublicKeyHex: string = recoveredKey.encode('hex')
    const recoveredCompressedPublicKeyHex: string = recoveredKey.encode('hex', true)
    const recoveredAddress: string = toEthereumAddress(recoveredPublicKeyHex)

    const signer: VerificationMethod | undefined = authenticators.find((pk: VerificationMethod) => {
      const keyHex = bytesToHex(extractPublicKeyBytes(pk))
      return (
        keyHex === recoveredPublicKeyHex ||
        keyHex === recoveredCompressedPublicKeyHex ||
        pk.ethereumAddress?.toLowerCase() === recoveredAddress ||
        pk.blockchainAccountId?.split('@eip155')?.[0].toLowerCase() === recoveredAddress || // CAIP-2
        verifyBlockchainAccountId(recoveredPublicKeyHex, pk.blockchainAccountId) // CAIP-10
      )
    })

    return signer
  }

  const signer: VerificationMethod[] = signatures
    .map(checkSignatureAgainstSigner)
    .filter((key) => typeof key !== 'undefined') as VerificationMethod[]

  if (signer.length === 0) throw new Error('invalid_signature: Signature invalid for JWT')
  return signer[0]
}

export function verifyEd25519(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  const clear: Uint8Array = stringToBytes(data)
  const sig: Uint8Array = base64ToBytes(signature)
  const signer = authenticators.find((pk: VerificationMethod) => {
    return verify(extractPublicKeyBytes(pk), clear, sig)
  })
  if (!signer) throw new Error('invalid_signature: Signature invalid for JWT')
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
  EdDSA: verifyEd25519,
}

function VerifierAlgorithm(alg: string): Verifier {
  const impl: Verifier = algorithms[alg]
  if (!impl) throw new Error(`not_supported: Unsupported algorithm ${alg}`)
  return impl
}

VerifierAlgorithm.toSignatureObject = toSignatureObject

export default VerifierAlgorithm
