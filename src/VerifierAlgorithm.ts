import { ec as EC } from 'elliptic'
import { sha256, toEthereumAddress } from './Digest'
import { verify } from '@stablelib/ed25519'
import { PublicKey } from 'did-resolver'
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

function extractPublicKeyBytes(pk: PublicKey): Uint8Array {
  if (pk.publicKeyBase58) {
    return base58ToBytes(pk.publicKeyBase58)
  } else if (pk.publicKeyBase64) {
    return base64ToBytes(pk.publicKeyBase64)
  } else if (pk.publicKeyHex) {
    return hexToBytes(pk.publicKeyHex)
  }
  return new Uint8Array()
}

export function verifyES256K(data: string, signature: string, authenticators: PublicKey[]): PublicKey {
  const hash: Uint8Array = sha256(data)
  const sigObj: EcdsaSignature = toSignatureObject(signature)
  const fullPublicKeys = authenticators.filter(({ ethereumAddress }) => {
    return typeof ethereumAddress === 'undefined'
  })
  const ethAddressKeys = authenticators.filter(({ ethereumAddress }) => {
    return typeof ethereumAddress !== 'undefined'
  })

  let signer: PublicKey = fullPublicKeys.find((pk: PublicKey) => {
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

export function verifyRecoverableES256K(data: string, signature: string, authenticators: PublicKey[]): PublicKey {
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

  const checkSignatureAgainstSigner = (sigObj: EcdsaSignature): PublicKey => {
    const hash: Uint8Array = sha256(data)
    const recoveredKey: any = secp256k1.recoverPubKey(hash, sigObj, sigObj.recoveryParam)
    const recoveredPublicKeyHex: string = recoveredKey.encode('hex')
    const recoveredCompressedPublicKeyHex: string = recoveredKey.encode('hex', true)
    const recoveredAddress: string = toEthereumAddress(recoveredPublicKeyHex)

    const signer: PublicKey = authenticators.find(
      ({ publicKeyHex, ethereumAddress }) =>
        publicKeyHex === recoveredPublicKeyHex ||
        publicKeyHex === recoveredCompressedPublicKeyHex ||
        ethereumAddress === recoveredAddress
    )

    return signer
  }

  const signer: PublicKey[] = signatures.map(checkSignatureAgainstSigner).filter(key => key != null)

  if (signer.length === 0) throw new Error('Signature invalid for JWT')
  return signer[0]
}

export function verifyEd25519(data: string, signature: string, authenticators: PublicKey[]): PublicKey {
  const clear: Uint8Array = stringToBytes(data)
  const sig: Uint8Array = base64ToBytes(signature)
  const signer: PublicKey = authenticators.find((pk: PublicKey) => {
    return verify(extractPublicKeyBytes(pk), clear, sig)
  }
  )
  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

type Verifier = (data: string, signature: string, authenticators: PublicKey[]) => PublicKey
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
