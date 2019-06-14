import { ec as EC } from 'elliptic'
import { sha256, toEthereumAddress } from './Digest'
import base64url from 'uport-base64url'
import nacl from 'tweetnacl'
import { EcdsaSignature } from './JWT'
import { PublicKey } from 'did-resolver'
import { encode } from '@stablelib/utf8'
import { base64ToBytes } from './util'

const secp256k1 = new EC('secp256k1')

// converts a JOSE signature to it's components
export function toSignatureObject(
  signature: string,
  recoverable = false
): EcdsaSignature {
  const rawsig: Buffer = base64url.toBuffer(signature)
  if (rawsig.length !== (recoverable ? 65 : 64)) {
    throw new Error('wrong signature length')
  }
  const r: string = rawsig.slice(0, 32).toString('hex')
  const s: string = rawsig.slice(32, 64).toString('hex')
  const sigObj: EcdsaSignature = { r, s }
  if (recoverable) {
    sigObj.recoveryParam = rawsig[64]
  }
  return sigObj
}

export function verifyES256K(
  data: string,
  signature: string,
  authenticators: PublicKey[]
): PublicKey {
  const hash: Buffer = sha256(data)
  const sigObj: EcdsaSignature = toSignatureObject(signature)
  const signer: PublicKey = authenticators.find(({ publicKeyHex }) =>
    secp256k1.keyFromPublic(publicKeyHex, 'hex').verify(hash, sigObj)
  )
  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

export function verifyRecoverableES256K(
  data: string,
  signature: string,
  authenticators: PublicKey[]
): PublicKey {
  const sigObj: EcdsaSignature = toSignatureObject(signature, true)
  const hash: Buffer = sha256(data)
  // what type is recoveredKey supposed to be?
  const recoveredKey: any = secp256k1.recoverPubKey(
    hash,
    sigObj,
    sigObj.recoveryParam
  )
  const recoveredPublicKeyHex: string = recoveredKey.encode('hex')
  const recoveredCompressedPublicKeyHex: string = recoveredKey.encode(
    'hex',
    true
  )
  const recoveredAddress: string = toEthereumAddress(recoveredPublicKeyHex)
  const signer: PublicKey = authenticators.find(
    ({ publicKeyHex, ethereumAddress }) =>
      publicKeyHex === recoveredPublicKeyHex ||
      publicKeyHex === recoveredCompressedPublicKeyHex ||
      ethereumAddress === recoveredAddress
  )
  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

export function verifyEd25519(
  data: string,
  signature: string,
  authenticators: PublicKey[]
): PublicKey {
  const clear: Uint8Array = encode(data)
  const sig: Uint8Array = base64ToBytes(base64url.toBase64(signature))
  const signer: PublicKey = authenticators.find(({ publicKeyBase64 }) =>
    nacl.sign.detached.verify(
      clear,
      sig,
      base64ToBytes(publicKeyBase64)
    )
  )
  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

type Verifier = (
  data: string,
  signature: string,
  authenticators: PublicKey[]
) => PublicKey
interface Algorithms {
  [name: string]: Verifier
}
const algorithms: Algorithms = {
  ES256K: verifyES256K,
  'ES256K-R': verifyRecoverableES256K,
  Ed25519: verifyEd25519
}

function VerifierAlgorithm(alg: string): Verifier {
  const impl: Verifier = algorithms[alg]
  if (!impl) throw new Error(`Unsupported algorithm ${alg}`)
  return impl
}

VerifierAlgorithm.toSignatureObject = toSignatureObject

export default VerifierAlgorithm
