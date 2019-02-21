import { ec as EC } from 'elliptic'
import { sha256, toEthereumAddress } from './Digest'
import base64url from 'base64url'
import nacl from 'tweetnacl'
import naclutil from 'tweetnacl-util'

const secp256k1 = new EC('secp256k1')

// converts a JOSE signature to it's components
export function toSignatureObject (signature, recoverable = false) {
  const rawsig = base64url.toBuffer(signature)
  if (rawsig.length !== (recoverable ? 65 : 64)) throw new Error('wrong signature length')
  const r = rawsig.slice(0, 32).toString('hex')
  const s = rawsig.slice(32, 64).toString('hex')
  const sigObj = { r, s }
  if (recoverable) {
    sigObj.recoveryParam = rawsig[64]
  }
  return sigObj
}

export function verifyES256K (data, signature, authenticators) {
  const hash = sha256(data)
  const sigObj = toSignatureObject(signature)
  const signer = authenticators.find(({ publicKeyHex }) => secp256k1.keyFromPublic(publicKeyHex, 'hex').verify(hash, sigObj))
  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

export function verifyRecoverableES256K (data, signature, authenticators) {
  const sigObj = toSignatureObject(signature, true)
  const hash = sha256(data)
  const recoveredKey = secp256k1.recoverPubKey(hash, sigObj, sigObj.recoveryParam)
  const recoveredPublicKeyHex = recoveredKey.encode('hex')
  const recoveredCompressedPublicKeyHex = recoveredKey.encode('hex', true)
  const recoveredAddress = toEthereumAddress(recoveredPublicKeyHex)
  const signer = authenticators.find(({ publicKeyHex, ethereumAddress }) => publicKeyHex === recoveredPublicKeyHex || publicKeyHex === recoveredCompressedPublicKeyHex || ethereumAddress === recoveredAddress)
  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

export function verifyEd25519 (data, signature, authenticators) {
  const clear = naclutil.decodeUTF8(data)
  const sig = naclutil.decodeBase64(base64url.toBase64(signature))
  const signer = authenticators.find(({ publicKeyBase64 }) => nacl.sign.detached.verify(clear, sig, naclutil.decodeBase64(publicKeyBase64)))
  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

const algorithms = { ES256K: verifyES256K, 'ES256K-R': verifyRecoverableES256K, 'Ed25519': verifyEd25519 }

function VerifierAlgorithm (alg) {
  const impl = algorithms[alg]
  if (!impl) throw new Error(`Unsupported algorithm ${alg}`)
  return impl
}

VerifierAlgorithm.toSignatureObject = toSignatureObject

module.exports = VerifierAlgorithm
