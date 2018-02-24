import { ec } from 'elliptic'
import { sha256 } from 'js-sha256'
import base64url from 'base64url'

export function ES256KSigner () {
  const secp256k1 = new ec('secp256k1')

  function hash (payload) {
    return Buffer.from(sha256.arrayBuffer(payload))
  }

  function toJose (signature) {
    const jose = Buffer.alloc(64)
    Buffer.from(signature.r, 'hex').copy(jose, 0)
    Buffer.from(signature.s, 'hex').copy(jose, 32)
    return base64url.encode(jose)
  }

  return async function sign (payload, signer) {
    const signature = await signer(hash(payload))
    return toJose(signature)
  }
}

const algorithms = { ES256K: ES256KSigner() }

function Signer (alg) {
  const impl = algorithms[alg]
  if (!impl) throw new Error(`Unsupported algorithm ${alg}`)
  return impl
}

module.exports = Signer
