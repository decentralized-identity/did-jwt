import { ec } from 'elliptic'
import { sha256 } from 'js-sha256'
import base64url from 'base64url'

export function ES256KVerifier () {
  const secp256k1 = new ec('secp256k1')
  function hash (jwt) {
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\./)
    return Buffer.from(sha256.arrayBuffer(parts[1]))
  }

  function toSignatureObject (signature) {
    const rawsig = base64url.toBuffer(signature)
    if (rawsig.length !== 64) throw new Error('wrong signature length')
    const r = rawsig.slice(0, 32).toString('hex')
    const s = rawsig.slice(32).toString('hex')
    return {r, s}
  }

  return function verify (jwt, payload, signature, authenticator) {
    const publicKey = secp256k1.keyFromPublic(authenticator, 'hex')
    return publicKey.verify(hash(jwt), toSignatureObject(signature))
  }
}

const algorithms = { ES256K: ES256KVerifier() }

function Verifier (alg) {
  const impl = algorithms[alg]
  if (!impl) throw new Error(`Unsupported algorithm ${alg}`)
  return impl
}

module.exports = Verifier
