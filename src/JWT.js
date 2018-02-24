import { isMNID } from 'mnid'
import Verifier from './Verifier'
import Signer from './Signer'
import base64url from 'base64url'
import resolve from 'did-resolver'
import registerUport from 'uport-did-resolver'

registerUport()

const SUPPORTED_PUBLIC_KEY_TYPES = {
  ES256K: ['Secp256k1SignatureVerificationKey2018', 'EcdsaPublicKeySecp256k1']
}

const JOSE_HEADER = {typ: 'JWT'}
const defaultAlg = 'ES256K'

function encodeSection (data) {
  return base64url.encode(JSON.stringify(data))
}

export const IAT_SKEW = 60

/**  @module uport-jwt/JWT */

function normalizeDID (mnidOrDid) {
  if (mnidOrDid.match(/^did:/)) return mnidOrDid
  if (isMNID(mnidOrDid)) return `did:uport:${mnidOrDid}`
  throw new Error(`Not a valid DID '${mnidOrDid}'`)
}

export function decodeJWT (jwt) {
  if (!jwt) throw new Error('no JWT passed into decodeJWT')
  const parts = jwt.match(/^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
  if (parts) {
    return {
      header: JSON.parse(base64url.decode(parts[1])),
      payload: JSON.parse(base64url.decode(parts[2])),
      signature: parts[3]
    }
  }
  throw new Error('Incorrect format JWT')
}

/**
*  Creates a signed JWT given an address which becomes the issuer, a signer, and a payload for which the signature is over.
*
*  @example
*  const signer = SimpleSigner(process.env.PRIVATE_KEY)
*  createJWT({address: '5A8bRWU3F7j3REx3vkJ...', signer}, {key1: 'value', key2: ..., ... }).then(jwt => {
*      ...
*  })
*
*  @param    {Object}            [config]           an unsigned credential object
*  @param    {String}            config.address     address, typically the uPort address of the signer which becomes the issuer
*  @param    {SimpleSigner}      config.signer      a signer, reference our SimpleSigner.js
*  @param    {Object}            payload            payload object
*  @return   {Promise<Object, Error>}               a promise which resolves with a signed JSON Web Token or rejects with an error
*/
export async function createJWT ({address, signer, alg}, payload) {
  if (!signer) throw new Error('No Signer functionality has been configured')
  if (!address) throw new Error('No application identity address has been configured')
  const iss = normalizeDID(address)
  const header = {...JOSE_HEADER, alg: alg || defaultAlg}
  const signingInput = [encodeSection(header),
    encodeSection({ iss, iat: Math.floor(Date.now() / 1000), ...payload })
  ].join('.')

  const jwtSigner = Signer(header.alg)
  const signature = await jwtSigner(signingInput, signer)
  return [signingInput, signature].join('.')
}

/**
*  Verifies given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT,
*  and the profile of the issuer of the JWT.
*
*  @example
*  verifyJWT({address: '5A8bRWU3F7j3REx3vkJ...'}, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJyZXF1Z....').then(obj => {
       const did = obj.did // DID of signer
*      const payload = obj.payload
*      const doc = obj.doc // DID Document of signer
*      const jwt = obj.jwt
*      const signerKeyId = obj.signerKeyId // ID of key in DID document that signed JWT
*      ...
*  })
*
*  @param    {Object}            [config]           an unsigned credential object
*  @param    {String}            config.address     address, typically the uPort address of the signer which becomes the issuer
*  @param    {String}            jwt                a JSON Web Token to verify
*  @param    {String}            callbackUrl        callback url in JWT
*  @return   {Promise<Object, Error>}               a promise which resolves with a response object or rejects with an error
*/
export async function verifyJWT ({address}, jwt, callbackUrl = null) {
  const aud = address ? normalizeDID(address) : undefined
  const {payload, header, signature} = decodeJWT(jwt)
  const {doc, authenticators, did} = await resolveAuthenticator(header.alg, payload.iss)
  const signer = Verifier(header.alg)(jwt, payload, signature, authenticators)
  if (signer) {
    if (payload.iat && payload.iat > (Date.now() / 1000 + IAT_SKEW)) {
      throw new Error(`JWT not valid yet (issued in the future): iat: ${payload.iat} > now: ${Date.now() / 1000}`)
    }
    if (payload.exp && (payload.exp <= Date.now() / 1000)) {
      throw new Error(`JWT has expired: exp: ${payload.exp} < now: ${Date.now() / 1000}`)
    }
    if (payload.aud) {
      if (payload.aud.match(/^did:/)) {
        if (!aud) {
          throw new Error('JWT audience is required but your app address has not been configured')
        }

        if (aud !== payload.aud) {
          throw new Error(`JWT audience does not match your DID: aud: ${payload.aud} !== yours: ${aud}`)
        }
      } else {
        if (!callbackUrl) {
          throw new Error('JWT audience matching your callback url is required but one wasn\'t passed in')
        }
        if (payload.aud !== callbackUrl) {
          throw new Error(`JWT audience does not match the callback url: aud: ${payload.aud} !== url: ${callbackUrl}`)
        }
      }
    }
    return ({payload, doc, did, signer, jwt})
  } else {
    throw new Error('Signature invalid for JWT')
  }
}

/**
* Resolves relevant public keys or other authenticating material used to verify signature from the DID document of provided DID
*
*  @example
*  resolveAuthenticator('did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX').then(obj => {
*      const payload = obj.payload
*      const profile = obj.profile
*      const jwt = obj.jwt
*      ...
*  })
*
*  @param    {String}            alg                a JWT algorithm
*  @param    {String}            did                a Decentralized IDentifier (DID) to lookup
*  @return   {Promise<Object, Error>}               a promise which resolves with a response object containing an array of authenticators or if non exist rejects with an error
*/

export async function resolveAuthenticator (alg, mnidOrDid) {
  const types = SUPPORTED_PUBLIC_KEY_TYPES[alg]
  if (!types || types.length === 0) throw new Error(`No supported signature types for algorithm ${alg}`)
  const did = normalizeDID(mnidOrDid)
  const doc = await resolve(did)
  if (!doc) throw new Error(`Unable to resolve DID document for ${did}`)
  const authenticators = (doc.publicKey || []).filter(({type}) => types.find(supported => supported === type))
  if (!authenticators || authenticators.length === 0) throw new Error(`DID document for ${did} does not have public keys for ${alg}`)
  return {authenticators, did, doc}
}

export default { decodeJWT, createJWT, verifyJWT, resolveAuthenticator }
