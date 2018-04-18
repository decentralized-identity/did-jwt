import { isMNID } from 'mnid'
import VerifierAlgorithm from './VerifierAlgorithm'
import SignerAlgorithm from './SignerAlgorithm'
import base64url from 'base64url'
import resolve from 'did-resolver'
import registerUport from 'uport-did-resolver'

registerUport()

const SUPPORTED_PUBLIC_KEY_TYPES = {
  ES256K: ['Secp256k1VerificationKey2018', 'Secp256k1SignatureVerificationKey2018', 'EcdsaPublicKeySecp256k1'],
  'ES256K-R': ['Secp256k1VerificationKey2018', 'Secp256k1SignatureVerificationKey2018', 'EcdsaPublicKeySecp256k1']
}

const JOSE_HEADER = {typ: 'JWT'}
const defaultAlg = 'ES256K'

function encodeSection (data) {
  return base64url.encode(JSON.stringify(data))
}

export const IAT_SKEW = 60

/**  @module did-jwt/JWT */

function isDIDOrMNID (mnidOrDid) {
  return mnidOrDid && (mnidOrDid.match(/^did:/) || isMNID(mnidOrDid))
}

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
      signature: parts[3],
      data: `${parts[1]}.${parts[2]}`
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
*  @param    {Object}            payload            payload object
*  @param    {Object}            [config]           an unsigned credential object
*  @param    {String}            config.issuer      The DID of the issuer (signer) of JWT
*  @param    {String}            config.alg         The JWT signing algorithm to use. Supports: [ES256K, ES256K-R], Defaults to: ES256K
*  @param    {SimpleSigner}      config.signer      a signer, reference our SimpleSigner.js
*  @return   {Promise<Object, Error>}               a promise which resolves with a signed JSON Web Token or rejects with an error
*/
export async function createJWT (payload, {issuer, signer, alg, expiresIn}) {
  if (!signer) throw new Error('No Signer functionality has been configured')
  if (!issuer) throw new Error('No issuing DID has been configured')
  const header = {...JOSE_HEADER, alg: alg || defaultAlg}
  const timestamps = { iat: Math.floor(Date.now() / 1000) }
  if (expiresIn) {
    if (typeof expiresIn === 'number') {
      timestamps.exp = timestamps.iat + Math.floor(expiresIn)
    } else {
      throw new Error('JWT expiresIn is not a number')
    }
  }
  const signingInput = [encodeSection(header),
    encodeSection({...timestamps, ...payload, iss: issuer})
  ].join('.')

  const jwtSigner = SignerAlgorithm(header.alg)
  const signature = await jwtSigner(signingInput, signer)
  return [signingInput, signature].join('.')
}

/**
*  Verifies given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT,
*  and the did doc of the issuer of the JWT.
*
*  @example
*  verifyJWT('did:uport:eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJyZXF1Z....', {audience: '5A8bRWU3F7j3REx3vkJ...', callbackUrl: 'https://...}).then(obj => {
       const did = obj.did // DID of signer
*      const payload = obj.payload
*      const doc = obj.doc // DID Document of signer
*      const jwt = obj.jwt
*      const signerKeyId = obj.signerKeyId // ID of key in DID document that signed JWT
*      ...
*  })
*
*  @param    {String}            jwt                a JSON Web Token to verify
*  @param    {Object}            [config]           an unsigned credential object
*  @param    {Boolean}           config.auth        Require signer to be listed in the authentication section of the DID document (for Authentication purposes)
*  @param    {String}            config.audience    DID of the recipient of the JWT
*  @param    {String}            config.callbackUrl callback url in JWT
*  @return   {Promise<Object, Error>}               a promise which resolves with a response object or rejects with an error
*/
export async function verifyJWT (jwt, options = {}) {
  const aud = options.audience ? normalizeDID(options.audience) : undefined
  const {payload, header, signature, data} = decodeJWT(jwt)
  const {doc, authenticators, issuer} = await resolveAuthenticator(header.alg, payload.iss, options.auth)
  const signer = VerifierAlgorithm(header.alg)(data, signature, authenticators)
  const now = Math.floor(Date.now() / 1000)
  if (signer) {
    if (payload.iat && payload.iat > (now + IAT_SKEW)) {
      throw new Error(`JWT not valid yet (issued in the future): iat: ${payload.iat} > now: ${now}`)
    }
    if (payload.exp && (payload.exp <= (now - IAT_SKEW))) {
      throw new Error(`JWT has expired: exp: ${payload.exp} < now: ${now}`)
    }
    if (payload.aud) {
      if (isDIDOrMNID(payload.aud)) {
        if (!aud) {
          throw new Error('JWT audience is required but your app address has not been configured')
        }

        if (aud !== normalizeDID(payload.aud)) {
          throw new Error(`JWT audience does not match your DID: aud: ${payload.aud} !== yours: ${aud}`)
        }
      } else {
        if (!options.callbackUrl) {
          throw new Error('JWT audience matching your callback url is required but one wasn\'t passed in')
        }
        if (payload.aud !== options.callbackUrl) {
          throw new Error(`JWT audience does not match the callback url: aud: ${payload.aud} !== url: ${options.callbackUrl}`)
        }
      }
    }
    return ({payload, doc, issuer, signer, jwt})
  } else {
    
  }
}

/**
* Resolves relevant public keys or other authenticating material used to verify signature from the DID document of provided DID
*
*  @example
*  resolveAuthenticator('ES256K', 'did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX').then(obj => {
*      const payload = obj.payload
*      const profile = obj.profile
*      const jwt = obj.jwt
*      ...
*  })
*
*  @param    {String}            alg                a JWT algorithm
*  @param    {String}            did                a Decentralized IDentifier (DID) to lookup
*  @param    {Boolean}           auth               Restrict public keys to ones specifically listed in the 'authentication' section of DID document
*  @return   {Promise<Object, Error>}               a promise which resolves with a response object containing an array of authenticators or if non exist rejects with an error
*/

export async function resolveAuthenticator (alg, mnidOrDid, auth) {
  const types = SUPPORTED_PUBLIC_KEY_TYPES[alg]
  if (!types || types.length === 0) throw new Error(`No supported signature types for algorithm ${alg}`)
  const issuer = normalizeDID(mnidOrDid)
  const doc = await resolve(issuer)
  if (!doc) throw new Error(`Unable to resolve DID document for ${issuer}`)
  const authenticationKeys = auth ? (doc.authentication || []).map(({publicKey}) => publicKey) : true
  const authenticators = (doc.publicKey || []).filter(({type, id}) => types.find(supported => supported === type && (!auth || authenticationKeys.indexOf(id) >= 0)))

  if (auth && (!authenticators || authenticators.length === 0)) throw new Error(`DID document for ${issuer} does not have public keys suitable for authenticationg user`)
  if (!authenticators || authenticators.length === 0) throw new Error(`DID document for ${issuer} does not have public keys for ${alg}`)
  return {authenticators, issuer, doc}
}

export default { decodeJWT, createJWT, verifyJWT, resolveAuthenticator }
