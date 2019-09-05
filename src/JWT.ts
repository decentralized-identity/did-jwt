import VerifierAlgorithm from './VerifierAlgorithm'
import SignerAlgorithm from './SignerAlgorithm'
import base64url from 'uport-base64url'
import { DIDDocument, PublicKey } from 'did-resolver'

export interface EcdsaSignature {
  r: string
  s: string
  recoveryParam?: number
}

export type Signer = (data: string) => Promise<EcdsaSignature | string>
export type SignerAlgorithm = (
  payload: string,
  signer: Signer
) => Promise<string>

interface JWTOptions {
  issuer: string
  signer: Signer
  alg?: string
  expiresIn?: number
}

interface Resolvable {
  resolve: (did: string) => Promise<DIDDocument | null>
}

interface JWTVerifyOptions {
  auth?: boolean
  audience?: string
  callbackUrl?: string
  resolver?: Resolvable
}

interface DIDAuthenticator {
  authenticators: PublicKey[]
  issuer: string
  doc: DIDDocument
}

interface JWTHeader {
  typ: 'JWT'
  alg: string
}

interface JWTPayload {
  iss?: string
  sub?: string
  aud?: string
  iat?: number
  nbf?: number
  type?: string
  exp?: number
  rexp?: number
}

interface JWTDecoded {
  header: JWTHeader
  payload: JWTPayload
  signature: string
  data: string
}

interface Verified {
  payload: any
  doc: DIDDocument
  issuer: string
  signer: object
  jwt: string
}

interface PublicKeyTypes {
  [name: string]: string[]
}
const SUPPORTED_PUBLIC_KEY_TYPES: PublicKeyTypes = {
  ES256K: [
    'Secp256k1VerificationKey2018',
    'Secp256k1SignatureVerificationKey2018',
    'EcdsaPublicKeySecp256k1'
  ],
  'ES256K-R': [
    'Secp256k1VerificationKey2018',
    'Secp256k1SignatureVerificationKey2018',
    'EcdsaPublicKeySecp256k1'
  ],
  Ed25519: ['ED25519SignatureVerification']
}

const defaultAlg = 'ES256K'

function encodeSection(data: any): string {
  return base64url.encode(JSON.stringify(data))
}

export const NBF_SKEW: number = 300

/**  @module did-jwt/JWT */

function isMNID(id: string): RegExpMatchArray {
  return id.match(
    /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/
  )
}

function isDIDOrMNID(mnidOrDid: string): RegExpMatchArray {
  return mnidOrDid && (mnidOrDid.match(/^did:/) || isMNID(mnidOrDid))
}

export function normalizeDID(mnidOrDid: string): string {
  if (mnidOrDid.match(/^did:/)) return mnidOrDid
  // Backwards compatibility
  if (isMNID(mnidOrDid)) return `did:uport:${mnidOrDid}`
  throw new Error(`Not a valid DID '${mnidOrDid}'`)
}

/**
 *  Decodes a JWT and returns an object representing the payload
 *
 *  @example
 *  decodeJWT('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1...')
 *
 *  @param    {String}            jwt                a JSON Web Token to verify
 *  @return   {Object}                               a JS object representing the decoded JWT
 */
export function decodeJWT(jwt: string): JWTDecoded {
  if (!jwt) throw new Error('no JWT passed into decodeJWT')
  const parts: RegExpMatchArray = jwt.match(
    /^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/
  )
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
 *  @param    {Object}            [options]           an unsigned credential object
 *  @param    {String}            options.issuer      The DID of the issuer (signer) of JWT
 *  @param    {String}            options.alg         The JWT signing algorithm to use. Supports: [ES256K, ES256K-R, Ed25519], Defaults to: ES256K
 *  @param    {SimpleSigner}      options.signer      a signer, reference our SimpleSigner.js
 *  @return   {Promise<Object, Error>}               a promise which resolves with a signed JSON Web Token or rejects with an error
 */
// export async function createJWT(payload, { issuer, signer, alg, expiresIn }) {
export async function createJWT(
  payload: any,
  { issuer, signer, alg, expiresIn }: JWTOptions
): Promise<string> {
  if (!signer) throw new Error('No Signer functionality has been configured')
  if (!issuer) throw new Error('No issuing DID has been configured')
  const header: JWTHeader = { typ: 'JWT', alg: alg || defaultAlg }
  const timestamps: Partial<JWTPayload> = {
    iat: Math.floor(Date.now() / 1000),
    exp: undefined
  }
  if (expiresIn && payload.nbf) {
    if (typeof expiresIn === 'number') {
      timestamps.exp = payload.nbf + Math.floor(expiresIn)
    } else {
      throw new Error('JWT expiresIn is not a number')
    }
  }
  const signingInput: string = [
    encodeSection(header),
    encodeSection({ ...timestamps, ...payload, iss: issuer })
  ].join('.')

  const jwtSigner: SignerAlgorithm = SignerAlgorithm(header.alg)
  const signature: string = await jwtSigner(signingInput, signer)
  return [signingInput, signature].join('.')
}

/**
 *  Verifies given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT,
 *  and the did doc of the issuer of the JWT.
 *
 *  @example
 *  verifyJWT('did:uport:eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJyZXF1Z....', {audience: '5A8bRWU3F7j3REx3vkJ...', callbackUrl: 'https://...'}).then(obj => {
 *      const did = obj.did // DID of signer
 *      const payload = obj.payload
 *      const doc = obj.doc // DID Document of signer
 *      const jwt = obj.jwt
 *      const signerKeyId = obj.signerKeyId // ID of key in DID document that signed JWT
 *      ...
 *  })
 *
 *  @param    {String}            jwt                a JSON Web Token to verify
 *  @param    {Object}            [options]           an unsigned credential object
 *  @param    {Boolean}           options.auth        Require signer to be listed in the authentication section of the DID document (for Authentication purposes)
 *  @param    {String}            options.audience    DID of the recipient of the JWT
 *  @param    {String}            options.callbackUrl callback url in JWT
 *  @return   {Promise<Object, Error>}               a promise which resolves with a response object or rejects with an error
 */
export async function verifyJWT(
  jwt: string,
  options: JWTVerifyOptions = { resolver: null, auth: null, audience: null, callbackUrl: null }
): Promise<Verified> {
  if (!options.resolver) throw new Error('No DID resolver has been configured')
  const aud: string = options.audience
    ? normalizeDID(options.audience)
    : undefined
  const { payload, header, signature, data }: JWTDecoded = decodeJWT(jwt)
  const {
    doc,
    authenticators,
    issuer
  }: DIDAuthenticator = await resolveAuthenticator(
    options.resolver,
    header.alg,
    payload.iss,
    options.auth
  )
  const signer: PublicKey = VerifierAlgorithm(header.alg)(
    data,
    signature,
    authenticators
  )
  const now: number = Math.floor(Date.now() / 1000)
  if (signer) {
    const nowSkewed = now + NBF_SKEW
    if (payload.nbf) {
      if (payload.nbf > nowSkewed) {
        throw new Error(`JWT not valid before nbf: ${payload.nbf}`)
      }
    } else if (payload.iat && payload.iat > nowSkewed) {
      throw new Error(`JWT not valid yet (issued in the future) iat: ${payload.iat}`)
    }
    if (payload.exp && payload.exp <= now - NBF_SKEW) {
      throw new Error(`JWT has expired: exp: ${payload.exp} < now: ${now}`)
    }
    if (payload.aud) {
      if (isDIDOrMNID(payload.aud)) {
        if (!aud) {
          throw new Error(
            'JWT audience is required but your app address has not been configured'
          )
        }

        if (aud !== normalizeDID(payload.aud)) {
          throw new Error(
            `JWT audience does not match your DID: aud: ${
              payload.aud
            } !== yours: ${aud}`
          )
        }
      } else {
        if (!options.callbackUrl) {
          throw new Error(
            "JWT audience matching your callback url is required but one wasn't passed in"
          )
        }
        if (payload.aud !== options.callbackUrl) {
          throw new Error(
            `JWT audience does not match the callback url: aud: ${
              payload.aud
            } !== url: ${options.callbackUrl}`
          )
        }
      }
    }
    return { payload, doc, issuer, signer, jwt }
  }
}

/**
 * Resolves relevant public keys or other authenticating material used to verify signature from the DID document of provided DID
 *
 *  @example
 *  resolveAuthenticator(resolver, 'ES256K', 'did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX').then(obj => {
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
export async function resolveAuthenticator(
  resolver: Resolvable,
  alg: string,
  mnidOrDid: string,
  auth?: boolean
): Promise<DIDAuthenticator> {
  const types: string[] = SUPPORTED_PUBLIC_KEY_TYPES[alg]
  if (!types || types.length === 0) {
    throw new Error(`No supported signature types for algorithm ${alg}`)
  }
  const issuer: string = normalizeDID(mnidOrDid)
  const doc: DIDDocument = await resolver.resolve(issuer)
  if (!doc) throw new Error(`Unable to resolve DID document for ${issuer}`)
  // is there some way to have authenticationKeys be a single type?
  const authenticationKeys: boolean | string[] = auth
    ? (doc.authentication || []).map(({ publicKey }) => publicKey)
    : true
  const authenticators: PublicKey[] = (doc.publicKey || []).filter(
    ({ type, id }) =>
      types.find(
        supported =>
          supported === type &&
          (!auth ||
            (Array.isArray(authenticationKeys) &&
              authenticationKeys.indexOf(id) >= 0))
      )
  )

  if (auth && (!authenticators || authenticators.length === 0)) {
    throw new Error(
      `DID document for ${issuer} does not have public keys suitable for authenticationg user`
    )
  }
  if (!authenticators || authenticators.length === 0) {
    throw new Error(
      `DID document for ${issuer} does not have public keys for ${alg}`
    )
  }
  return { authenticators, issuer, doc }
}
