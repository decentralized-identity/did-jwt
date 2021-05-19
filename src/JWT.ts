import canonicalizeData from 'canonicalize'
import type { DIDDocument, DIDResolutionResult, Resolvable, VerificationMethod } from 'did-resolver'
import SignerAlg from './SignerAlgorithm'
import { decodeBase64url, EcdsaSignature, encodeBase64url } from './util'
import VerifierAlgorithm from './VerifierAlgorithm'

export type Signer = (data: string | Uint8Array) => Promise<EcdsaSignature | string>
export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>

export interface JWTOptions {
  issuer: string
  signer: Signer
  /**
   * @deprecated Please use `header.alg` to specify the JWT algorithm.
   */
  alg?: string
  expiresIn?: number
  canonicalize?: boolean
}

export interface JWTVerifyOptions {
  /** @deprecated Please use `proofPurpose: 'authentication' instead` */
  auth?: boolean
  audience?: string
  callbackUrl?: string
  resolver?: Resolvable
  skewTime?: number
  /** See https://www.w3.org/TR/did-spec-registries/#verification-relationships */
  proofPurpose?: 'authentication' | 'assertionMethod' | 'capabilityDelegation' | 'capabilityInvocation' | string
}

export interface JWSCreationOptions {
  canonicalize?: boolean
}

export interface DIDAuthenticator {
  authenticators: VerificationMethod[]
  issuer: string
  didResolutionResult: DIDResolutionResult
}

export interface JWTHeader {
  typ: 'JWT'
  alg: string
  [x: string]: any
}

export interface JWTPayload {
  iss?: string
  sub?: string
  aud?: string | string[]
  iat?: number
  nbf?: number
  type?: string
  exp?: number
  rexp?: number
  [x: string]: any
}

export interface JWTDecoded {
  header: JWTHeader
  payload: JWTPayload
  signature: string
  data: string
}

export interface JWSDecoded {
  header: JWTHeader
  payload: string
  signature: string
  data: string
}

export interface JWTVerified {
  payload: any
  didResolutionResult: DIDResolutionResult
  issuer: string
  signer: object
  jwt: string
}

export interface PublicKeyTypes {
  [name: string]: string[]
}
export const SUPPORTED_PUBLIC_KEY_TYPES: PublicKeyTypes = {
  ES256K: [
    'EcdsaSecp256k1VerificationKey2019',
    /**
     * Equivalent to EcdsaSecp256k1VerificationKey2019 when key is an ethereumAddress
     */
    'EcdsaSecp256k1RecoveryMethod2020',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is not an ethereumAddress
     */
    'Secp256k1VerificationKey2018',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is not an ethereumAddress
     */
    'Secp256k1SignatureVerificationKey2018',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is not an ethereumAddress
     */
    'EcdsaPublicKeySecp256k1'
  ],
  'ES256K-R': [
    'EcdsaSecp256k1VerificationKey2019',
    /**
     * Equivalent to EcdsaSecp256k1VerificationKey2019 when key is an ethereumAddress
     */
    'EcdsaSecp256k1RecoveryMethod2020',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is not an ethereumAddress
     */
    'Secp256k1VerificationKey2018',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is not an ethereumAddress
     */
    'Secp256k1SignatureVerificationKey2018',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is not an ethereumAddress
     */
    'EcdsaPublicKeySecp256k1'
  ],
  Ed25519: ['ED25519SignatureVerification', 'Ed25519VerificationKey2018'],
  EdDSA: ['ED25519SignatureVerification', 'Ed25519VerificationKey2018']
}

const defaultAlg = 'ES256K'
const DID_JSON = 'application/did+json'

function encodeSection(data: any, shouldCanonicalize: boolean = false): string {
  if (shouldCanonicalize) {
    return encodeBase64url(canonicalizeData(data))
  } else {
    return encodeBase64url(JSON.stringify(data))
  }
}

export const NBF_SKEW: number = 300

function decodeJWS(jws: string): JWSDecoded {
  const parts: RegExpMatchArray = jws.match(/^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
  if (parts) {
    return {
      header: JSON.parse(decodeBase64url(parts[1])),
      payload: parts[2],
      signature: parts[3],
      data: `${parts[1]}.${parts[2]}`
    }
  }
  throw new Error('Incorrect format JWS')
}

/**  @module did-jwt/JWT */

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
  try {
    const jws = decodeJWS(jwt)
    const decodedJwt: JWTDecoded = Object.assign(jws, { payload: JSON.parse(decodeBase64url(jws.payload)) })
    return decodedJwt
  } catch (e) {
    throw new Error('Incorrect format JWT')
  }
}

/**
 *  Creates a signed JWS given a payload, a signer, and an optional header.
 *
 *  @example
 *  const signer = ES256KSigner(process.env.PRIVATE_KEY)
 *  const jws = await createJWS({ my: 'payload' }, signer)
 *
 *  @param    {Object}            payload           payload object
 *  @param    {Signer}            signer            a signer, see `ES256KSigner or `EdDSASigner`
 *  @param    {Object}            header            optional object to specify or customize the JWS header
 *  @return   {Promise<Object, Error>}              a promise which resolves with a JWS string or rejects with an error
 */
export async function createJWS(
  payload: string | any,
  signer: Signer,
  header: Partial<JWTHeader> = {},
  options: JWSCreationOptions = {}
): Promise<string> {
  if (!header.alg) header.alg = defaultAlg
  const encodedPayload = typeof payload === 'string' ? payload : encodeSection(payload, options.canonicalize)
  const signingInput: string = [encodeSection(header, options.canonicalize), encodedPayload].join('.')

  const jwtSigner: SignerAlgorithm = SignerAlg(header.alg)
  const signature: string = await jwtSigner(signingInput, signer)
  return [signingInput, signature].join('.')
}

/**
 *  Creates a signed JWT given an address which becomes the issuer, a signer, and a payload for which the signature is over.
 *
 *  @example
 *  const signer = ES256KSigner(process.env.PRIVATE_KEY)
 *  createJWT({address: '5A8bRWU3F7j3REx3vkJ...', signer}, {key1: 'value', key2: ..., ... }).then(jwt => {
 *      ...
 *  })
 *
 *  @param    {Object}            payload               payload object
 *  @param    {Object}            [options]             an unsigned credential object
 *  @param    {String}            options.issuer        The DID of the issuer (signer) of JWT
 *  @param    {String}            options.alg           [DEPRECATED] The JWT signing algorithm to use. Supports: [ES256K, ES256K-R, Ed25519, EdDSA], Defaults to: ES256K.
 *                                                      Please use `header.alg` to specify the algorithm
 *  @param    {Signer}            options.signer        a `Signer` function, Please see `ES256KSigner` or `EdDSASigner`
 *  @param    {boolean}           options.canonicalize  optional flag to canonicalize header and payload before signing
 *  @param    {Object}            header                optional object to specify or customize the JWT header
 *  @return   {Promise<Object, Error>}                  a promise which resolves with a signed JSON Web Token or rejects with an error
 */
export async function createJWT(
  payload: any,
  { issuer, signer, alg, expiresIn, canonicalize }: JWTOptions,
  header: Partial<JWTHeader> = {}
): Promise<string> {
  if (!signer) throw new Error('No Signer functionality has been configured')
  if (!issuer) throw new Error('No issuing DID has been configured')
  if (!header.typ) header.typ = 'JWT'
  if (!header.alg) header.alg = alg
  const timestamps: Partial<JWTPayload> = {
    iat: Math.floor(Date.now() / 1000),
    exp: undefined
  }
  if (expiresIn) {
    if (typeof expiresIn === 'number') {
      timestamps.exp = (payload.nbf || timestamps.iat) + Math.floor(expiresIn)
    } else {
      throw new Error('JWT expiresIn is not a number')
    }
  }
  const fullPayload = { ...timestamps, ...payload, iss: issuer }
  return createJWS(fullPayload, signer, header, { canonicalize })
}

function verifyJWSDecoded(
  { header, data, signature }: JWSDecoded,
  pubkeys: VerificationMethod | VerificationMethod[]
): VerificationMethod {
  if (!Array.isArray(pubkeys)) pubkeys = [pubkeys]
  const signer: VerificationMethod = VerifierAlgorithm(header.alg)(data, signature, pubkeys)
  return signer
}

/**
 *  Verifies given JWS. If the JWS is valid, returns the public key that was
 *  used to sign the JWS, or throws an `Error` if none of the `pubkeys` match.
 *
 *  @example
 *  const pubkey = verifyJWT('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJyZXF1Z....', { publicKeyHex: '0x12341...' })
 *
 *  @param    {String}                          jws         A JWS string to verify
 *  @param    {Array<VerificationMethod> | VerificationMethod}    pubkeys     The public keys used to verify the JWS
 *  @return   {VerificationMethod}                       The public key used to sign the JWS
 */
export function verifyJWS(jws: string, pubkeys: VerificationMethod | VerificationMethod[]): VerificationMethod {
  const jwsDecoded: JWSDecoded = decodeJWS(jws)
  return verifyJWSDecoded(jwsDecoded, pubkeys)
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
  options: JWTVerifyOptions = {
    resolver: null,
    auth: null,
    audience: null,
    callbackUrl: null,
    skewTime: null,
    proofPurpose: null
  }
): Promise<JWTVerified> {
  if (!options.resolver) throw new Error('No DID resolver has been configured')
  const { payload, header, signature, data }: JWTDecoded = decodeJWT(jwt)
  const proofPurpose: string | undefined = options.hasOwnProperty('auth')
    ? options.auth
      ? 'authentication'
      : undefined
    : options.proofPurpose
  const { didResolutionResult, authenticators, issuer }: DIDAuthenticator = await resolveAuthenticator(
    options.resolver,
    header.alg,
    payload.iss,
    proofPurpose
  )
  const signer: VerificationMethod = await verifyJWSDecoded({ header, data, signature } as JWSDecoded, authenticators)
  const now: number = Math.floor(Date.now() / 1000)
  const skewTime = options.skewTime >= 0 ? options.skewTime : NBF_SKEW
  if (signer) {
    const nowSkewed = now + skewTime
    if (payload.nbf) {
      if (payload.nbf > nowSkewed) {
        throw new Error(`JWT not valid before nbf: ${payload.nbf}`)
      }
    } else if (payload.iat && payload.iat > nowSkewed) {
      throw new Error(`JWT not valid yet (issued in the future) iat: ${payload.iat}`)
    }
    if (payload.exp && payload.exp <= now - skewTime) {
      throw new Error(`JWT has expired: exp: ${payload.exp} < now: ${now}`)
    }
    if (payload.aud) {
      if (!options.audience && !options.callbackUrl) {
        throw new Error('JWT audience is required but your app address has not been configured')
      }
      const audArray = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
      const matchedAudience = audArray.find((item) => options.audience === item || options.callbackUrl === item)

      if (typeof matchedAudience === 'undefined') {
        throw new Error(`JWT audience does not match your DID or callback url`)
      }
    }
    return { payload, didResolutionResult, issuer, signer, jwt }
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
 *  @return   {Promise<DIDAuthenticator>}               a promise which resolves with a response object containing an array of authenticators or if non exist rejects with an error
 */
export async function resolveAuthenticator(
  resolver: Resolvable,
  alg: string,
  issuer: string,
  proofPurpose?: string
): Promise<DIDAuthenticator> {
  const types: string[] = SUPPORTED_PUBLIC_KEY_TYPES[alg]
  if (!types || types.length === 0) {
    throw new Error(`No supported signature types for algorithm ${alg}`)
  }
  let didResult: DIDResolutionResult

  const result = (await resolver.resolve(issuer, { accept: DID_JSON })) as unknown
  // support legacy resolvers that do not produce DIDResolutionResult
  if (Object.getOwnPropertyNames(result).indexOf('didDocument') === -1) {
    didResult = {
      didDocument: result as DIDDocument,
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: DID_JSON }
    }
  } else {
    didResult = result as DIDResolutionResult
  }

  if (didResult.didResolutionMetadata?.error) {
    const { error, message } = didResult.didResolutionMetadata
    throw new Error(`Unable to resolve DID document for ${issuer}: ${error}, ${message || ''}`)
  }

  const getPublicKeyById = (verificationMethods: VerificationMethod[], pubid: string): VerificationMethod | null => {
    const filtered = verificationMethods.filter(({ id }) => pubid === id)
    return filtered.length > 0 ? filtered[0] : null
  }

  let publicKeysToCheck: VerificationMethod[] = [
    ...(didResult?.didDocument?.verificationMethod || []),
    ...(didResult?.didDocument?.publicKey || [])
  ]
  if (typeof proofPurpose === 'string') {
    // support legacy DID Documents that do not list assertionMethod
    if (proofPurpose.startsWith('assertion') && !didResult.didDocument.hasOwnProperty('assertionMethod')) {
      didResult.didDocument.assertionMethod = [...publicKeysToCheck.map((pk) => pk.id)]
    }

    publicKeysToCheck = (didResult.didDocument[proofPurpose] || [])
      .map((verificationMethod) => {
        if (typeof verificationMethod === 'string') {
          return getPublicKeyById(publicKeysToCheck, verificationMethod)
        } else if (typeof (<any>verificationMethod).publicKey === 'string') {
          // this is a legacy format
          return getPublicKeyById(publicKeysToCheck, (<any>verificationMethod).publicKey)
        } else {
          return <VerificationMethod>verificationMethod
        }
      })
      .filter((key) => key != null)
  }

  const authenticators: VerificationMethod[] = publicKeysToCheck.filter(({ type }) =>
    types.find((supported) => supported === type)
  )

  if (typeof proofPurpose === 'string' && (!authenticators || authenticators.length === 0)) {
    throw new Error(
      `DID document for ${issuer} does not have public keys suitable for ${alg} with ${proofPurpose} purpose`
    )
  }
  if (!authenticators || authenticators.length === 0) {
    throw new Error(`DID document for ${issuer} does not have public keys for ${alg}`)
  }
  return { authenticators, issuer, didResolutionResult: didResult }
}
